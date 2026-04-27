#!/usr/bin/env bash
# Integration test for SNI-based backend routing.
#
# Spins up three PostgreSQL backends via docker compose, starts the proxy with
# different configs, and verifies SNI-based routing behavior including:
#   - Basic SNI routing to 3 backends
#   - Unknown SNI rejection (no default backend)
#   - Default backend fallback
#   - Write operations (INSERT/SELECT) through the proxy
#   - Multiple queries in a single session
#   - Concurrent connections to different backends
#   - Repeated connections are consistent
#
# Usage: ./tests/integration.sh
#
# Requirements: docker, docker compose, cargo
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROXY_PID=""
COMPOSE_STARTED=false

PASS=0
FAIL=0
TOTAL=0
PROXY_PORT=15431

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    stop_proxy
    if [ "$COMPOSE_STARTED" = true ]; then
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" down -v 2>/dev/null || true
        echo "Stopped docker compose"
    fi
}

trap cleanup EXIT

stop_proxy() {
    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        # Use SIGINT for a quick shutdown (pingora exits immediately on SIGINT)
        kill -INT "$PROXY_PID" 2>/dev/null || true
        # Wait briefly, then force kill if still running
        for _ in 1 2 3 4 5; do
            kill -0 "$PROXY_PID" 2>/dev/null || break
            sleep 0.5
        done
        kill -9 "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
        echo "Stopped proxy (pid $PROXY_PID)"
        PROXY_PID=""
    fi
}

start_proxy() {
    local config="$1"
    stop_proxy
    RUST_LOG=info "$PROJECT_DIR/target/debug/pgproxy" \
        --cert-path "$PROJECT_DIR/local-certs/server/server.crt" \
        --key-path "$PROJECT_DIR/local-certs/server/key.pem" \
        --config "$config" &
    PROXY_PID=$!

    # Wait for proxy to be ready (retry connecting for up to 5 seconds)
    local retries=0
    while [ $retries -lt 10 ]; do
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            echo "FATAL: Proxy process exited unexpectedly"
            exit 1
        fi
        if bash -c "echo > /dev/tcp/127.0.0.1/$PROXY_PORT" 2>/dev/null; then
            echo "Proxy is ready (pid $PROXY_PID, config: $(basename "$config"))"
            return 0
        fi
        sleep 0.5
        retries=$((retries + 1))
    done
    echo "FATAL: Proxy failed to start accepting connections"
    exit 1
}

# Run a psql query through the proxy with a given SNI hostname.
# Uses hostaddr to set the actual IP while host controls the SNI.
run_query() {
    local sni="$1"
    shift
    docker run --rm --network host \
        -e PGCONNECT_TIMEOUT=5 \
        postgres:16-alpine \
        psql "hostaddr=127.0.0.1 host=$sni port=$PROXY_PORT user=postgres password=postgres dbname=postgres sslmode=require" \
        -t -A "$@" 2>/dev/null
}

# Run multiple SQL statements in one psql session via a single command string.
run_multi_query() {
    local sni="$1"
    local sql="$2"
    docker run --rm --network host \
        -e PGCONNECT_TIMEOUT=5 \
        postgres:16-alpine \
        psql "hostaddr=127.0.0.1 host=$sni port=$PROXY_PORT user=postgres password=postgres dbname=postgres sslmode=require" \
        -t -A -c "$sql" 2>/dev/null
}

assert_eq() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    actual=$(echo "$actual" | tr -d '[:space:]')
    if [ "$actual" = "$expected" ]; then
        echo "  PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $test_name (expected '$expected', got '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

assert_fail() {
    local test_name="$1"
    local exit_code="$2"
    TOTAL=$((TOTAL + 1))
    if [ "$exit_code" -ne 0 ]; then
        echo "  PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $test_name (expected failure but succeeded)"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

echo "=== Starting PostgreSQL backends (pg1, pg2, pg3) ==="
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d --wait
COMPOSE_STARTED=true
echo "All backends are ready"

echo ""
echo "=== Building proxy ==="
cargo build --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1

# ===================================================================
# PHASE 1: Tests with no default backend (test-config.json)
# ===================================================================
echo ""
echo "==========================================="
echo " PHASE 1: SNI routing (no default backend)"
echo "==========================================="
start_proxy "$SCRIPT_DIR/test-config.json"

# --- Basic SNI routing ---
echo ""
echo "--- Basic SNI routing ---"

RESULT=$(run_query "db1.db.local" -c "SELECT id FROM backend_info LIMIT 1;") || true
assert_eq "db1.db.local -> pg1" "pg1" "$RESULT"

RESULT=$(run_query "db2.db.local" -c "SELECT id FROM backend_info LIMIT 1;") || true
assert_eq "db2.db.local -> pg2" "pg2" "$RESULT"

RESULT=$(run_query "db3.db.local" -c "SELECT id FROM backend_info LIMIT 1;") || true
assert_eq "db3.db.local -> pg3" "pg3" "$RESULT"

# --- Unknown SNI rejection ---
echo ""
echo "--- Unknown SNI rejection ---"

if run_query "unknown.host" -c "SELECT 1;" >/dev/null 2>&1; then
    assert_fail "unknown SNI is rejected" 0
else
    assert_fail "unknown SNI is rejected" 1
fi

if run_query "not-a-backend.db.local" -c "SELECT 1;" >/dev/null 2>&1; then
    assert_fail "unregistered *.db.local SNI is rejected" 0
else
    assert_fail "unregistered *.db.local SNI is rejected" 1
fi

# --- Write operations through the proxy ---
echo ""
echo "--- Write operations ---"

run_query "db1.db.local" -c "INSERT INTO test_data (key, value) VALUES ('k1', 'hello_from_pg1');" >/dev/null 2>&1 || true
RESULT=$(run_query "db1.db.local" -c "SELECT value FROM test_data WHERE key = 'k1';") || true
assert_eq "INSERT+SELECT on pg1 via proxy" "hello_from_pg1" "$RESULT"

run_query "db2.db.local" -c "INSERT INTO test_data (key, value) VALUES ('k2', 'hello_from_pg2');" >/dev/null 2>&1 || true
RESULT=$(run_query "db2.db.local" -c "SELECT value FROM test_data WHERE key = 'k2';") || true
assert_eq "INSERT+SELECT on pg2 via proxy" "hello_from_pg2" "$RESULT"

# --- Data isolation: writes to pg1 should not appear on pg2 ---
echo ""
echo "--- Data isolation between backends ---"

RESULT=$(run_query "db2.db.local" -c "SELECT count(*) FROM test_data WHERE key = 'k1';") || true
assert_eq "pg1 write not visible on pg2" "0" "$RESULT"

RESULT=$(run_query "db1.db.local" -c "SELECT count(*) FROM test_data WHERE key = 'k2';") || true
assert_eq "pg2 write not visible on pg1" "0" "$RESULT"

# --- Multiple queries in a single session ---
echo ""
echo "--- Multi-statement session ---"

# Use separate -c flags so psql runs them as separate commands in one session.
# We only care about the last SELECT result.
RESULT=$(run_query "db1.db.local" \
    -c "INSERT INTO test_data (key, value) VALUES ('multi1', 'val1');" \
    -c "INSERT INTO test_data (key, value) VALUES ('multi2', 'val2');" \
    -c "SELECT count(*) FROM test_data WHERE key LIKE 'multi%';") || true
# psql -t -A outputs each command result on its own line; grab the last line
RESULT=$(echo "$RESULT" | tail -1)
assert_eq "multi-statement INSERT+SELECT in one session" "2" "$RESULT"

# --- Repeated connections are consistent ---
echo ""
echo "--- Repeated connection consistency ---"

for i in 1 2 3 4 5; do
    RESULT=$(run_query "db1.db.local" -c "SELECT id FROM backend_info LIMIT 1;") || true
    RESULT=$(echo "$RESULT" | tr -d '[:space:]')
    if [ "$RESULT" != "pg1" ]; then
        FAIL=$((FAIL + 1))
        TOTAL=$((TOTAL + 1))
        echo "  FAIL: repeated connection #$i to db1.db.local got '$RESULT' (expected 'pg1')"
        break
    fi
done
if [ "$RESULT" = "pg1" ]; then
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
    echo "  PASS: 5 repeated connections to db1.db.local all routed to pg1"
fi

# --- Concurrent connections to different backends ---
echo ""
echo "--- Concurrent connections ---"

TMPDIR=$(mktemp -d)
PIDS=""
for sni in db1.db.local db2.db.local db3.db.local; do
    timeout 15 docker run --rm --network host \
        -e PGCONNECT_TIMEOUT=5 \
        postgres:16-alpine \
        psql "hostaddr=127.0.0.1 host=$sni port=$PROXY_PORT user=postgres password=postgres dbname=postgres sslmode=require" \
        -t -A -c "SELECT id FROM backend_info LIMIT 1;" > "$TMPDIR/$sni" 2>/dev/null &
    PIDS="$PIDS $!"
done
# Wait for all background jobs with a global timeout
for pid in $PIDS; do
    wait "$pid" 2>/dev/null || true
done

C1=$(cat "$TMPDIR/db1.db.local" 2>/dev/null | tr -d '[:space:]')
C2=$(cat "$TMPDIR/db2.db.local" 2>/dev/null | tr -d '[:space:]')
C3=$(cat "$TMPDIR/db3.db.local" 2>/dev/null | tr -d '[:space:]')
rm -rf "$TMPDIR"

assert_eq "concurrent: db1.db.local -> pg1" "pg1" "$C1"
assert_eq "concurrent: db2.db.local -> pg2" "pg2" "$C2"
assert_eq "concurrent: db3.db.local -> pg3" "pg3" "$C3"

# ===================================================================
# PHASE 2: Tests with default backend (test-config-with-default.json)
# ===================================================================
echo ""
echo "==========================================="
echo " PHASE 2: SNI routing (with default backend)"
echo "==========================================="
start_proxy "$SCRIPT_DIR/test-config-with-default.json"

# --- Matched SNIs still work ---
echo ""
echo "--- Matched SNIs still route correctly ---"

RESULT=$(run_query "db1.db.local" -c "SELECT id FROM backend_info LIMIT 1;") || true
assert_eq "db1.db.local -> pg1 (with default)" "pg1" "$RESULT"

RESULT=$(run_query "db2.db.local" -c "SELECT id FROM backend_info LIMIT 1;") || true
assert_eq "db2.db.local -> pg2 (with default)" "pg2" "$RESULT"

# --- Unknown SNI falls back to default backend (pg3) ---
echo ""
echo "--- Default backend fallback ---"

RESULT=$(run_query "unknown.host" -c "SELECT id FROM backend_info LIMIT 1;") || true
assert_eq "unknown SNI falls back to default (pg3)" "pg3" "$RESULT"

RESULT=$(run_query "another-unknown.example.com" -c "SELECT id FROM backend_info LIMIT 1;") || true
assert_eq "another unknown SNI falls back to default (pg3)" "pg3" "$RESULT"

# --- Writes through default backend ---
echo ""
echo "--- Write through default backend ---"

run_query "fallback.test" -c "INSERT INTO test_data (key, value) VALUES ('default_write', 'via_fallback');" >/dev/null 2>&1 || true
RESULT=$(run_query "fallback.test" -c "SELECT value FROM test_data WHERE key = 'default_write';") || true
assert_eq "INSERT+SELECT on default backend via unknown SNI" "via_fallback" "$RESULT"

# Verify it actually went to pg3, not pg1 or pg2
RESULT=$(run_query "db1.db.local" -c "SELECT count(*) FROM test_data WHERE key = 'default_write';") || true
assert_eq "default backend write not visible on pg1" "0" "$RESULT"

# ===================================================================
# Results
# ===================================================================
echo ""
echo "==========================================="
echo " Results: $PASS/$TOTAL passed, $FAIL failed"
echo "==========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
