#!/usr/bin/env bash
# Integration test for SNI-based backend routing.
#
# Spins up two PostgreSQL backends via docker compose, starts the proxy with
# a test config, then verifies that connections with different SNI hostnames
# are routed to the correct backend.
#
# Usage: ./tests/integration.sh
#
# Requirements: docker, docker compose, cargo
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROXY_PID=""
COMPOSE_STARTED=false

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
        echo "Stopped proxy (pid $PROXY_PID)"
    fi
    if [ "$COMPOSE_STARTED" = true ]; then
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" down -v 2>/dev/null || true
        echo "Stopped docker compose"
    fi
}

trap cleanup EXIT

# --- 1. Start PostgreSQL backends ---
echo "=== Starting PostgreSQL backends ==="
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d --wait
COMPOSE_STARTED=true
echo "Backends are ready"

# --- 2. Build the proxy ---
echo ""
echo "=== Building proxy ==="
cargo build --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1

# --- 3. Start the proxy ---
echo ""
echo "=== Starting proxy ==="
RUST_LOG=info "$PROJECT_DIR/target/debug/pgproxy" \
    --cert-path "$PROJECT_DIR/local-certs/server/server.crt" \
    --key-path "$PROJECT_DIR/local-certs/server/key.pem" \
    --config "$SCRIPT_DIR/test-config.json" &
PROXY_PID=$!
sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "FAIL: Proxy failed to start"
    exit 1
fi
echo "Proxy is running (pid $PROXY_PID)"

# --- 4. Run tests ---
PASS=0
FAIL=0

run_query() {
    local sni="$1"
    local query="$2"
    # Use psql from a postgres container with host networking to connect
    # through the proxy. hostaddr sets the IP, host sets the SNI hostname.
    docker run --rm --network host \
        -e PGCONNECT_TIMEOUT=5 \
        postgres:16-alpine \
        psql "hostaddr=127.0.0.1 host=$sni port=15431 user=postgres password=postgres dbname=postgres sslmode=require" \
        -t -A -c "$query" 2>/dev/null
}

assert_eq() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    actual=$(echo "$actual" | tr -d '[:space:]')
    if [ "$actual" = "$expected" ]; then
        echo "  PASS: $test_name (got '$actual')"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $test_name (expected '$expected', got '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "=== Test 1: SNI db1.db.local routes to pg1 ==="
RESULT=$(run_query "db1.db.local" "SELECT id FROM backend_info LIMIT 1;") || true
assert_eq "db1.db.local -> pg1" "pg1" "$RESULT"

echo ""
echo "=== Test 2: SNI db2.db.local routes to pg2 ==="
RESULT=$(run_query "db2.db.local" "SELECT id FROM backend_info LIMIT 1;") || true
assert_eq "db2.db.local -> pg2" "pg2" "$RESULT"

echo ""
echo "=== Test 3: Unknown SNI is rejected (no default backend) ==="
# The test config has no default_backend, so an unknown SNI should fail
if run_query "unknown.host" "SELECT 1;" >/dev/null 2>&1; then
    echo "  FAIL: unknown SNI should have been rejected"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: unknown SNI was rejected"
    PASS=$((PASS + 1))
fi

# --- 5. Report results ---
echo ""
echo "==============================="
echo "Results: $PASS passed, $FAIL failed"
echo "==============================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
