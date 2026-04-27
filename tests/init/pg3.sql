CREATE TABLE backend_info (id TEXT PRIMARY KEY);
INSERT INTO backend_info VALUES ('pg3');

-- Writable test table for verifying write operations through the proxy
CREATE TABLE test_data (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
