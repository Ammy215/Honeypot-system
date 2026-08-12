-- HoneyShield v2 schema — SQLite (local dev only), adapted from schema_postgres.sql.
-- Same tables/columns; Postgres-only types (INET, JSONB, TIMESTAMPTZ, BIGSERIAL, now())
-- are mapped to SQLite equivalents. Applied via database/db_async.py when DATABASE_URL
-- is not set (SQLITE_PATH is used instead).

CREATE TABLE IF NOT EXISTS attackers (
    ip_address        TEXT PRIMARY KEY,
    first_seen        TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen         TEXT NOT NULL DEFAULT (datetime('now')),
    country           TEXT,
    city              TEXT,
    asn               TEXT,
    isp               TEXT,
    is_tor_exit       INTEGER DEFAULT 0,
    abuseipdb_score   INTEGER,
    otx_pulse_count   INTEGER DEFAULT 0,
    threat_score      INTEGER DEFAULT 0,
    verdict           TEXT,
    total_connections INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS connections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address      TEXT REFERENCES attackers(ip_address),
    service         TEXT NOT NULL,
    port            INTEGER NOT NULL,
    connected_at    TEXT NOT NULL DEFAULT (datetime('now')),
    disconnected_at TEXT,
    bytes_sent      INTEGER DEFAULT 0,
    bytes_received  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id INTEGER REFERENCES connections(id),
    ip_address    TEXT REFERENCES attackers(ip_address),
    username      TEXT,
    password      TEXT,
    attempted_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS attacker_commands (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id INTEGER REFERENCES connections(id),
    ip_address    TEXT REFERENCES attackers(ip_address),
    command_text  TEXT,
    issued_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address    TEXT REFERENCES attackers(ip_address),
    alert_type    TEXT NOT NULL,
    severity      TEXT NOT NULL,
    evidence      TEXT,                    -- JSON stored as text (no JSONB in SQLite)
    acknowledged  INTEGER DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ai_reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address    TEXT REFERENCES attackers(ip_address),
    report_text   TEXT,
    generated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS service_stats (
    service           TEXT PRIMARY KEY,
    total_connections INTEGER DEFAULT 0,
    last_hit          TEXT
);

CREATE TABLE IF NOT EXISTS ioc_matches (
    ip_address    TEXT PRIMARY KEY REFERENCES attackers(ip_address),
    matched_list  TEXT,
    matched_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS admin_users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    locked_until    TEXT,
    last_login      TEXT
);

CREATE INDEX IF NOT EXISTS idx_connections_ip_time ON connections(ip_address, connected_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_address, attempted_at);
