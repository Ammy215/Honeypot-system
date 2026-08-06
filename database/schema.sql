-- Core attacker identity table
CREATE TABLE IF NOT EXISTS attackers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address      TEXT NOT NULL UNIQUE,
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_connections INTEGER DEFAULT 0,
    total_login_attempts INTEGER DEFAULT 0,
    unique_usernames INTEGER DEFAULT 0,
    unique_passwords INTEGER DEFAULT 0,
    threat_score    INTEGER DEFAULT 0,
    verdict         TEXT DEFAULT 'UNKNOWN',
    country         TEXT,
    country_code    TEXT,
    city            TEXT,
    region          TEXT,
    isp             TEXT,
    asn             TEXT,
    latitude        REAL,
    longitude       REAL,
    abuseipdb_score INTEGER DEFAULT 0,
    otx_pulses      INTEGER DEFAULT 0,
    is_known_bad    INTEGER DEFAULT 0,
    is_tor_exit     INTEGER DEFAULT 0,
    geo_enriched    INTEGER DEFAULT 0,
    intel_enriched  INTEGER DEFAULT 0,
    notes           TEXT
);

-- Every single connection attempt recorded
CREATE TABLE IF NOT EXISTS connections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attacker_id     INTEGER REFERENCES attackers(id),
    ip_address      TEXT NOT NULL,
    source_port     INTEGER,
    destination_port INTEGER NOT NULL,
    service_name    TEXT NOT NULL,
    protocol        TEXT DEFAULT 'TCP',
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    duration_seconds REAL DEFAULT 0,
    bytes_received  INTEGER DEFAULT 0,
    raw_data        TEXT,
    connection_closed_by TEXT DEFAULT 'server'
);

-- Every credential attempt
CREATE TABLE IF NOT EXISTS login_attempts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attacker_id     INTEGER REFERENCES attackers(id),
    ip_address      TEXT NOT NULL,
    service_name    TEXT NOT NULL,
    username        TEXT,
    password_attempt TEXT,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    attempt_number  INTEGER DEFAULT 1,
    time_since_last_attempt REAL
);

-- Raw commands/input sent by attacker after "login"
CREATE TABLE IF NOT EXISTS attacker_commands (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attacker_id     INTEGER REFERENCES attackers(id),
    ip_address      TEXT NOT NULL,
    service_name    TEXT NOT NULL,
    command         TEXT NOT NULL,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- All generated alerts
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attacker_id     INTEGER REFERENCES attackers(id),
    ip_address      TEXT NOT NULL,
    alert_type      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    description     TEXT NOT NULL,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged    INTEGER DEFAULT 0,
    acknowledged_at TIMESTAMP
);

-- AI-generated threat reports
CREATE TABLE IF NOT EXISTS ai_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attacker_id     INTEGER REFERENCES attackers(id),
    ip_address      TEXT,
    report_type     TEXT NOT NULL,
    content         TEXT NOT NULL,
    model_used      TEXT,
    generated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Service activity tracking
CREATE TABLE IF NOT EXISTS service_stats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name    TEXT NOT NULL,
    port            INTEGER NOT NULL,
    total_connections INTEGER DEFAULT 0,
    total_login_attempts INTEGER DEFAULT 0,
    unique_ips      INTEGER DEFAULT 0,
    last_activity   TIMESTAMP
);

-- IOC tracking
CREATE TABLE IF NOT EXISTS ioc_matches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address      TEXT NOT NULL,
    ioc_source      TEXT NOT NULL,
    match_type      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    matched_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_connections_ip ON connections(ip_address);
CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections(timestamp);
CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_timestamp ON login_attempts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_attackers_score ON attackers(threat_score);
