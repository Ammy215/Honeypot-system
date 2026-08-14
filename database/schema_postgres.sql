-- HoneyShield v2 schema — PostgreSQL (production), per HONEYSHIELD_PROJECT.md section 4.
-- Raw SQL, no ORM. Applied via database/db_async.py when DATABASE_URL is set.

CREATE TABLE IF NOT EXISTS attackers (
    ip_address       INET PRIMARY KEY,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
    country           TEXT,
    city              TEXT,
    asn               TEXT,
    isp               TEXT,
    is_tor_exit       BOOLEAN DEFAULT FALSE,
    abuseipdb_score    INT,
    otx_pulse_count    INT DEFAULT 0,
    threat_score       INT DEFAULT 0,
    verdict            TEXT,               -- LOW / MEDIUM / HIGH / CRITICAL
    total_connections  INT DEFAULT 0,
    -- Enrichment cache timestamps (phase 3) — NULL means never checked.
    -- Each enrichment source has its own TTL, checked independently.
    geo_checked_at       TIMESTAMPTZ,
    abuseipdb_checked_at TIMESTAMPTZ,
    otx_checked_at       TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS connections (
    id            BIGSERIAL PRIMARY KEY,
    ip_address    INET REFERENCES attackers(ip_address),
    service       TEXT NOT NULL,           -- ssh / ftp / http / telnet
    port          INT NOT NULL,
    connected_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    disconnected_at TIMESTAMPTZ,
    bytes_sent    INT DEFAULT 0,
    bytes_received INT DEFAULT 0,
    -- Raw proxy forwarding header, verbatim, when running behind a load
    -- balancer. ip_address above holds the *resolved* client. Kept because a
    -- spoofed X-Forwarded-For is itself attacker intel: it shows an attempt to
    -- forge a source IP. Inert text, never parsed for trust decisions.
    forwarded_for_raw TEXT
);

-- Migration for databases created before forwarded_for_raw existed.
ALTER TABLE connections ADD COLUMN IF NOT EXISTS forwarded_for_raw TEXT;

CREATE TABLE IF NOT EXISTS login_attempts (
    id            BIGSERIAL PRIMARY KEY,
    connection_id BIGINT REFERENCES connections(id),
    ip_address    INET REFERENCES attackers(ip_address),
    username      TEXT,                    -- store as literal text, escape on render
    password      TEXT,
    attempted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attacker_commands (
    id            BIGSERIAL PRIMARY KEY,
    connection_id BIGINT REFERENCES connections(id),
    ip_address    INET REFERENCES attackers(ip_address),
    command_text  TEXT,                    -- NEVER executed, storage only
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alerts (
    id            BIGSERIAL PRIMARY KEY,
    ip_address    INET REFERENCES attackers(ip_address),
    alert_type    TEXT NOT NULL,           -- brute_force / credential_stuffing / rapid_fire / multi_service
    severity      TEXT NOT NULL,           -- LOW / MEDIUM / HIGH / CRITICAL
    evidence      JSONB,
    acknowledged  BOOLEAN DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_reports (
    id            BIGSERIAL PRIMARY KEY,
    ip_address    INET REFERENCES attackers(ip_address),
    report_text   TEXT,
    generated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS service_stats (
    service       TEXT PRIMARY KEY,
    total_connections INT DEFAULT 0,
    last_hit      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS ioc_matches (
    ip_address    INET PRIMARY KEY REFERENCES attackers(ip_address),
    matched_list  TEXT,                    -- e.g. "known_bad_ips.txt"
    matched_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,           -- argon2/bcrypt, never plaintext
    failed_attempts INT DEFAULT 0,
    locked_until  TIMESTAMPTZ,
    last_login    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_connections_ip_time ON connections(ip_address, connected_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_address, attempted_at);

-- Connections dropped by IGNORE_UNFORWARDED_CONNECTIONS (config.py) — a proxy
-- header was expected but absent, in practice almost always a platform health
-- check. Deliberately separate from `connections`/`attackers`: this is
-- unvalidated noise-filtering, not captured attacker data, and mixing the two
-- would corrupt real detection/scoring. Exists so "genuinely low traffic" and
-- "traffic being silently filtered" are distinguishable during a live
-- validation window instead of both looking identical from outside — see
-- docs/RENDER.md. No FK to attackers(ip_address): peer_ip here is the raw,
-- unresolved socket peer, not a trusted/resolved attacker identity.
CREATE TABLE IF NOT EXISTS filtered_connections (
    id           BIGSERIAL PRIMARY KEY,
    peer_ip      INET NOT NULL,
    service      TEXT NOT NULL,
    port         INT NOT NULL,
    method       TEXT,                    -- NULL when no HTTP data arrived at all (bare TCP probe)
    path         TEXT,                    -- NULL when no HTTP data arrived at all
    filtered_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
