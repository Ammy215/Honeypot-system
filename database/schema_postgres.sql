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
    forwarded_for_raw TEXT,
    -- What the attacker actually asked for. Without these, a capture records
    -- only that someone connected — which cannot distinguish a scanner
    -- fingerprinting the host from one hunting for exposed `.env` files or a
    -- known CMS exploit path. All three are attacker-controlled and stored
    -- verbatim as inert text; they are truncated on write (see
    -- honeypot/services/http_honeypot.py) so a hostile client cannot use them
    -- as an unbounded write primitive. NULL means no request data arrived at
    -- all — a bare TCP probe — which is itself a meaningful distinction.
    method     TEXT,
    path       TEXT,
    user_agent TEXT,

    -- Labels traffic that came from the hosting platform rather than from the
    -- internet: Render probes the service once, a second after every restart,
    -- and that request is captured like any other visitor. NULL means "not
    -- shown to be a probe" — the honeypot never writes these, they are applied
    -- afterwards by scripts/tag_restart_probes.py, and the rows are labelled
    -- rather than deleted because they are true records of what arrived.
    -- See database/traffic_classification.py for the rule and the evidence.
    traffic_class      TEXT,
    traffic_class_note TEXT
);

-- Migrations for databases created before these columns existed. Additive and
-- nullable, so existing rows stay valid and older code that never selects them
-- keeps working unchanged.
ALTER TABLE connections ADD COLUMN IF NOT EXISTS forwarded_for_raw TEXT;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS method TEXT;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS path TEXT;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS traffic_class TEXT;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS traffic_class_note TEXT;
-- Derived from the rows above: set only when EVERY connection from that source
-- is a probe. Recomputed by the same script, so it cannot drift on its own.
ALTER TABLE attackers   ADD COLUMN IF NOT EXISTS traffic_class TEXT;

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
