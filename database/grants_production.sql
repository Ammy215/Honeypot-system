-- HoneyShield v2 — least-privilege production database user.
--
-- Run this ONCE, as the database owner (in Supabase: the SQL editor, which
-- runs as postgres), AFTER applying database/schema_postgres.sql.
--
-- The honeypot process runs as a deliberately exposed service handling hostile
-- input, so the credential it holds is the one most likely to leak. This role
-- is scoped so that a leak is survivable: the holder can read and write
-- honeypot data, and cannot destroy it, alter the schema, or touch the admin
-- credential table.
--
-- Granted:     SELECT, INSERT, UPDATE on the data tables
--              USAGE on the sequences behind the BIGSERIAL primary keys
-- NOT granted: DELETE, TRUNCATE, DROP, ALTER, CREATE, REFERENCES, TRIGGER
--              any access at all to admin_users
--
-- SELECT is required and is not optional: the honeypot's own detection logic
-- reads constantly — brute-force and credential-stuffing counting, enrichment
-- cache TTL checks (is_stale), duplicate-alert suppression, correlation. A
-- role with INSERT/UPDATE alone fails on the first connection.
--
-- USAGE on sequences is the grant most often forgotten. BIGSERIAL columns call
-- nextval() on an implicitly-created sequence; without USAGE, every INSERT
-- fails at runtime with "permission denied for sequence" even though the table
-- grants look correct.

-- ── 1. Create the role ────────────────────────────────────────────────────
-- Replace the password before running. Generate a fresh one; do not reuse the
-- dev credential, and do not reuse the DB owner's password.
CREATE ROLE honeyshield_app WITH LOGIN PASSWORD 'REPLACE_ME_WITH_A_GENERATED_PASSWORD';

-- Baseline connect access. No schema-level CREATE: this role must never be
-- able to add objects of its own.
GRANT CONNECT ON DATABASE postgres TO honeyshield_app;
GRANT USAGE ON SCHEMA public TO honeyshield_app;
REVOKE CREATE ON SCHEMA public FROM honeyshield_app;

-- ── 2. Data tables ────────────────────────────────────────────────────────
-- Listed explicitly rather than using ALL TABLES IN SCHEMA, so that
-- admin_users is excluded by construction and any table added later has to be
-- granted deliberately rather than being swept in by accident.
GRANT SELECT, INSERT, UPDATE ON
    attackers,
    connections,
    login_attempts,
    attacker_commands,
    alerts,
    ai_reports,
    service_stats,
    ioc_matches
TO honeyshield_app;

-- ── 2b. Filtered-connection log (INSERT only) ─────────────────────────────
-- filtered_connections holds connections dropped by IGNORE_UNFORWARDED_
-- CONNECTIONS (config.py) — see schema_postgres.sql for the full rationale.
-- Deliberately narrower than the tables above: nothing in the app ever reads
-- this table back, so it gets INSERT only, not SELECT/UPDATE. Matches the
-- same evidenced-grants-only discipline used for grants_dashboard.sql.
GRANT INSERT ON filtered_connections TO honeyshield_app;

-- ── 3. Sequences (BIGSERIAL primary keys) ─────────────────────────────────
GRANT USAGE ON
    connections_id_seq,
    login_attempts_id_seq,
    attacker_commands_id_seq,
    alerts_id_seq,
    ai_reports_id_seq,
    filtered_connections_id_seq
TO honeyshield_app;

-- ── 4. Explicitly deny the admin credential table ─────────────────────────
-- The honeypot process never reads or writes admin_users — that table is only
-- touched by the dashboard, which runs on a trusted machine under a separate
-- credential. Revoking here means a compromised honeypot cannot read admin
-- password hashes or lockout state, and cannot create itself an admin account.
REVOKE ALL ON admin_users FROM honeyshield_app;

-- ── 4b. Close the Supabase REST API surface (IMPORTANT) ───────────────────
-- Supabase automatically exposes every table in the `public` schema over a
-- PostgREST endpoint at https://<project>.supabase.co/rest/v1/<table>, reachable
-- with the project's `anon` key. That key is designed to be public — it ships in
-- browser frontends — so anything the `anon` role can read is effectively
-- world-readable over HTTPS, regardless of how tightly the Postgres role above
-- is scoped.
--
-- This database stores captured plaintext credentials. Leaving the default
-- grants in place would publish them.
--
-- Revoking the API roles is preferred here over enabling RLS: RLS with no
-- policies would also block honeyshield_app, whereas this closes the REST
-- surface while leaving direct Postgres connections working normally. Nothing
-- in this project uses PostgREST — the honeypot and dashboard both connect
-- straight to Postgres via asyncpg.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM anon, authenticated;
REVOKE USAGE ON SCHEMA public FROM anon, authenticated;

-- Stop future tables from inheriting the default API grants.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon, authenticated;

-- ── 5. Verify ─────────────────────────────────────────────────────────────
-- Expect SELECT/INSERT/UPDATE on the eight main data tables, plus INSERT-only
-- on filtered_connections (25 rows total). Any row naming admin_users, or any
-- DELETE/TRUNCATE/REFERENCES/TRIGGER privilege, means something above did not
-- apply.
SELECT table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee = 'honeyshield_app'
ORDER BY table_name, privilege_type;

-- Confirm the role holds no superuser/createdb/createrole/bypassrls flags.
-- Every boolean column here should be false.
SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolreplication
FROM pg_roles
WHERE rolname = 'honeyshield_app';

-- Confirm the REST API roles have no access left. This must return ZERO rows;
-- any row means captured credentials are reachable over the public REST
-- endpoint with the anon key.
SELECT grantee, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee IN ('anon', 'authenticated')
  AND table_schema = 'public';

-- ── 6. Connection string ──────────────────────────────────────────────────
-- Put this in the production .env as DATABASE_URL, and keep DB_SSL_MODE=require
-- (or verify-full) so asyncpg refuses an unencrypted connection:
--
--   DATABASE_URL=postgresql://honeyshield_app:<password>@<host>:5432/postgres
--   DB_SSL_MODE=require
--   SKIP_SCHEMA_INIT=true
--
-- SKIP_SCHEMA_INIT is required: this role cannot run CREATE TABLE, so startup
-- must not attempt init_schema(). The schema is owned by the DB owner and
-- applied once, above.
