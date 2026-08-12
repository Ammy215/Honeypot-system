-- HoneyShield v2 — dashboard database role.
--
-- Run this ONCE, as the database owner, AFTER grants_production.sql and
-- rls_policies.sql.
--
-- WHY A THIRD ROLE, NOT THE OWNER AND NOT honeyshield_app
-- The dashboard needs two things honeyshield_app deliberately cannot have:
-- SELECT/INSERT/UPDATE on admin_users (login, lockout, first-run bootstrap)
-- and read access across the operational tables to render the SOC pages.
-- Running the dashboard as the database OWNER would work, but hands a local
-- Streamlit process superuser-equivalent access (DROP/ALTER/CREATE/DELETE on
-- everything) to do what is actually a narrow set of reads plus two writes.
-- honeyshield_app stays exactly as restricted as before — this does not
-- touch its grants — because it is the role exposed to attacker-controlled
-- input on a public PaaS deployment; the dashboard never leaves this machine.
--
-- Every grant below is evidenced, not assumed: derived by grepping every
-- db.* call reachable from a dashboard page load, including the AI analyst
-- (honeypot/ai/async_analyst.py) and campaign correlation
-- (honeypot/detectors/async_correlation.py), both of which run under this
-- same connection when triggered from a page. Neither attacker_commands nor
-- ioc_matches is referenced anywhere in that call graph, so neither gets a
-- grant here — matching actual code, not speculative future use.
--
-- Per-table verbs, and why:
--   admin_users        SELECT, INSERT, UPDATE  — login/lockout/bootstrap
--   attackers          SELECT                  — list_attackers, get_attacker,
--                                                 get_attackers_by_ips, aggregates
--   connections        SELECT                  — recent feed, timeline,
--                                                 per-IP history, campaign detection
--   login_attempts     SELECT                  — per-IP history, credential search
--   alerts             SELECT, UPDATE          — list + acknowledge_alert
--   ai_reports         SELECT, INSERT          — list + record_ai_report (AI Analyst page)
--   service_stats      SELECT                  — service_breakdown
--   attacker_commands  (none)                  — never queried by any dashboard page
--   ioc_matches        (none)                  — IOC matching isn't wired into
--                                                 any current dashboard page
--
-- Idempotent: safe to re-run.

-- ── 1. Create the role ────────────────────────────────────────────────────
-- Replace the password before running. Generate a fresh one — do not reuse
-- the DB owner's or honeyshield_app's password.
CREATE ROLE honeyshield_dashboard WITH LOGIN PASSWORD 'REPLACE_ME_WITH_A_GENERATED_PASSWORD';

GRANT CONNECT ON DATABASE postgres TO honeyshield_dashboard;
GRANT USAGE ON SCHEMA public TO honeyshield_dashboard;
REVOKE CREATE ON SCHEMA public FROM honeyshield_dashboard;

-- ── 2. Table grants, exactly matching the evidenced verb list above ───────
GRANT SELECT, INSERT, UPDATE ON admin_users TO honeyshield_dashboard;
GRANT SELECT ON attackers TO honeyshield_dashboard;
GRANT SELECT ON connections TO honeyshield_dashboard;
GRANT SELECT ON login_attempts TO honeyshield_dashboard;
GRANT SELECT, UPDATE ON alerts TO honeyshield_dashboard;
GRANT SELECT, INSERT ON ai_reports TO honeyshield_dashboard;
GRANT SELECT ON service_stats TO honeyshield_dashboard;
-- No grant at all on attacker_commands or ioc_matches — see rationale above.

-- ── 3. Sequences ────────────────────────────────────────────────────────
-- Only for tables this role actually INSERTs into.
GRANT USAGE ON admin_users_id_seq TO honeyshield_dashboard;
GRANT USAGE ON ai_reports_id_seq TO honeyshield_dashboard;

-- ── 4. RLS policies ────────────────────────────────────────────────────
-- RLS is already enabled on all 9 tables (rls_policies.sql). A role with a
-- table grant but no matching policy still sees nothing — these are required,
-- not optional, for this role to function at all.
DROP POLICY IF EXISTS honeyshield_dashboard_select ON admin_users;
CREATE POLICY honeyshield_dashboard_select ON admin_users FOR SELECT TO honeyshield_dashboard USING (current_user = 'honeyshield_dashboard');
DROP POLICY IF EXISTS honeyshield_dashboard_insert ON admin_users;
CREATE POLICY honeyshield_dashboard_insert ON admin_users FOR INSERT TO honeyshield_dashboard WITH CHECK (current_user = 'honeyshield_dashboard');
DROP POLICY IF EXISTS honeyshield_dashboard_update ON admin_users;
CREATE POLICY honeyshield_dashboard_update ON admin_users FOR UPDATE TO honeyshield_dashboard USING (current_user = 'honeyshield_dashboard') WITH CHECK (current_user = 'honeyshield_dashboard');

DROP POLICY IF EXISTS honeyshield_dashboard_select ON attackers;
CREATE POLICY honeyshield_dashboard_select ON attackers FOR SELECT TO honeyshield_dashboard USING (current_user = 'honeyshield_dashboard');

DROP POLICY IF EXISTS honeyshield_dashboard_select ON connections;
CREATE POLICY honeyshield_dashboard_select ON connections FOR SELECT TO honeyshield_dashboard USING (current_user = 'honeyshield_dashboard');

DROP POLICY IF EXISTS honeyshield_dashboard_select ON login_attempts;
CREATE POLICY honeyshield_dashboard_select ON login_attempts FOR SELECT TO honeyshield_dashboard USING (current_user = 'honeyshield_dashboard');

DROP POLICY IF EXISTS honeyshield_dashboard_select ON alerts;
CREATE POLICY honeyshield_dashboard_select ON alerts FOR SELECT TO honeyshield_dashboard USING (current_user = 'honeyshield_dashboard');
DROP POLICY IF EXISTS honeyshield_dashboard_update ON alerts;
CREATE POLICY honeyshield_dashboard_update ON alerts FOR UPDATE TO honeyshield_dashboard USING (current_user = 'honeyshield_dashboard') WITH CHECK (current_user = 'honeyshield_dashboard');

DROP POLICY IF EXISTS honeyshield_dashboard_select ON ai_reports;
CREATE POLICY honeyshield_dashboard_select ON ai_reports FOR SELECT TO honeyshield_dashboard USING (current_user = 'honeyshield_dashboard');
DROP POLICY IF EXISTS honeyshield_dashboard_insert ON ai_reports;
CREATE POLICY honeyshield_dashboard_insert ON ai_reports FOR INSERT TO honeyshield_dashboard WITH CHECK (current_user = 'honeyshield_dashboard');

DROP POLICY IF EXISTS honeyshield_dashboard_select ON service_stats;
CREATE POLICY honeyshield_dashboard_select ON service_stats FOR SELECT TO honeyshield_dashboard USING (current_user = 'honeyshield_dashboard');

-- ── 5. Verify ─────────────────────────────────────────────────────────────
SELECT table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee = 'honeyshield_dashboard'
ORDER BY table_name, privilege_type;

SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolreplication
FROM pg_roles WHERE rolname = 'honeyshield_dashboard';

SELECT tablename, policyname, cmd
FROM pg_policies
WHERE 'honeyshield_dashboard' = ANY(roles)
ORDER BY tablename, cmd;

-- ── 6. Connection string ──────────────────────────────────────────────────
-- Put this in the LOCAL .env used to run `streamlit run dashboard/app.py` —
-- never in Koyeb's env config, which holds honeyshield_app for the deployed
-- honeypot instead. Keep DB_SSL_MODE=require and SKIP_SCHEMA_INIT=true —
-- this role cannot run CREATE TABLE either.
--
--   DATABASE_URL=postgresql://honeyshield_dashboard.<project-ref>:<password>@<pooler-host>:5432/postgres
