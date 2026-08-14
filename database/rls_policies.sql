-- HoneyShield v2 — Row Level Security, as defense-in-depth behind the
-- least-privilege grants in database/grants_production.sql.
--
-- Run this ONCE, as the database owner, AFTER grants_production.sql.
--
-- WHY THIS EXISTS
-- Supabase's own security advisor flags every public-schema table as exposed
-- because RLS is off by default. Taken at face value that's alarming, but
-- it's not accurate for this database specifically: grants_production.sql
-- already REVOKEs all privileges from `anon`/`authenticated`, so those roles
-- cannot execute so much as a SELECT — there's no row to filter, because
-- there's no query they're allowed to run in the first place. Verified
-- directly: a real anon key against login_attempts/attackers/admin_users all
-- return 42501 permission denied, not data.
--
-- RLS is added anyway as a SECOND, INDEPENDENT layer: if the REVOKE in
-- grants_production.sql is ever accidentally undone by a future migration,
-- RLS with no policy for anon/authenticated still blocks them outright.
--
-- WHY NOT THE ADVISOR'S GENERIC REMEDIATION
-- Blindly running `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` with no
-- policies would break the honeypot itself. honeyshield_app is not the table
-- owner and does not have BYPASSRLS (confirmed: pg_roles.rolbypassrls =
-- false), so it is subject to RLS exactly like anon/authenticated — enabling
-- RLS with zero policies would silently block its own INSERTs and SELECTs.
-- This file adds explicit policies for honeyshield_app before/alongside
-- enabling RLS, so its existing access keeps working.
--
-- WHY current_user, NOT auth.uid()
-- Supabase's usual RLS examples key policies off auth.uid(), because most
-- Supabase apps connect through PostgREST/GoTrue using end-user JWTs. This
-- app doesn't use Supabase Auth at all — it connects directly to Postgres as
-- the honeyshield_app role via asyncpg. The correct policy predicate here is
-- current_user = 'honeyshield_app', which is what direct role-based
-- connections actually authenticate as.
--
-- Idempotent: safe to re-run. DROP POLICY IF EXISTS precedes each CREATE
-- POLICY, since Postgres has no CREATE POLICY IF NOT EXISTS.

-- ── Data tables: honeyshield_app gets exactly what it was already granted ──
-- SELECT/INSERT/UPDATE only, matching grants_production.sql precisely. No
-- DELETE policy is added — there is no DELETE grant either, so this isn't
-- reducing access, it's a second wall behind access that already isn't there.

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'attackers', 'connections', 'login_attempts', 'attacker_commands',
        'alerts', 'ai_reports', 'service_stats', 'ioc_matches'
    ]
    LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);

        EXECUTE format('DROP POLICY IF EXISTS honeyshield_app_select ON public.%I', t);
        EXECUTE format(
            'CREATE POLICY honeyshield_app_select ON public.%I FOR SELECT TO honeyshield_app USING (current_user = ''honeyshield_app'')',
            t
        );

        EXECUTE format('DROP POLICY IF EXISTS honeyshield_app_insert ON public.%I', t);
        EXECUTE format(
            'CREATE POLICY honeyshield_app_insert ON public.%I FOR INSERT TO honeyshield_app WITH CHECK (current_user = ''honeyshield_app'')',
            t
        );

        EXECUTE format('DROP POLICY IF EXISTS honeyshield_app_update ON public.%I', t);
        EXECUTE format(
            'CREATE POLICY honeyshield_app_update ON public.%I FOR UPDATE TO honeyshield_app USING (current_user = ''honeyshield_app'') WITH CHECK (current_user = ''honeyshield_app'')',
            t
        );
    END LOOP;
END $$;

-- ── filtered_connections: INSERT-only policy, matching its narrower grant ──
-- Unlike the loop above, this table only has an INSERT grant for
-- honeyshield_app (see grants_production.sql §2b) — nothing in the app ever
-- reads it back — so it gets one policy, not three, keeping policies an exact
-- mirror of grants rather than a superset that implies access that isn't there.
ALTER TABLE public.filtered_connections ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS honeyshield_app_insert ON public.filtered_connections;
CREATE POLICY honeyshield_app_insert ON public.filtered_connections
    FOR INSERT TO honeyshield_app WITH CHECK (current_user = 'honeyshield_app');

-- ── admin_users: RLS enabled, deliberately ZERO policies ──────────────────
-- honeyshield_app has no grants here at all (see grants_production.sql §4),
-- so no policy is added for it either — enabling RLS with nothing to admit
-- it makes the lockout absolute for every non-owner role, matching intent.
-- The local dashboard connects as the table OWNER (postgres), which always
-- bypasses RLS regardless of policy — this does not affect dashboard login.
ALTER TABLE public.admin_users ENABLE ROW LEVEL SECURITY;

-- ── Verify ──────────────────────────────────────────────────────────────
-- Expect all 10 rows with rowsecurity = true.
SELECT schemaname, tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;

-- Expect 3 rows per main data table (select/insert/update), 1 row
-- (insert-only) for filtered_connections, 0 for admin_users, all restricted
-- to honeyshield_app.
SELECT tablename, policyname, cmd, roles
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, cmd;
