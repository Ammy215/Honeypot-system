"""
Async database layer for HoneyShield v2 — raw SQL, no ORM.

Backend is chosen by config: DATABASE_URL (PostgreSQL, via asyncpg) for
production, SQLITE_PATH (stdlib sqlite3, run in a thread executor so it
doesn't block the event loop) for local development. Same public API
either way, so honeypot services don't need to know which one is active.
"""

import asyncio
import json
import sqlite3
import logging
from pathlib import Path
from typing import Optional

import config

logger = logging.getLogger("honeypot.database")


async def _decode_inet_as_text(conn):
    """
    Return INET columns as plain strings instead of ipaddress objects.

    asyncpg decodes INET into ipaddress.IPv4Address/IPv6Address. Both Plotly's
    JSON encoder and pyarrow reject those types outright, so any dashboard page
    that charted or tabulated an IP column crashed with "Object of type
    IPv4Address is not JSON serializable" — while the SQLite backend, which
    returns strings, worked fine. Normalising at the driver keeps both backends
    returning the same Python types, rather than pushing str() calls into every
    page and every query.

    The trailing /32 (or /128) that Postgres prints for a host address is
    stripped, since every IP stored here is a single host, never a subnet.
    """
    def _decode(value: str) -> str:
        return value.split("/", 1)[0] if value.endswith(("/32", "/128")) else value

    await conn.set_type_codec(
        "inet", encoder=str, decoder=_decode, schema="pg_catalog", format="text"
    )


async def _skip_session_reset(conn) -> None:
    """
    Release a connection to the pool without a server round trip.

    asyncpg's default release runs `pg_advisory_unlock_all(); CLOSE ALL;
    UNLISTEN *; RESET ALL;` — a full round trip, awaited before `async with
    pool.acquire()` returns. Against this database that is ~256 ms, measured,
    and it was being paid on EVERY query: a pooled query cost 510 ms where the
    query itself took 251. Half of all database time in the dashboard was
    resetting session state that nothing had set.

    Safe because nothing here creates that state — no advisory locks, no
    cursors outside transactions, no LISTEN, no SET (grep-verified; keep it that
    way, and restore the default reset if you ever add one). The protection
    that DOES matter is preserved: when a custom reset is supplied, asyncpg
    still runs its internal Connection._reset() first, which rolls back any
    open transaction before this is called. A connection can never be handed
    to the next caller mid-transaction; tests/test_dashboard_performance.py
    asserts exactly that against the live database.
    """
    return None


class AsyncDatabase:
    def __init__(self):
        self.backend = "postgres" if config.DATABASE_URL else "sqlite"
        self._pg_pool = None
        self._sqlite_path = None
        self._connect_lock = None
        self._connect_lock_loop = None

        if self.backend == "sqlite":
            self._sqlite_path = Path(config.SQLITE_PATH)
            self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)

    async def connect(self):
        """
        Establish the backend connection (pool for Postgres; no-op for SQLite).

        Idempotent: calling it again with a live pool is a no-op. The dashboard
        relies on this — dashboard/async_bridge.run() calls it before every
        query so that landing directly on a page (bookmark, refresh, rerun)
        works without the login script having run first. Without the guard,
        each call would build another pool and orphan the previous one.
        """
        if self._pg_pool is not None:
            return

        # The check above is not enough on its own. Pool creation awaits several
        # TLS handshakes, and while it does, a second caller on the same loop
        # also sees _pg_pool is None and builds a SECOND pool; whichever assigns
        # last wins and the other's connections are orphaned — four of the
        # pooler's fifteen client slots, gone until the process exits. The
        # dashboard now warms its pool in the background while a page may also
        # be connecting, so the race is real. One lock per event loop (asyncio
        # locks are loop-bound, and tests drive more than one loop).
        loop = asyncio.get_running_loop()
        if self._connect_lock is None or self._connect_lock_loop is not loop:
            self._connect_lock, self._connect_lock_loop = asyncio.Lock(), loop
        async with self._connect_lock:
            if self._pg_pool is not None:
                return
            await self._open()

    async def _open(self):
        if self.backend == "postgres":
            import asyncpg
            # TLS is required explicitly, not left to negotiation. asyncpg
            # defaults to "prefer": it will happily fall back to an unencrypted
            # connection if the server doesn't offer TLS, which would put
            # captured credentials on the wire in cleartext. "require" refuses
            # to connect without encryption; "verify-full" additionally checks
            # the certificate chain and hostname.
            # Pool sizing, which was previously left at asyncpg's defaults of
            # min_size=10, max_size=10 — so every process eagerly opened TEN
            # connections before serving anything. Two costs, both measured:
            #
            #  - Cold start. Ten TLS handshakes against a pooler with a ~214ms
            #    round-trip floor is ~3.1s before the first page can render.
            #  - Supabase's pooler admits 15 clients total. The dashboard alone
            #    claimed 10, so running the dashboard and the test suite at the
            #    same time hit "EMAXCONNSESSION: max clients reached".
            #
            # DB_POOL_SIZE (config.py, default 5) finally becomes the cap it
            # always claimed to be. min_size matches the widest concurrent read:
            # a dashboard bundle now issues up to FIVE queries at once (the
            # multi-query readers gather their parts), and a pool that starts
            # smaller opens the missing connection mid-render — 1.6 s of TLS +
            # SCRAM, measured, landing on whichever page happens to need it
            # first. Opening them all up front costs the operator nothing: the
            # dashboard warms its pool in the background while the sign-in form
            # is on screen (see dashboard/login.py). Capped at 5 regardless of
            # DB_POOL_SIZE, because the pooler admits only 15 clients in total.
            min_size = min(5, config.DB_POOL_SIZE)
            self._pg_pool = await asyncpg.create_pool(
                config.DATABASE_URL,
                ssl=config.DB_SSL_MODE,
                init=_decode_inet_as_text,
                reset=_skip_session_reset,
                min_size=min_size,
                max_size=config.DB_POOL_SIZE,
            )
            logger.info(f"Connected to PostgreSQL (ssl={config.DB_SSL_MODE})")
        else:
            logger.info(f"Using local SQLite dev database: {self._sqlite_path}")

    async def close(self):
        if self._pg_pool:
            await self._pg_pool.close()
            # Clear it so a later connect() rebuilds rather than handing back a
            # closed pool — connect() is now idempotent on this field.
            self._pg_pool = None

    async def init_schema(self):
        """
        Create all tables/indexes if they don't already exist.

        Skipped in production (SKIP_SCHEMA_INIT=true): the production Postgres
        user is least-privilege — SELECT/INSERT/UPDATE only — and cannot run
        CREATE TABLE. Apply database/schema_postgres.sql once as the database
        owner instead; see database/grants_production.sql.
        """
        if config.SKIP_SCHEMA_INIT:
            logger.info("SKIP_SCHEMA_INIT set — leaving schema management to the DB owner")
            return

        if self.backend == "postgres":
            schema_sql = Path("database/schema_postgres.sql").read_text(encoding="utf-8")
            async with self._pg_pool.acquire() as conn:
                await conn.execute(schema_sql)
        else:
            schema_sql = Path("database/schema_sqlite_dev.sql").read_text(encoding="utf-8")
            await self._run_sqlite(lambda conn: conn.executescript(schema_sql))
            await self._migrate_sqlite()

        logger.info(f"Database schema initialized ({self.backend})")

    async def _migrate_sqlite(self):
        """
        Add columns introduced after a dev database was first created. SQLite
        has no ADD COLUMN IF NOT EXISTS, so existing columns are checked first.
        Postgres handles the equivalent inline in schema_postgres.sql.
        """
        added = {
            "connections": ("forwarded_for_raw", "method", "path", "user_agent",
                            "traffic_class", "traffic_class_note"),
            "attackers": ("traffic_class",),
        }

        def _work(conn: sqlite3.Connection):
            for table, columns in added.items():
                existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
                for column in columns:
                    if column not in existing:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")
                        logger.info(f"Migrated SQLite dev DB: added {table}.{column}")

        await self._run_sqlite(_work)

    def _sqlite_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._sqlite_path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    async def _run_sqlite(self, fn):
        """Run a sync sqlite3 callable in a worker thread, off the event loop."""
        loop = asyncio.get_running_loop()

        def _work():
            conn = self._sqlite_conn()
            try:
                result = fn(conn)
                conn.commit()
                return result
            finally:
                conn.close()

        return await loop.run_in_executor(None, _work)

    async def record_connection(
        self,
        ip_address: str,
        service: str,
        port: int,
        forwarded_for_raw: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> int:
        """
        Upsert the attacker row and insert a connections row. Returns the new connection id.

        `ip_address` is the *resolved* client address (see
        honeypot/core/client_ip.py). `forwarded_for_raw` stores the untouched
        proxy header alongside it as evidence — parameterized like every other
        attacker-controlled value, never interpolated.

        `method`, `path` and `user_agent` record what was actually requested,
        so a capture can distinguish a scanner fingerprinting the host from one
        hunting a specific exploit path. All three are attacker-controlled,
        default to None (non-HTTP services and bare TCP probes pass nothing),
        and are truncated by the caller before they reach here.
        """
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO attackers (ip_address, total_connections)
                        VALUES ($1, 1)
                        ON CONFLICT (ip_address) DO UPDATE
                        SET last_seen = now(),
                            total_connections = attackers.total_connections + 1
                        """,
                        ip_address,
                    )
                    row = await conn.fetchrow(
                        """
                        INSERT INTO connections
                            (ip_address, service, port, forwarded_for_raw, method, path, user_agent)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        RETURNING id
                        """,
                        ip_address, service, port, forwarded_for_raw, method, path, user_agent,
                    )
                    return row["id"]

        def _work(conn: sqlite3.Connection):
            conn.execute(
                """
                INSERT INTO attackers (ip_address, total_connections)
                VALUES (?, 1)
                ON CONFLICT(ip_address) DO UPDATE SET
                    last_seen = datetime('now'),
                    total_connections = total_connections + 1
                """,
                (ip_address,),
            )
            cur = conn.execute(
                "INSERT INTO connections "
                "(ip_address, service, port, forwarded_for_raw, method, path, user_agent) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ip_address, service, port, forwarded_for_raw, method, path, user_agent),
            )
            return cur.lastrowid

        return await self._run_sqlite(_work)

    async def record_filtered_connection(
        self, peer_ip: str, service: str, port: int, method: Optional[str], path: Optional[str]
    ) -> None:
        """
        Record a connection dropped by IGNORE_UNFORWARDED_CONNECTIONS, separate
        from attackers/connections so the real capture tables stay untouched.
        peer_ip is the raw, unresolved socket peer — not a validated attacker
        identity — so this never touches the attackers table at all.

        No RETURNING id, deliberately: honeyshield_app's grant on this table is
        INSERT-only (nothing in the app ever reads it back), and under RLS,
        RETURNING requires the inserted row to be visible under a SELECT policy
        — which doesn't exist here by design. Adding one just to support an id
        nothing consumes would be over-granting a diagnostic-only table. Caught
        live: a plain INSERT ... RETURNING id here failed with "permission
        denied for table filtered_connections" even though the INSERT grant and
        RLS policy were both confirmed correct — the RETURNING clause itself
        was the problem, not the privileges.
        """
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO filtered_connections (peer_ip, service, port, method, path)
                    VALUES ($1, $2, $3, $4, $5)
                    """,
                    peer_ip, service, port, method, path,
                )
            return

        def _work(conn: sqlite3.Connection):
            conn.execute(
                "INSERT INTO filtered_connections (peer_ip, service, port, method, path) VALUES (?, ?, ?, ?, ?)",
                (peer_ip, service, port, method, path),
            )

        await self._run_sqlite(_work)

    async def filtered_connection_stats(self, recent_limit: int = 10) -> dict:
        """
        Summarise filtered (unforwarded) connections for the dashboard.

        Read-only counterpart to record_filtered_connection above. Only the
        dashboard role can run this — honeyshield_app holds INSERT and nothing
        else — so the process exposed to attackers cannot read back or reason
        about what got filtered.

        Exists so "no attacks arrived" and "attacks arrived but were filtered
        out" are distinguishable during a validation window. Without it both
        look identical: an empty Live Feed.
        """
        empty = {"total": 0, "last_hour": 0, "last_24h": 0, "latest": None, "recent": []}

        if self.backend == "postgres":
            # Two independent reads, issued together on separate pooled
            # connections. Run one after the other on a single connection they
            # cost two round trips — 540 ms measured, the long pole of both the
            # Overview and Live Feed bundles. Gathered, they cost one.
            row, recent = await asyncio.gather(
                self._pg_pool.fetchrow(
                    """
                    SELECT count(*) AS total,
                           count(*) FILTER (WHERE filtered_at > now() - interval '1 hour')  AS last_hour,
                           count(*) FILTER (WHERE filtered_at > now() - interval '24 hours') AS last_24h,
                           max(filtered_at) AS latest
                    FROM filtered_connections
                    """
                ),
                self._pg_pool.fetch(
                    """
                    SELECT host(peer_ip) AS peer_ip, service, port, method, path,
                           count(*) AS hits, max(filtered_at) AS latest
                    FROM filtered_connections
                    GROUP BY 1, 2, 3, 4, 5
                    ORDER BY hits DESC
                    LIMIT $1
                    """,
                    recent_limit,
                ),
            )
            if not row:
                return empty
            return {**dict(row), "recent": [dict(r) for r in recent]}

        def _work(conn: sqlite3.Connection):
            # Without this, rows come back as plain tuples and the dict(row)
            # calls below raise "cannot convert dictionary update sequence
            # element #0 to a sequence" — _sqlite_conn() does not set it.
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT count(*) AS total,
                       sum(CASE WHEN filtered_at > datetime('now', '-1 hour')  THEN 1 ELSE 0 END) AS last_hour,
                       sum(CASE WHEN filtered_at > datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS last_24h,
                       max(filtered_at) AS latest
                FROM filtered_connections
                """
            ).fetchone()
            recent = conn.execute(
                """
                SELECT peer_ip, service, port, method, path,
                       count(*) AS hits, max(filtered_at) AS latest
                FROM filtered_connections
                GROUP BY peer_ip, service, port, method, path
                ORDER BY hits DESC
                LIMIT ?
                """,
                (recent_limit,),
            ).fetchall()
            if row is None:
                return empty
            d = dict(row)
            # SUM over zero rows yields NULL in SQLite, unlike COUNT FILTER.
            d["last_hour"] = d["last_hour"] or 0
            d["last_24h"] = d["last_24h"] or 0
            return {**d, "recent": [dict(r) for r in recent]}

        return await self._run_sqlite(_work)

    async def record_login_attempt(
        self, connection_id: int, ip_address: str, username: Optional[str], password: Optional[str]
    ) -> int:
        """Insert a login_attempts row and bump the attacker's last_seen. Returns the new row id."""
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute(
                        "UPDATE attackers SET last_seen = now() WHERE ip_address = $1", ip_address
                    )
                    row = await conn.fetchrow(
                        """
                        INSERT INTO login_attempts (connection_id, ip_address, username, password)
                        VALUES ($1, $2, $3, $4)
                        RETURNING id
                        """,
                        connection_id, ip_address, username, password,
                    )
                    return row["id"]

        def _work(conn: sqlite3.Connection):
            conn.execute(
                "UPDATE attackers SET last_seen = datetime('now') WHERE ip_address = ?",
                (ip_address,),
            )
            cur = conn.execute(
                """
                INSERT INTO login_attempts (connection_id, ip_address, username, password)
                VALUES (?, ?, ?, ?)
                """,
                (connection_id, ip_address, username, password),
            )
            return cur.lastrowid

        return await self._run_sqlite(_work)

    async def count_login_attempts_since(self, ip_address: str, service: str, window_seconds: int) -> int:
        """Count login attempts for one IP on one service within the last window_seconds."""
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM login_attempts la
                    JOIN connections c ON c.id = la.connection_id
                    WHERE c.ip_address = $1 AND c.service = $2
                      AND la.attempted_at >= now() - make_interval(secs => $3::int)
                    """,
                    ip_address, service, window_seconds,
                )
                return row["cnt"]

        def _work(conn: sqlite3.Connection):
            cur = conn.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM login_attempts la
                JOIN connections c ON c.id = la.connection_id
                WHERE c.ip_address = ? AND c.service = ?
                  AND la.attempted_at >= datetime('now', '-' || ? || ' seconds')
                """,
                (ip_address, service, window_seconds),
            )
            return cur.fetchone()[0]

        return await self._run_sqlite(_work)

    async def count_distinct_usernames_since(self, ip_address: str, window_seconds: int) -> int:
        """Count distinct usernames tried by one IP across any service within window_seconds."""
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT COUNT(DISTINCT la.username) AS cnt
                    FROM login_attempts la
                    JOIN connections c ON c.id = la.connection_id
                    WHERE c.ip_address = $1
                      AND la.attempted_at >= now() - make_interval(secs => $2::int)
                    """,
                    ip_address, window_seconds,
                )
                return row["cnt"]

        def _work(conn: sqlite3.Connection):
            cur = conn.execute(
                """
                SELECT COUNT(DISTINCT la.username) AS cnt
                FROM login_attempts la
                JOIN connections c ON c.id = la.connection_id
                WHERE c.ip_address = ?
                  AND la.attempted_at >= datetime('now', '-' || ? || ' seconds')
                """,
                (ip_address, window_seconds),
            )
            return cur.fetchone()[0]

        return await self._run_sqlite(_work)

    async def recent_alert_exists(self, ip_address: str, alert_type: str, window_seconds: int) -> bool:
        """De-dup guard: has this IP already triggered this alert type recently?"""
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT 1 FROM alerts
                    WHERE ip_address = $1 AND alert_type = $2
                      AND created_at >= now() - make_interval(secs => $3::int)
                    LIMIT 1
                    """,
                    ip_address, alert_type, window_seconds,
                )
                return row is not None

        def _work(conn: sqlite3.Connection):
            cur = conn.execute(
                """
                SELECT 1 FROM alerts
                WHERE ip_address = ? AND alert_type = ?
                  AND created_at >= datetime('now', '-' || ? || ' seconds')
                LIMIT 1
                """,
                (ip_address, alert_type, window_seconds),
            )
            return cur.fetchone() is not None

        return await self._run_sqlite(_work)

    async def record_alert(self, ip_address: str, alert_type: str, severity: str, evidence: dict) -> int:
        """Insert an alerts row. Returns the new row id."""
        evidence_json = json.dumps(evidence)

        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    INSERT INTO alerts (ip_address, alert_type, severity, evidence)
                    VALUES ($1, $2, $3, $4::jsonb)
                    RETURNING id
                    """,
                    ip_address, alert_type, severity, evidence_json,
                )
                return row["id"]

        def _work(conn: sqlite3.Connection):
            cur = conn.execute(
                """
                INSERT INTO alerts (ip_address, alert_type, severity, evidence)
                VALUES (?, ?, ?, ?)
                """,
                (ip_address, alert_type, severity, evidence_json),
            )
            return cur.lastrowid

        return await self._run_sqlite(_work)

    # ── Enrichment (phase 3) ──────────────────────────────────────────

    _ENRICHMENT_TIMESTAMP_COLUMNS = {"geo_checked_at", "abuseipdb_checked_at", "otx_checked_at"}

    async def get_attacker(self, ip_address: str) -> Optional[dict]:
        """Fetch the full attackers row as a plain dict, or None if not seen yet."""
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow("SELECT * FROM attackers WHERE ip_address = $1", ip_address)
                return dict(row) if row else None

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT * FROM attackers WHERE ip_address = ?", (ip_address,))
            row = cur.fetchone()
            return dict(row) if row else None

        return await self._run_sqlite(_work)

    async def is_stale(self, ip_address: str, checked_at_column: str, ttl_seconds: int) -> bool:
        """True if the given enrichment timestamp is NULL or older than ttl_seconds."""
        if checked_at_column not in self._ENRICHMENT_TIMESTAMP_COLUMNS:
            raise ValueError(f"Unknown enrichment timestamp column: {checked_at_column}")

        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    f"""
                    SELECT ({checked_at_column} IS NULL
                            OR {checked_at_column} < now() - make_interval(secs => $2::int)) AS stale
                    FROM attackers WHERE ip_address = $1
                    """,
                    ip_address, ttl_seconds,
                )
                return row["stale"] if row else True

        def _work(conn: sqlite3.Connection):
            cur = conn.execute(
                f"""
                SELECT ({checked_at_column} IS NULL
                        OR {checked_at_column} < datetime('now', '-' || ? || ' seconds')) AS stale
                FROM attackers WHERE ip_address = ?
                """,
                (ttl_seconds, ip_address),
            )
            row = cur.fetchone()
            return bool(row[0]) if row else True

        return await self._run_sqlite(_work)

    async def update_geolocation(self, ip_address: str, country: Optional[str], city: Optional[str],
                                  isp: Optional[str], asn: Optional[str]):
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE attackers
                    SET country = $2, city = $3, isp = $4, asn = $5, geo_checked_at = now()
                    WHERE ip_address = $1
                    """,
                    ip_address, country, city, isp, asn,
                )
            return

        def _work(conn: sqlite3.Connection):
            conn.execute(
                """
                UPDATE attackers
                SET country = ?, city = ?, isp = ?, asn = ?, geo_checked_at = datetime('now')
                WHERE ip_address = ?
                """,
                (country, city, isp, asn, ip_address),
            )

        await self._run_sqlite(_work)

    async def update_abuseipdb(self, ip_address: str, score: Optional[int]):
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                await conn.execute(
                    "UPDATE attackers SET abuseipdb_score = $2, abuseipdb_checked_at = now() WHERE ip_address = $1",
                    ip_address, score,
                )
            return

        def _work(conn: sqlite3.Connection):
            conn.execute(
                "UPDATE attackers SET abuseipdb_score = ?, abuseipdb_checked_at = datetime('now') WHERE ip_address = ?",
                (score, ip_address),
            )

        await self._run_sqlite(_work)

    async def update_otx(self, ip_address: str, pulse_count: int):
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                await conn.execute(
                    "UPDATE attackers SET otx_pulse_count = $2, otx_checked_at = now() WHERE ip_address = $1",
                    ip_address, pulse_count,
                )
            return

        def _work(conn: sqlite3.Connection):
            conn.execute(
                "UPDATE attackers SET otx_pulse_count = ?, otx_checked_at = datetime('now') WHERE ip_address = ?",
                (pulse_count, ip_address),
            )

        await self._run_sqlite(_work)

    async def update_threat_score(self, ip_address: str, score: int, verdict: str):
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                await conn.execute(
                    "UPDATE attackers SET threat_score = $2, verdict = $3 WHERE ip_address = $1",
                    ip_address, score, verdict,
                )
            return

        def _work(conn: sqlite3.Connection):
            conn.execute(
                "UPDATE attackers SET threat_score = ?, verdict = ? WHERE ip_address = ?",
                (score, verdict, ip_address),
            )

        await self._run_sqlite(_work)

    async def count_login_attempts_total(self, ip_address: str) -> int:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT COUNT(*) AS cnt FROM login_attempts WHERE ip_address = $1", ip_address
                )
                return row["cnt"]

        def _work(conn: sqlite3.Connection):
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM login_attempts WHERE ip_address = ?", (ip_address,))
            return cur.fetchone()[0]

        return await self._run_sqlite(_work)

    async def count_distinct_usernames_total(self, ip_address: str) -> int:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT COUNT(DISTINCT username) AS cnt FROM login_attempts WHERE ip_address = $1", ip_address
                )
                return row["cnt"]

        def _work(conn: sqlite3.Connection):
            cur = conn.execute(
                "SELECT COUNT(DISTINCT username) AS cnt FROM login_attempts WHERE ip_address = ?", (ip_address,)
            )
            return cur.fetchone()[0]

        return await self._run_sqlite(_work)

    async def list_attacker_ips(self, limit: int = 50) -> list:
        """Most recently seen attacker IPs, for batch enrichment."""
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT ip_address FROM attackers ORDER BY last_seen DESC LIMIT $1", limit
                )
                return [str(r["ip_address"]) for r in rows]

        def _work(conn: sqlite3.Connection):
            cur = conn.execute("SELECT ip_address FROM attackers ORDER BY last_seen DESC LIMIT ?", (limit,))
            return [r[0] for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    # ── Admin users (phase 4) ─────────────────────────────────────────

    async def count_admin_users(self) -> int:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow("SELECT COUNT(*) AS cnt FROM admin_users")
                return row["cnt"]

        def _work(conn: sqlite3.Connection):
            return conn.execute("SELECT COUNT(*) AS cnt FROM admin_users").fetchone()[0]

        return await self._run_sqlite(_work)

    async def create_admin_user(self, username: str, password_hash: str) -> int:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "INSERT INTO admin_users (username, password_hash) VALUES ($1, $2) RETURNING id",
                    username, password_hash,
                )
                return row["id"]

        def _work(conn: sqlite3.Connection):
            cur = conn.execute(
                "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)", (username, password_hash)
            )
            return cur.lastrowid

        return await self._run_sqlite(_work)

    async def get_admin_user(self, username: str) -> Optional[dict]:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow("SELECT * FROM admin_users WHERE username = $1", username)
                return dict(row) if row else None

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM admin_users WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None

        return await self._run_sqlite(_work)

    async def record_admin_login_success(self, username: str):
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE admin_users
                    SET failed_attempts = 0, locked_until = NULL, last_login = now()
                    WHERE username = $1
                    """,
                    username,
                )
            return

        def _work(conn: sqlite3.Connection):
            conn.execute(
                """
                UPDATE admin_users
                SET failed_attempts = 0, locked_until = NULL, last_login = datetime('now')
                WHERE username = ?
                """,
                (username,),
            )

        await self._run_sqlite(_work)

    async def is_admin_locked_out(self, username: str) -> bool:
        """True if locked_until is set and still in the future — checked DB-side to avoid
        cross-backend datetime parsing (Postgres datetime vs SQLite ISO text)."""
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT (locked_until IS NOT NULL AND locked_until > now()) AS locked "
                    "FROM admin_users WHERE username = $1",
                    username,
                )
                return bool(row["locked"]) if row else False

        def _work(conn: sqlite3.Connection):
            row = conn.execute(
                "SELECT (locked_until IS NOT NULL AND locked_until > datetime('now')) AS locked "
                "FROM admin_users WHERE username = ?",
                (username,),
            ).fetchone()
            return bool(row[0]) if row else False

        return await self._run_sqlite(_work)

    async def record_admin_login_failure(self, username: str, max_attempts: int, lockout_minutes: int):
        """Increment failed_attempts; lock the account once max_attempts is reached."""
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE admin_users
                    SET failed_attempts = failed_attempts + 1,
                        locked_until = CASE
                            WHEN failed_attempts + 1 >= $2
                            THEN now() + make_interval(mins => $3::int)
                            ELSE locked_until
                        END
                    WHERE username = $1
                    """,
                    username, max_attempts, lockout_minutes,
                )
            return

        def _work(conn: sqlite3.Connection):
            conn.execute(
                """
                UPDATE admin_users
                SET failed_attempts = failed_attempts + 1,
                    locked_until = CASE
                        WHEN failed_attempts + 1 >= ?
                        THEN datetime('now', '+' || ? || ' minutes')
                        ELSE locked_until
                    END
                WHERE username = ?
                """,
                (max_attempts, lockout_minutes, username),
            )

        await self._run_sqlite(_work)

    # ── Dashboard read queries (phase 4) ──────────────────────────────

    async def list_recent_connections(self, limit: int = 100, service: Optional[str] = None) -> list:
        base = """
            SELECT c.id, c.ip_address, c.service, c.port, c.connected_at,
                   c.method, c.path, c.user_agent, c.traffic_class,
                   a.country, a.threat_score, a.verdict
            FROM connections c
            LEFT JOIN attackers a ON a.ip_address = c.ip_address
        """
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                if service:
                    rows = await conn.fetch(
                        base + " WHERE c.service = $1 ORDER BY c.connected_at DESC LIMIT $2", service, limit
                    )
                else:
                    rows = await conn.fetch(base + " ORDER BY c.connected_at DESC LIMIT $1", limit)
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            if service:
                cur = conn.execute(
                    base + " WHERE c.service = ? ORDER BY c.connected_at DESC LIMIT ?", (service, limit)
                )
            else:
                cur = conn.execute(base + " ORDER BY c.connected_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    async def traffic_breakdown(self) -> dict:
        """
        How much of what was captured is the hosting platform's own restart
        probes, and how much is unattributed.

        Counted from `connections`, not from `attackers`: the label describes a
        request, and a source IP could send a probe today and be reassigned to
        something real tomorrow (see database/traffic_classification.py). The
        per-source figures are derived here for the same reason — so they can
        never disagree with the rows they summarise.
        """
        sql = """
            SELECT
                count(*)                                            AS connections,
                count(*) FILTER (WHERE traffic_class = 'restart_probe')        AS probe,
                count(*) FILTER (WHERE traffic_class = 'restart_probe_likely') AS likely,
                count(*) FILTER (WHERE traffic_class IS NULL)                  AS unlabelled,
                count(DISTINCT ip_address)                          AS sources,
                count(DISTINCT ip_address) FILTER (WHERE traffic_class IS NULL) AS sources_unlabelled
            FROM connections
        """
        empty = {"connections": 0, "probe": 0, "likely": 0, "unlabelled": 0,
                 "sources": 0, "sources_unlabelled": 0}

        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(sql)
            return dict(row) if row else empty

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            # SQLite has no FILTER clause before 3.30 and none in older builds
            # bundled with Python on Windows; SUM(CASE) is equivalent and portable.
            row = conn.execute("""
                SELECT count(*) AS connections,
                       sum(CASE WHEN traffic_class = 'restart_probe' THEN 1 ELSE 0 END) AS probe,
                       sum(CASE WHEN traffic_class = 'restart_probe_likely' THEN 1 ELSE 0 END) AS likely,
                       sum(CASE WHEN traffic_class IS NULL THEN 1 ELSE 0 END) AS unlabelled,
                       count(DISTINCT ip_address) AS sources,
                       count(DISTINCT CASE WHEN traffic_class IS NULL THEN ip_address END)
                           AS sources_unlabelled
                FROM connections
            """).fetchone()
            return {k: (v or 0) for k, v in dict(row).items()} if row else empty

        return await self._run_sqlite(_work)

    async def list_attackers(self, limit: int = 100, search_ip: Optional[str] = None) -> list:
        base = "SELECT * FROM attackers"
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                if search_ip:
                    rows = await conn.fetch(
                        base + " WHERE host(ip_address) LIKE $1 ORDER BY threat_score DESC LIMIT $2",
                        f"%{search_ip}%", limit,
                    )
                else:
                    rows = await conn.fetch(base + " ORDER BY threat_score DESC LIMIT $1", limit)
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            if search_ip:
                cur = conn.execute(
                    base + " WHERE ip_address LIKE ? ORDER BY threat_score DESC LIMIT ?",
                    (f"%{search_ip}%", limit),
                )
            else:
                cur = conn.execute(base + " ORDER BY threat_score DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    async def list_login_attempts_for_ip(self, ip_address: str, limit: int = 50) -> list:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT la.username, la.password, la.attempted_at, c.service
                    FROM login_attempts la
                    JOIN connections c ON c.id = la.connection_id
                    WHERE la.ip_address = $1
                    ORDER BY la.attempted_at DESC LIMIT $2
                    """,
                    ip_address, limit,
                )
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                """
                SELECT la.username, la.password, la.attempted_at, c.service
                FROM login_attempts la
                JOIN connections c ON c.id = la.connection_id
                WHERE la.ip_address = ?
                ORDER BY la.attempted_at DESC LIMIT ?
                """,
                (ip_address, limit),
            )
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    async def list_alerts(self, limit: int = 100, severity: Optional[str] = None,
                           acknowledged: Optional[bool] = None) -> list:
        """Alerts, optionally filtered by severity and/or acknowledged status."""
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                if severity is not None and acknowledged is not None:
                    rows = await conn.fetch(
                        "SELECT * FROM alerts WHERE severity = $1 AND acknowledged = $2 ORDER BY created_at DESC LIMIT $3",
                        severity, acknowledged, limit,
                    )
                elif severity is not None:
                    rows = await conn.fetch(
                        "SELECT * FROM alerts WHERE severity = $1 ORDER BY created_at DESC LIMIT $2", severity, limit
                    )
                elif acknowledged is not None:
                    rows = await conn.fetch(
                        "SELECT * FROM alerts WHERE acknowledged = $1 ORDER BY created_at DESC LIMIT $2",
                        acknowledged, limit,
                    )
                else:
                    rows = await conn.fetch("SELECT * FROM alerts ORDER BY created_at DESC LIMIT $1", limit)
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            ack = None if acknowledged is None else int(acknowledged)
            if severity is not None and ack is not None:
                cur = conn.execute(
                    "SELECT * FROM alerts WHERE severity = ? AND acknowledged = ? ORDER BY created_at DESC LIMIT ?",
                    (severity, ack, limit),
                )
            elif severity is not None:
                cur = conn.execute(
                    "SELECT * FROM alerts WHERE severity = ? ORDER BY created_at DESC LIMIT ?", (severity, limit)
                )
            elif ack is not None:
                cur = conn.execute(
                    "SELECT * FROM alerts WHERE acknowledged = ? ORDER BY created_at DESC LIMIT ?", (ack, limit)
                )
            else:
                cur = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    async def acknowledge_alert(self, alert_id: int):
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                await conn.execute("UPDATE alerts SET acknowledged = TRUE WHERE id = $1", alert_id)
            return

        def _work(conn: sqlite3.Connection):
            conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))

        await self._run_sqlite(_work)

    async def service_breakdown(self, hours: Optional[int] = None) -> list:
        """
        Connections per service. `hours` restricts to a trailing window.

        The window exists because this sits beside a windowed timeline on the
        Analytics page. Counting all time there was silently wrong: moving the
        window slider changed the timeline and left this panel untouched, so
        the two disagreed with no indication that they measured different
        spans. `None` keeps the all-time behaviour for any other caller.
        """
        where, params = "", []
        if hours is not None:
            if self.backend == "postgres":
                where = "WHERE connected_at >= now() - make_interval(hours => $1::int)"
                params = [hours]
            else:
                where = "WHERE connected_at >= datetime('now', '-' || ? || ' hours')"
                params = [hours]
        query = (f"SELECT service, COUNT(*) AS cnt FROM connections {where} "
                 f"GROUP BY service ORDER BY cnt DESC")

        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(query, params).fetchall()]

        return await self._run_sqlite(_work)

    async def verdict_breakdown(self, hours: Optional[int] = None) -> list:
        """
        Attackers per verdict. `hours` restricts to those seen in the window.

        Note the unit differs from service_breakdown: this counts ATTACKERS,
        that counts CONNECTIONS. The two are rendered side by side, so the UI
        must label which is which — the numbers legitimately disagree.

        Windowing uses last_seen, since an attacker has no single timestamp;
        "active in the last N hours" is the question a window implies here.
        """
        clause, params = "WHERE verdict IS NOT NULL", []
        if hours is not None:
            if self.backend == "postgres":
                clause += " AND last_seen >= now() - make_interval(hours => $1::int)"
                params = [hours]
            else:
                clause += " AND last_seen >= datetime('now', '-' || ? || ' hours')"
                params = [hours]
        query = f"SELECT verdict, COUNT(*) AS cnt FROM attackers {clause} GROUP BY verdict"

        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(query, params).fetchall()]

        return await self._run_sqlite(_work)

    async def connections_timeline(self, hours: int = 24) -> list:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT date_trunc('hour', connected_at) AS bucket, COUNT(*) AS cnt
                    FROM connections
                    WHERE connected_at >= now() - make_interval(hours => $1::int)
                    GROUP BY bucket ORDER BY bucket
                    """,
                    hours,
                )
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                """
                SELECT strftime('%Y-%m-%d %H:00', connected_at) AS bucket, COUNT(*) AS cnt
                FROM connections
                WHERE connected_at >= datetime('now', '-' || ? || ' hours')
                GROUP BY bucket ORDER BY bucket
                """,
                (hours,),
            )
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    async def summary_counts(self) -> dict:
        """
        The four headline counts, in ONE round trip.

        This previously issued four separate queries in a loop. Against a
        remote pooler that is four network round trips for four integers —
        measured at 1.9s of a 4.3s page load, with a 214ms latency floor per
        trip. The counts are independent scalars, so a single SELECT of four
        subqueries returns identical results for a quarter of the wall time.
        """
        ack_false = "FALSE" if self.backend == "postgres" else "0"
        sql = f"""
            SELECT
              (SELECT COUNT(*) FROM connections)                            AS total_connections,
              (SELECT COUNT(*) FROM attackers)                              AS total_attackers,
              (SELECT COUNT(*) FROM alerts WHERE acknowledged = {ack_false}) AS active_alerts,
              (SELECT COUNT(*) FROM attackers WHERE verdict = 'CRITICAL')   AS critical_attackers
        """
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                return dict(await conn.fetchrow(sql))

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            return dict(conn.execute(sql).fetchone())

        return await self._run_sqlite(_work)

    async def count_login_attempts(self) -> int:
        """
        Size of the captured-credential corpus.

        Threat Hunting only ever displayed this number, but obtained it by
        fetching up to 500 rows and calling len() — transferring the whole
        corpus to count it.
        """
        sql = "SELECT COUNT(*) AS cnt FROM login_attempts"
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                return await conn.fetchval(sql)

        def _work(conn: sqlite3.Connection):
            return conn.execute(sql).fetchone()[0]

        return await self._run_sqlite(_work)

    async def credential_stats(self, top_n: int = 10) -> dict:
        """
        Shape of the captured-credential corpus: totals plus the most-tried
        usernames and passwords.

        Threat Hunting opened with empty search boxes and no indication of what
        was searchable. "What are they actually trying?" is the first question
        an operator has, and it is answerable with aggregates — no search term
        required. Returned as counts, so nothing attacker-supplied needs to
        reach a raw-HTML sink; the values themselves still render via
        theme.table, which is inert.
        """
        empty = {"total": 0, "unique_usernames": 0, "unique_passwords": 0,
                 "unique_sources": 0, "top_usernames": [], "top_passwords": []}

        totals_sql = """
            SELECT COUNT(*)                        AS total,
                   COUNT(DISTINCT username)        AS unique_usernames,
                   COUNT(DISTINCT password)        AS unique_passwords,
                   COUNT(DISTINCT ip_address)      AS unique_sources
            FROM login_attempts
        """
        top_sql = ("SELECT {col} AS value, COUNT(*) AS attempts, "
                   "COUNT(DISTINCT ip_address) AS sources "
                   "FROM login_attempts WHERE {col} IS NOT NULL "
                   "GROUP BY {col} ORDER BY attempts DESC, value ASC LIMIT {lim}")

        if self.backend == "postgres":
            # Three independent aggregates, issued together. Sequential on one
            # connection they were three round trips (917 ms measured, the long
            # pole of Threat Hunting); gathered, one.
            totals, users, pwds = await asyncio.gather(
                self._pg_pool.fetchrow(totals_sql),
                self._pg_pool.fetch(top_sql.format(col="username", lim=int(top_n))),
                self._pg_pool.fetch(top_sql.format(col="password", lim=int(top_n))),
            )
            if not totals:
                return empty
            return {**dict(totals),
                    "top_usernames": [dict(r) for r in users],
                    "top_passwords": [dict(r) for r in pwds]}

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            totals = conn.execute(totals_sql).fetchone()
            users = conn.execute(top_sql.format(col="username", lim=int(top_n))).fetchall()
            pwds = conn.execute(top_sql.format(col="password", lim=int(top_n))).fetchall()
            if totals is None:
                return empty
            return {**dict(totals),
                    "top_usernames": [dict(r) for r in users],
                    "top_passwords": [dict(r) for r in pwds]}

        return await self._run_sqlite(_work)

    async def search_login_attempts(self, pattern: str, limit: int = 100) -> list:
        """Substring search across username/password — used by Threat Hunting."""
        like = f"%{pattern}%"
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT la.ip_address, la.username, la.password, la.attempted_at, c.service
                    FROM login_attempts la
                    JOIN connections c ON c.id = la.connection_id
                    WHERE la.username ILIKE $1 OR la.password ILIKE $1
                    ORDER BY la.attempted_at DESC LIMIT $2
                    """,
                    like, limit,
                )
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                """
                SELECT la.ip_address, la.username, la.password, la.attempted_at, c.service
                FROM login_attempts la
                JOIN connections c ON c.id = la.connection_id
                WHERE la.username LIKE ? OR la.password LIKE ?
                ORDER BY la.attempted_at DESC LIMIT ?
                """,
                (like, like, limit),
            )
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    # ── Correlation engine (phase 5) ──────────────────────────────────

    async def get_service_sequence_since(self, ip_address: str, window_seconds: int) -> list:
        """Chronological (service, connected_at) pairs for one IP within the window —
        used as multi-service alert evidence (which services, what order, what timestamps)."""
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT service, connected_at FROM connections
                    WHERE ip_address = $1 AND connected_at >= now() - make_interval(secs => $2::int)
                    ORDER BY connected_at ASC
                    """,
                    ip_address, window_seconds,
                )
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                """
                SELECT service, connected_at FROM connections
                WHERE ip_address = ? AND connected_at >= datetime('now', '-' || ? || ' seconds')
                ORDER BY connected_at ASC
                """,
                (ip_address, window_seconds),
            )
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    async def count_distinct_services_since(self, ip_address: str, window_seconds: int) -> int:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT COUNT(DISTINCT service) AS cnt FROM connections
                    WHERE ip_address = $1 AND connected_at >= now() - make_interval(secs => $2::int)
                    """,
                    ip_address, window_seconds,
                )
                return row["cnt"]

        def _work(conn: sqlite3.Connection):
            cur = conn.execute(
                """
                SELECT COUNT(DISTINCT service) AS cnt FROM connections
                WHERE ip_address = ? AND connected_at >= datetime('now', '-' || ? || ' seconds')
                """,
                (ip_address, window_seconds),
            )
            return cur.fetchone()[0]

        return await self._run_sqlite(_work)

    async def count_distinct_services_total(self, ip_address: str) -> int:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT COUNT(DISTINCT service) AS cnt FROM connections WHERE ip_address = $1", ip_address
                )
                return row["cnt"]

        def _work(conn: sqlite3.Connection):
            cur = conn.execute("SELECT COUNT(DISTINCT service) AS cnt FROM connections WHERE ip_address = ?", (ip_address,))
            return cur.fetchone()[0]

        return await self._run_sqlite(_work)

    async def detect_asn_campaigns(self, window_seconds: int, min_attackers: int) -> list:
        """Group attackers by ASN where >= min_attackers distinct IPs were active
        within the last window_seconds — same shape as v1's campaign_detector.py."""
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT asn,
                           COUNT(DISTINCT ip_address) AS attacker_count,
                           string_agg(DISTINCT host(ip_address), ',') AS ip_list,
                           MIN(first_seen) AS campaign_start,
                           MAX(last_seen) AS campaign_end,
                           SUM(total_connections) AS total_connections
                    FROM attackers
                    WHERE asn IS NOT NULL AND last_seen >= now() - make_interval(secs => $1::int)
                    GROUP BY asn
                    HAVING COUNT(DISTINCT ip_address) >= $2
                    ORDER BY attacker_count DESC
                    """,
                    window_seconds, min_attackers,
                )
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                """
                SELECT asn,
                       COUNT(DISTINCT ip_address) AS attacker_count,
                       GROUP_CONCAT(DISTINCT ip_address) AS ip_list,
                       MIN(first_seen) AS campaign_start,
                       MAX(last_seen) AS campaign_end,
                       SUM(total_connections) AS total_connections
                FROM attackers
                WHERE asn IS NOT NULL AND last_seen >= datetime('now', '-' || ? || ' seconds')
                GROUP BY asn
                HAVING attacker_count >= ?
                ORDER BY attacker_count DESC
                """,
                (window_seconds, min_attackers),
            )
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    async def get_attackers_by_ips(self, ip_addresses: list) -> list:
        """Full attacker rows for a specific set of IPs — used to expand a campaign's membership."""
        if not ip_addresses:
            return []

        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM attackers WHERE host(ip_address) = ANY($1::text[])", ip_addresses
                )
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            placeholders = ",".join("?" for _ in ip_addresses)
            cur = conn.execute(f"SELECT * FROM attackers WHERE ip_address IN ({placeholders})", ip_addresses)
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    # ── AI analyst (phase 6) ──────────────────────────────────────────

    async def list_connections_for_ip(self, ip_address: str, limit: int = 50) -> list:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT service, port, connected_at FROM connections "
                    "WHERE ip_address = $1 ORDER BY connected_at DESC LIMIT $2",
                    ip_address, limit,
                )
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT service, port, connected_at FROM connections "
                "WHERE ip_address = ? ORDER BY connected_at DESC LIMIT ?",
                (ip_address, limit),
            )
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    async def list_alerts_for_ip(self, ip_address: str, limit: int = 20) -> list:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT alert_type, severity, evidence, created_at FROM alerts "
                    "WHERE ip_address = $1 ORDER BY created_at DESC LIMIT $2",
                    ip_address, limit,
                )
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT alert_type, severity, evidence, created_at FROM alerts "
                "WHERE ip_address = ? ORDER BY created_at DESC LIMIT ?",
                (ip_address, limit),
            )
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)

    async def record_ai_report(self, ip_address: str, report_text: str) -> int:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "INSERT INTO ai_reports (ip_address, report_text) VALUES ($1, $2) RETURNING id",
                    ip_address, report_text,
                )
                return row["id"]

        def _work(conn: sqlite3.Connection):
            cur = conn.execute(
                "INSERT INTO ai_reports (ip_address, report_text) VALUES (?, ?)", (ip_address, report_text)
            )
            return cur.lastrowid

        return await self._run_sqlite(_work)

    async def list_ai_reports_for_ip(self, ip_address: str, limit: int = 10) -> list:
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT id, report_text, generated_at FROM ai_reports "
                    "WHERE ip_address = $1 ORDER BY generated_at DESC LIMIT $2",
                    ip_address, limit,
                )
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT id, report_text, generated_at FROM ai_reports "
                "WHERE ip_address = ? ORDER BY generated_at DESC LIMIT ?",
                (ip_address, limit),
            )
            return [dict(r) for r in cur.fetchall()]

        return await self._run_sqlite(_work)


db = AsyncDatabase()
