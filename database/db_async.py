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


class AsyncDatabase:
    def __init__(self):
        self.backend = "postgres" if config.DATABASE_URL else "sqlite"
        self._pg_pool = None
        self._sqlite_path = None

        if self.backend == "sqlite":
            self._sqlite_path = Path(config.SQLITE_PATH)
            self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)

    async def connect(self):
        """Establish the backend connection (pool for Postgres; no-op for SQLite)."""
        if self.backend == "postgres":
            import asyncpg
            # TLS is required explicitly, not left to negotiation. asyncpg
            # defaults to "prefer": it will happily fall back to an unencrypted
            # connection if the server doesn't offer TLS, which would put
            # captured credentials on the wire in cleartext. "require" refuses
            # to connect without encryption; "verify-full" additionally checks
            # the certificate chain and hostname.
            self._pg_pool = await asyncpg.create_pool(
                config.DATABASE_URL,
                ssl=config.DB_SSL_MODE,
            )
            logger.info(f"Connected to PostgreSQL (ssl={config.DB_SSL_MODE})")
        else:
            logger.info(f"Using local SQLite dev database: {self._sqlite_path}")

    async def close(self):
        if self._pg_pool:
            await self._pg_pool.close()

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
        def _work(conn: sqlite3.Connection):
            existing = {row[1] for row in conn.execute("PRAGMA table_info(connections)")}
            if "forwarded_for_raw" not in existing:
                conn.execute("ALTER TABLE connections ADD COLUMN forwarded_for_raw TEXT")
                logger.info("Migrated SQLite dev DB: added connections.forwarded_for_raw")

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
        self, ip_address: str, service: str, port: int, forwarded_for_raw: Optional[str] = None
    ) -> int:
        """
        Upsert the attacker row and insert a connections row. Returns the new connection id.

        `ip_address` is the *resolved* client address (see
        honeypot/core/client_ip.py). `forwarded_for_raw` stores the untouched
        proxy header alongside it as evidence — parameterized like every other
        attacker-controlled value, never interpolated.
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
                        INSERT INTO connections (ip_address, service, port, forwarded_for_raw)
                        VALUES ($1, $2, $3, $4)
                        RETURNING id
                        """,
                        ip_address, service, port, forwarded_for_raw,
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
                "INSERT INTO connections (ip_address, service, port, forwarded_for_raw) VALUES (?, ?, ?, ?)",
                (ip_address, service, port, forwarded_for_raw),
            )
            return cur.lastrowid

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

    async def service_breakdown(self) -> list:
        query = "SELECT service, COUNT(*) AS cnt FROM connections GROUP BY service ORDER BY cnt DESC"
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(query)
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(query).fetchall()]

        return await self._run_sqlite(_work)

    async def verdict_breakdown(self) -> list:
        query = "SELECT verdict, COUNT(*) AS cnt FROM attackers WHERE verdict IS NOT NULL GROUP BY verdict"
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(query)
                return [dict(r) for r in rows]

        def _work(conn: sqlite3.Connection):
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(query).fetchall()]

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
        queries = {
            "total_connections": "SELECT COUNT(*) AS cnt FROM connections",
            "total_attackers": "SELECT COUNT(*) AS cnt FROM attackers",
            "active_alerts": "SELECT COUNT(*) AS cnt FROM alerts WHERE acknowledged = {}".format(
                "FALSE" if self.backend == "postgres" else "0"
            ),
            "critical_attackers": "SELECT COUNT(*) AS cnt FROM attackers WHERE verdict = 'CRITICAL'",
        }
        result = {}
        if self.backend == "postgres":
            async with self._pg_pool.acquire() as conn:
                for key, q in queries.items():
                    row = await conn.fetchrow(q)
                    result[key] = row["cnt"]
            return result

        def _work(conn: sqlite3.Connection):
            out = {}
            for key, q in queries.items():
                out[key] = conn.execute(q).fetchone()[0]
            return out

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
