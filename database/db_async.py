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
            self._pg_pool = await asyncpg.create_pool(config.DATABASE_URL)
            logger.info("Connected to PostgreSQL")
        else:
            logger.info(f"Using local SQLite dev database: {self._sqlite_path}")

    async def close(self):
        if self._pg_pool:
            await self._pg_pool.close()

    async def init_schema(self):
        """Create all tables/indexes if they don't already exist."""
        if self.backend == "postgres":
            schema_sql = Path("database/schema_postgres.sql").read_text(encoding="utf-8")
            async with self._pg_pool.acquire() as conn:
                await conn.execute(schema_sql)
        else:
            schema_sql = Path("database/schema_sqlite_dev.sql").read_text(encoding="utf-8")
            await self._run_sqlite(lambda conn: conn.executescript(schema_sql))

        logger.info(f"Database schema initialized ({self.backend})")

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

    async def record_connection(self, ip_address: str, service: str, port: int) -> int:
        """Upsert the attacker row and insert a connections row. Returns the new connection id."""
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
                        INSERT INTO connections (ip_address, service, port)
                        VALUES ($1, $2, $3)
                        RETURNING id
                        """,
                        ip_address, service, port,
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
                "INSERT INTO connections (ip_address, service, port) VALUES (?, ?, ?)",
                (ip_address, service, port),
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


db = AsyncDatabase()
