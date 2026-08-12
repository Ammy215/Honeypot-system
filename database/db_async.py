"""
Async database layer for HoneyShield v2 — raw SQL, no ORM.

Backend is chosen by config: DATABASE_URL (PostgreSQL, via asyncpg) for
production, SQLITE_PATH (stdlib sqlite3, run in a thread executor so it
doesn't block the event loop) for local development. Same public API
either way, so honeypot services don't need to know which one is active.
"""

import asyncio
import sqlite3
import logging
from pathlib import Path

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


db = AsyncDatabase()
