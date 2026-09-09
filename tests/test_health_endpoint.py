#!/usr/bin/env python3
"""
Health endpoint — answers a ping, records absolutely nothing.

Run directly:  python tests/test_health_endpoint.py

The endpoint exists so an uptime monitor can keep a free-tier PaaS awake
without polluting captured data, so the property under test is a NEGATIVE one:
after hammering /_health, every capture table must hold exactly as many rows as
it did before. Asserting "it returns 200" would pass while the endpoint quietly
wrote a row per ping, which is the failure that actually matters.

Both deployment shapes are exercised, because the endpoint sits above BOTH
recording branches and only testing one would miss half of it:

  - direct exposure          -> would otherwise write to `connections`
  - behind a proxy, no XFF   -> would otherwise write to `filtered_connections`
  - behind a proxy, with XFF -> would otherwise write to `connections`

Alongside that, the decoy paths must keep behaving exactly as before — the
point of the honeypot is that /wp-login.php is still a trap — and near-miss
paths (/_healthz, /_health/../wp-login.php, POST /_health) must NOT be treated
as health checks, since each would otherwise be a way to slip past logging.

Uses a throwaway SQLite database; production is never touched.
"""

import os
import socket
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_DB = REPO_ROOT / "data" / "test_health_endpoint.db"
os.environ["SQLITE_PATH"] = str(TEST_DB)
os.environ["DATABASE_URL"] = ""   # never point this at production
sys.path.insert(0, str(REPO_ROOT))

import asyncio  # noqa: E402
import sqlite3  # noqa: E402

import config  # noqa: E402

config.SKIP_SCHEMA_INIT = False
config.HEALTH_CHECK_PATH = "/_health"

from database.db_async import db  # noqa: E402
from honeypot.services.http_honeypot import HTTPHoneypot  # noqa: E402

RESULTS = []


def check(name, got, expected):
    ok = got == expected
    RESULTS.append((name, ok))
    print(("  PASS  " if ok else "  FAIL  ") + name)
    if not ok:
        print(f"          expected: {expected!r}")
        print(f"          actual:   {got!r}")


def check_true(name, got, note=""):
    check(name, bool(got), True)
    if not got and note:
        print(f"          note: {note}")


def section(t):
    print(f"\n{'=' * 74}\n{t}\n{'=' * 74}")


def counts() -> dict:
    """Row counts across every table a request could possibly write to."""
    c = sqlite3.connect(TEST_DB)
    try:
        out = {}
        for table in ("connections", "filtered_connections", "attackers",
                      "login_attempts", "alerts"):
            try:
                out[table] = c.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            except sqlite3.OperationalError:
                out[table] = 0   # table not present in this schema build
        return out
    finally:
        c.close()


def paths(table: str, col: str = "path") -> list:
    c = sqlite3.connect(TEST_DB)
    try:
        return [r[0] for r in c.execute(f"SELECT {col} FROM {table} ORDER BY id")]
    finally:
        c.close()


def send(port: int, payload: bytes) -> bytes:
    """Open a real TCP connection, send raw bytes, return whatever comes back."""
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        s.sendall(payload)
        s.settimeout(10)
        chunks = []
        try:
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
        except socket.timeout:
            pass
        return b"".join(chunks)
    finally:
        s.close()


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def req(method: str, path: str, xff: str = None) -> bytes:
    head = f"{method} {path} HTTP/1.1\r\nHost: x\r\nUser-Agent: HealthTest/1.0\r\n"
    if xff:
        head += f"X-Forwarded-For: {xff}\r\n"
    return (head + "\r\n").encode()


async def main():
    TEST_DB.unlink(missing_ok=True)
    await db.connect()
    await db.init_schema()

    port = free_port()
    honeypot = HTTPHoneypot(port=port, host="127.0.0.1")
    server_task = asyncio.create_task(honeypot.start())
    await asyncio.sleep(0.6)  # let the listener bind

    loop = asyncio.get_running_loop()

    async def fire(payload: bytes) -> bytes:
        return await loop.run_in_executor(None, send, port, payload)

    try:
        # ── Direct exposure ───────────────────────────────────────────────
        config.TRUST_PROXY_HEADERS = False
        config.IGNORE_UNFORWARDED_CONNECTIONS = False

        section("Direct exposure — /_health writes nothing, decoys still log")

        before = counts()
        reply = await fire(req("GET", "/_health"))
        check_true("/_health returns 200", reply.startswith(b"HTTP/1.1 200 OK"))
        check_true("/_health body is inert text", b"ok" in reply)
        check_true("/_health does not leak a honeypot decoy page",
                   b"Login" not in reply and b"WordPress" not in reply)

        # Hammer it the way a monitor would.
        for _ in range(24):
            await fire(req("GET", "/_health"))
        await fire(req("HEAD", "/_health"))
        await fire(req("GET", "/_health?cachebust=99"))
        await asyncio.sleep(1.2)   # let any background write settle

        after = counts()
        check("27 health pings produced zero connection rows",
              after["connections"], before["connections"])
        check("...zero filtered_connections rows",
              after["filtered_connections"], before["filtered_connections"])
        check("...zero attacker rows", after["attackers"], before["attackers"])
        check("...zero login_attempts", after["login_attempts"], before["login_attempts"])
        check("...zero alerts", after["alerts"], before["alerts"])
        check_true("query string is ignored, not treated as a different path",
                   after["connections"] == 0)

        section("Decoy paths keep full logging, unchanged")

        await fire(req("GET", "/wp-login.php"))
        await fire(req("GET", "/admin"))
        await fire(req("POST", "/admin"))
        await asyncio.sleep(1.2)

        logged = paths("connections")
        check("three decoy requests produced three rows", len(logged), 3)
        check_true("/wp-login.php logged", "/wp-login.php" in logged)
        check_true("/admin logged", "/admin" in logged)
        check_true("decoy rows created attacker records", counts()["attackers"] >= 1)

        section("Near misses are NOT health checks — no logging bypass")

        baseline = counts()["connections"]
        bypasses = [
            ("GET", "/_healthz"),                    # prefix extension
            ("GET", "/_health/../wp-login.php"),     # traversal into a decoy
            ("GET", "/_health/sub"),                 # subpath
            ("GET", "/_HEALTH"),                     # case variation
            ("GET", "/x/_health"),                   # not at the root
            ("POST", "/_health"),                    # wrong method
        ]
        for method, path in bypasses:
            await fire(req(method, path))
        await asyncio.sleep(1.4)

        now = counts()["connections"]
        check(f"all {len(bypasses)} near-miss requests were captured",
              now - baseline, len(bypasses))
        captured = paths("connections")
        for _, path in bypasses:
            check_true(f"captured verbatim: {path}", path in captured)

        # ── Behind a proxy ────────────────────────────────────────────────
        config.TRUST_PROXY_HEADERS = True
        config.IGNORE_UNFORWARDED_CONNECTIONS = True
        config.TRUSTED_PROXY_HOPS = 1
        config.TRUSTED_CLIENT_IP_HEADER = ""

        section("Behind a proxy — invisible on both the forwarded and unforwarded path")

        before = counts()

        # An external monitor: arrives WITH a forwarding header, so without the
        # early return it would be written to `connections` as an attacker.
        for _ in range(10):
            await fire(req("GET", "/_health", xff="203.0.113.9"))
        # The platform's own internal checker: arrives WITHOUT one, so without
        # the early return it would be written to `filtered_connections`.
        for _ in range(10):
            await fire(req("GET", "/_health"))
        await asyncio.sleep(1.4)

        after = counts()
        check("monitor pings (with XFF) wrote no connection rows",
              after["connections"], before["connections"])
        check("platform pings (no XFF) wrote no filtered_connections rows",
              after["filtered_connections"], before["filtered_connections"])
        check("no attacker record created for either",
              after["attackers"], before["attackers"])

        section("Behind a proxy — decoys still route correctly, as before")

        before = counts()
        await fire(req("GET", "/wp-login.php", xff="203.0.113.9"))
        await asyncio.sleep(1.2)
        mid = counts()
        check("forwarded decoy request logged to connections",
              mid["connections"] - before["connections"], 1)
        check("...and not to filtered_connections",
              mid["filtered_connections"], before["filtered_connections"])

        await fire(req("GET", "/wp-login.php"))
        await asyncio.sleep(1.2)
        end = counts()
        check("unforwarded decoy request filtered, as designed",
              end["filtered_connections"] - mid["filtered_connections"], 1)
        check("...and not counted as a real connection",
              end["connections"], mid["connections"])
        check_true("filtered row still records what was asked for",
                   "/wp-login.php" in paths("filtered_connections"))

        section("Disabling the endpoint restores pure honeypot behaviour")

        config.HEALTH_CHECK_PATH = ""
        before = counts()
        await fire(req("GET", "/_health", xff="203.0.113.9"))
        await asyncio.sleep(1.2)
        check("with HEALTH_CHECK_PATH empty, /_health is captured like any path",
              counts()["connections"] - before["connections"], 1)
        config.HEALTH_CHECK_PATH = "/_health"

    finally:
        await honeypot.stop()
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, Exception):
            pass
        await db.close()
        TEST_DB.unlink(missing_ok=True)

    p = sum(1 for _, ok in RESULTS if ok)
    f = len(RESULTS) - p
    print(f"\n{'=' * 74}\n  HEALTH ENDPOINT TOTAL: {len(RESULTS)} run, "
          f"{p} passed, {f} failed\n{'=' * 74}")
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
