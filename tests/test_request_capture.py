#!/usr/bin/env python3
"""
Request-detail capture — method, path and User-Agent on real connections.

Run directly:  python tests/test_request_capture.py

Drives the real HTTPHoneypot over a real TCP socket on a loopback port and
asserts what lands in the database. Not mocked: the point is that an actual
request produces an actual row, including the awkward cases — a bare TCP probe
that sends nothing, a malformed request line, and oversized attacker-controlled
values that must be truncated rather than stored whole or dropped.

Uses a throwaway SQLite database; production is never touched.
"""

import os
import socket
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_DB = REPO_ROOT / "data" / "test_request_capture.db"
os.environ["SQLITE_PATH"] = str(TEST_DB)
os.environ["DATABASE_URL"] = ""   # never point this at production
sys.path.insert(0, str(REPO_ROOT))

import asyncio  # noqa: E402
import sqlite3  # noqa: E402

import config  # noqa: E402

config.SKIP_SCHEMA_INIT = False
# Direct exposure: no proxy in front of a loopback socket, so the peer address
# is the client and the unforwarded-connection filter must stay off.
config.TRUST_PROXY_HEADERS = False
config.IGNORE_UNFORWARDED_CONNECTIONS = False

from database.db_async import db  # noqa: E402
from honeypot.services.http_honeypot import (  # noqa: E402
    HTTPHoneypot, MAX_METHOD_LEN, MAX_PATH_LEN, MAX_USER_AGENT_LEN,
)

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


def rows():
    c = sqlite3.connect(TEST_DB)
    try:
        c.row_factory = sqlite3.Row
        return [dict(r) for r in c.execute(
            "SELECT id, ip_address, service, port, method, path, user_agent, "
            "forwarded_for_raw FROM connections ORDER BY id")]
    finally:
        c.close()


def send(port: int, payload: bytes, read_reply: bool = True):
    """Open a real TCP connection and send raw bytes."""
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        if payload:
            s.sendall(payload)
        if read_reply:
            s.settimeout(10)
            try:
                s.recv(4096)
            except socket.timeout:
                pass
    finally:
        s.close()


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def main():
    TEST_DB.unlink(missing_ok=True)
    await db.connect()
    await db.init_schema()

    port = free_port()
    honeypot = HTTPHoneypot(port=port, host="127.0.0.1")
    server_task = asyncio.create_task(honeypot.start())
    await asyncio.sleep(0.6)  # let the listener bind

    try:
        section("Schema — new columns exist and are additive")
        _c = sqlite3.connect(TEST_DB)
        try:
            cols = {r[1] for r in _c.execute("PRAGMA table_info(connections)")}
        finally:
            _c.close()
        for col in ("method", "path", "user_agent"):
            check_true(f"connections.{col} exists", col in cols)
        check_true("pre-existing columns untouched",
                   {"id", "ip_address", "service", "port", "connected_at",
                    "forwarded_for_raw"} <= cols)

        section("Real requests over a real socket")

        # 1. Ordinary GET with a User-Agent.
        await asyncio.get_running_loop().run_in_executor(None, send, port, (
            b"GET /admin HTTP/1.1\r\nHost: x\r\n"
            b"User-Agent: Mozilla/5.0 (compatible; TestScanner/1.0)\r\n\r\n"
        ))
        # 2. A recon probe for a commonly-exploited path.
        await asyncio.get_running_loop().run_in_executor(None, send, port, (
            b"GET /.env HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8.4.0\r\n\r\n"
        ))
        # 3. POST — method must not be flattened to GET.
        await asyncio.get_running_loop().run_in_executor(None, send, port, (
            b"POST /admin HTTP/1.1\r\nHost: x\r\nUser-Agent: python-requests/2.31\r\n"
            b"Content-Length: 27\r\n\r\nusername=admin&password=abc"
        ))
        # 4. Bare TCP connect, no bytes at all.
        await asyncio.get_running_loop().run_in_executor(None, send, port, b"")
        # 5. Malformed request line.
        await asyncio.get_running_loop().run_in_executor(None, send, port, b"GARBAGE\r\n\r\n")
        # 6. Oversized path and User-Agent — must truncate, not drop or store whole.
        await asyncio.get_running_loop().run_in_executor(None, send, port, (
            b"GET /" + b"A" * 5000 + b" HTTP/1.1\r\nHost: x\r\n"
            b"User-Agent: " + b"B" * 3000 + b"\r\n\r\n"
        ))
        await asyncio.sleep(1.2)  # let background writes settle

        captured = rows()
        print(f"\n  {len(captured)} connection row(s) recorded")
        for r in captured:
            print(f"    id={r['id']} method={r['method']!r} "
                  f"path={(r['path'] or '')[:40]!r} ua={(r['user_agent'] or '')[:34]!r}")

        by_req = {(r["method"], r["path"]): r for r in captured if r["path"]}

        check("all six connections recorded", len(captured), 6)

        check_true("GET /admin captured", ("GET", "/admin") in by_req)
        if ("GET", "/admin") in by_req:
            check("user-agent recorded", by_req[("GET", "/admin")]["user_agent"],
                  "Mozilla/5.0 (compatible; TestScanner/1.0)")

        check_true("recon path /.env captured verbatim", ("GET", "/.env") in by_req)
        if ("GET", "/.env") in by_req:
            check("curl user-agent recorded",
                  by_req[("GET", "/.env")]["user_agent"], "curl/8.4.0")
        check_true("same path with a different method is a distinct row",
                   ("POST", "/admin") in by_req)

        posts = [r for r in captured if r["method"] == "POST"]
        check("POST recorded as POST, not flattened", len(posts), 1)

        nulls = [r for r in captured if r["method"] is None]
        check("bare probe and malformed request stored NULL, not empty string", len(nulls), 2)
        check_true("NULL rows still recorded as connections (not dropped)",
                   all(r["ip_address"] for r in nulls))

        section("Truncation of attacker-controlled values")
        oversized = [r for r in captured if r["path"] and len(r["path"]) >= 100]
        check("oversized request produced exactly one row", len(oversized), 1)
        if oversized:
            r = oversized[0]
            check(f"path truncated to MAX_PATH_LEN ({MAX_PATH_LEN})", len(r["path"]), MAX_PATH_LEN)
            check(f"user_agent truncated to MAX_USER_AGENT_LEN ({MAX_USER_AGENT_LEN})",
                  len(r["user_agent"]), MAX_USER_AGENT_LEN)
            check_true("truncated path keeps its meaningful prefix", r["path"].startswith("/AAA"))
            check_true("method still bounded", len(r["method"] or "") <= MAX_METHOD_LEN)

        section("Read path exposes the new columns")
        recent = await db.list_recent_connections(limit=10)
        check_true("list_recent_connections returns method/path/user_agent",
                   all(k in recent[0] for k in ("method", "path", "user_agent")))

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
    print(f"\n{'=' * 74}\n  REQUEST CAPTURE TOTAL: {len(RESULTS)} run, {p} passed, {f} failed\n{'=' * 74}")
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
