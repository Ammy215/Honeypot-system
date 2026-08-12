#!/usr/bin/env python3
"""
Tests for the Option A (HTTP-only PaaS deployment) fixes.

Run directly:  python tests/test_option_a_fixes.py

Covers, in order:
  1. Client IP resolution behind a proxy, including deliberate X-Forwarded-For
     spoofing — the case that would otherwise let an attacker forge their
     source IP, and the whole reason this module exists.
  2. End-to-end: a real request to a real listener with a spoofed header,
     asserted against the actual database row.
  3. $PORT binding.
  4. ENABLED_SERVICES gating.
  5. asyncpg TLS enforcement.
"""

import os
import sys
import subprocess
from pathlib import Path

# Isolate from the real dev database. Must precede any project import, since
# config reads the environment at import time and the db singleton is built
# from it at module scope.
REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_DB = REPO_ROOT / "data" / "test_option_a.db"
os.environ["SQLITE_PATH"] = str(TEST_DB)
os.environ.pop("DATABASE_URL", None)
sys.path.insert(0, str(REPO_ROOT))

import asyncio  # noqa: E402
import sqlite3  # noqa: E402
import types  # noqa: E402

import config  # noqa: E402
from honeypot.core.client_ip import resolve_client_ip  # noqa: E402

PASS, FAIL = [], []


def check(name, got, expected):
    if got == expected:
        PASS.append(name)
        print(f"  PASS  {name}")
    else:
        FAIL.append(name)
        print(f"  FAIL  {name}\n          expected: {expected!r}\n          got:      {expected.__class__.__name__} {got!r}")


def section(title):
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


# ─────────────────────────────────────────────────────────────────────────────
section("1. Client IP resolution / X-Forwarded-For spoofing")
# ─────────────────────────────────────────────────────────────────────────────

PEER = "10.0.0.1"          # stands in for the PaaS load balancer
ATTACKER = "203.0.113.7"   # the address the platform actually observed
SPOOF = "1.2.3.4"          # what the attacker claims to be

# --- Trust disabled (direct exposure / local dev) ---------------------------
config.TRUST_PROXY_HEADERS = False
config.TRUSTED_CLIENT_IP_HEADER = ""
config.FORWARDED_IP_HEADER = "x-forwarded-for"
config.TRUSTED_PROXY_HOPS = 1

check(
    "trust disabled: header is ignored entirely",
    resolve_client_ip({"x-forwarded-for": SPOOF}, PEER),
    (PEER, None),
)

# --- Trust enabled, single proxy hop ---------------------------------------
config.TRUST_PROXY_HEADERS = True

check(
    "no header present: falls back to peer",
    resolve_client_ip({}, PEER),
    (PEER, None),
)
check(
    "single entry (attacker sent nothing): that entry is the client",
    resolve_client_ip({"x-forwarded-for": ATTACKER}, PEER),
    (ATTACKER, ATTACKER),
)

# THE critical case. Attacker sends "X-Forwarded-For: 1.2.3.4"; the balancer
# appends the address it actually saw, giving "1.2.3.4, 203.0.113.7".
# Taking the FIRST entry would hand the attacker a forged source IP.
check(
    "SPOOFED single: takes rightmost (real), not leftmost (attacker-supplied)",
    resolve_client_ip({"x-forwarded-for": f"{SPOOF}, {ATTACKER}"}, PEER),
    (ATTACKER, f"{SPOOF}, {ATTACKER}"),
)
check(
    "SPOOFED chain: multiple fake entries still resolve to the real client",
    resolve_client_ip({"x-forwarded-for": f"{SPOOF}, 5.6.7.8, 9.9.9.9, {ATTACKER}"}, PEER),
    (ATTACKER, f"{SPOOF}, 5.6.7.8, 9.9.9.9, {ATTACKER}"),
)
check(
    "SPOOFED with private-range decoys: still resolves to the real client",
    resolve_client_ip({"x-forwarded-for": f"127.0.0.1, 192.168.1.1, {ATTACKER}"}, PEER),
    (ATTACKER, f"127.0.0.1, 192.168.1.1, {ATTACKER}"),
)

# --- Malformed / hostile input ---------------------------------------------
check(
    "garbage header: falls back to peer, keeps raw for evidence",
    resolve_client_ip({"x-forwarded-for": "not-an-ip"}, PEER),
    (PEER, "not-an-ip"),
)
check(
    "SQLi-style header value: not parsed as an IP, falls back to peer",
    resolve_client_ip({"x-forwarded-for": "'; DROP TABLE connections;--"}, PEER),
    (PEER, "'; DROP TABLE connections;--"),
)
check(
    "empty header: falls back to peer",
    resolve_client_ip({"x-forwarded-for": ""}, PEER),
    (PEER, None),
)
check(
    "IPv4 with port is stripped",
    resolve_client_ip({"x-forwarded-for": f"{SPOOF}, {ATTACKER}:44321"}, PEER),
    (ATTACKER, f"{SPOOF}, {ATTACKER}:44321"),
)
check(
    "bracketed IPv6 with port is unwrapped",
    resolve_client_ip({"x-forwarded-for": "[2001:db8::1]:443"}, PEER),
    ("2001:db8::1", "[2001:db8::1]:443"),
)
check(
    "bare IPv6 is preserved (not mistaken for host:port)",
    resolve_client_ip({"x-forwarded-for": "2001:db8::1"}, PEER),
    ("2001:db8::1", "2001:db8::1"),
)

# --- Two trusted hops (e.g. Cloudflare in front of the PaaS) ----------------
config.TRUSTED_PROXY_HOPS = 2
check(
    "2 hops: counts two from the right, skipping the inner proxy",
    resolve_client_ip({"x-forwarded-for": f"{SPOOF}, {ATTACKER}, 10.0.0.9"}, PEER),
    (ATTACKER, f"{SPOOF}, {ATTACKER}, 10.0.0.9"),
)
check(
    "2 hops but only 1 entry: degrades to leftmost, does not crash",
    resolve_client_ip({"x-forwarded-for": ATTACKER}, PEER),
    (ATTACKER, ATTACKER),
)
config.TRUSTED_PROXY_HOPS = 1

# --- Platform-set single-value header takes precedence ----------------------
config.TRUSTED_CLIENT_IP_HEADER = "cf-connecting-ip"
check(
    "platform header wins over a polluted X-Forwarded-For",
    resolve_client_ip(
        {"cf-connecting-ip": ATTACKER, "x-forwarded-for": f"{SPOOF}, {SPOOF}"}, PEER
    ),
    (ATTACKER, ATTACKER),
)
check(
    "platform header unparseable: falls through to XFF rightmost",
    resolve_client_ip(
        {"cf-connecting-ip": "bogus", "x-forwarded-for": f"{SPOOF}, {ATTACKER}"}, PEER
    ),
    (ATTACKER, f"{SPOOF}, {ATTACKER}"),
)
config.TRUSTED_CLIENT_IP_HEADER = ""


# ─────────────────────────────────────────────────────────────────────────────
section("2. End-to-end: spoofed request -> listener -> database row")
# ─────────────────────────────────────────────────────────────────────────────

TEST_DB.unlink(missing_ok=True)

from database.db_async import db  # noqa: E402
from honeypot.services.http_honeypot import HTTPHoneypot  # noqa: E402

E2E_PORT = 18080
E2E_ATTACKER = "198.51.100.23"
E2E_SPOOF = "8.8.8.8"


async def e2e():
    config.TRUST_PROXY_HEADERS = True
    await db.connect()
    await db.init_schema()

    service = HTTPHoneypot(port=E2E_PORT, host="127.0.0.1")
    server_task = asyncio.create_task(service.start())
    await asyncio.sleep(0.4)

    # A POST carrying credentials, with an attacker-forged X-Forwarded-For
    # prefix — exactly the shape of a real credential-stuffing bot behind a
    # load balancer that also tries to hide its source.
    body = "username=admin&password=hunter2"
    request = (
        f"POST /admin HTTP/1.1\r\n"
        f"Host: honeypot.example\r\n"
        f"X-Forwarded-For: {E2E_SPOOF}, {E2E_ATTACKER}\r\n"
        f"User-Agent: sqlmap/1.7\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n{body}"
    )

    reader, writer = await asyncio.open_connection("127.0.0.1", E2E_PORT)
    writer.write(request.encode())
    await writer.drain()
    response = await reader.read(4096)
    writer.close()
    await writer.wait_closed()
    await asyncio.sleep(0.6)

    service_stopped = service.stop()
    server_task.cancel()
    await service_stopped

    return response.decode("utf-8", errors="ignore")


response = asyncio.run(e2e())

check("responds with valid HTTP", response.startswith("HTTP/1.1 200"), True)

conn = sqlite3.connect(TEST_DB)
row = conn.execute(
    "SELECT ip_address, service, port, forwarded_for_raw FROM connections ORDER BY id DESC LIMIT 1"
).fetchone()
login = conn.execute(
    "SELECT ip_address, username, password FROM login_attempts ORDER BY id DESC LIMIT 1"
).fetchone()
attacker_ips = [r[0] for r in conn.execute("SELECT ip_address FROM attackers")]
conn.close()

check("connection row records the RESOLVED client IP", row[0], E2E_ATTACKER)
check("connection row does NOT record the spoofed IP", row[0] != E2E_SPOOF, True)
check("connection row does NOT record the loopback peer", row[0] != "127.0.0.1", True)
check("raw forwarded header stored verbatim", row[3], f"{E2E_SPOOF}, {E2E_ATTACKER}")
check("login attempt attributed to the resolved IP", login[0], E2E_ATTACKER)
check("captured credentials intact", (login[1], login[2]), ("admin", "hunter2"))
check("attackers table keyed on the resolved IP only", attacker_ips, [E2E_ATTACKER])


# ─────────────────────────────────────────────────────────────────────────────
section("3. $PORT binding  /  4. ENABLED_SERVICES gating")
# ─────────────────────────────────────────────────────────────────────────────

# The banner and status lines use non-ASCII glyphs. When stdout is a pipe
# rather than a terminal, Windows falls back to cp1252 and rich raises
# UnicodeEncodeError before main.run() gets anywhere. That's an artifact of
# capturing output here, not a defect under test — the deployment sets the
# same variable so piped container logs behave identically.
SUBPROC_ENV = {"PYTHONIOENCODING": "utf-8"}


def probe(env_extra, expr):
    """Read a config value in a clean subprocess, so env is applied at import."""
    env = {**os.environ, **SUBPROC_ENV, **env_extra}
    env.pop("DATABASE_URL", None)
    out = subprocess.run(
        [sys.executable, "-c", f"import config; print({expr})"],
        capture_output=True, text=True, cwd=REPO_ROOT, env=env,
    )
    if out.returncode != 0:
        return f"ERROR: {out.stderr.strip()[-200:]}"
    return out.stdout.strip()


check("no $PORT: falls back to the local-dev port 8080",
      probe({}, "config.HTTP_PORT"), "8080")
check("$PORT=8000 (PaaS-injected): binds 8000",
      probe({"PORT": "8000"}, "config.HTTP_PORT"), "8000")
check("HTTPHoneypot picks up $PORT",
      probe({"PORT": "3000"},
            "__import__('honeypot.services.http_honeypot', fromlist=['x']).HTTPHoneypot().port"),
      "3000")

check("default ENABLED_SERVICES: all four",
      probe({}, "','.join(config.ENABLED_SERVICES)"), "SSH,FTP,TELNET,HTTP")
check("production ENABLED_SERVICES=HTTP: HTTP only",
      probe({"ENABLED_SERVICES": "HTTP"}, "','.join(config.ENABLED_SERVICES)"), "HTTP")
check("ENABLED_SERVICES is case/space tolerant",
      probe({"ENABLED_SERVICES": " http , ssh "}, "','.join(config.ENABLED_SERVICES)"), "HTTP,SSH")

# main.py must reject an unknown name rather than silently starting nothing.
bad = subprocess.run(
    [sys.executable, "-c",
     "import asyncio, main; asyncio.run(main.run())"],
    capture_output=True, text=True, cwd=REPO_ROOT,
    env={**os.environ, **SUBPROC_ENV,
         "ENABLED_SERVICES": "HTTP,NOPE", "SQLITE_PATH": str(TEST_DB)},
    timeout=60,
)
check("unknown service name is rejected loudly",
      "unknown service" in (bad.stdout + bad.stderr).lower(), True)
check("...and names the offending value",
      "NOPE" in (bad.stdout + bad.stderr), True)


# ─────────────────────────────────────────────────────────────────────────────
section("5. asyncpg TLS enforcement")
# ─────────────────────────────────────────────────────────────────────────────

captured = {}


class _FakePool:
    async def close(self):
        pass


async def _fake_create_pool(dsn, **kwargs):
    captured["dsn"] = dsn
    captured["kwargs"] = kwargs
    return _FakePool()


sys.modules["asyncpg"] = types.SimpleNamespace(create_pool=_fake_create_pool)

config.DATABASE_URL = "postgresql://honeyshield_app:pw@db.example.com:5432/postgres"
config.DB_SSL_MODE = "require"

from database.db_async import AsyncDatabase  # noqa: E402

pg = AsyncDatabase()
check("postgres backend selected when DATABASE_URL is set", pg.backend, "postgres")
asyncio.run(pg.connect())
check("create_pool received an explicit ssl argument", "ssl" in captured["kwargs"], True)
check("ssl mode is 'require' (not left to negotiation)", captured["kwargs"].get("ssl"), "require")

config.DB_SSL_MODE = "verify-full"
asyncio.run(AsyncDatabase().connect())
check("ssl mode is configurable to verify-full", captured["kwargs"].get("ssl"), "verify-full")

# SKIP_SCHEMA_INIT must stop CREATE TABLE from ever being attempted, since the
# production role has no schema rights.
config.SKIP_SCHEMA_INIT = True
skipped_db = AsyncDatabase()
asyncio.run(skipped_db.connect())
asyncio.run(skipped_db.init_schema())  # would raise if it tried to execute DDL
check("SKIP_SCHEMA_INIT suppresses init_schema DDL", True, True)


# ─────────────────────────────────────────────────────────────────────────────
TEST_DB.unlink(missing_ok=True)
print(f"\n{'=' * 72}")
print(f"  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("\n  Failures:")
    for name in FAIL:
        print(f"    - {name}")
print(f"{'=' * 72}")
sys.exit(1 if FAIL else 0)
