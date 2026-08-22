#!/usr/bin/env python3
"""
Full pre-deployment test pass — everything testable without the live Render deploy.

Run directly:  python tests/test_predeployment.py

Sections (numbered to match the pre-deployment audit request):
  2.  Each service, normal path + idle-client case (HTTP/SSH/FTP/Telnet)
  3.  Malformed / hostile input against the HTTP service
  4.  IP resolution edge cases
  5.  Detection engines at exact thresholds (+ negative cases)
  6.  Threat scoring — hand-calculated, all 14 weights, verdict bands
  10. Filtered-connections logging

Sections 1 (existing suite), 7 (dashboard/auth), 8 (production DB permissions)
and 9 (AI analyst) are run by their own scripts — they need Streamlit's AppTest,
real production credentials, and a live Gemini call respectively.
"""

import os
import sys
from pathlib import Path

# Isolate from the real dev/production database. Must precede any project import.
# DATABASE_URL is set to "" rather than popped: python-dotenv's load_dotenv()
# (called at config.py import) only preserves variables that are still PRESENT,
# so popping the key lets dotenv repopulate it from the real .env. See the same
# note in test_option_a_fixes.py — this bug was caught live once already.
REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_DB = REPO_ROOT / "data" / "test_predeployment.db"
os.environ["SQLITE_PATH"] = str(TEST_DB)
os.environ["DATABASE_URL"] = ""
sys.path.insert(0, str(REPO_ROOT))

import asyncio  # noqa: E402
import sqlite3  # noqa: E402
import time  # noqa: E402

import config  # noqa: E402

# SKIP_SCHEMA_INIT=true leaks in from the real .env (set there for the
# production/dashboard roles, which can't run CREATE TABLE) and would leave this
# test database schema-less. Read fresh on every call, so a direct override works.
config.SKIP_SCHEMA_INIT = False

from database.db_async import db  # noqa: E402
from honeypot.core.client_ip import resolve_client_ip  # noqa: E402
from honeypot.services.http_honeypot import HTTPHoneypot  # noqa: E402
from honeypot.services.ssh_honeypot import SSHHoneypot  # noqa: E402
from honeypot.services.ftp_honeypot import FTPHoneypot  # noqa: E402
from honeypot.services.telnet_honeypot import TelnetHoneypot  # noqa: E402
from honeypot.detectors import async_detection  # noqa: E402
from honeypot.detectors.async_correlation import detect_asn_campaigns  # noqa: E402
from honeypot.intelligence import async_threat_scorer as scorer  # noqa: E402

RESULTS = []   # (section, name, passed, detail)
_SECTION = {"cur": "?"}


def section(title):
    _SECTION["cur"] = title.split(".")[0].strip()
    print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")


def check(name, got, expected, note=""):
    ok = got == expected
    RESULTS.append((_SECTION["cur"], name, ok, "" if ok else f"expected={expected!r} actual={got!r}"))
    if ok:
        print(f"  PASS  {name}")
    else:
        print(f"  FAIL  {name}")
        print(f"          expected: {expected!r}")
        print(f"          actual:   {got!r}")
        if note:
            print(f"          note:     {note}")


def check_true(name, got, note=""):
    check(name, bool(got), True, note)


# ── shared helpers ──────────────────────────────────────────────────────────

class RunningService:
    """Start a honeypot service on a local port for the duration of a block."""

    def __init__(self, service_cls, port):
        self.service_cls, self.port = service_cls, port

    async def __aenter__(self):
        self.service = self.service_cls(port=self.port, host="127.0.0.1")
        self.task = asyncio.create_task(self.service.start())
        await asyncio.sleep(0.4)
        return self.service

    async def __aexit__(self, *exc):
        stopped = self.service.stop()
        self.task.cancel()
        try:
            await stopped
        except Exception:
            pass
        await asyncio.sleep(0.1)


async def raw_send(port, payload: bytes, read_timeout=8.0, hold_open=False):
    """Send raw bytes, read whatever comes back, optionally hold the socket open."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    if payload:
        writer.write(payload)
        await writer.drain()
    try:
        resp = await asyncio.wait_for(reader.read(65536), timeout=read_timeout)
    except (asyncio.TimeoutError, ConnectionError):
        resp = b""
    if hold_open:
        return resp, writer
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return resp, None


def q(sql, params=()):
    c = sqlite3.connect(TEST_DB)
    c.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in c.execute(sql, params).fetchall()]
    finally:
        c.close()


def count(table, where="1=1", params=()):
    return q(f"SELECT COUNT(*) AS n FROM {table} WHERE {where}", params)[0]["n"]


def wipe():
    c = sqlite3.connect(TEST_DB)
    for t in ("login_attempts", "connections", "alerts", "ai_reports",
              "attacker_commands", "ioc_matches", "filtered_connections", "attackers"):
        try:
            c.execute(f"DELETE FROM {t}")
        except sqlite3.OperationalError:
            pass
    c.commit()
    c.close()


def seed_attacker(ip, connections=0, abuseipdb=None, otx=0, isp=None, asn=None, last_seen_ago=0):
    c = sqlite3.connect(TEST_DB)
    c.execute(
        "INSERT OR REPLACE INTO attackers "
        "(ip_address, total_connections, abuseipdb_score, otx_pulse_count, isp, asn, "
        " first_seen, last_seen) "
        "VALUES (?,?,?,?,?,?, datetime('now', '-' || ? || ' seconds'), datetime('now', '-' || ? || ' seconds'))",
        (ip, connections, abuseipdb, otx, isp, asn, last_seen_ago, last_seen_ago),
    )
    c.commit()
    c.close()


def seed_connection(ip, service, seconds_ago=0, port=8080):
    c = sqlite3.connect(TEST_DB)
    cur = c.execute(
        "INSERT INTO connections (ip_address, service, port, connected_at) "
        "VALUES (?,?,?, datetime('now', '-' || ? || ' seconds'))",
        (ip, service, port, seconds_ago),
    )
    c.commit()
    rid = cur.lastrowid
    c.close()
    return rid


def seed_login(conn_id, ip, username, password, seconds_ago=0):
    c = sqlite3.connect(TEST_DB)
    c.execute(
        "INSERT INTO login_attempts (connection_id, ip_address, username, password, attempted_at) "
        "VALUES (?,?,?,?, datetime('now', '-' || ? || ' seconds'))",
        (conn_id, ip, username, password, seconds_ago),
    )
    c.commit()
    c.close()


# ═══════════════════════════════════════════════════════════════════════════
async def s2_services():
    section("2. Each service — normal path, banner/response, DB rows, idle client")

    # ---- HTTP (the deploy target) ----
    wipe()
    async with RunningService(HTTPHoneypot, 19080):
        body = "username=root&password=toor"
        resp, _ = await raw_send(19080, (
            f"POST /wp-login.php HTTP/1.1\r\nHost: x\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}"
        ).encode())
        await asyncio.sleep(0.5)
    text = resp.decode("utf-8", "ignore")
    check_true("HTTP: returns valid HTTP/1.1 response", text.startswith("HTTP/1.1"))
    check_true("HTTP: WordPress decoy content served", "WordPress" in text or "loginform" in text)
    check("HTTP: connection row written", count("connections", "service='http'"), 1)
    check("HTTP: login attempt captured", count("login_attempts"), 1)
    check("HTTP: credentials stored verbatim",
          (q("SELECT username, password FROM login_attempts")[0]["username"],
           q("SELECT username, password FROM login_attempts")[0]["password"]), ("root", "toor"))

    # ---- SSH ----
    wipe()
    async with RunningService(SSHHoneypot, 19022):
        resp, _ = await raw_send(19022, b"SSH-2.0-libssh_0.9.6\r\n")
        await asyncio.sleep(6.0)  # SSH reads up to 3 packets before recording
    check_true("SSH: sends OpenSSH banner", resp.decode("utf-8", "ignore").startswith("SSH-2.0-OpenSSH"))
    check("SSH: connection row written", count("connections", "service='ssh'"), 1)

    # ---- FTP ----
    wipe()
    async with RunningService(FTPHoneypot, 19021) as svc:
        reader, writer = await asyncio.open_connection("127.0.0.1", 19021)
        banner = await asyncio.wait_for(reader.read(4096), timeout=6)
        writer.write(b"USER admin\r\n"); await writer.drain()
        r1 = await asyncio.wait_for(reader.read(4096), timeout=6)
        writer.write(b"PASS hunter2\r\n"); await writer.drain()
        try:
            await asyncio.wait_for(reader.read(4096), timeout=6)
        except asyncio.TimeoutError:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await asyncio.sleep(0.5)
    check_true("FTP: sends ProFTPD banner", banner.decode("utf-8", "ignore").startswith("220 ProFTPD"))
    check_true("FTP: USER prompts for password", b"331" in r1)
    check("FTP: connection row written", count("connections", "service='ftp'"), 1)
    check("FTP: login attempt captured", count("login_attempts"), 1)
    check("FTP: credentials stored verbatim",
          (q("SELECT username, password FROM login_attempts")[0]["username"],
           q("SELECT username, password FROM login_attempts")[0]["password"]), ("admin", "hunter2"))

    # ---- Telnet ----
    wipe()
    async with RunningService(TelnetHoneypot, 19023):
        reader, writer = await asyncio.open_connection("127.0.0.1", 19023)
        banner = await asyncio.wait_for(reader.read(4096), timeout=6)
        writer.write(b"root\r\n"); await writer.drain()
        prompt = await asyncio.wait_for(reader.read(4096), timeout=6)
        writer.write(b"admin123\r\n"); await writer.drain()
        try:
            await asyncio.wait_for(reader.read(4096), timeout=6)
        except asyncio.TimeoutError:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await asyncio.sleep(0.5)
    check_true("Telnet: sends Ubuntu login banner", b"login:" in banner)
    check_true("Telnet: prompts for password", b"Password" in prompt)
    check("Telnet: connection row written", count("connections", "service='telnet'"), 1)
    check("Telnet: login attempt captured", count("login_attempts"), 1)
    check("Telnet: credentials stored verbatim",
          (q("SELECT username, password FROM login_attempts")[0]["username"],
           q("SELECT username, password FROM login_attempts")[0]["password"]), ("root", "admin123"))

    # ---- Idle client on all four: connect, send NOTHING, do NOT disconnect ----
    # This is the Phase 1 regression case. Each service must still log the
    # connection rather than hanging until the outer 30s watchdog (which would
    # skip logging entirely).
    for name, cls, port, svc_key, wait in (
        ("HTTP", HTTPHoneypot, 19180, "http", 7.0),
        ("SSH", SSHHoneypot, 19122, "ssh", 7.0),
        ("FTP", FTPHoneypot, 19121, "ftp", 2.0),
        ("Telnet", TelnetHoneypot, 19123, "telnet", 2.0),
    ):
        wipe()
        async with RunningService(cls, port):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            # deliberately send nothing and hold the socket open
            await asyncio.sleep(wait)
            logged = count("connections", "service=?", (svc_key,))
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        check(f"{name}: idle client (no data, still connected) is still logged", logged, 1)


# ═══════════════════════════════════════════════════════════════════════════
async def s3_hostile():
    section("3. Malformed / hostile input against the HTTP service")

    cases = [
        ("empty request then close", b""),
        ("incomplete HTTP (no CRLF terminator)", b"GET /admin HTTP/1.1"),
        ("no HTTP at all, plain text", b"hello world\r\n\r\n"),
        ("binary garbage", bytes(range(256)) * 4),
        ("null bytes in request line", b"GET /ad\x00min HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("oversized payload (32KB, buffer is 8KB)",
         b"GET /admin HTTP/1.1\r\nHost: x\r\nX-Pad: " + b"A" * 32768 + b"\r\n\r\n"),
        ("extremely long header value (64KB)",
         b"GET /admin HTTP/1.1\r\nHost: x\r\nX-Long: " + b"B" * 65536 + b"\r\n\r\n"),
        ("PUT method", b"PUT /admin HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("DELETE method", b"DELETE /admin HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("OPTIONS method", b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("TRACE method", b"TRACE /admin HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("path traversal attempt", b"GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("CRLF injection in header", b"GET /admin HTTP/1.1\r\nHost: x\r\nEvil: a\r\nInjected: b\r\n\r\n"),
        ("only newlines", b"\n\n\n\n"),
        ("very long request line", b"GET /" + b"a" * 20000 + b" HTTP/1.1\r\nHost: x\r\n\r\n"),
    ]

    wipe()
    async with RunningService(HTTPHoneypot, 19081):
        for name, payload in cases:
            try:
                resp, _ = await raw_send(19081, payload, read_timeout=9.0)
                crashed = False
            except Exception as e:
                resp, crashed = b"", repr(e)
            check(f"hostile input handled without crashing listener: {name}", crashed, False)

        # The real proof the listener survived everything above: a normal
        # request still works afterwards, on the same still-running service.
        good, _ = await raw_send(19081, b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n")
        await asyncio.sleep(0.5)
    check_true("listener still serves a valid request after all hostile input",
               good.decode("utf-8", "ignore").startswith("HTTP/1.1 200"))

    # Nothing hostile should have been executed or mis-stored: no login rows
    # (none of the above posted credentials), and every connection row is inert.
    check("no phantom login_attempts created by hostile input", count("login_attempts"), 0)
    check_true("connections were still logged (input captured, not silently dropped)",
               count("connections") >= len(cases))

    # ---- unicode / emoji / injection payloads in actual credentials ----
    wipe()
    payloads = [
        ("emoji username", "user\U0001F600\U0001F4A5", "pass123"),
        ("unicode/CJK username", "管理员", "密码"),
        ("RTL override", "admin\u202Egnp.exe", "x"),
        ("XSS payload", "<script>alert(1)</script>", "<img src=x onerror=alert(1)>"),
        ("SQLi payload", "' OR '1'='1", "'; DROP TABLE users;--"),
        ("null byte in credential", "ad\x00min", "pa\x00ss"),
        # NOTE: an over-8KB credential pair is covered separately below, because
        # it is deliberately truncated rather than stored whole — see there.
        ("format-string payload", "%s%s%s%n", "%x%x%x"),
        ("shell metacharacters", "$(whoami)", "`id`; rm -rf /"),
    ]
    async with RunningService(HTTPHoneypot, 19082):
        for name, user, pw in payloads:
            from urllib.parse import quote_plus
            body = f"username={quote_plus(user)}&password={quote_plus(pw)}"
            await raw_send(19082, (
                f"POST /admin HTTP/1.1\r\nHost: x\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n\r\n{body}"
            ).encode())
            await asyncio.sleep(0.35)
        await asyncio.sleep(0.6)

    rows = q("SELECT username, password FROM login_attempts ORDER BY id")
    check("all hostile credential payloads captured", len(rows), len(payloads))
    for (name, user, pw), row in zip(payloads, rows):
        # Stored byte-for-byte as literal text — never interpreted, never executed.
        check(f"stored inert & verbatim: {name}", (row["username"], row["password"]), (user, pw))

    # The database itself must be intact — proof the SQLi payload was parameterized.
    check_true("login_attempts table still exists after SQLi payload (parameterized)",
               count("login_attempts") == len(payloads))

    # ---- oversized credentials: truncated at the read boundary, BY DESIGN ----
    # recv_safe reads a bounded 8192 bytes in a single read, so a request larger
    # than that is captured only up to the boundary. That bound is a protection,
    # not a defect: an unbounded read would let an attacker exhaust memory with a
    # single huge body. What matters is that truncation is clean — a prefix of
    # what was sent, no crash, no corruption, no mis-attribution to another field.
    wipe()
    big_user, big_pass = "u" * 8000, "p" * 8000
    async with RunningService(HTTPHoneypot, 19088):
        body = f"username={big_user}&password={big_pass}"
        await raw_send(19088, (
            f"POST /admin HTTP/1.1\r\nHost: x\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}"
        ).encode())
        await asyncio.sleep(0.6)
    row = q("SELECT username, password FROM login_attempts")
    check("oversized credentials: still recorded (not dropped)", len(row), 1)
    if row:
        u, p = row[0]["username"], row[0]["password"]
        check("oversized: username captured in full (fits inside the 8KB window)", u, big_user)
        check_true("oversized: password truncated, not corrupted (clean prefix of what was sent)",
                   p and big_pass.startswith(p) and len(p) < len(big_pass))
        check_true("oversized: truncation lands at the 8192-byte read boundary, as designed",
                   0 < len(p) < 200)

    # ---- duplicate / conflicting X-Forwarded-For headers ----
    wipe()
    config.TRUST_PROXY_HEADERS = True
    config.TRUSTED_PROXY_HOPS = 1
    async with RunningService(HTTPHoneypot, 19083):
        await raw_send(19083, (
            b"GET /admin HTTP/1.1\r\nHost: x\r\n"
            b"X-Forwarded-For: 1.1.1.1\r\n"
            b"X-Forwarded-For: 203.0.113.77\r\n\r\n"
        ))
        await asyncio.sleep(0.6)
    row = q("SELECT ip_address, forwarded_for_raw FROM connections ORDER BY id DESC LIMIT 1")
    check("duplicate XFF headers: last occurrence wins (documented behavior)",
          row[0]["ip_address"] if row else None, "203.0.113.77")
    config.TRUST_PROXY_HEADERS = False


# ═══════════════════════════════════════════════════════════════════════════
def s4_ip_resolution():
    section("4. IP resolution edge cases")

    PEER, REAL, SPOOF = "10.0.0.1", "203.0.113.7", "1.2.3.4"
    config.TRUSTED_CLIENT_IP_HEADER = ""
    config.FORWARDED_IP_HEADER = "x-forwarded-for"

    config.TRUST_PROXY_HEADERS = False
    check("trust disabled: header ignored entirely (direct-exposure safety)",
          resolve_client_ip({"x-forwarded-for": SPOOF}, PEER), (PEER, None))

    config.TRUST_PROXY_HEADERS = True
    config.TRUSTED_PROXY_HOPS = 1
    check("missing header entirely: falls back to peer",
          resolve_client_ip({}, PEER), (PEER, None))
    check("single IP", resolve_client_ip({"x-forwarded-for": REAL}, PEER), (REAL, REAL))
    check("chained IPs: rightmost wins at 1 hop",
          resolve_client_ip({"x-forwarded-for": f"{SPOOF}, 9.9.9.9, {REAL}"}, PEER),
          (REAL, f"{SPOOF}, 9.9.9.9, {REAL}"))
    check("SPOOFED prepended value is NOT trusted",
          resolve_client_ip({"x-forwarded-for": f"{SPOOF}, {REAL}"}, PEER)[0], REAL)
    check("private-range decoys ignored",
          resolve_client_ip({"x-forwarded-for": f"10.0.0.5, 192.168.1.1, {REAL}"}, PEER)[0], REAL)
    check("IPv6 bracketed with port",
          resolve_client_ip({"x-forwarded-for": "[2001:db8::1]:443"}, PEER)[0], "2001:db8::1")
    check("IPv6 bare (not mistaken for host:port)",
          resolve_client_ip({"x-forwarded-for": "2001:db8::1"}, PEER)[0], "2001:db8::1")
    check("IPv4 with port stripped",
          resolve_client_ip({"x-forwarded-for": f"{REAL}:44321"}, PEER)[0], REAL)
    check("garbage value: falls back to peer, keeps raw as evidence",
          resolve_client_ip({"x-forwarded-for": "not-an-ip"}, PEER), (PEER, "not-an-ip"))
    check("SQLi-shaped value: not parsed as IP, falls back to peer",
          resolve_client_ip({"x-forwarded-for": "'; DROP TABLE connections;--"}, PEER)[0], PEER)
    check("empty header value: falls back to peer",
          resolve_client_ip({"x-forwarded-for": ""}, PEER), (PEER, None))
    check("whitespace-only header: falls back to peer",
          resolve_client_ip({"x-forwarded-for": "   "}, PEER)[0], PEER)
    check("trailing comma tolerated",
          resolve_client_ip({"x-forwarded-for": f"{SPOOF}, {REAL},"}, PEER)[0], REAL)

    # TRUSTED_PROXY_HOPS=2 — the value docs/RENDER.md ships as a best guess.
    config.TRUSTED_PROXY_HOPS = 2
    check("2 hops: counts 2 from the right (skips the inner proxy)",
          resolve_client_ip({"x-forwarded-for": f"{SPOOF}, {REAL}, 10.0.0.9"}, PEER)[0], REAL)
    check("2 hops, only 1 entry: degrades to leftmost without crashing",
          resolve_client_ip({"x-forwarded-for": REAL}, PEER)[0], REAL)
    # THE risk case from the audit: at 2 hops with a 2-entry chain, index = 0,
    # which selects the attacker-supplied value. Proven here as real behavior —
    # this is exactly why live §5 must confirm the true hop count.
    check("2 hops + 2-entry chain selects the LEFTMOST (attacker-controlled) value",
          resolve_client_ip({"x-forwarded-for": f"{SPOOF}, {REAL}"}, PEER)[0], SPOOF,
          note="Not a bug — correct for a genuine 2-hop chain. Dangerous only if Render is actually 1 hop.")
    config.TRUSTED_PROXY_HOPS = 1

    config.TRUSTED_CLIENT_IP_HEADER = "cf-connecting-ip"
    check("platform single-value header beats a polluted XFF",
          resolve_client_ip({"cf-connecting-ip": REAL, "x-forwarded-for": f"{SPOOF}, {SPOOF}"}, PEER)[0], REAL)
    check("platform header unparseable: falls through to XFF",
          resolve_client_ip({"cf-connecting-ip": "bogus", "x-forwarded-for": f"{SPOOF}, {REAL}"}, PEER)[0], REAL)
    config.TRUSTED_CLIENT_IP_HEADER = ""
    config.TRUST_PROXY_HEADERS = False


# ═══════════════════════════════════════════════════════════════════════════
async def s5_detection():
    section("5. Detection engines — exact thresholds, boundaries, negative cases")

    # ---- brute force: HTTP threshold is 10 in 600s ----
    wipe()
    ip = "198.51.100.10"
    seed_attacker(ip, connections=1)
    cid = seed_connection(ip, "http")
    for i in range(9):
        seed_login(cid, ip, f"u{i}", "p")
    fired = await async_detection.check_brute_force(ip, "http")
    check("brute force: 9 attempts (just below threshold of 10) does NOT fire", fired, None)

    seed_login(cid, ip, "u9", "p")   # 10th — exactly at threshold
    fired = await async_detection.check_brute_force(ip, "http")
    check_true("brute force: fires exactly at the threshold (10)", fired is not None)
    check("brute force: alert severity", fired["severity"] if fired else None, "HIGH")
    check("brute force: evidence records the real count",
          fired["evidence"]["attempt_count"] if fired else None, 10)

    seed_login(cid, ip, "u10", "p")  # 11th
    again = await async_detection.check_brute_force(ip, "http")
    check("brute force: does NOT double-fire while alert is recent", again, None)
    check("brute force: exactly one alert row exists",
          count("alerts", "alert_type='brute_force'"), 1)

    # per-service thresholds differ — telnet is 5, not 10
    wipe()
    ipt = "198.51.100.11"
    seed_attacker(ipt, connections=1)
    cidt = seed_connection(ipt, "telnet")
    for i in range(4):
        seed_login(cidt, ipt, f"t{i}", "p")
    check("brute force (telnet): 4 attempts below its lower threshold of 5 does NOT fire",
          await async_detection.check_brute_force(ipt, "telnet"), None)
    seed_login(cidt, ipt, "t4", "p")
    check_true("brute force (telnet): fires at its own threshold of 5",
               await async_detection.check_brute_force(ipt, "telnet") is not None)

    # out-of-window attempts must not count
    wipe()
    ipw = "198.51.100.12"
    seed_attacker(ipw, connections=1)
    cidw = seed_connection(ipw, "http")
    for i in range(15):
        seed_login(cidw, ipw, f"o{i}", "p", seconds_ago=1200)  # 20 min ago, window is 600s
    check("brute force: 15 attempts OUTSIDE the window does NOT fire",
          await async_detection.check_brute_force(ipw, "http"), None)

    # ---- credential stuffing: 5 distinct usernames in 600s ----
    wipe()
    ipc = "198.51.100.20"
    seed_attacker(ipc, connections=1)
    cidc = seed_connection(ipc, "http")
    for i in range(4):
        seed_login(cidc, ipc, f"user{i}", "p")
    check("credential stuffing: 4 distinct usernames (below 5) does NOT fire",
          await async_detection.check_credential_stuffing(ipc), None)
    seed_login(cidc, ipc, "user4", "p")
    fired = await async_detection.check_credential_stuffing(ipc)
    check_true("credential stuffing: fires exactly at 5 distinct usernames", fired is not None)
    check("credential stuffing: evidence count correct",
          fired["evidence"]["unique_usernames"] if fired else None, 5)
    check("credential stuffing: does not double-fire",
          await async_detection.check_credential_stuffing(ipc), None)

    # same username repeated is NOT stuffing
    wipe()
    ipr = "198.51.100.21"
    seed_attacker(ipr, connections=1)
    cidr = seed_connection(ipr, "http")
    for _ in range(20):
        seed_login(cidr, ipr, "sameuser", "p")
    check("credential stuffing: 20x the SAME username does NOT fire (distinct count is 1)",
          await async_detection.check_credential_stuffing(ipr), None)

    # ---- rapid_fire: NOT IMPLEMENTED — verified, not assumed ----
    has_rapid_fire = hasattr(async_detection, "check_rapid_fire")
    check("rapid_fire detector is absent from the codebase (documented out-of-scope)",
          has_rapid_fire, False,
          note="config.RAPID_FIRE_THRESHOLD exists but no detector consumes it.")
    check("RAPID_FIRE_THRESHOLD config value exists but is unused (dead config)",
          hasattr(config, "RAPID_FIRE_THRESHOLD"), True)

    # ---- multi-service: must be inert in HTTP-only config, without erroring ----
    wipe()
    ipm = "198.51.100.30"
    seed_attacker(ipm, connections=3)
    for _ in range(3):
        seed_connection(ipm, "http")
    res = await async_detection.check_multi_service(ipm)
    check("multi_service: correctly inert with only HTTP live (no error, no alert)", res, None)
    alerts = await async_detection.check_connection_patterns(ipm)
    check("check_connection_patterns runs cleanly in HTTP-only config", alerts, [])

    # ...and still works correctly if a 2nd service ever goes live
    seed_connection(ipm, "ftp")
    res2 = await async_detection.check_multi_service(ipm)
    check_true("multi_service: DOES fire once a 2nd service appears (activates with no code change)",
               res2 is not None)
    check("multi_service: evidence records 2 services",
          res2["evidence"]["service_count"] if res2 else None, 2)

    # ---- campaign detection: 3+ same-ASN IPs within 24h ----
    wipe()
    for i in range(2):
        seed_attacker(f"203.0.113.{i}", connections=1, asn="AS12345")
    camps = await detect_asn_campaigns(config.CAMPAIGN_WINDOW_SECONDS, config.CAMPAIGN_MIN_ATTACKERS)
    check("campaigns: 2 same-ASN IPs (below min of 3) does NOT group", len(camps), 0)

    seed_attacker("203.0.113.2", connections=1, asn="AS12345")
    camps = await detect_asn_campaigns(config.CAMPAIGN_WINDOW_SECONDS, config.CAMPAIGN_MIN_ATTACKERS)
    check("campaigns: 3 same-ASN IPs in-window DOES group", len(camps), 1)
    check("campaigns: correct attacker count", camps[0]["attacker_count"] if camps else None, 3)
    check("campaigns: correct ASN", camps[0]["asn"] if camps else None, "AS12345")

    # different ASNs must not be merged
    for i in range(3):
        seed_attacker(f"203.0.113.1{i}", connections=1, asn="AS99999")
    camps = await detect_asn_campaigns(config.CAMPAIGN_WINDOW_SECONDS, config.CAMPAIGN_MIN_ATTACKERS)
    check("campaigns: different ASNs form separate campaigns, not one merged group", len(camps), 2)

    # out-of-window attackers excluded
    wipe()
    for i in range(3):
        seed_attacker(f"203.0.113.2{i}", connections=1, asn="AS55555", last_seen_ago=90000)  # >24h
    camps = await detect_asn_campaigns(config.CAMPAIGN_WINDOW_SECONDS, config.CAMPAIGN_MIN_ATTACKERS)
    check("campaigns: same-ASN IPs OUTSIDE the 24h window are excluded", len(camps), 0)

    # NULL ASN (unenriched) must not group into a phantom campaign
    wipe()
    for i in range(5):
        seed_attacker(f"203.0.113.3{i}", connections=1, asn=None)
    camps = await detect_asn_campaigns(config.CAMPAIGN_WINDOW_SECONDS, config.CAMPAIGN_MIN_ATTACKERS)
    check("campaigns: un-enriched attackers (NULL asn) do NOT form a phantom campaign", len(camps), 0)


# ═══════════════════════════════════════════════════════════════════════════
async def s6_scoring():
    section("6. Threat scoring — hand-calculated, all 14 weights, verdict bands")

    # Verdict band boundaries, tested directly (bands are [lo, hi) half-open).
    for score, expected in ((0, "LOW"), (14, "LOW"), (15, "MEDIUM"), (34, "MEDIUM"),
                            (35, "HIGH"), (59, "HIGH"), (60, "CRITICAL"), (100, "CRITICAL")):
        check(f"verdict band: score {score} -> {expected}", scorer._get_verdict(score), expected)

    # ---- CRITICAL attacker: hand-calculated ----
    # connections 25   -> connections_over_20        20
    # logins 60        -> login_attempts_over_50     30
    # usernames 8      -> multiple_usernames_over_5  10
    # abuseipdb 95     -> abuseipdb_score_over_90    25
    # otx 3            -> otx_pulse_match            15
    # isp DigitalOcean -> datacenter_hosting_ip       5
    # services 2       -> multi_service_targeting    15
    #                                        raw = 120 -> capped 100 -> CRITICAL
    wipe()
    hi = "198.51.100.90"
    seed_attacker(hi, connections=25, abuseipdb=95, otx=3, isp="DigitalOcean Hosting LLC")
    c1 = seed_connection(hi, "http")
    seed_connection(hi, "ftp")
    for i in range(60):
        seed_login(c1, hi, f"user{i % 8}", "p")   # 60 attempts, 8 distinct usernames
    res = await scorer.calculate_threat_score(hi)
    check("CRITICAL attacker: raw score caps at 100", res["score"], 100)
    check("CRITICAL attacker: verdict", res["verdict"], "CRITICAL")
    b = res["breakdown"]
    check("  weight: connections_over_20 (20)", b.get("connections"), 20)
    check("  weight: login_attempts_over_50 (30)", b.get("login_attempts"), 30)
    check("  weight: multiple_usernames_over_5 (10)", b.get("credential_stuffing"), 10)
    check("  weight: abuseipdb_score_over_90 (25)", b.get("abuseipdb"), 25)
    check("  weight: otx_pulse_match (15)", b.get("otx_pulses"), 15)
    check("  weight: datacenter_hosting_ip (5)", b.get("datacenter"), 5)
    check("  weight: multi_service_targeting (15)", b.get("multi_service"), 15)
    check("  hand-calculated raw total before cap = 120", sum(b.values()), 120)

    # ---- LOW attacker ----
    # connections 1 -> 5.  Nothing else applies.  Total 5 -> LOW
    wipe()
    lo = "198.51.100.91"
    seed_attacker(lo, connections=1, abuseipdb=None, otx=0, isp="Comcast Cable Residential")
    seed_connection(lo, "http")
    res = await scorer.calculate_threat_score(lo)
    check("LOW attacker: score", res["score"], 5)
    check("LOW attacker: verdict", res["verdict"], "LOW")
    check("LOW attacker: only the connections weight applied",
          sorted(res["breakdown"].keys()), ["connections"])

    # ---- Partial enrichment (production reality: OTX unset) ----
    # connections 3 -> 5;  logins 5 -> 5;  usernames 2 -> 0 (needs >5)
    # abuseipdb 60  -> 15; otx 0 -> 0 (absent, not wrong); isp Amazon AWS -> 5
    # services 1    -> 0                                        total = 30 -> MEDIUM
    wipe()
    pt = "198.51.100.92"
    seed_attacker(pt, connections=3, abuseipdb=60, otx=0, isp="Amazon AWS")
    c3 = seed_connection(pt, "http")
    for i in range(5):
        seed_login(c3, pt, f"u{i % 2}", "p")
    res = await scorer.calculate_threat_score(pt)
    check("partial enrichment (no OTX, as in production): score", res["score"], 30)
    check("partial enrichment: verdict", res["verdict"], "MEDIUM")
    check("partial enrichment: OTX weight correctly ABSENT, not zero-scored wrongly",
          "otx_pulses" in res["breakdown"], False)
    check("partial enrichment: abuseipdb tier 50-74 applied (15)", res["breakdown"].get("abuseipdb"), 15)

    # ---- Remaining untested tiers, so all 14 weights are covered ----
    wipe()
    t1 = "198.51.100.93"
    seed_attacker(t1, connections=10, abuseipdb=80, otx=0, isp="x")
    c4 = seed_connection(t1, "http")
    for i in range(20):
        seed_login(c4, t1, f"u{i}", "p")
    res = await scorer.calculate_threat_score(t1)
    check("tier: connections_6_to_20 (10)", res["breakdown"].get("connections"), 10)
    check("tier: login_attempts_11_to_50 (15)", res["breakdown"].get("login_attempts"), 15)
    check("tier: abuseipdb_score_over_75 (20)", res["breakdown"].get("abuseipdb"), 20)

    wipe()
    t2 = "198.51.100.94"
    seed_attacker(t2, connections=2, abuseipdb=30, otx=0, isp=None)
    c5 = seed_connection(t2, "http")
    seed_login(c5, t2, "solo", "p")
    res = await scorer.calculate_threat_score(t2)
    check("tier: connections_1_to_5 (5)", res["breakdown"].get("connections"), 5)
    check("tier: login_attempts_1_to_10 (5)", res["breakdown"].get("login_attempts"), 5)
    check("tier: abuseipdb_score_over_25 (10)", res["breakdown"].get("abuseipdb"), 10)

    # abuseipdb below the lowest band contributes nothing
    wipe()
    t3 = "198.51.100.95"
    seed_attacker(t3, connections=1, abuseipdb=10, otx=0)
    seed_connection(t3, "http")
    res = await scorer.calculate_threat_score(t3)
    check("abuseipdb score of 10 (below lowest band of 25) adds nothing",
          "abuseipdb" in res["breakdown"], False)

    # unknown attacker doesn't crash
    res = await scorer.calculate_threat_score("192.0.2.254")
    check("scoring an unknown IP returns UNKNOWN rather than crashing", res["verdict"], "UNKNOWN")


# ═══════════════════════════════════════════════════════════════════════════
async def s10_filtered():
    section("10. Filtered-connections logging (the new visible-not-silent behavior)")

    config.TRUST_PROXY_HEADERS = True
    config.IGNORE_UNFORWARDED_CONNECTIONS = True
    config.TRUSTED_PROXY_HOPS = 1

    # Sub-case A: an HTTP request that simply lacks the forwarding header.
    wipe()
    async with RunningService(HTTPHoneypot, 19084):
        resp, _ = await raw_send(19084, b"GET /admin HTTP/1.1\r\nHost: healthcheck\r\n\r\n")
        await asyncio.sleep(0.7)
    check_true("A: unforwarded HTTP request still gets a valid response",
               resp.decode("utf-8", "ignore").startswith("HTTP/1.1"))
    check("A: logged to filtered_connections", count("filtered_connections"), 1)
    check("A: ZERO rows in connections", count("connections"), 0)
    check("A: ZERO rows in attackers", count("attackers"), 0)
    row = q("SELECT peer_ip, service, method, path FROM filtered_connections")[0]
    check("A: method/path captured", (row["method"], row["path"]), ("GET", "/admin"))
    check("A: service tagged", row["service"], "http")

    # Sub-case B: a bare TCP probe that sends no HTTP at all.
    wipe()
    async with RunningService(HTTPHoneypot, 19085):
        reader, writer = await asyncio.open_connection("127.0.0.1", 19085)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await asyncio.sleep(0.8)
    check("B: bare TCP probe logged to filtered_connections", count("filtered_connections"), 1)
    check("B: ZERO rows in connections", count("connections"), 0)
    check("B: ZERO rows in attackers", count("attackers"), 0)
    row = q("SELECT method, path FROM filtered_connections")[0]
    check("B: method/path NULL (no HTTP data), not a crash", (row["method"], row["path"]), (None, None))

    # Control: with the flag OFF, the same probe is recorded normally and
    # filtered_connections stays untouched — proves the filter is what acted.
    wipe()
    config.IGNORE_UNFORWARDED_CONNECTIONS = False
    async with RunningService(HTTPHoneypot, 19086):
        await raw_send(19086, b"GET /admin HTTP/1.1\r\nHost: healthcheck\r\n\r\n")
        await asyncio.sleep(0.7)
    check("control: flag OFF -> recorded in connections normally", count("connections"), 1)
    check("control: flag OFF -> filtered_connections untouched", count("filtered_connections"), 0)

    # A forwarded request must never be filtered, even with the flag on.
    wipe()
    config.IGNORE_UNFORWARDED_CONNECTIONS = True
    async with RunningService(HTTPHoneypot, 19087):
        await raw_send(19087, b"GET /admin HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.44\r\n\r\n")
        await asyncio.sleep(0.7)
    check("real forwarded traffic is NOT filtered when the flag is on", count("connections"), 1)
    check("real forwarded traffic resolves to the client IP",
          q("SELECT ip_address FROM connections")[0]["ip_address"], "203.0.113.44")
    check("real forwarded traffic adds nothing to filtered_connections",
          count("filtered_connections"), 0)

    config.TRUST_PROXY_HEADERS = False
    config.IGNORE_UNFORWARDED_CONNECTIONS = False


# ═══════════════════════════════════════════════════════════════════════════
async def main():
    TEST_DB.unlink(missing_ok=True)
    await db.connect()
    await db.init_schema()

    t0 = time.time()
    await s2_services()
    await s3_hostile()
    s4_ip_resolution()
    await s5_detection()
    await s6_scoring()
    await s10_filtered()
    elapsed = time.time() - t0

    await db.close()
    TEST_DB.unlink(missing_ok=True)

    print(f"\n{'=' * 74}")
    print("SUMMARY BY SECTION")
    print(f"{'=' * 74}")
    print(f"  {'Section':<10} {'Run':>5} {'Pass':>6} {'Fail':>6}")
    order, seen = [], set()
    for sec, *_ in RESULTS:
        if sec not in seen:
            seen.add(sec)
            order.append(sec)
    total_p = total_f = 0
    for sec in order:
        rows = [r for r in RESULTS if r[0] == sec]
        p = sum(1 for r in rows if r[2])
        f = len(rows) - p
        total_p += p
        total_f += f
        print(f"  {sec:<10} {len(rows):>5} {p:>6} {f:>6}")
    print(f"  {'-' * 30}")
    print(f"  {'TOTAL':<10} {total_p + total_f:>5} {total_p:>6} {total_f:>6}    ({elapsed:.1f}s)")

    if total_f:
        print("\n  FAILURES:")
        for sec, name, ok, detail in RESULTS:
            if not ok:
                print(f"    [{sec}] {name}\n         {detail}")
    print(f"{'=' * 74}")
    return 1 if total_f else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
