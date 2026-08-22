#!/usr/bin/env python3
"""
Section 7 of the pre-deployment pass — auth and dashboard security.

Run directly:  python tests/test_dashboard_security.py

Covers:
  - argon2 login: correct password, wrong password, lockout at 10, locked-out
    correct password still fails
  - no user enumeration, no password leakage into logs/DB/UI
  - attacker-controlled XSS/SQLi payloads render as literal text
  - all 7 dashboard pages load without raising, via Streamlit's own AppTest

Separate from test_predeployment.py because it needs Streamlit's AppTest
harness, which drives real page scripts rather than plain function calls.
"""

import os
import sys
import io
import logging
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_DB = REPO_ROOT / "data" / "test_dashboard.db"
os.environ["SQLITE_PATH"] = str(TEST_DB)
os.environ["DATABASE_URL"] = ""   # see note in test_predeployment.py
sys.path.insert(0, str(REPO_ROOT))

import asyncio  # noqa: E402
import sqlite3  # noqa: E402

import config  # noqa: E402
config.SKIP_SCHEMA_INIT = False

from database.db_async import db  # noqa: E402
from auth import async_admin_auth as auth  # noqa: E402

RESULTS = []
_SEC = {"cur": "7"}


def check(name, got, expected):
    ok = got == expected
    RESULTS.append((name, ok, "" if ok else f"expected={expected!r} actual={got!r}"))
    print(("  PASS  " if ok else "  FAIL  ") + name)
    if not ok:
        print(f"          expected: {expected!r}")
        print(f"          actual:   {got!r}")


def check_true(name, got):
    check(name, bool(got), True)


def section(t):
    print(f"\n{'=' * 74}\n{t}\n{'=' * 74}")


def sql_exec(stmt, params=()):
    """Run a write and CLOSE the connection — an un-closed sqlite3 handle holds
    a write lock and makes every later async call fail with 'database is locked'."""
    c = sqlite3.connect(TEST_DB)
    try:
        c.execute(stmt, params)
        c.commit()
    finally:
        c.close()


def sql_one(stmt, params=()):
    c = sqlite3.connect(TEST_DB)
    try:
        row = c.execute(stmt, params).fetchone()
        return row
    finally:
        c.close()


XSS = "<script>alert('pwned')</script>"
SQLI = "'; DROP TABLE login_attempts;--"
IMG_XSS = '<img src=x onerror="alert(1)">'


def seed_hostile_data():
    """Seed attacker-controlled payloads into every table the dashboard renders."""
    c = sqlite3.connect(TEST_DB)
    c.execute("INSERT OR REPLACE INTO attackers (ip_address, total_connections, country, city, isp, asn, "
              "threat_score, verdict, abuseipdb_score, otx_pulse_count) "
              "VALUES ('203.0.113.5', 5, ?, ?, ?, ?, 90, 'CRITICAL', 95, 2)",
              (XSS, IMG_XSS, SQLI, XSS))
    cur = c.execute("INSERT INTO connections (ip_address, service, port) VALUES ('203.0.113.5','http',8080)")
    cid = cur.lastrowid
    c.execute("INSERT INTO login_attempts (connection_id, ip_address, username, password) VALUES (?,?,?,?)",
              (cid, "203.0.113.5", XSS, SQLI))
    c.execute("INSERT INTO login_attempts (connection_id, ip_address, username, password) VALUES (?,?,?,?)",
              (cid, "203.0.113.5", IMG_XSS, "javascript:alert(1)"))
    c.execute("INSERT INTO alerts (ip_address, alert_type, severity, evidence) "
              "VALUES ('203.0.113.5','brute_force','HIGH', ?)", ('{"note": "' + XSS + '"}',))
    c.execute("INSERT INTO ai_reports (ip_address, report_text) VALUES ('203.0.113.5', ?)", (XSS,))
    c.commit()
    c.close()


# ═══════════════════════════════════════════════════════════════════════════
async def auth_tests():
    section("7a. Admin authentication — argon2, lockout, no enumeration/leakage")

    # capture the auth logger so we can prove the password never reaches logs
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    handler.setLevel(logging.DEBUG)
    auth_logger = logging.getLogger("honeypot.dashboard.auth")
    auth_logger.addHandler(handler)
    auth_logger.setLevel(logging.DEBUG)

    await db.connect()
    await db.init_schema()
    sql_exec("DELETE FROM admin_users")

    pw = await auth.bootstrap_admin_if_needed()
    check_true("bootstrap creates the first admin account and returns its password", pw is not None)
    check("bootstrap is idempotent — second call creates nothing",
          await auth.bootstrap_admin_if_needed(), None)

    check("correct password authenticates", await auth.authenticate("admin", pw), True)
    check("wrong password is rejected", await auth.authenticate("admin", "wrong-password"), False)
    check("unknown username is rejected", await auth.authenticate("no_such_user", pw), False)
    check("empty password is rejected", await auth.authenticate("admin", ""), False)
    check("SQLi-shaped username is rejected (and does not break the query)",
          await auth.authenticate("' OR 1=1--", "x"), False)
    check("SQLi payload did not damage admin_users (parameterized)",
          sql_one("SELECT COUNT(*) FROM admin_users")[0], 1)

    # ---- lockout at exactly MAX_FAILED_ATTEMPTS ----
    sql_exec("DELETE FROM admin_users")
    pw2 = await auth.bootstrap_admin_if_needed()

    for i in range(auth.MAX_FAILED_ATTEMPTS - 1):
        await auth.authenticate("admin", f"bad{i}")
    check(f"correct password still works at {auth.MAX_FAILED_ATTEMPTS - 1} failures (below lockout)",
          await auth.authenticate("admin", pw2), True)

    # a success resets the counter, so drive it all the way to the threshold again
    for i in range(auth.MAX_FAILED_ATTEMPTS):
        await auth.authenticate("admin", f"bad{i}")
    locked = await db.is_admin_locked_out("admin")
    check(f"account is locked out after exactly {auth.MAX_FAILED_ATTEMPTS} failed attempts", locked, True)
    check("locked-out account rejects the CORRECT password too",
          await auth.authenticate("admin", pw2), False)

    row = sql_one("SELECT failed_attempts, locked_until FROM admin_users WHERE username='admin'")
    check_true("lockout expiry timestamp is recorded", row[1] is not None)

    # ---- no leakage ----
    logs = log_stream.getvalue()
    check("password never appears in auth logs", pw2 in logs, False)
    check("logs do not distinguish 'no such user' from 'wrong password' in a way that enumerates",
          "no such user" in logs.lower(), False)

    stored = sql_one("SELECT password_hash FROM admin_users WHERE username='admin'")[0]
    check("stored credential is an argon2 hash, not plaintext", stored.startswith("$argon2"), True)
    check("plaintext password is not stored anywhere in admin_users", pw2 in stored, False)

    # login.py must show one generic message for every failure mode
    login_src = (REPO_ROOT / "dashboard" / "login.py").read_text(encoding="utf-8")
    check("login UI uses a single generic failure message (no user enumeration)",
          login_src.count('st.error("Invalid username or password.")'), 1)
    check_true("login UI never renders the submitted password back",
               "value=password" not in login_src and "st.write(password" not in login_src)

    auth_logger.removeHandler(handler)
    await db.close()


# ═══════════════════════════════════════════════════════════════════════════
def dashboard_tests():
    section("7b. Dashboard — XSS/SQLi rendering, all 7 pages load")

    # Structural guarantee first: unsafe_allow_html is never actually used.
    real_usage = []
    for py in list((REPO_ROOT / "dashboard").rglob("*.py")):
        for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if "unsafe_allow_html" in line and not stripped.startswith("#") and "=" in line.split("unsafe_allow_html")[1][:3]:
                real_usage.append(f"{py.name}:{i}")
    check("unsafe_allow_html is never passed anywhere in dashboard/ (only named in comments)",
          real_usage, [])

    try:
        from streamlit.testing.v1 import AppTest
    except ImportError:
        check("Streamlit AppTest available", False, True)
        return

    pages = [
        ("Live Feed", "dashboard/pages/01_🔴_Live_Feed.py"),
        ("Attacker Intel", "dashboard/pages/02_🌍_Attacker_Intel.py"),
        ("Analytics", "dashboard/pages/03_📈_Analytics.py"),
        ("Alerts", "dashboard/pages/04_🚨_Alerts.py"),
        ("Threat Hunting", "dashboard/pages/05_🔍_Threat_Hunting.py"),
        ("Campaigns", "dashboard/pages/06_🎪_Campaigns.py"),
        ("AI Analysis", "dashboard/pages/07_🤖_AI_Analysis.py"),
    ]

    for name, rel in pages:
        path = REPO_ROOT / rel
        if not path.exists():
            check(f"page exists: {name}", False, True)
            continue
        try:
            at = AppTest.from_file(str(path), default_timeout=60)
            at.session_state["authenticated"] = True
            at.session_state["username"] = "admin"
            at.run()
            check(f"page loads without exception: {name}",
                  [str(e.value) for e in at.exception], [])
        except Exception as e:
            check(f"page loads without exception: {name}", repr(e), [])

    # The hostile payloads must reach the UI as inert data. Every attacker-derived
    # field goes through st.dataframe, which never interprets HTML/markdown in
    # cell contents — so presence in a dataframe IS the safety property.
    try:
        at = AppTest.from_file(str(REPO_ROOT / "dashboard/pages/01_🔴_Live_Feed.py"), default_timeout=60)
        at.session_state["authenticated"] = True
        at.session_state["username"] = "admin"
        at.run()
        found_in_df = False
        for dfel in at.dataframe:
            try:
                blob = dfel.value.to_string()
            except Exception:
                blob = str(dfel.value)
            if "<script>" in blob or "DROP TABLE" in blob:
                found_in_df = True
        check("XSS/SQLi payloads surface inside st.dataframe (inert), not raw markup", found_in_df, True)

        md_blob = " ".join(str(m.value) for m in at.markdown)
        check("XSS payload is NOT emitted into any markdown element", "<script>alert" in md_blob, False)
    except Exception as e:
        check("hostile-payload rendering check ran", repr(e), "ok")


# ═══════════════════════════════════════════════════════════════════════════
async def main():
    TEST_DB.unlink(missing_ok=True)
    await db.connect()
    await db.init_schema()
    await db.close()
    seed_hostile_data()

    await auth_tests()
    dashboard_tests()

    TEST_DB.unlink(missing_ok=True)

    p = sum(1 for _, ok, _ in RESULTS if ok)
    f = len(RESULTS) - p
    print(f"\n{'=' * 74}")
    print(f"  SECTION 7 TOTAL: {len(RESULTS)} run, {p} passed, {f} failed")
    if f:
        print("\n  FAILURES:")
        for name, ok, detail in RESULTS:
            if not ok:
                print(f"    {name}\n         {detail}")
    print(f"{'=' * 74}")
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
