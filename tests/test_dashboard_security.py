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

import ast
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
def escapes_hostile_input():
    """
    Feed XSS payloads through every design-system helper that emits raw HTML.

    theme.py is the one module allowed to pass unsafe_allow_html with
    interpolated content, so its escaping is load-bearing. This asserts the
    property directly — hostile text in, inert text out — rather than trusting
    a structural rule to imply it.
    """
    from unittest.mock import patch

    from dashboard import theme

    # Every payload here carries an HTML metacharacter, because that is what
    # escaping defends against. A bare string like "javascript:alert(1)" is
    # deliberately NOT included: it survives escaping unchanged and is inert as
    # a text node, so asserting it gets escaped would be asserting the wrong
    # property. The attribute-breakout payload is the important one — `tone` is
    # interpolated into a style="" attribute, the only attribute context here.
    payloads = [
        XSS,
        IMG_XSS,
        '"><script>alert(1)</script>',
        '" onmouseover="alert(1)',          # attribute breakout
        "</style><script>alert(1)</script>",  # style-context escape
    ]

    for payload in payloads:
        emitted = []
        with patch("streamlit.markdown", side_effect=lambda html, **kw: emitted.append(html)):
            # Every helper in theme.py that emits raw HTML must appear here.
            # A sink added without a payload test is how this guarantee rots.
            theme.page_header(payload, payload, payload, eyebrow=payload)
            theme.kpis([{"label": payload, "value": payload, "note": payload, "tone": payload}])
            theme.section(payload, payload)
            theme.empty_state(payload, payload, payload)
            theme.subsection(payload)
            theme.facts({payload: payload, "Country": payload})
            theme.meter(payload, 42, tone=payload, note=payload)
            theme.meter(payload, None, note=payload)
            theme.auth_brand(payload, payload)
            theme.composition([{"label": payload, "value": 1, "color": payload}])
        blob = " ".join(emitted)
        check(f"payload never emitted raw: {payload[:24]!r}", payload in blob, False)
        check_true(f"payload appears HTML-escaped instead: {payload[:24]!r}",
                   "&lt;" in blob or "&quot;" in blob or "&#x27;" in blob)

    # sidebar_identity takes the session username, which is operator-supplied
    # rather than attacker-supplied, but is escaped on the same principle.
    emitted = []
    with patch("streamlit.sidebar") as sidebar:
        sidebar.markdown.side_effect = lambda html, **kw: emitted.append(html)
        theme.sidebar_identity(XSS)
    check("sidebar identity escapes its username", XSS in " ".join(emitted), False)

    # Completeness: every public helper that emits raw HTML must be exercised
    # above. Without this, adding a sink and forgetting to test it silently
    # narrows the guarantee — the payload tests would still pass, on the
    # helpers that happen to be listed.
    import ast
    theme_src = (REPO_ROOT / "dashboard" / "theme.py").read_text(encoding="utf-8")
    sinks = {
        n.name for n in ast.walk(ast.parse(theme_src))
        if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")
        and "unsafe_allow_html=True" in (ast.get_source_segment(theme_src, n) or "")
    }
    # Exempt only helpers that interpolate NO caller-supplied value: inject()
    # emits the static stylesheet, sidebar_nav() a fixed label plus page links.
    NO_USER_DATA = {"inject", "sidebar_nav"}
    this_test = (REPO_ROOT / "tests" / "test_dashboard_security.py").read_text(encoding="utf-8")
    untested = sorted(s for s in sinks - NO_USER_DATA if f"theme.{s}(" not in this_test)
    check("every raw-HTML theme helper is XSS-tested", untested, [])


# ═══════════════════════════════════════════════════════════════════════════
def dashboard_tests():
    section("7b. Dashboard — XSS/SQLi rendering, all 7 pages load")

    # Structural guarantee: raw HTML may only be emitted from the audited design
    # system, and everywhere else only as a string literal.
    #
    # This replaced a blanket "unsafe_allow_html is never used" ban when the UI
    # was redesigned. The blanket ban was a proxy for the property that actually
    # matters — attacker-controlled text must never reach a raw-HTML sink — and
    # once any styling exists the proxy fails while the real property still
    # holds. The two checks below assert the real property directly:
    #
    #   (a) outside dashboard/theme.py, the content passed with
    #       unsafe_allow_html=True must be a string LITERAL. No f-strings, no
    #       variables, no .format() — so a page physically cannot interpolate a
    #       database value into markup.
    #   (b) inside theme.py, every interpolation must be wrapped in esc() or be
    #       a module-level constant (a colour).
    #
    # The behavioural test further down (XSS payload never reaches markdown)
    # remains the backstop.
    def _is_literal(node) -> bool:
        """True for a plain string constant, including implicit concatenation."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return _is_literal(node.left) and _is_literal(node.right)
        return False

    # theme.py composes markup from pre-escaped fragments ("".join(parts) and
    # similar), which no reasonable AST rule can follow. It is therefore exempt
    # here and covered instead by escapes_hostile_input() below, which feeds it
    # real XSS payloads and inspects the output — direct evidence rather than a
    # structural proxy.
    real_usage = []
    for py in sorted((REPO_ROOT / "dashboard").rglob("*.py")):
        if py.name == "theme.py":
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            uses_raw_html = any(
                kw.arg == "unsafe_allow_html"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            )
            if not uses_raw_html or not node.args:
                continue
            if not _is_literal(node.args[0]):
                real_usage.append(f"{py.name}:{node.lineno}")

    check("outside theme.py, raw HTML is only ever a string literal",
          real_usage, [])

    escapes_hostile_input()

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
