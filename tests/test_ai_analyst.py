#!/usr/bin/env python3
"""
Section 9 of the pre-deployment pass — the Gemini AI analyst.

Run directly:  python tests/test_ai_analyst.py

Covers:
  - a report on a RICH attacker, with every factual claim traced back to real
    stored rows (the anti-hallucination check)
  - a report on a SPARSE attacker, confirming gaps are stated rather than filled
    with invented detail — the main failure mode for this feature
  - clean error handling when the Gemini call fails or no key is configured

Makes REAL Gemini API calls, so it is separate from the offline suites and will
be skipped with a clear message if no key is configured.
"""

import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_DB = REPO_ROOT / "data" / "test_ai_analyst.db"
os.environ["SQLITE_PATH"] = str(TEST_DB)
os.environ["DATABASE_URL"] = ""   # never point the analyst at production
sys.path.insert(0, str(REPO_ROOT))

import asyncio  # noqa: E402
import sqlite3  # noqa: E402
from unittest.mock import patch  # noqa: E402

import config  # noqa: E402
config.SKIP_SCHEMA_INIT = False

from database.db_async import db  # noqa: E402
from honeypot.ai import async_analyst as analyst  # noqa: E402

RESULTS = []


def check(name, got, expected):
    ok = got == expected
    RESULTS.append((name, ok, "" if ok else f"expected={expected!r} actual={got!r}"))
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


def sql(stmt, params=()):
    c = sqlite3.connect(TEST_DB)
    try:
        cur = c.execute(stmt, params)
        c.commit()
        return cur.lastrowid
    finally:
        c.close()


def sql_count(stmt, params=()):
    """Count helper that CLOSES its handle — an open sqlite3 connection keeps a
    Windows file lock and makes the final TEST_DB.unlink() fail with WinError 32."""
    c = sqlite3.connect(TEST_DB)
    try:
        return c.execute(stmt, params).fetchone()[0]
    finally:
        c.close()


RICH_IP = "203.0.113.201"
SPARSE_IP = "203.0.113.202"


def seed():
    sql("INSERT OR REPLACE INTO attackers (ip_address, total_connections, country, city, isp, asn, "
        "abuseipdb_score, otx_pulse_count, threat_score, verdict) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (RICH_IP, 12, "Netherlands", "Amsterdam", "DigitalOcean LLC", "AS14061", 88, 4, 85, "CRITICAL"))
    cid = sql("INSERT INTO connections (ip_address, service, port) VALUES (?, 'http', 8080)", (RICH_IP,))
    for u, p in [("admin", "admin"), ("root", "toor"), ("administrator", "password123"),
                 ("wpadmin", "letmein"), ("test", "test123")]:
        sql("INSERT INTO login_attempts (connection_id, ip_address, username, password) VALUES (?,?,?,?)",
            (cid, RICH_IP, u, p))
    sql("INSERT INTO alerts (ip_address, alert_type, severity, evidence) VALUES (?,?,?,?)",
        (RICH_IP, "credential_stuffing", "HIGH", '{"unique_usernames": 5}'))

    # Sparse: exactly one connection, no logins, no enrichment, no alerts.
    sql("INSERT OR REPLACE INTO attackers (ip_address, total_connections) VALUES (?, 1)", (SPARSE_IP,))
    sql("INSERT INTO connections (ip_address, service, port) VALUES (?, 'http', 8080)", (SPARSE_IP,))


class FakeGeminiClient:
    """
    Stands in for genai.Client, replaying a scripted sequence of outcomes.

    An entry that is an Exception is raised; anything else is returned as the
    response object. Records how many calls were made, which is what lets these
    tests assert on the PRODUCT's retry behaviour rather than performing the
    retries themselves.
    """

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0
        client = self

        class _Models:
            async def generate_content(self, **kwargs):
                client.calls += 1
                outcome = client.outcomes[min(client.calls - 1, len(client.outcomes) - 1)]
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome

        class _Aio:
            models = _Models()

        self.aio = _Aio()


class FakeText:
    """Minimal stand-in for a successful generate_content response."""

    def __init__(self, text):
        self.text = text


def transient_error():
    """A real APIError shaped like Gemini's 503 load-shedding response."""
    from google.genai.errors import APIError

    class _Resp:
        body_segments = [{"error": {"code": 503, "message": "high demand",
                                    "status": "UNAVAILABLE"}}]
        headers = {}

        def json(self):
            return self.body_segments[0]

    return APIError(503, _Resp())


def permanent_error():
    """A non-retryable error: a rejected API key looks like this."""
    from google.genai.errors import APIError

    class _Resp:
        body_segments = [{"error": {"code": 400, "message": "API key not valid",
                                    "status": "INVALID_ARGUMENT"}}]
        headers = {}

        def json(self):
            return self.body_segments[0]

    return APIError(400, _Resp())


async def main():
    TEST_DB.unlink(missing_ok=True)
    await db.connect()
    await db.init_schema()
    seed()

    # ── 9c. Error handling first (no live key needed) ──────────────────────
    section("9c. Error handling — API failure and missing key")

    # These blocks now exercise the retry path, so shrink the backoff schedule
    # to keep the suite fast. The number of attempts is unchanged — that is what
    # the assertions below actually care about.
    real_delays = analyst.RETRY_DELAYS
    analyst.RETRY_DELAYS = (0.01, 0.01, 0.01)

    from google.genai.errors import APIError

    class _FakeResponse:
        """Minimal stand-in matching what APIError's constructor reads."""
        body_segments = [{"error": {"code": 503, "message": "simulated outage",
                                    "status": "UNAVAILABLE"}}]
        headers = {}

        def json(self):
            return self.body_segments[0]

    with patch.object(analyst, "_get_client") as mock_client:
        mock_client.side_effect = APIError(503, _FakeResponse())
        res = await analyst.generate_attacker_report(RICH_IP)
        check("API failure returns error=True rather than raising", res.get("error"), True)
        check_true("API failure surfaces a message", res.get("report_text"))
        rows = sql_count("SELECT COUNT(*) FROM ai_reports WHERE ip_address=?", (RICH_IP,))
        check("nothing written to ai_reports on API failure", rows, 0)

    # Regression: an exception carrying NO message (httpx.ReadTimeout is the real
    # one that occurred during pre-deployment testing) must not produce a bare
    # "AI report generation failed: " with no cause. A timeout is retryable, so
    # the cause now lands in `detail` while report_text carries the operator
    # message — the cause must still be somewhere, not swallowed.
    import httpx
    with patch.object(analyst, "_get_client") as mock_client:
        mock_client.side_effect = httpx.ReadTimeout("")
        res = await analyst.generate_attacker_report(RICH_IP)
        check("timeout failure returns error=True", res.get("error"), True)
        surfaced = f"{res.get('report_text', '')} {res.get('detail', '')}"
        check_true(f"message-less exception still names a cause (got: {surfaced!r})",
                   surfaced.strip() not in ("AI report generation failed:", "AI report generation failed: ")
                   and "ReadTimeout" in surfaced)

    # ── 9c-bis. The PRODUCT retries transient conditions, not the test ────────
    section("9c-bis. Retry behaviour lives in the product")

    try:
        # Classification is the load-bearing decision — assert it directly.
        check_true("503/UNAVAILABLE classified transient",
                   analyst._is_transient(transient_error()))
        check_true("429/RESOURCE_EXHAUSTED classified transient",
                   analyst._is_transient(Exception("429 RESOURCE_EXHAUSTED")))
        check_true("httpx.ReadTimeout classified transient",
                   analyst._is_transient(httpx.ReadTimeout("")))
        check("invalid API key NOT classified transient",
              analyst._is_transient(permanent_error()), False)
        check("safety block NOT classified transient",
              analyst._is_transient(ValueError("blocked by safety filters")), False)

        # Two transient failures then success: the product must ride through it.
        fake = FakeGeminiClient([transient_error(), transient_error(),
                                 FakeText("Recovered report body, long enough to be real. " * 4)])
        with patch.object(analyst, "_get_client", return_value=fake):
            res = await analyst.generate_attacker_report(RICH_IP)
        check("recovers after 2 transient failures", bool(res.get("error")), False)
        check("made exactly 3 attempts", fake.calls, 3)
        check_true("returned the recovered report", "Recovered report body" in res.get("report_text", ""))
        # A recovered report is a real report: it must be persisted like any other.
        check("recovered report IS written to ai_reports",
              sql_count("SELECT COUNT(*) FROM ai_reports WHERE ip_address=?", (RICH_IP,)), 1)
        # Clear it so the "nothing written on failure" assertions below measure
        # their own effect rather than inheriting this row.
        sql("DELETE FROM ai_reports WHERE ip_address=?", (RICH_IP,))

        # Persistently unavailable: bounded attempts, readable message.
        fake = FakeGeminiClient([transient_error()])
        with patch.object(analyst, "_get_client", return_value=fake):
            res = await analyst.generate_attacker_report(RICH_IP)
        check("gives up after the full schedule", fake.calls, len(analyst.RETRY_DELAYS))
        check("exhausted retries flagged transient", res.get("transient"), True)
        msg = res.get("report_text", "")
        check_true(f"message is human-readable, not a JSON dump (got: {msg[:60]!r})",
                   "{'error'" not in msg and "'code'" not in msg)
        check_true("message says it retried", "retried" in msg.lower())
        check_true("message tells the operator what to do", "try again" in msg.lower())
        check("nothing written to ai_reports when retries are exhausted",
              sql_count("SELECT COUNT(*) FROM ai_reports WHERE ip_address=?", (RICH_IP,)), 0)

        # Permanent failure: must NOT retry — retrying burns quota and delays
        # the error the operator actually needs to see.
        fake = FakeGeminiClient([permanent_error()])
        with patch.object(analyst, "_get_client", return_value=fake):
            res = await analyst.generate_attacker_report(RICH_IP)
        check("permanent error attempted exactly once", fake.calls, 1)
        check("permanent error returns error=True", res.get("error"), True)
        check("permanent error not flagged transient", res.get("transient"), None)
        check_true("permanent error surfaces the real cause",
                   "API key not valid" in res.get("report_text", ""))
    finally:
        analyst.RETRY_DELAYS = real_delays

    real_key = config.GEMINI_API_KEY
    config.GEMINI_API_KEY = ""
    check("is_available() reports False with no key", analyst.is_available(), False)
    res = await analyst.generate_attacker_report(RICH_IP)
    check("missing key returns a clean error, not a crash", res.get("error"), True)
    check("nothing written to ai_reports with no key",
          sql_count("SELECT COUNT(*) FROM ai_reports WHERE ip_address=?", (RICH_IP,)), 0)
    config.GEMINI_API_KEY = real_key

    if not analyst.is_available():
        print("\n  SKIPPED: no GEMINI_API_KEY configured — live report tests not run.")
        await db.close()
        TEST_DB.unlink(missing_ok=True)
        return 0

    # ── 9a. Rich attacker — every claim must trace to real data ────────────
    section("9a. Rich attacker — anti-hallucination, claim-by-claim")

    res = await analyst.generate_attacker_report(RICH_IP)
    if res.get("transient"):
        # The provider is shedding load right now. The product already retried
        # on its full schedule and reported it correctly — that behaviour is
        # verified deterministically in 9c-bis with mocks. The remaining live
        # checks grade the CONTENT of a real report, which cannot be graded
        # when no report can be obtained. Skipping is the honest outcome;
        # failing would report a provider outage as a defect in this code.
        print("\n  SKIP  9a/9b live content checks — Gemini is currently unavailable")
        print(f"        {res.get('report_text')}")
        print("        Retry behaviour itself is covered by 9c-bis (mocked, deterministic).")
        await db.close()
        return 0
    if res.get("error"):
        check(f"live report generated (got error: {res.get('report_text')})", False, True)
        await db.close()
        return 1
    report = res["report_text"]
    check_true("live report generated", report and len(report) > 100)
    print(f"\n  --- report ({len(report)} chars) ---")
    for line in report.splitlines():
        print("  | " + line)
    print("  --- end ---\n")

    low = report.lower()

    # Every IPv4 mentioned must be the subject IP — an invented one is the
    # clearest possible hallucination signal.
    ips = set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", report))
    check("no IP address appears that isn't the real subject IP", ips - {RICH_IP}, set())

    # Real stored facts should be reflected, not contradicted.
    check_true("report references the correct subject IP", RICH_IP in report)
    for fact, label in [("digitalocean", "ISP DigitalOcean"), ("netherlands", "country Netherlands")]:
        check_true(f"real enrichment fact present: {label}", fact in low)

    # Any credential-looking token it quotes must be one actually captured.
    # NOTE: match BOTH usernames and passwords — an earlier version of this test
    # only allowlisted usernames and then flagged real passwords (toor, letmein,
    # password123, test123) as "invented", which was a bug in the test, not the
    # report. Structural tokens from evidence JSON are excluded too.
    captured_creds = {"admin", "root", "administrator", "wpadmin", "test",
                      "toor", "password123", "letmein", "test123"}
    structural = {"http", "https", "critical", "high", "medium", "low",
                  "digitalocean", "netherlands", "amsterdam", "abuseipdb",
                  "otx", "credential", "stuffing", "credential_stuffing",
                  "unique_usernames", "honeypot", "wordpress", "unknown",
                  "none", "null", "n_a"}
    quoted = set(re.findall(r"[`'\"]([a-zA-Z][a-zA-Z0-9_]{2,20})[`'\"]", report))
    invented = {u for u in quoted
                if u.lower() not in captured_creds and u.lower() not in structural}
    check("no invented credentials presented as captured", invented, set())

    # Every credential actually stored should appear — nothing silently dropped.
    missing = {c for c in captured_creds if c not in report}
    check("every captured credential appears in the report (nothing omitted)", missing, set())

    # Contradiction check: it must not claim services that were never touched.
    for absent in ("ssh", "telnet", "ftp"):
        if absent in low:
            # allowed only if clearly negated ("no SSH activity")
            ctx = [s for s in re.split(r"[.\n]", low) if absent in s]
            negated = all(any(n in s for n in ("no ", "not ", "only ", "absent", "without", "n/a"))
                          for s in ctx)
            check(f"does not falsely claim {absent.upper()} activity (only HTTP was captured)", negated, True)

    check("report persisted to ai_reports",
          sql_count("SELECT COUNT(*) FROM ai_reports WHERE ip_address=?", (RICH_IP,)), 1)

    # ── 9b. Sparse attacker — gaps stated, not invented ────────────────────
    section("9b. Sparse attacker — must not invent detail to fill gaps")

    res2 = await analyst.generate_attacker_report(SPARSE_IP)
    if res2.get("error"):
        check(f"sparse report generated (got error: {res2.get('report_text')})", False, True)
        await db.close()
        return 1
    sparse = res2["report_text"]
    check_true("sparse report generated", sparse and len(sparse) > 50)
    print(f"\n  --- sparse report ({len(sparse)} chars) ---")
    for line in sparse.splitlines():
        print("  | " + line)
    print("  --- end ---\n")

    slow = sparse.lower()
    ips2 = set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", sparse))
    check("sparse: no invented IP addresses", ips2 - {SPARSE_IP}, set())

    # This attacker has NO geolocation, NO reputation, NO credentials, NO alerts.
    # Naming any of those as fact would be fabrication.
    for term, label in [("netherlands", "a country"), ("digitalocean", "an ISP"),
                        ("amsterdam", "a city"), ("as14061", "an ASN")]:
        check(f"sparse: does not invent {label} (bled from the other attacker)", term in slow, False)

    check("sparse: does not invent captured credentials",
          any(w in slow for w in ("admin/admin", "root/toor", "password123")), False)

    # It should be visibly shorter — a sparse record should yield a sparse report,
    # not a padded one of the same length.
    check_true(f"sparse report is materially shorter than the rich one "
               f"({len(sparse)} vs {len(report)} chars)", len(sparse) < len(report))

    # And it should acknowledge the absence of data somewhere.
    acknowledges = any(w in slow for w in
                       ("no ", "not ", "limited", "sparse", "minimal", "unknown", "absent",
                        "insufficient", "lack", "unavailable", "none"))
    check_true("sparse: explicitly acknowledges limited/absent data", acknowledges)

    await db.close()
    try:
        TEST_DB.unlink(missing_ok=True)
    except PermissionError:
        pass   # Windows may still hold the handle briefly; harmless test residue

    p = sum(1 for _, ok, _ in RESULTS if ok)
    f = len(RESULTS) - p
    print(f"\n{'=' * 74}\n  SECTION 9 TOTAL: {len(RESULTS)} run, {p} passed, {f} failed\n{'=' * 74}")
    if f:
        for n, ok, d in RESULTS:
            if not ok:
                print(f"    FAIL {n} :: {d}")
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
