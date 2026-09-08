#!/usr/bin/env python3
"""
Analytics numeric accuracy — rendered values vs a known seeded dataset.

Run directly:  python tests/test_analytics_accuracy.py

The existing suites assert that pages RENDER. That is not the same as asserting
they render the RIGHT NUMBERS, and the difference mattered: the Analytics
composition panels ignored the time window entirely from the day the page was
written (commit bc294fb), reporting all-time counts under a "last N hours"
heading, and every render test passed the whole time.

The seeded dataset is deliberately built so a wrong query gives a WRONG NUMBER:
rows exist both inside and outside the window, so an unwindowed COUNT returns 7
where the correct answer is 3. A test that seeded only in-window rows would
pass against the bug.

Uses a throwaway SQLite database; production is never touched.
"""

import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_DB = REPO_ROOT / "data" / "test_analytics.db"
os.environ["SQLITE_PATH"] = str(TEST_DB)
os.environ["DATABASE_URL"] = ""          # never point this at production
sys.path.insert(0, str(REPO_ROOT))

import asyncio  # noqa: E402
import sqlite3  # noqa: E402
from unittest.mock import patch  # noqa: E402

import config  # noqa: E402
config.SKIP_SCHEMA_INIT = False

from database.db_async import db  # noqa: E402

WINDOW = 24
RESULTS = []


def check(name, got, expected):
    ok = got == expected
    RESULTS.append((name, ok))
    print(("  PASS  " if ok else "  FAIL  ") + f"{name}: {got}")
    if not ok:
        print(f"          expected {expected!r}, got {got!r}")


def section(t):
    print(f"\n{'=' * 74}\n{t}\n{'=' * 74}")


def hour_start(hours_ago: int) -> datetime:
    """Start of the clock hour N hours back, in UTC."""
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    return now - timedelta(hours=hours_ago)


def at(hours_ago: int, minute: int = 0) -> str:
    """
    A timestamp anchored to an hour boundary.

    Offsets like "2.0 and 2.1 hours ago" are NOT deterministic: whether they
    share a bucket depends on the current minute, so the same test passes at
    11:30 and fails at 11:05. Anchoring to the hour makes bucket membership
    explicit instead of incidental.
    """
    return (hour_start(hours_ago) + timedelta(minutes=minute)).strftime(
        "%Y-%m-%d %H:%M:%S")


# ── The dataset, and the answers it implies ───────────────────────────────
# Inside a 24h window: 3 connections (2 in one hour, 1 in another), 2 attackers.
# Outside it: 4 connections, 2 attackers — including the only HIGH verdict, so
# an unwindowed "high or critical" count would wrongly report 1.
# Two share the hour-2 bucket, one sits alone in hour-5 — so the busiest
# bucket is unambiguously 2, whatever time the suite happens to run.
IN_WINDOW_CONNECTIONS = [(2, 10, "http"), (2, 20, "http"), (5, 15, "http")]
OUT_OF_WINDOW_CONNECTIONS = [(50, 0, "http"), (51, 0, "http"), (52, 0, "ssh"), (99, 0, "http")]

ATTACKERS = [
    # ip,            last_seen_hours_ago, verdict,    score, total_connections
    ("198.51.100.1", 2,  "LOW",      10, 2),
    ("198.51.100.2", 5,  "MEDIUM",   40, 1),
    ("198.51.100.3", 50, "HIGH",     70, 3),   # outside the window
    ("198.51.100.4", 99, "LOW",       5, 1),   # outside the window
]

EXPECTED = {
    "In window": 3,              # unwindowed would be 7
    "Busiest bucket": 2,         # the two hits sharing one hour
    "Sources ranked": 4,
    "High or critical": 0,       # the HIGH attacker is outside the window
    "service composition": 3,    # unwindowed would be 7
    "verdict composition": 2,    # unwindowed would be 4
    "timeline sum": 3,
    "top-sources sum": 7,        # all-time by design: 2+1+3+1
}


def seed():
    TEST_DB.unlink(missing_ok=True)
    asyncio.run(_create_schema())
    c = sqlite3.connect(TEST_DB)
    try:
        for ip, hrs, verdict, score, total in ATTACKERS:
            c.execute(
                "INSERT INTO attackers (ip_address, first_seen, last_seen, verdict, "
                "threat_score, total_connections, country, isp) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (ip, at(hrs + 1, 30), at(hrs, 30), verdict, score, total,
                 "Testland", "TestNet"))
        for hrs, minute, svc in IN_WINDOW_CONNECTIONS + OUT_OF_WINDOW_CONNECTIONS:
            c.execute(
                "INSERT INTO connections (ip_address, service, port, connected_at) "
                "VALUES (?,?,?,?)",
                (ATTACKERS[0][0], svc, 8080, at(hrs, minute)))
        c.commit()
    finally:
        c.close()


async def _create_schema():
    await db.connect()
    await db.init_schema()
    await db.close()


# ── Render the real page and extract what it actually shows ───────────────
KPI_RE = re.compile(r'hs-k-label">(.*?)</div><div class="hs-k-value[^"]*">(.*?)</div>')
COMP_NUM_RE = re.compile(r'hs-c-num">(\d+)</span>')
COMP_OPEN = '<div class="hs-comp">'


def strip_tags(s):
    return re.sub(r"<[^>]+>", "", s).strip()


def render():
    from streamlit.testing.v1 import AppTest
    from dashboard import data, theme
    data.refresh()   # never assert against a cached bundle

    # AppTest cannot read plotly_chart.value (it requires selection state), so
    # capture figures where the page hands them to theme.plot().
    captured = []
    real_plot = theme.plot

    def recording_plot(fig, height=320):
        captured.append(fig)
        return real_plot(fig, height)

    at = AppTest.from_file(
        str(REPO_ROOT / "dashboard" / "pages" / "03_📈_Analytics.py"), default_timeout=240)
    at.session_state["authenticated"] = True
    at.session_state["username"] = "admin"
    with patch.object(theme, "plot", recording_plot):
        at.run()
        if at.slider and at.slider[0].value != WINDOW:
            captured.clear()
            at.slider[0].set_value(WINDOW).run()

    kpis, comps = {}, []
    for m in at.markdown:
        v = str(m.value)
        if '<div class="hs-kpis">' in v:
            for label, val in KPI_RE.findall(v):
                kpis[strip_tags(label)] = strip_tags(val)
        if COMP_OPEN in v:
            for block in v.split(COMP_OPEN)[1:]:
                comps.append(sum(int(n) for n in COMP_NUM_RE.findall(block)))

    return kpis, comps, captured, [e.message for e in at.exception]


def main():
    print("=" * 74)
    print("Analytics accuracy — rendered values vs a known dataset")
    print("=" * 74)
    seed()
    print(f"seeded: {len(IN_WINDOW_CONNECTIONS)} connections inside a {WINDOW}h window, "
          f"{len(OUT_OF_WINDOW_CONNECTIONS)} outside; {len(ATTACKERS)} attackers")
    print("a query that ignores the window would report 7 connections and 4 attackers")

    kpis, comps, charts, errors = render()
    if errors:
        print("\nPAGE EXCEPTIONS:", errors)

    section("KPIs")
    for label in ("In window", "Busiest bucket", "Sources ranked", "High or critical"):
        check(f"KPI {label}", kpis.get(label, "absent"), str(EXPECTED[label]))

    section("Charts and composition")
    if charts:
        ys = list(charts[0].data[0].y)
        check("timeline bar sum", int(sum(ys)), EXPECTED["timeline sum"])
        check("timeline is zero-filled across the window", len(ys), WINDOW + 1)
        check("timeline peak equals the busiest hour", int(max(ys)), EXPECTED["Busiest bucket"])
    else:
        check("timeline rendered", False, True)

    check("service composition sum", comps[0] if comps else None,
          EXPECTED["service composition"])
    check("verdict composition sum", comps[1] if len(comps) > 1 else None,
          EXPECTED["verdict composition"])

    if len(charts) > 1:
        total = sum(int(sum(tr.x)) for tr in charts[-1].data)
        check("top-sources bar sum (all-time by design)", total, EXPECTED["top-sources sum"])

    section("Guard: the seed would expose an unwindowed query")
    c = sqlite3.connect(TEST_DB)
    try:
        unwindowed = c.execute("SELECT count(*) FROM connections").fetchone()[0]
        unwindowed_att = c.execute(
            "SELECT count(*) FROM attackers WHERE verdict IS NOT NULL").fetchone()[0]
    finally:
        c.close()
    check("all-time connections differ from windowed", unwindowed != EXPECTED["In window"], True)
    check("all-time attackers differ from windowed",
          unwindowed_att != EXPECTED["verdict composition"], True)

    TEST_DB.unlink(missing_ok=True)

    p = sum(1 for _, ok in RESULTS if ok)
    f = len(RESULTS) - p
    print(f"\n{'=' * 74}\n  ANALYTICS ACCURACY: {len(RESULTS)} run, {p} passed, {f} failed\n{'=' * 74}")
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(main())
