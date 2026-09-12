#!/usr/bin/env python3
"""
Restart-probe labelling — the rule, the schema, and its visibility on screen.

Run directly:  python tests/test_traffic_classification.py

The hosting platform probes the honeypot once, about a second after every
deploy or restart, and that request is captured exactly like a visitor. Those
rows are labelled, never deleted (database/traffic_classification.py).

The checks that matter most here are the ones that must NOT label:
a real attacker that happens to arrive seconds after a restart, a request from
somewhere other than the platform's network, and a row with no restart to
attribute it to. Labelling is a claim about evidence; over-labelling would
quietly delete attacker traffic from every count on the dashboard.

Uses a throwaway SQLite database; production is never touched.
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_DB = REPO_ROOT / "data" / "test_traffic_classification.db"
os.environ["SQLITE_PATH"] = str(TEST_DB)
os.environ["DATABASE_URL"] = ""
sys.path.insert(0, str(REPO_ROOT))

import asyncio  # noqa: E402
import sqlite3  # noqa: E402

import config  # noqa: E402

config.SKIP_SCHEMA_INIT = False

from streamlit.testing.v1 import AppTest  # noqa: E402

from database.db_async import db  # noqa: E402
from database.traffic_classification import (  # noqa: E402
    CLASS_LIKELY, CLASS_PROBE, attacker_class, classify,
)

APP = REPO_ROOT / "dashboard" / "app.py"
LIVE_FEED = REPO_ROOT / "dashboard" / "pages" / "01_🔴_Live_Feed.py"

passed = failed = 0
BOOT = datetime(2026, 9, 12, 4, 28, 47, tzinfo=timezone.utc)
MARKERS = [BOOT - timedelta(days=1), BOOT]
PLATFORM = {"isp": "Google LLC", "city": "The Dalles", "asn": "AS396982 Google LLC"}


def check(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}" + (f"\n          {detail}" if detail else ""))


def section(t):
    print(f"\n{t}")


def row(**kw):
    base = {"connected_at": BOOT + timedelta(seconds=1.1), "method": "GET",
            "path": "/", "user_agent": "Go-http-client/2.0", **PLATFORM}
    base.update(kw)
    return base


def test_rule():
    section("[1] What the rule labels — and what it refuses to")

    klass, note = classify(row(), MARKERS)
    check("the real thing: GET / from the platform, 1.1 s after a restart",
          klass == CLASS_PROBE, f"{klass} / {note}")
    check("...and records why", note and "after instance start" in note, str(note))

    klass, _ = classify(row(connected_at=BOOT + timedelta(seconds=9.3)), MARKERS)
    check("9.3 s after a restart still counts (observed range is 1-10 s)",
          klass == CLASS_PROBE)

    klass, note = classify(row(connected_at=BOOT + timedelta(minutes=2)), MARKERS)
    check("two minutes after a restart does NOT", klass is None, str(note))

    klass, _ = classify(row(method=None, path=None, user_agent=None), MARKERS)
    check("request never recorded -> 'likely', not confirmed", klass == CLASS_LIKELY)

    # The one that protects the data: a real attacker can arrive at any moment,
    # including one second after a deploy.
    klass, note = classify(row(method="POST", path="/wp-login.php",
                               user_agent="python-requests/2.31"), MARKERS)
    check("an ATTACKER arriving 1 s after a restart is NOT labelled",
          klass is None, f"{klass} / {note}")
    klass, _ = classify(row(path="/.env"), MARKERS)
    check("...nor is a recon request for /.env", klass is None)
    klass, _ = classify(row(user_agent="curl/8.4.0"), MARKERS)
    check("...nor GET / from a different client", klass is None)

    klass, note = classify(row(isp="DigitalOcean", city="Bengaluru", asn="AS14061"), MARKERS)
    check("same request from another network is NOT labelled", klass is None, str(note))

    klass, note = classify(row(connected_at=BOOT - timedelta(days=30)), MARKERS)
    check("a row with no restart before it is left alone", klass is None, str(note))

    check("source labelled only when every one of its rows is a probe",
          attacker_class([CLASS_PROBE, CLASS_PROBE]) == CLASS_PROBE
          and attacker_class([CLASS_PROBE, CLASS_LIKELY]) == CLASS_LIKELY
          and attacker_class([CLASS_PROBE, None]) is None
          and attacker_class([]) is None)


def test_schema_and_counts():
    section("[2] Columns exist on both backends, and the counts add up")

    for name in ("schema_postgres.sql", "schema_sqlite_dev.sql"):
        sql = (REPO_ROOT / "database" / name).read_text(encoding="utf-8")
        check(f"{name} defines traffic_class", "traffic_class" in sql)

    async def seed_and_count():
        TEST_DB.unlink(missing_ok=True)
        await db.connect()
        await db.init_schema()
        cols = {}
        c = sqlite3.connect(TEST_DB)
        try:
            for table in ("connections", "attackers"):
                cols[table] = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
        finally:
            c.close()

        # record_connection upserts the attacker row too.
        ids = [await db.record_connection(ip_address=ip, service="http", port=80)
               for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3")]
        c = sqlite3.connect(TEST_DB)
        try:
            c.execute("UPDATE connections SET traffic_class='restart_probe' WHERE id=?", (ids[0],))
            c.execute("UPDATE connections SET traffic_class='restart_probe_likely' WHERE id=?", (ids[1],))
            c.commit()
        finally:
            c.close()
        counts = await db.traffic_breakdown()
        await db.close()
        return cols, counts

    cols, counts = asyncio.run(seed_and_count())
    check("SQLite migration added connections.traffic_class",
          "traffic_class" in cols["connections"])
    check("SQLite migration added connections.traffic_class_note",
          "traffic_class_note" in cols["connections"])
    check("SQLite migration added attackers.traffic_class",
          "traffic_class" in cols["attackers"])
    check("traffic_breakdown counts probes", counts["probe"] == 1, str(counts))
    check("...likely", counts["likely"] == 1, str(counts))
    check("...and leaves the rest unlabelled", counts["unlabelled"] == 1, str(counts))
    check("...with sources counted from the rows",
          counts["sources"] == 3 and counts["sources_unlabelled"] == 1, str(counts))


def test_visible_on_screen():
    section("[3] It is on the page, not just in the database")

    traffic = {"connections": 19, "probe": 12, "likely": 6, "unlabelled": 1,
               "sources": 12, "sources_unlabelled": 1}
    overview = {
        "summary": {"total_connections": 19, "total_attackers": 12,
                    "active_alerts": 0, "critical_attackers": 0},
        "filtered": {"total": 2832, "last_hour": 0, "last_24h": 0, "latest": None, "recent": []},
        "recent": [], "top": [], "traffic": traffic,
    }
    probe = {"state": "online", "latency_ms": 250, "http_status": 200,
             "url": "https://x/_health", "detail": "answered in 250ms"}

    with patch("dashboard.data.overview", return_value=overview), \
         patch("dashboard.data.sensor_status", return_value=probe):
        at = AppTest.from_file(str(APP), default_timeout=180)
        at.session_state["authenticated"] = True
        at.session_state["username"] = "admin"
        at.run()
    text = " ".join(str(m.value) for m in at.markdown if "<style>" not in str(m.value))
    text += " " + " ".join(str(c.value) for c in at.caption)
    check("Overview renders without error", not list(at.exception), str(list(at.exception)[:1]))
    check("Overview states the split", "What was captured" in text, text[:300])
    check("...names the platform probes", "restart probe" in text.lower())
    check("...and says nothing is confirmed organic",
          "confirmed as organic" in text.lower(), text[-400:])
    check("headline KPI is annotated, not silently wrong",
          "platform probes" in text)

    feed = {"summary": overview["summary"], "filtered": overview["filtered"],
            "alerts": [], "traffic": traffic,
            "connections": [{"id": 1, "ip_address": "34.168.108.203", "service": "http",
                             "port": 10000, "connected_at": "2026-09-12 04:28:48",
                             "method": "GET", "path": "/", "user_agent": "Go-http-client/2.0",
                             "traffic_class": "restart_probe", "country": "United States",
                             "threat_score": 5, "verdict": "LOW"}]}
    with patch("dashboard.data.live_feed", return_value=feed):
        at = AppTest.from_file(str(LIVE_FEED), default_timeout=180)
        at.session_state["authenticated"] = True
        at.session_state["username"] = "admin"
        at.run()
    check("Live Feed renders without error", not list(at.exception), str(list(at.exception)[:1]))
    feed_text = " ".join(str(m.value) for m in at.markdown if "<style>" not in str(m.value))
    check("Live Feed explains the Origin column", "Origin" in feed_text, feed_text[:300])
    frames = [df for df in at.dataframe]
    check("Live Feed table carries the label per row",
          any("traffic_class" in list(df.value.columns) for df in frames) if frames else False)
    if frames:
        labels = [str(v) for df in frames for v in df.value.get("traffic_class", [])]
        check("...rendered as words, not a database value",
              any("Render restart probe" == v for v in labels), str(labels))


if __name__ == "__main__":
    try:
        test_rule()
        test_schema_and_counts()
        test_visible_on_screen()
    finally:
        TEST_DB.unlink(missing_ok=True)
    print(f"\npassed: {passed}   failed: {failed}")
    sys.exit(1 if failed else 0)
