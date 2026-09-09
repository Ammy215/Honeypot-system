#!/usr/bin/env python3
"""
Sensor liveness — the signal must reflect reality, not a side effect.

Run directly:  python tests/test_sensor_liveness.py

THE REGRESSION THIS EXISTS TO CATCH.
Sensor health used to be inferred from how recently a row landed in
`filtered_connections`: the platform's health checker hit a decoy path every
few seconds, so a fresh filtered row implied a live listener. Adding a health
endpoint that deliberately records nothing repointed that checker, the table
froze, and Overview began reporting a permanently STALE sensor — critical red,
"check the deployment" — for a service that was healthy and answering every
ping.

Every existing test passed throughout, because they asserted the panel
RENDERS. It did. It rendered a lie.

So the tests below assert the property instead: with the old noise source
completely silent, a live honeypot must still read as live; and with that
source flowing freely, a dead honeypot must still read as dead. Either
direction failing means the panel has drifted back to reading a side effect.
"""

import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from datetime import datetime, timedelta, timezone  # noqa: E402

import requests  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

import config  # noqa: E402
from dashboard import sensor  # noqa: E402

APP = REPO_ROOT / "dashboard" / "app.py"
LIVE_FEED = REPO_ROOT / "dashboard" / "pages" / "01_🔴_Live_Feed.py"

RESULTS = []


def check(name, condition, detail=""):
    ok = bool(condition)
    RESULTS.append((name, ok))
    print(("  PASS  " if ok else "  FAIL  ") + name)
    if not ok and detail:
        print(f"          {detail}")


def section(t):
    print(f"\n{'=' * 74}\n{t}\n{'=' * 74}")


class FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.text = "ok"


def stub_get(status_code=200, delay=0.0, raises=None):
    """A requests.get replacement with controllable outcome."""
    def _get(url, **kwargs):
        if raises is not None:
            raise raises
        if delay:
            import time
            time.sleep(delay)
        return FakeResponse(status_code)
    return _get


def bundle(filtered_latest, total=2830):
    """An overview() payload with the filtered noise source in a chosen state."""
    return {
        "summary": {"total_connections": 16, "total_attackers": 9,
                    "active_alerts": 0, "critical_attackers": 0},
        "filtered": {"total": total, "last_hour": 0, "last_24h": 0,
                     "latest": filtered_latest, "recent": []},
        "recent": [],
        "top": [],
    }


def render_overview(probe_result, overview_bundle):
    """Render Overview with both the probe and the DB read stubbed."""
    at = AppTest.from_file(str(APP), default_timeout=180)
    at.session_state["authenticated"] = True
    at.session_state["username"] = "admin"
    with patch("dashboard.data.sensor_status", return_value=probe_result), \
         patch("dashboard.data.overview", return_value=overview_bundle):
        at.run()
    return at


def markup(at) -> str:
    """
    The page's own markup, excluding the injected stylesheet.

    theme.inject() emits a <style> block through st.markdown, and CSS comments
    in it mention state names. Including it made every "state X is not shown"
    assertion pass or fail on the stylesheet rather than on what the panel
    actually rendered — a test measuring the wrong thing.
    """
    return " ".join(str(m.value) for m in at.markdown if "<style>" not in str(m.value))


def main():
    # ── Classification ────────────────────────────────────────────────────
    section("probe() classifies real outcomes correctly")

    config.HONEYPOT_PUBLIC_URL = "https://example.invalid"
    config.HEALTH_CHECK_PATH = "/_health"
    config.SENSOR_WAKING_THRESHOLD_SECONDS = 0.3
    config.SENSOR_PROBE_TIMEOUT_SECONDS = 35

    check("probe_url() joins base and path",
          sensor.probe_url() == "https://example.invalid/_health", sensor.probe_url())

    with patch("requests.get", stub_get(200)):
        r = sensor.probe()
    check("fast 200 -> online", r["state"] == sensor.ONLINE, r)
    check("online reports a latency", r["latency_ms"] is not None)

    with patch("requests.get", stub_get(200, delay=0.45)):
        r = sensor.probe()
    check("slow 200 -> waking (cold start, NOT down)", r["state"] == sensor.WAKING, r)

    with patch("requests.get", stub_get(503)):
        r = sensor.probe()
    check("503 -> degraded (reachable, misbehaving)", r["state"] == sensor.DEGRADED, r)
    check("degraded records the status code", r["http_status"] == 503, r)

    with patch("requests.get", stub_get(raises=requests.exceptions.Timeout())):
        r = sensor.probe()
    check("timeout -> unreachable", r["state"] == sensor.UNREACHABLE, r)

    with patch("requests.get", stub_get(raises=requests.exceptions.ConnectionError())):
        r = sensor.probe()
    check("connection error -> unreachable", r["state"] == sensor.UNREACHABLE, r)

    check("probe() never raises — a reachability panel must not itself fail",
          isinstance(r, dict))

    saved = config.HONEYPOT_PUBLIC_URL
    config.HONEYPOT_PUBLIC_URL = ""
    r = sensor.probe()
    check("no URL configured -> unconfigured, not a false 'down'",
          r["state"] == sensor.UNCONFIGURED, r)
    check("unconfigured probes nothing", sensor.probe_url() is None)
    config.HONEYPOT_PUBLIC_URL = saved

    # ── THE regression ────────────────────────────────────────────────────
    section("Liveness survives the noise source going silent (the regression)")

    # filtered_connections frozen three days ago — exactly what repointing the
    # platform health check did. Under the old inference this rendered STALE.
    ancient = datetime.now(timezone.utc) - timedelta(days=3)
    at = render_overview({"state": sensor.ONLINE, "latency_ms": 271,
                          "http_status": 200, "url": "https://x/_health",
                          "detail": "answered in 271ms"},
                         bundle(filtered_latest=ancient))
    m = markup(at)
    check("no exception rendering Overview", not list(at.exception),
          str(list(at.exception)[:1]))
    check("live honeypot reads ONLINE despite 3-day-old filtered data",
          "ONLINE" in m, m[:400])
    check("...and does NOT report STALE", "STALE" not in m)
    check("...no 'check the deployment' alarm on a healthy service",
          not any("check the deployment" in str(e.value).lower() for e in at.error))

    # The same, but the noise source has never produced a row at all.
    at = render_overview({"state": sensor.ONLINE, "latency_ms": 300,
                          "http_status": 200, "url": "https://x/_health",
                          "detail": "answered in 300ms"},
                         bundle(filtered_latest=None, total=0))
    m = markup(at)
    check("live honeypot reads ONLINE with zero filtered rows ever",
          "ONLINE" in m, m[:400])
    check("...and does NOT report NO SIGNAL", "NO SIGNAL" not in m)

    # ── The inverse coupling ──────────────────────────────────────────────
    section("A dead honeypot reads dead, even while noise is flowing")

    fresh = datetime.now(timezone.utc)
    at = render_overview({"state": sensor.UNREACHABLE, "latency_ms": 35000,
                          "http_status": None, "url": "https://x/_health",
                          "detail": "no response within 35s"},
                         bundle(filtered_latest=fresh))
    m = markup(at)
    check("unreachable honeypot reads UNREACHABLE despite fresh filtered rows",
          "UNREACHABLE" in m, m[:400])
    check("...and does NOT read ONLINE", "ONLINE" not in m)
    check("...and raises a visible error", len(list(at.error)) >= 1)

    at = render_overview({"state": sensor.DEGRADED, "latency_ms": 400,
                          "http_status": 502, "url": "https://x/_health",
                          "detail": "answered HTTP 502, expected 200"},
                         bundle(filtered_latest=fresh))
    m = markup(at)
    check("502 reads DEGRADED, not ONLINE", "DEGRADED" in m and "ONLINE" not in m,
          m[:400])

    # ── Structural: the coupling cannot come back ─────────────────────────
    section("Overview cannot drift back to inferring liveness from noise")

    app_src = APP.read_text(encoding="utf-8")
    check("Overview calls data.sensor_status()", "data.sensor_status()" in app_src)
    check("Overview no longer reads filtered['latest']",
          'filtered["latest"]' not in app_src and "filtered.get(\"latest\")" not in app_src,
          "the frozen-timestamp inference is back")
    check("Overview no longer computes a STALE state from row age",
          '"STALE"' not in app_src and "'STALE'" not in app_src)

    feed_src = LIVE_FEED.read_text(encoding="utf-8")
    check("Live Feed no longer calls filtered traffic a liveness signal",
          "tells you the honeypot is alive" not in feed_src)
    check("Live Feed points liveness at the Overview probe instead",
          "Overview" in feed_src)

    # The panel must degrade honestly rather than inventing a state.
    at = render_overview({"state": sensor.UNCONFIGURED, "latency_ms": None,
                          "http_status": None, "url": None,
                          "detail": "HONEYPOT_PUBLIC_URL is not set"},
                         bundle(filtered_latest=fresh))
    m = markup(at)
    check("unconfigured reads NOT CHECKED, never a fabricated ONLINE",
          "NOT CHECKED" in m and "ONLINE" not in m, m[:400])

    p = sum(1 for _, ok in RESULTS if ok)
    f = len(RESULTS) - p
    print(f"\n{'=' * 74}\n  SENSOR LIVENESS TOTAL: {len(RESULTS)} run, "
          f"{p} passed, {f} failed\n{'=' * 74}")
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(main())
