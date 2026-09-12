"""
HoneyShield v2 dashboard — main entry point.

Reads from the v2 async database (database/db_async.py) through
dashboard/async_bridge.py, since Streamlit pages are plain synchronous
scripts. That bridge owns one event loop for the process — see its module
docstring for why per-call asyncio.run() was silently broken here.
Bound to 127.0.0.1 only — see .streamlit/config.toml.
"""

import sys
from pathlib import Path

import streamlit as st

_ROOT = str(Path(__file__).parent.parent)
if _ROOT not in sys.path:  # guarded: this line runs on every rerun
    sys.path.insert(0, _ROOT)

from dashboard import theme
from dashboard.login import require_auth

st.set_page_config(
    page_title="HoneyShield — Overview",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="expanded",
)

require_auth("🍯", "Overview")

# Heavy imports sit below the auth gate on purpose: see _import_page_modules
# in dashboard/login.py for why, and for what loads them in the background.
import pandas as pd  # noqa: E402
from dashboard import data, sensor  # noqa: E402

theme.page_header(
    "",
    "Operations Overview",
    "Live state of the deployed HTTP honeypot. Capture volume is expected to be "
    "low — this is a single unadvertised host, so a quiet feed is a normal "
    "reading rather than a fault.",
    eyebrow="HoneyShield SOC",
)

# One gathered, cached database read for the whole page (see dashboard/data.py
# for why it is a bundle), overlapped with the sensor's HTTP health probe. The
# two are independent and used to run back to back, so a cache miss cost their
# sum — measured 765 ms + 964 ms. Run together, the page waits for the slower.
_d, probe = data.concurrently(data.overview, data.sensor_status)
summary, filtered = _d["summary"], _d["filtered"]

traffic = _d["traffic"]
_probes = traffic["probe"] + traffic["likely"]

theme.kpis([
    {"label": "Attackers", "value": summary["total_attackers"],
     "note": f"distinct source IPs · {traffic['sources'] - traffic['sources_unlabelled']}"
             f" are platform probes" if _probes else "distinct source IPs",
     "tone": theme.ACCENT},
    {"label": "Connections", "value": summary["total_connections"],
     "note": f"captured sessions · {_probes} are platform probes" if _probes
             else "captured sessions",
     "tone": "#4A9EFF"},
    {"label": "Active alerts", "value": summary["active_alerts"],
     "note": "awaiting triage",
     "tone": theme.SEVERITY["HIGH"] if summary["active_alerts"] else theme.MUTED},
    {"label": "Critical threats", "value": summary["critical_attackers"],
     "note": "score ≥ 80",
     "tone": theme.SEVERITY["CRITICAL"] if summary["critical_attackers"] else theme.MUTED},
])

# ── What was actually captured ────────────────────────────────────────────
# The headline counts above are honest about rows and misleading about
# attackers: the hosting platform probes the service once, about a second after
# every restart, and that request is captured like any other visitor. Labelling
# it is not enough — nobody should have to remember this — so the split is
# stated here, on the page, every time.
if _probes:
    theme.section(
        "What was captured",
        "Every deploy or restart of the honeypot is followed a second later by one "
        "request from the hosting platform itself (GET / from Google Cloud in "
        "Oregon, where Render runs). Those are labelled and kept, never deleted — "
        "they are true records, just not attacker traffic.",
    )
    theme.composition([
        {"label": "Platform restart probes", "value": traffic["probe"],
         "color": theme.MUTED},
        {"label": "Likely restart probes", "value": traffic["likely"],
         "color": "#55607A"},
        {"label": "Unattributed", "value": traffic["unlabelled"],
         "color": theme.ACCENT},
    ])
    st.caption(
        f"{traffic['probe']} confirmed by timing, origin and request; "
        f"{traffic['likely']} match timing and origin but were captured before "
        f"request details were logged, so they cannot be confirmed; "
        f"{traffic['unlabelled']} could not be attributed to a restart. "
        f"Nothing captured so far has been confirmed as organic attacker traffic — "
        f"see database/traffic_classification.py for the rule and the evidence."
    )

# ── Sensor health ─────────────────────────────────────────────────────────
# The single most valuable thing this page can answer is "is the sensor alive?"
# Without it, an empty feed is ambiguous: genuinely quiet, or silently down.
#
# This asks the honeypot directly. It used to infer liveness from how recently
# a row landed in filtered_connections — which broke silently the moment the
# platform's health check was repointed at an endpoint that records nothing:
# the table froze, and this panel reported a permanently STALE sensor for a
# service that was healthy. A liveness signal has to test the property it
# claims to report, not a side effect of someone else's configuration.
theme.section(
    "Sensor health",
    "The console requests the honeypot's health endpoint directly and reports "
    "what came back. This is independent of attacker traffic, of capture volume, "
    "and of how the platform happens to route its own health checks.",
)

state = probe["state"]

STATES = {
    sensor.ONLINE: ("ONLINE", theme.SEVERITY["LOW"]),
    sensor.WAKING: ("WAKING", theme.SEVERITY["MEDIUM"]),
    sensor.DEGRADED: ("DEGRADED", theme.SEVERITY["HIGH"]),
    sensor.UNREACHABLE: ("UNREACHABLE", theme.SEVERITY["CRITICAL"]),
    sensor.UNCONFIGURED: ("NOT CHECKED", theme.MUTED),
}
status, tone = STATES.get(state, ("UNKNOWN", theme.MUTED))

theme.kpis([
    {"label": "Sensor status", "value": status, "note": probe["detail"],
     "tone": tone, "dot": True},
    {"label": "Response time", "tone": theme.MUTED, "note": "round trip to the honeypot",
     "value": f"{probe['latency_ms']} ms" if probe["latency_ms"] is not None else "—"},
    {"label": "Captured sessions", "value": summary["total_connections"],
     "note": "real traffic, all time", "tone": theme.MUTED},
    {"label": "Noise filtered", "value": filtered["total"],
     "note": "kept out of capture data", "tone": theme.MUTED},
])

if state == sensor.UNREACHABLE:
    st.error(
        "The honeypot did not answer. On a free tier this can be a cold start that "
        "outlasted the probe timeout, so retry before assuming an outage — but if "
        "it persists, the sensor is genuinely down and capturing nothing."
    )
elif state == sensor.DEGRADED:
    st.warning(
        f"The honeypot answered with HTTP {probe['http_status']} instead of 200. It "
        "is reachable, so this points at the application rather than the platform."
    )
elif state == sensor.UNCONFIGURED:
    st.info(
        "Set HONEYPOT_PUBLIC_URL in .env to the deployed honeypot's base URL and the "
        "console will check liveness directly. Without it this panel cannot tell a "
        "quiet honeypot from a dead one."
    )

# ── Recent activity ───────────────────────────────────────────────────────
theme.section("Recent activity", "The five most recent captured connections.")

recent = _d["recent"]
if recent:
    df = pd.DataFrame(recent)
    keep = [c for c in ("connected_at", "ip_address", "country", "service", "port",
                        "threat_score", "verdict") if c in df.columns]
    theme.table(df[keep])
    st.page_link("pages/01_🔴_Live_Feed.py", label="Open the full live feed", icon=":material/arrow_forward:")
else:
    theme.empty_state(
        "📡",
        "No connections captured yet",
        "The honeypot is listening but nothing has reached it. New hosts are "
        "typically found within minutes via Certificate Transparency logs, so "
        "the first arrivals are usually automated scanners.",
    )

# ── Top attackers ─────────────────────────────────────────────────────────
theme.section("Highest-scoring attackers", "Ranked by weighted threat score out of 100.")

top = _d["top"]
if top:
    tdf = pd.DataFrame(top)
    keep = [c for c in ("ip_address", "country", "isp", "threat_score", "verdict",
                        "total_connections", "last_seen") if c in tdf.columns]
    theme.table(tdf[keep])
    st.page_link("pages/02_🌍_Attacker_Intel.py", label="Open attacker intelligence", icon=":material/arrow_forward:")
else:
    theme.empty_state(
        "🌍",
        "No attackers profiled yet",
        "Once a connection is captured, its source IP is enriched with "
        "geolocation, AbuseIPDB reputation and AlienVault OTX pulse data, then "
        "scored across 14 weighted factors.",
    )
