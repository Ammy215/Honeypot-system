"""
Live Feed — real-time connection stream.

Nothing on this page renders attacker-controlled text through markup:
ip_address is a validated address, service/port are our own literals,
country comes from ip-api.com (not attacker input). Everything from the
database is rendered via st.dataframe, which never interprets cell
contents as HTML/markdown.
"""

import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard import theme
from dashboard import data
from dashboard.login import require_auth

st.set_page_config(page_title="HoneyShield — Live Feed", page_icon="🔴", layout="wide")
require_auth("🔴", "Live Feed")

theme.page_header(
    "",
    "Live Attack Feed",
    "Every connection the honeypot captured, newest first, with enrichment "
    "resolved at capture time.",
    eyebrow="Real-time",
)

with st.sidebar:
    st.markdown("<div style='height:.4rem'></div>", unsafe_allow_html=True)
    st.markdown("**Feed controls**")
    auto_refresh = st.checkbox("Auto-refresh (15s)", value=False)
    service_filter = st.selectbox("Service", ["All", "ssh", "ftp", "telnet", "http"])

_d = data.live_feed(service_filter if service_filter != "All" else None)
summary = _d["summary"]
theme.kpis([
    {"label": "Connections", "value": summary["total_connections"], "note": "captured sessions"},
    {"label": "Attackers", "value": summary["total_attackers"], "note": "distinct source IPs",
     "tone": "#4A9EFF"},
    {"label": "Active alerts", "value": summary["active_alerts"], "note": "awaiting triage",
     "tone": theme.SEVERITY["HIGH"] if summary["active_alerts"] else theme.MUTED},
    {"label": "Critical", "value": summary["critical_attackers"], "note": "score ≥ 80",
     "tone": theme.SEVERITY["CRITICAL"] if summary["critical_attackers"] else theme.MUTED},
])

# ── Connections ───────────────────────────────────────────────────────────
theme.section("Captured connections", "Resolved source IP, service and enrichment per session.")

service = None if service_filter == "All" else service_filter
connections = _d["connections"]

if connections:
    df = pd.DataFrame(connections)
    order = [c for c in ("connected_at", "ip_address", "country", "method", "path",
                         "user_agent", "service", "port", "threat_score", "verdict", "id")
             if c in df.columns]
    # method/path/user_agent are attacker-controlled. st.dataframe renders cell
    # contents as inert text, which is why they appear here and never in a
    # markdown or HTML sink.
    theme.table(df[order], height=430)
    st.caption(f"Showing {len(df)} most recent connection(s). `method`, `path` and "
               "`user_agent` are recorded verbatim from the request — they show what "
               "was probed for, not just that someone connected.")

    probed = df[df["path"].notna()] if "path" in df.columns else df.iloc[0:0]
    if not probed.empty:
        theme.subsection("Most-probed paths")
        counts = (probed.groupby("path").size().reset_index(name="hits")
                  .sort_values("hits", ascending=False).head(15))
        theme.table(counts)
elif service:
    theme.empty_state(
        "🔍",
        f"No {service_filter.upper()} connections",
        "Only the HTTP honeypot is deployed on the current platform — SSH, FTP "
        "and Telnet are built and tested but not exposed. Switch the Service "
        "filter back to All.",
    )
else:
    theme.empty_state(
        "📡",
        "Nothing captured yet",
        "The listener is up but no connection has arrived. Check Sensor health on "
        "the Overview page to confirm the honeypot is reachable — a quiet feed and "
        "a dead sensor look identical here.",
    )

# ── Filtered traffic ──────────────────────────────────────────────────────
theme.section(
    "Filtered traffic",
    "Connections dropped by IGNORE_UNFORWARDED_CONNECTIONS — no proxy header, in "
    "practice the platform's own health checks. Kept out of the capture tables "
    "above so they cannot pollute detection or scoring, but surfaced here so an "
    "empty feed reads as 'genuinely quiet' rather than 'silently filtered'.",
)

filtered = _d["filtered"]
theme.kpis([
    {"label": "Filtered total", "value": filtered["total"], "note": "since deployment",
     "tone": theme.MUTED},
    {"label": "Last hour", "value": filtered["last_hour"], "note": "probes", "tone": theme.MUTED},
    {"label": "Last 24h", "value": filtered["last_24h"], "note": "probes", "tone": theme.MUTED},
    {"label": "Most recent", "note": "probe timestamp", "tone": theme.MUTED,
     "value": filtered["latest"].strftime("%H:%M:%S") if filtered["latest"] else "—"},
])

if filtered["recent"]:
    with st.expander(f"Breakdown by source ({len(filtered['recent'])} shown)"):
        # st.dataframe never interprets cell contents as HTML/markdown, which
        # matters here: `path` and `method` come off the wire from whoever
        # connected, so they are attacker-controlled text.
        theme.table(pd.DataFrame(filtered["recent"]))
elif filtered["total"] == 0:
    theme.empty_state(
        "🛡️",
        "Nothing filtered yet",
        "If this stays at zero while the service is up, the platform health check "
        "is not reaching the honeypot at all — worth investigating, because it "
        "also means you have no independent liveness signal.",
    )

# ── Alerts ────────────────────────────────────────────────────────────────
theme.section("Recent alerts", "Detections raised by the brute-force and correlation engines.")

alerts = _d["alerts"]
if alerts:
    theme.table(pd.DataFrame(alerts))
else:
    theme.empty_state(
        "🔔",
        "No alerts raised",
        "Detectors fire on credential stuffing, brute-force thresholds and "
        "multi-service probing. None has triggered — consistent with scanner "
        "traffic that connects without attempting a login.",
    )

if auto_refresh:
    time.sleep(15)
    st.rerun()
