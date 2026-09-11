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

_ROOT = str(Path(__file__).parent.parent.parent)
if _ROOT not in sys.path:  # guarded: this line runs on every rerun
    sys.path.insert(0, _ROOT)

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

# ── Filtered noise ────────────────────────────────────────────────────────
# Deliberately NOT a liveness signal. It was treated as one once — the platform's
# health checker hit a decoy path on a fixed cadence, so a recent row here
# implied a live listener. Repointing that checker at the no-op health endpoint
# froze this table, and the inference silently became false. Sensor health on
# the Overview page now probes the honeypot directly instead; this panel only
# accounts for what was excluded from capture.
theme.section(
    "Filtered noise",
    "Connections dropped by IGNORE_UNFORWARDED_CONNECTIONS — they arrived with no "
    "proxy header, meaning they bypassed the load balancer. Recorded separately so "
    "they cannot pollute detection or scoring, and shown here so a quiet feed reads "
    "as 'genuinely quiet' rather than 'silently discarded'. This is an accounting "
    "of what was excluded, not a heartbeat — Overview checks liveness directly.",
)

filtered = _d["filtered"]
theme.kpis([
    {"label": "Filtered total", "value": filtered["total"], "note": "since deployment",
     "tone": theme.MUTED},
    {"label": "Last hour", "value": filtered["last_hour"], "note": "excluded", "tone": theme.MUTED},
    {"label": "Last 24h", "value": filtered["last_24h"], "note": "excluded", "tone": theme.MUTED},
    {"label": "Most recent", "note": "last exclusion", "tone": theme.MUTED,
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
        "Nothing filtered",
        "No connection has arrived without a proxy header. Zero is a perfectly "
        "healthy reading — it means nothing is bypassing the load balancer, and it "
        "says nothing either way about whether the honeypot is up. Sensor health on "
        "the Overview page answers that.",
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
