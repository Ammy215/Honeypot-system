"""
Alerts — triage queue for detector output.

`evidence` is detector-generated JSON, but may embed attacker-supplied values
(usernames tried, paths probed), so it is rendered via st.code / st.dataframe,
never as markdown.
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard import theme
from dashboard.async_bridge import run as bridge_run
from dashboard.login import require_auth
from database.db_async import db

st.set_page_config(page_title="HoneyShield — Alerts", page_icon="🚨", layout="wide")
require_auth("🚨", "Alerts")

theme.page_header(
    "",
    "Alerts",
    "Detections raised by the brute-force, credential-stuffing and correlation "
    "engines. Acknowledge an alert once you have triaged it.",
    eyebrow="Triage",
)

with st.sidebar:
    st.markdown("**Alert filters**")
    severity_filter = st.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    ack_filter = st.selectbox("Status", ["All", "Unacknowledged", "Acknowledged"])

severity = None if severity_filter == "All" else severity_filter
acknowledged = {"All": None, "Unacknowledged": False, "Acknowledged": True}[ack_filter]

alerts = bridge_run(db.list_alerts(limit=200, severity=severity, acknowledged=acknowledged))
all_alerts = bridge_run(db.list_alerts(limit=500))

counts = {level: sum(1 for a in all_alerts if a.get("severity") == level)
          for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
theme.kpis([
    {"label": lvl.title(), "value": counts[lvl], "note": "alerts",
     "tone": theme.SEVERITY[lvl] if counts[lvl] else theme.MUTED}
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
])

if not alerts:
    if all_alerts:
        theme.empty_state(
            "🎯", "No alerts match this filter",
            "There are alerts recorded, just none matching the current severity and "
            "status selection. Reset the filters in the sidebar.",
        )
    else:
        theme.empty_state(
            "🔔",
            "No alerts raised — and that is a real finding",
            "Detectors fire on brute-force thresholds, credential stuffing and "
            "multi-service probing. None has triggered, meaning every visitor so far "
            "connected without attempting a login. That is scanner behaviour, not an "
            "intrusion attempt.",
        )
    st.stop()

theme.section("Queue", f"{len(alerts)} alert(s) matching the current filter.", rule=False)

severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

for alert in alerts:
    tone = theme.severity_tone(alert.get("severity"))
    with st.container(border=True):
        head, action = st.columns([4, 1])
        with head:
            st.markdown(
                f"{severity_icon.get(alert['severity'], '⚪')} "
                f"**{alert['severity']}** · {alert['alert_type']}"
            )
            st.caption(f"{alert['ip_address']} — {alert['created_at']}")
            with st.expander("Evidence"):
                st.code(alert.get("evidence") or "{}", language="json")
        with action:
            if bool(alert.get("acknowledged")):
                st.success("Acknowledged")
            elif st.button("Acknowledge", key=f"ack_{alert['id']}", width="stretch"):
                bridge_run(db.acknowledge_alert(alert["id"]))
                st.rerun()

theme.section("Table view", "The same alerts, sortable and exportable.")
theme.table(pd.DataFrame(alerts))
