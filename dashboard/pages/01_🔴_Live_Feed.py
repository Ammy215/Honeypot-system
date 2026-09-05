"""
Live Feed — real-time connection stream.

Nothing on this page renders attacker-controlled text: ip_address is a
validated address, service/port are our own literals, country comes from
ip-api.com (not attacker input). Still rendered via st.dataframe, which
never interprets cell contents as HTML/markdown.
"""

import sys
import time
from pathlib import Path

import streamlit as st
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard.login import check_authentication, show_login_page, show_user_info
from dashboard.async_bridge import run as bridge_run
from database.db_async import db

st.set_page_config(page_title="Live Feed", page_icon="🔴", layout="wide")

if not check_authentication():
    show_login_page()
    st.stop()

show_user_info()

st.title("🔴 Live Attack Feed")

auto_refresh = st.sidebar.checkbox("Auto-refresh (15s)", value=False)
service_filter = st.sidebar.selectbox("Service", ["All", "ssh", "ftp", "telnet", "http"])

summary = bridge_run(db.summary_counts())
col1, col2, col3, col4 = st.columns(4)
col1.metric("Connections", summary["total_connections"])
col2.metric("Attackers", summary["total_attackers"])
col3.metric("Active Alerts", summary["active_alerts"])
col4.metric("Critical", summary["critical_attackers"])

st.markdown("---")
st.subheader("Recent Connections")

service = None if service_filter == "All" else service_filter
connections = bridge_run(db.list_recent_connections(limit=100, service=service))

if connections:
    df = pd.DataFrame(connections)
    st.dataframe(df, width='stretch', height=500)
    st.caption(f"Showing {len(df)} most recent connections")
else:
    st.info("No connections yet.")

st.markdown("---")
st.subheader("Filtered Traffic")
st.caption(
    "Connections dropped by IGNORE_UNFORWARDED_CONNECTIONS — no proxy header, "
    "in practice the platform's own health checks. Kept out of the capture "
    "tables above so they can't pollute detection or scoring. Shown here so an "
    "empty feed reads as 'genuinely quiet' rather than 'silently filtered'."
)

filtered = bridge_run(db.filtered_connection_stats())

fcol1, fcol2, fcol3, fcol4 = st.columns(4)
fcol1.metric("Filtered (total)", filtered["total"])
fcol2.metric("Last hour", filtered["last_hour"])
fcol3.metric("Last 24h", filtered["last_24h"])
fcol4.metric(
    "Most recent",
    filtered["latest"].strftime("%H:%M:%S") if filtered["latest"] else "—",
)

if filtered["recent"]:
    with st.expander(f"Breakdown by source ({len(filtered['recent'])} shown)"):
        # st.dataframe never interprets cell contents as HTML/markdown, which
        # matters here: `path` and `method` come off the wire from whoever
        # connected, so they are attacker-controlled text.
        st.dataframe(pd.DataFrame(filtered["recent"]), width='stretch')
elif filtered["total"] == 0:
    st.info(
        "Nothing filtered yet. If this stays at zero while the service is up, "
        "the health check isn't reaching the honeypot at all — worth checking."
    )

st.markdown("---")
st.subheader("Recent Alerts")

alerts = bridge_run(db.list_alerts(limit=10))
if alerts:
    st.dataframe(pd.DataFrame(alerts), width='stretch')
else:
    st.info("No alerts yet.")

if auto_refresh:
    time.sleep(15)
    st.rerun()
