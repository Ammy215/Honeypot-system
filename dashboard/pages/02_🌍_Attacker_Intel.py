"""
Attacker Intelligence — IP profiles, leaderboard, reputation gauge.

SECURITY: the "recent login attempts" table below renders attacker-
supplied username/password values. These are displayed exclusively via
st.dataframe (never st.markdown/unsafe_allow_html), which renders cell
contents as plain text and never interprets HTML or executes scripts —
per HONEYSHIELD_PROJECT.md section 6 point 3.
"""

import asyncio
import sys
from pathlib import Path

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard.login import check_authentication, show_login_page, show_user_info
from database.db_async import db

st.set_page_config(page_title="Attacker Intel", page_icon="🌍", layout="wide")

if not check_authentication():
    show_login_page()
    st.stop()

show_user_info()

st.title("🌍 Attacker Intelligence")

search = st.text_input("Search by IP (substring match)")
attackers = asyncio.run(db.list_attackers(limit=200, search_ip=search or None))

st.subheader("Leaderboard")
if attackers:
    df = pd.DataFrame(attackers)
    display_cols = [c for c in ["ip_address", "country", "isp", "threat_score", "verdict",
                                 "abuseipdb_score", "otx_pulse_count", "total_connections", "last_seen"]
                     if c in df.columns]
    st.dataframe(df[display_cols], width='stretch', height=350)
else:
    st.info("No attackers captured yet.")

st.markdown("---")
st.subheader("Attacker Profile")

ip_options = [a["ip_address"] for a in attackers]
selected_ip = st.selectbox("Select an IP for details", ip_options) if ip_options else None

if selected_ip:
    attacker = next(a for a in attackers if a["ip_address"] == selected_ip)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Threat Score", f"{attacker.get('threat_score', 0)}/100")
        st.metric("Verdict", attacker.get("verdict") or "UNKNOWN")
    with col2:
        st.metric("AbuseIPDB Score", attacker.get("abuseipdb_score") if attacker.get("abuseipdb_score") is not None else "—")
        st.metric("OTX Pulses", attacker.get("otx_pulse_count") or 0)
    with col3:
        st.metric("Country", attacker.get("country") or "Unknown")
        st.metric("Total Connections", attacker.get("total_connections") or 0)

    if attacker.get("abuseipdb_score") is not None:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=attacker["abuseipdb_score"],
            title={"text": "AbuseIPDB Confidence"},
            gauge={"axis": {"range": [0, 100]},
                   "bar": {"color": "darkred" if attacker["abuseipdb_score"] >= 75 else "orange"},
                   "steps": [{"range": [0, 25], "color": "lightgreen"},
                             {"range": [25, 75], "color": "yellow"},
                             {"range": [75, 100], "color": "lightcoral"}]},
        ))
        st.plotly_chart(fig, width='stretch')

    st.markdown(f"**ISP:** {attacker.get('isp') or 'Unknown'} &nbsp;|&nbsp; **ASN:** {attacker.get('asn') or 'Unknown'}")

    st.markdown("#### Recent Login Attempts")
    st.caption("Rendered via st.dataframe — attacker-supplied text is never interpreted as HTML/markdown.")
    login_attempts = asyncio.run(db.list_login_attempts_for_ip(selected_ip, limit=50))
    if login_attempts:
        st.dataframe(pd.DataFrame(login_attempts), width='stretch')
    else:
        st.info("No login attempts recorded for this IP.")
