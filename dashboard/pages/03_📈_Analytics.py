"""
Analytics — timeline, top attackers, service/verdict breakdowns.

No attacker-supplied free text is rendered on this page (IPs, service
names, and verdict labels are all our own constrained values).
"""

import asyncio
import sys
from pathlib import Path

import streamlit as st
import pandas as pd
import plotly.express as px

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard.login import check_authentication, show_login_page, show_user_info
from database.db_async import db

st.set_page_config(page_title="Analytics", page_icon="📈", layout="wide")

if not check_authentication():
    show_login_page()
    st.stop()

show_user_info()

st.title("📈 Analytics")

hours = st.slider("Timeline window (hours)", 1, 168, 24)

st.subheader("Connections Over Time")
timeline = asyncio.run(db.connections_timeline(hours=hours))
if timeline:
    df = pd.DataFrame(timeline)
    fig = px.bar(df, x="bucket", y="cnt", labels={"bucket": "Time", "cnt": "Connections"})
    st.plotly_chart(fig, width='stretch')
else:
    st.info("No connection data in this window yet.")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Connections by Service")
    services = asyncio.run(db.service_breakdown())
    if services:
        df = pd.DataFrame(services)
        fig = px.pie(df, names="service", values="cnt")
        st.plotly_chart(fig, width='stretch')
    else:
        st.info("No connections yet.")

with col2:
    st.subheader("Attackers by Verdict")
    verdicts = asyncio.run(db.verdict_breakdown())
    if verdicts:
        df = pd.DataFrame(verdicts)
        color_map = {"LOW": "green", "MEDIUM": "gold", "HIGH": "orange", "CRITICAL": "red"}
        fig = px.bar(df, x="verdict", y="cnt", color="verdict", color_discrete_map=color_map)
        st.plotly_chart(fig, width='stretch')
    else:
        st.info("No scored attackers yet.")

st.subheader("Top Attackers by Connection Volume")
attackers = asyncio.run(db.list_attackers(limit=10))
if attackers:
    df = pd.DataFrame(attackers)
    df = df.sort_values("total_connections", ascending=False)
    fig = px.bar(df, x="ip_address", y="total_connections", hover_data=["country", "verdict"])
    st.plotly_chart(fig, width='stretch')
else:
    st.info("No attackers yet.")
