"""
HoneyShield v2 dashboard — main entry point.

Reads from the v2 async database (database/db_async.py) via a small
asyncio.run() bridge, since Streamlit pages are plain synchronous scripts.
Bound to 127.0.0.1 only — see .streamlit/config.toml.
"""

import asyncio
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent))

from dashboard.login import check_authentication, show_login_page, show_user_info
from database.db_async import db

st.set_page_config(
    page_title="HoneyShield Intelligence Platform",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="expanded",
)

if not check_authentication():
    show_login_page()
    st.stop()

st.title("🍯 HoneyShield Intelligence Platform")

with st.sidebar:
    st.title("Navigation")
    show_user_info()
    st.markdown("---")
    st.markdown(
        "### Dashboard Pages\n"
        "- 🔴 Live Feed\n"
        "- 🌍 Attacker Intel\n"
        "- 📈 Analytics\n"
        "- 🚨 Alerts\n"
        "- 🔍 Threat Hunting\n"
        "- 🤖 AI Analysis\n"
    )
    st.markdown("---")
    st.caption("HoneyShield v2 — bound to 127.0.0.1")

summary = asyncio.run(db.summary_counts())

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Attackers", summary["total_attackers"])
col2.metric("Total Connections", summary["total_connections"])
col3.metric("Active Alerts", summary["active_alerts"])
col4.metric("Critical Threats", summary["critical_attackers"])

st.markdown("---")
st.info("Select a page from the sidebar to explore live feed, attacker profiles, analytics, alerts, and threat hunting.")
