"""
Threat Hunting — search captured usernames/passwords and attacker IPs.

SECURITY: search results render attacker-supplied username/password
values pulled straight from login_attempts. Rendered exclusively via
st.dataframe, which treats cell contents as plain text — never markdown,
never unsafe_allow_html — per HONEYSHIELD_PROJECT.md section 6 point 3.

IOC list matching and campaign/correlation detection are not built yet
(later phases — ioc_matches stays empty here on purpose, and campaign
detection is phase 5's correlation engine). This page only searches data
phases 1-3 actually capture.
"""

import asyncio
import sys
from pathlib import Path

import streamlit as st
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard.login import check_authentication, show_login_page, show_user_info
from database.db_async import db

st.set_page_config(page_title="Threat Hunting", page_icon="🔍", layout="wide")

if not check_authentication():
    show_login_page()
    st.stop()

show_user_info()

st.title("🔍 Threat Hunting")
st.caption("IOC list matching and campaign correlation land in a later phase — this searches captured credentials and IPs only.")

st.subheader("Search Captured Credentials")
pattern = st.text_input("Username or password contains...", placeholder="e.g. admin")

if pattern:
    results = asyncio.run(db.search_login_attempts(pattern, limit=200))
    if results:
        st.dataframe(pd.DataFrame(results), width='stretch', height=400)
        st.caption(f"{len(results)} matching login attempt(s). Values shown exactly as captured — never executed or reinterpreted.")
    else:
        st.info("No matches.")
else:
    st.info("Enter a search term above.")

st.markdown("---")
st.subheader("Search Attacker IPs")
ip_pattern = st.text_input("IP contains...", placeholder="e.g. 101.96")
if ip_pattern:
    attackers = asyncio.run(db.list_attackers(limit=200, search_ip=ip_pattern))
    if attackers:
        st.dataframe(pd.DataFrame(attackers), width='stretch')
    else:
        st.info("No matching attackers.")
