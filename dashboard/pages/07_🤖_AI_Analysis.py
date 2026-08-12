"""
AI Analysis — generates a threat report for a selected attacker via the
direct Google Gemini SDK call in honeypot/ai/async_analyst.py (phase 6).

SECURITY: the report text is model-generated prose built from attacker-
supplied data (usernames/passwords may be quoted back verbatim by the
model). Rendered via st.markdown WITHOUT unsafe_allow_html — proven safe
in phase 4's testing (Streamlit escapes raw HTML tags by default even in
markdown) — so a quoted XSS-style payload still can't execute, only
display as text.
"""

import asyncio
import sys
from pathlib import Path

import streamlit as st
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard.login import check_authentication, show_login_page, show_user_info
from database.db_async import db
from honeypot.ai.async_analyst import generate_attacker_report, is_available

st.set_page_config(page_title="AI Analysis", page_icon="🤖", layout="wide")

if not check_authentication():
    show_login_page()
    st.stop()

show_user_info()

st.title("🤖 AI Analysis")

if not is_available():
    st.warning(
        "AI analyst unavailable — GEMINI_API_KEY is not set in .env. "
        "Reports will still be requestable below, but will return a clear "
        "error instead of crashing."
    )

attackers = asyncio.run(db.list_attackers(limit=200))
ip_options = [a["ip_address"] for a in attackers]

if not ip_options:
    st.info("No attackers captured yet — nothing to report on.")
    st.stop()

selected_ip = st.selectbox("Select an attacker IP", ip_options)

if st.button("Generate Threat Report", type="primary"):
    with st.spinner(f"Generating report for {selected_ip}..."):
        result = asyncio.run(generate_attacker_report(selected_ip))

    if result["error"]:
        st.error(result["report_text"])
    else:
        st.success(f"Report generated ({result.get('model', 'unknown model')})")
        st.markdown(result["report_text"])

st.markdown("---")
st.subheader(f"Report History — {selected_ip}")
reports = asyncio.run(db.list_ai_reports_for_ip(selected_ip, limit=10))
if reports:
    for r in reports:
        with st.expander(f"Report from {r['generated_at']}"):
            st.markdown(r["report_text"])
else:
    st.info("No reports generated yet for this IP.")
