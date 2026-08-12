"""
AI Analysis — placeholder.

The AI analyst (direct OpenAI SDK call, per HONEYSHIELD_PROJECT.md section
10 phase 6) hasn't been built yet. This page is honest about that rather
than faking report generation — it shows the (currently empty) ai_reports
table structure so the page has a real home once phase 6 lands.
"""

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard.login import check_authentication, show_login_page, show_user_info

st.set_page_config(page_title="AI Analysis", page_icon="🤖", layout="wide")

if not check_authentication():
    show_login_page()
    st.stop()

show_user_info()

st.title("🤖 AI Analysis")
st.info(
    "Not available yet — the AI analyst (direct OpenAI SDK call, no LangChain) is "
    "phase 6 of the rebuild. This page will generate threat reports from captured "
    "attacker sessions once that phase lands."
)
