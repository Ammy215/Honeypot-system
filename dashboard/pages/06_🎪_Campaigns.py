"""
Campaigns — coordinated attacks grouped by ASN within a time window.

Restored in phase 5 now that honeypot/detectors/async_correlation.py
actually backs it with real data (it was dropped in phase 4 pending this
phase). Computed on demand — no persisted campaigns table exists in the
v2 schema (HONEYSHIELD_PROJECT.md section 4), so this is a live query,
not an alert type.
"""

import asyncio
import sys
from pathlib import Path

import streamlit as st
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard.login import check_authentication, show_login_page, show_user_info
from honeypot.detectors.async_correlation import detect_asn_campaigns, get_campaign_members
import config

st.set_page_config(page_title="Campaigns", page_icon="🎪", layout="wide")

if not check_authentication():
    show_login_page()
    st.stop()

show_user_info()

st.title("🎪 Campaigns")

col1, col2 = st.columns(2)
window_hours = col1.slider("Time window (hours)", 1, 72, config.CAMPAIGN_WINDOW_SECONDS // 3600)
min_attackers = col2.slider("Minimum attackers per ASN", 2, 10, config.CAMPAIGN_MIN_ATTACKERS)

campaigns = asyncio.run(detect_asn_campaigns(window_seconds=window_hours * 3600, min_attackers=min_attackers))

if not campaigns:
    st.info(
        f"No campaigns detected — needs {min_attackers}+ distinct IPs from the same ASN "
        f"active within the last {window_hours}h."
    )
else:
    st.subheader(f"{len(campaigns)} Campaign(s) Detected")
    summary_df = pd.DataFrame(campaigns)[
        ["asn", "attacker_count", "total_connections", "campaign_start", "campaign_end", "severity"]
    ]
    st.dataframe(summary_df, width='stretch')

    st.markdown("---")
    st.subheader("Campaign Detail")
    asn_options = [c["asn"] for c in campaigns]
    selected_asn = st.selectbox("Select an ASN to inspect", asn_options)

    if selected_asn:
        campaign = next(c for c in campaigns if c["asn"] == selected_asn)

        m1, m2, m3 = st.columns(3)
        m1.metric("Attackers", campaign["attacker_count"])
        m2.metric("Total Connections", campaign["total_connections"])
        m3.metric("Severity", campaign["severity"])

        st.caption(f"Active {campaign['campaign_start']} → {campaign['campaign_end']}")

        members = asyncio.run(get_campaign_members(campaign["ip_addresses"]))
        if members:
            st.dataframe(pd.DataFrame(members), width='stretch')
