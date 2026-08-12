"""
Threat Hunting — credential/IP search, multi-service attackers, campaign preview.

SECURITY: search results render attacker-supplied username/password
values pulled straight from login_attempts. Rendered exclusively via
st.dataframe, which treats cell contents as plain text — never markdown,
never unsafe_allow_html — per HONEYSHIELD_PROJECT.md section 6 point 3.

Phase 5 wires this page to the new correlation engine
(honeypot/detectors/async_detection.py's multi-service check and
honeypot/detectors/async_correlation.py's ASN campaign grouping) — the
full campaign drill-down lives on the dedicated Campaigns page.

IOC list matching still isn't built (no detector backs it) — this page's
"pattern search" is the credential/IP substring search below, not IOC
list membership.
"""

import asyncio
import sys
from pathlib import Path

import streamlit as st
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard.login import check_authentication, show_login_page, show_user_info
from database.db_async import db
from honeypot.detectors.async_correlation import detect_asn_campaigns

st.set_page_config(page_title="Threat Hunting", page_icon="🔍", layout="wide")

if not check_authentication():
    show_login_page()
    st.stop()

show_user_info()

st.title("🔍 Threat Hunting")
st.caption("No IOC list is built yet — this searches captured credentials/IPs and surfaces correlation-engine results.")

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

st.markdown("---")
st.subheader("Multi-Service Attackers (Correlation Engine)")
st.caption("IPs that hit 2+ honeypot services within a short window — classic recon/scanning behavior.")

all_alerts = asyncio.run(db.list_alerts(limit=500))
multi_service_alerts = [a for a in all_alerts if a["alert_type"] == "multi_service"]
if multi_service_alerts:
    rows = []
    for a in multi_service_alerts:
        rows.append({"ip_address": a["ip_address"], "created_at": a["created_at"], "evidence": a["evidence"]})
    st.dataframe(pd.DataFrame(rows), width='stretch')
else:
    st.info("No multi-service attacks detected yet.")

st.markdown("---")
st.subheader("ASN Campaigns (preview)")
campaigns = asyncio.run(detect_asn_campaigns())
if campaigns:
    st.dataframe(pd.DataFrame(campaigns)[["asn", "attacker_count", "campaign_start", "campaign_end", "severity"]],
                 width='stretch')
    st.caption("Full member breakdown is on the Campaigns page.")
else:
    st.info("No ASN campaigns detected yet (needs 3+ IPs from the same ASN active within the campaign window).")
