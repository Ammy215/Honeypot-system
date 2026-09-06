"""
Campaigns — coordinated activity grouped by ASN.

All values are computed by the correlation engine or come from enrichment
lookups; no attacker-supplied text is rendered as markup.
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import config
from dashboard import theme
from dashboard.async_bridge import run as bridge_run
from dashboard.login import require_auth
from honeypot.detectors.async_correlation import detect_asn_campaigns, get_campaign_members

st.set_page_config(page_title="HoneyShield — Campaigns", page_icon="🎪", layout="wide")
require_auth("🎪", "Campaigns")

theme.page_header(
    "",
    "Attack Campaigns",
    "Distinct IPs from one network acting inside a shared window. Individually they "
    "look like unrelated visitors; grouped by ASN they resolve into a single "
    "operation running across rented infrastructure.",
    eyebrow="Correlation",
)

with st.sidebar:
    st.markdown("**Campaign parameters**")
    window_hours = st.slider("Time window (hours)", 1, 72,
                             config.CAMPAIGN_WINDOW_SECONDS // 3600)
    min_attackers = st.slider("Minimum attackers per ASN", 2, 10,
                              config.CAMPAIGN_MIN_ATTACKERS)

campaigns = bridge_run(
    detect_asn_campaigns(window_seconds=window_hours * 3600, min_attackers=min_attackers)
)

if not campaigns:
    theme.empty_state(
        "🎪",
        "No campaigns detected",
        f"Nothing meets the current threshold of {min_attackers}+ distinct IPs from "
        f"one ASN active within {window_hours}h. Loosen the parameters in the sidebar "
        f"to widen the search, or wait for more traffic.",
    )
    st.stop()

total_ips = sum(c["attacker_count"] for c in campaigns)
total_conns = sum(c["total_connections"] for c in campaigns)
worst = max(campaigns, key=lambda c: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(c["severity"])
            if c["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else 0)

theme.kpis([
    {"label": "Campaigns", "value": len(campaigns), "note": "ASN groups"},
    {"label": "IPs involved", "value": total_ips, "note": "across all campaigns", "tone": "#4A9EFF"},
    {"label": "Connections", "value": total_conns, "note": "attributable sessions",
     "tone": theme.MUTED},
    {"label": "Highest severity", "value": worst["severity"], "note": "any campaign",
     "tone": theme.severity_tone(worst["severity"])},
])

theme.section("Detected campaigns", "One row per network showing coordinated activity.")
theme.table(pd.DataFrame(campaigns)[["asn", "attacker_count", "total_connections",
                             "campaign_start", "campaign_end", "severity"]])

# ── Detail ────────────────────────────────────────────────────────────────
theme.section("Campaign detail", "Member IPs and their individual enrichment.")

selected_asn = st.selectbox("Select an ASN to inspect", [c["asn"] for c in campaigns])
campaign = next(c for c in campaigns if c["asn"] == selected_asn)

theme.kpis([
    {"label": "Attackers", "value": campaign["attacker_count"], "note": "distinct IPs"},
    {"label": "Connections", "value": campaign["total_connections"], "note": "total sessions",
     "tone": "#4A9EFF"},
    {"label": "Severity", "value": campaign["severity"], "note": "campaign rating",
     "tone": theme.severity_tone(campaign["severity"])},
    {"label": "Window", "note": "first → last activity", "tone": theme.MUTED,
     "value": f"{campaign['campaign_start']:%H:%M} → {campaign['campaign_end']:%H:%M}"
     if hasattr(campaign["campaign_start"], "strftime") else "—"},
])

st.caption(f"Active {campaign['campaign_start']} → {campaign['campaign_end']}")

members = bridge_run(get_campaign_members(campaign["ip_addresses"]))
if members:
    mdf = pd.DataFrame(members)
    cols = [c for c in ("ip_address", "country", "city", "isp", "threat_score",
                        "verdict", "total_connections", "last_seen") if c in mdf.columns]
    theme.table(mdf[cols])
else:
    theme.empty_state("👥", "No member detail available",
                      "The campaign was detected but member enrichment could not be loaded.")
