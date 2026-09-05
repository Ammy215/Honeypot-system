"""
Attacker Intel — per-IP enrichment profiles.

Enrichment values (country, ISP, ASN) come from ip-api.com, AbuseIPDB and
AlienVault OTX, not from attacker input. Captured credentials are rendered
exclusively via st.dataframe, which treats cell contents as inert text.
"""

import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard import theme
from dashboard.async_bridge import run as bridge_run
from dashboard.login import require_auth
from database.db_async import db

st.set_page_config(page_title="HoneyShield — Attacker Intel", page_icon="🌍", layout="wide")
require_auth("🌍", "Attacker Intel")

theme.page_header(
    "🌍",
    "Attacker Intelligence",
    "Every captured source IP, enriched with geolocation, reputation and threat-feed "
    "data, then scored across 14 weighted factors.",
    eyebrow="Profiles",
)

search = st.text_input("Filter by IP", placeholder="substring match, e.g. 35.227")
attackers = bridge_run(db.list_attackers(limit=200, search_ip=search or None))

if not attackers:
    if search:
        theme.empty_state("🔍", "No matching attackers",
                          f"Nothing captured so far matches that filter. Clear it to see all profiles.")
    else:
        theme.empty_state(
            "🌍",
            "No attackers profiled yet",
            "Profiles are created the moment a connection is captured. Until then "
            "there is nothing to enrich or score.",
        )
    st.stop()

scored = [a for a in attackers if (a.get("threat_score") or 0) > 0]
flagged = [a for a in attackers if (a.get("otx_pulse_count") or 0) > 0
           or (a.get("abuseipdb_score") or 0) > 0]
theme.kpis([
    {"label": "Profiles", "value": len(attackers), "note": "distinct source IPs"},
    {"label": "Scored", "value": len(scored), "note": "threat score above zero", "tone": "#4A9EFF"},
    {"label": "Feed-flagged", "value": len(flagged),
     "note": "known to OTX or AbuseIPDB",
     "tone": theme.SEVERITY["MEDIUM"] if flagged else theme.MUTED},
    {"label": "Countries", "value": len({a.get("country") for a in attackers if a.get("country")}),
     "note": "distinct origins", "tone": theme.MUTED},
])

theme.section("Leaderboard", "Ranked by threat score. Click a column header to re-sort.")
df = pd.DataFrame(attackers)
cols = [c for c in ("ip_address", "country", "isp", "threat_score", "verdict",
                    "abuseipdb_score", "otx_pulse_count", "total_connections", "last_seen")
        if c in df.columns]
st.dataframe(df[cols], width="stretch", height=300, hide_index=True)

# ── Profile drill-down ────────────────────────────────────────────────────
theme.section("Profile", "Full enrichment record and captured credential history for one IP.")

selected_ip = st.selectbox("Select an IP", [a["ip_address"] for a in attackers])
attacker = next(a for a in attackers if a["ip_address"] == selected_ip)

verdict = attacker.get("verdict") or "UNSCORED"
theme.kpis([
    {"label": "Threat score", "value": f"{attacker.get('threat_score', 0)}/100",
     "note": verdict, "tone": theme.severity_tone(verdict)},
    {"label": "AbuseIPDB", "note": "abuse confidence", "tone": "#4A9EFF",
     "value": attacker["abuseipdb_score"] if attacker.get("abuseipdb_score") is not None else "—"},
    {"label": "OTX pulses", "value": attacker.get("otx_pulse_count") or 0,
     "note": "threat-feed mentions",
     "tone": theme.SEVERITY["MEDIUM"] if attacker.get("otx_pulse_count") else theme.MUTED},
    {"label": "Connections", "value": attacker.get("total_connections") or 0,
     "note": "sessions from this IP", "tone": theme.MUTED},
])

left, right = st.columns([1, 1])

with left:
    st.markdown("##### Origin")
    origin = {
        "Country": attacker.get("country") or "unknown",
        "City": attacker.get("city") or "unknown",
        "ISP": attacker.get("isp") or "unknown",
        "ASN": attacker.get("asn") or "unknown",
        "First seen": attacker.get("first_seen"),
        "Last seen": attacker.get("last_seen"),
    }
    st.dataframe(
        pd.DataFrame({"Field": list(origin), "Value": [str(v) for v in origin.values()]}),
        width="stretch", hide_index=True,
    )

with right:
    st.markdown("##### Reputation")
    score = attacker.get("abuseipdb_score")
    if score is not None:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            number={"font": {"color": theme.TEXT, "size": 34}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": theme.MUTED},
                "bar": {"color": theme.severity_tone(
                    "CRITICAL" if score >= 75 else "MEDIUM" if score >= 25 else "LOW")},
                "bgcolor": theme.SURFACE_2,
                "borderwidth": 1,
                "bordercolor": theme.BORDER,
                "steps": [
                    {"range": [0, 25], "color": "rgba(61,214,140,.12)"},
                    {"range": [25, 75], "color": "rgba(245,165,36,.12)"},
                    {"range": [75, 100], "color": "rgba(240,66,107,.14)"},
                ],
            },
        ))
        st.plotly_chart(theme.style_chart(fig, height=260), width="stretch")
        st.caption("AbuseIPDB abuse-confidence score. 0 means no community reports — "
                   "common for freshly rented cloud hosts.")
    else:
        theme.empty_state("📊", "Not checked", "No AbuseIPDB lookup has run for this IP yet.")

theme.section("Captured credentials",
              "Usernames and passwords submitted to the honeypot by this IP, exactly as "
              "received. Rendered as inert text — never interpreted as markup.")

login_attempts = bridge_run(db.list_login_attempts_for_ip(selected_ip, limit=50))
if login_attempts:
    st.dataframe(pd.DataFrame(login_attempts), width="stretch", hide_index=True)
else:
    theme.empty_state(
        "🔑",
        "No credentials submitted",
        "This IP connected but never attempted a login. That pattern is typical of "
        "reconnaissance scanners fingerprinting a host rather than trying to break "
        "into it.",
    )
