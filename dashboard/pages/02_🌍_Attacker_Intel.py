"""
Attacker Intel — per-IP enrichment profiles.

Enrichment values (country, ISP, ASN) come from ip-api.com, AbuseIPDB and
AlienVault OTX, not from attacker input, so they are safe for theme.facts().
Captured credentials ARE attacker input and are rendered exclusively via
theme.table() / st.dataframe, which treats cell contents as inert text.
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

_ROOT = str(Path(__file__).parent.parent.parent)
if _ROOT not in sys.path:  # guarded: this line runs on every rerun
    sys.path.insert(0, _ROOT)

from dashboard import data, theme
from dashboard.login import require_auth

st.set_page_config(page_title="HoneyShield — Attacker Intel", page_icon="🌍", layout="wide")
require_auth("🌍", "Attacker Intel")

theme.page_header(
    "",
    "Attacker Intelligence",
    "Every captured source IP, enriched with geolocation, reputation and threat-feed "
    "data, then scored across 14 weighted factors.",
    eyebrow="Profiles",
)

# Filters live in the sidebar on every page in this console, so the main column
# stays content rather than controls.
with st.sidebar:
    st.markdown("**Profile filters**")
    search = st.text_input("Filter by IP", placeholder="e.g. 35.227",
                           label_visibility="collapsed")

attackers = data.attackers(search or None)

if not attackers:
    if search:
        theme.empty_state(
            "🔍", "No matching profiles",
            "Nothing captured so far matches that filter. Clear it in the sidebar "
            "to see every profile.",
        )
    else:
        theme.empty_state(
            "🌍",
            "No attackers profiled yet",
            "A profile is created the moment a connection is captured, then enriched "
            "with geolocation, AbuseIPDB reputation and AlienVault OTX pulse data. "
            "Until something arrives there is nothing to enrich or score.",
        )
    st.stop()

scored = [a for a in attackers if (a.get("threat_score") or 0) > 0]
flagged = [a for a in attackers if (a.get("otx_pulse_count") or 0) > 0
           or (a.get("abuseipdb_score") or 0) > 0]
countries = {a.get("country") for a in attackers if a.get("country")}

theme.kpis([
    {"label": "Profiles", "value": len(attackers), "note": "distinct source IPs"},
    {"label": "Scored", "value": len(scored), "note": "threat score above zero",
     "tone": "#4A9EFF"},
    {"label": "Feed-flagged", "value": len(flagged), "note": "known to OTX or AbuseIPDB",
     "tone": theme.SEVERITY["MEDIUM"] if flagged else theme.MUTED},
    {"label": "Origins", "value": len(countries), "note": "distinct countries",
     "tone": theme.MUTED},
])

# ── Leaderboard ───────────────────────────────────────────────────────────
theme.section("Leaderboard", "Ranked by weighted threat score. Any column header re-sorts.")

df = pd.DataFrame(attackers)
theme.table(df, columns=("ip_address", "country", "isp", "threat_score", "verdict",
                         "abuseipdb_score", "otx_pulse_count", "total_connections",
                         "last_seen"), height=300)

# ── Profile drill-down ────────────────────────────────────────────────────
theme.section("Profile", "The complete enrichment record for one source.")

selected_ip = st.selectbox("Select a source IP", [a["ip_address"] for a in attackers])
attacker = next(a for a in attackers if a["ip_address"] == selected_ip)
verdict = attacker.get("verdict") or "UNSCORED"

theme.kpis([
    {"label": "Threat score", "value": f"{attacker.get('threat_score', 0)}/100",
     "note": verdict, "tone": theme.severity_tone(verdict)},
    {"label": "Sessions", "value": attacker.get("total_connections") or 0,
     "note": "connections from this IP", "tone": "#4A9EFF"},
    {"label": "OTX pulses", "value": attacker.get("otx_pulse_count") or 0,
     "note": "threat-feed mentions",
     "tone": theme.SEVERITY["MEDIUM"] if attacker.get("otx_pulse_count") else theme.MUTED},
    {"label": "Origin", "value": attacker.get("country") or "unknown",
     "note": attacker.get("city") or "city unknown", "tone": theme.MUTED},
])

left, right = st.columns([1, 1], gap="medium")

with left:
    theme.subsection("Network origin")
    theme.facts({
        "Country": attacker.get("country"),
        "City": attacker.get("city"),
        "Network": attacker.get("isp"),
        "ASN": attacker.get("asn"),
        "First seen": attacker.get("first_seen"),
        "Last seen": attacker.get("last_seen"),
    })

with right:
    theme.subsection("Reputation")
    score = attacker.get("abuseipdb_score")
    theme.meter(
        "AbuseIPDB confidence", score, tone=theme.severity_tone(
            "CRITICAL" if (score or 0) >= 75 else "MEDIUM" if (score or 0) >= 25 else "LOW"),
        note=("No community reports. Normal for a freshly rented cloud host — absence "
              "of reputation is not evidence of good intent."
              if score == 0 else
              "Share of AbuseIPDB reporters who consider this address malicious."),
    )
    st.markdown("<div style='height:.6rem'></div>", unsafe_allow_html=True)
    theme.meter(
        "Weighted threat score", attacker.get("threat_score"),
        tone=theme.severity_tone(verdict),
        note=f"Verdict {verdict}. Combines 14 factors — reputation, feed matches, "
             f"behaviour and volume — not any single signal.",
    )

# ── Captured credentials ──────────────────────────────────────────────────
theme.section(
    "Captured credentials",
    "Usernames and passwords this source submitted, exactly as received. Rendered "
    "as inert text and never interpreted as markup.",
)

login_attempts = data.login_attempts_for(selected_ip)
if login_attempts:
    theme.table(pd.DataFrame(login_attempts),
                columns=("attempted_at", "username", "password", "service", "connection_id"))
    st.caption(f"{len(login_attempts)} credential attempt(s) from {selected_ip}.")
else:
    theme.empty_state(
        "🔑",
        "No credentials submitted",
        "This source connected but never attempted a login — reconnaissance "
        "fingerprinting the host rather than trying to break into it. The Live Feed "
        "shows which paths it requested.",
    )
