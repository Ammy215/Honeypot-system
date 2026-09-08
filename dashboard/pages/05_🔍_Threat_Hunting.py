"""
Threat Hunting — credential/IP search, multi-service attackers, campaign preview.

SECURITY: this page renders attacker-supplied username/password values pulled
straight from login_attempts. They go exclusively through theme.table /
st.dataframe, which treat cell contents as plain text — never markdown, never a
raw-HTML sink — per HONEYSHIELD_PROJECT.md section 6 point 3.

Phase 5 wires this page to the correlation engine
(honeypot/detectors/async_detection.py's multi-service check and
honeypot/detectors/async_correlation.py's ASN campaign grouping) — the full
campaign drill-down lives on the dedicated Campaigns page.

IOC list matching still isn't built (no detector backs it) — this page's
"pattern search" is the credential/IP substring search below, not IOC list
membership.
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard import data, theme
from dashboard.login import require_auth

st.set_page_config(page_title="HoneyShield — Threat Hunting", page_icon="🔍", layout="wide")
require_auth("🔍", "Threat Hunting")

theme.page_header(
    "",
    "Threat Hunting",
    "Live Feed answers “what is happening?”. This page answers “has this specific "
    "thing ever happened?” — search everything captured so far, then pivot into the "
    "correlation engine's findings.",
    eyebrow="Investigate",
)

_d = data.hunting_context()
creds = _d["credentials"]
total_attempts = creds["total"]

# ── What is searchable ────────────────────────────────────────────────────
# The page used to open on three empty boxes with no indication of what the
# corpus contained — you cannot hunt through something whose shape you cannot
# see. These answer "is there anything here?" before any term is typed.
theme.kpis([
    {"label": "Credentials", "value": total_attempts, "note": "captured attempts",
     "tone": theme.ACCENT},
    {"label": "Usernames", "value": creds["unique_usernames"], "note": "distinct values",
     "tone": "#4A9EFF"},
    {"label": "Passwords", "value": creds["unique_passwords"], "note": "distinct values",
     "tone": "#A78BFA"},
    {"label": "Sources", "value": creds["unique_sources"], "note": "IPs that tried a login",
     "tone": theme.MUTED},
])

with st.expander("How to use this page"):
    st.markdown(
        """
**Search captured credentials** — every username and password submitted to the
honeypot is stored verbatim. Search it to answer questions like:

- *Is a password from a known breach being sprayed at me?* Search the password.
- *Is anyone targeting a real account name from my org?* Search the username.
- *What is being tried most?* The rankings below answer that with no search at all.

**Search attacker IPs** — substring matching, so `35.227` finds an entire
range. Useful for spotting whether one provider or subnet is responsible for
many apparently distinct sources.

**Multi-service attackers** — IPs that hit two or more honeypot services in a
short window. This is the strongest single signal separating a deliberate
actor from a single-port scanner. Currently only HTTP is deployed, so this
will stay empty by design until other services are exposed.

**ASN campaigns** — three or more IPs from the same network acting inside one
window. Catches distributed scanning from a single rented provider that would
look like unrelated visitors if you only ever looked at individual IPs.
"""
    )

# ── Most-tried credentials ────────────────────────────────────────────────
theme.section(
    "Most-tried credentials",
    "What attackers are actually guessing, ranked by attempt count. `sources` "
    "separates one persistent host from a distributed attempt at the same value.",
)

if total_attempts:
    left, right = st.columns(2, gap="medium")
    with left:
        theme.subsection("Usernames")
        theme.table(pd.DataFrame(creds["top_usernames"]),
                    columns=("value", "attempts", "sources"))
    with right:
        theme.subsection("Passwords")
        theme.table(pd.DataFrame(creds["top_passwords"]),
                    columns=("value", "attempts", "sources"))
else:
    theme.empty_state(
        "🔑",
        "No credentials captured yet — nothing to hunt through",
        "This becomes useful the moment something tries to log in. Every visitor so "
        "far connected and left without submitting a credential, which is "
        "reconnaissance rather than intrusion. The Live Feed shows what they probed "
        "for instead.",
    )

# ── Credential search ─────────────────────────────────────────────────────
theme.section(
    "Search captured credentials",
    "Substring match across usernames and passwords. Values are shown exactly as "
    "received and are never interpreted as markup.",
)

pattern = st.text_input("Username or password contains…",
                        placeholder="e.g. admin, root, 123456",
                        disabled=not total_attempts)

if pattern:
    results = data.credential_search(pattern)
    if results:
        theme.table(pd.DataFrame(results), height=380,
                    columns=("attempted_at", "ip_address", "username", "password", "service"))
        st.caption(f"{len(results)} of {total_attempts} captured attempt(s) match.")
    else:
        theme.empty_state(
            "🕳️", "No matches",
            f"No captured credential contains that string. {total_attempts} attempt(s) "
            "are searchable in total.")
elif total_attempts:
    st.caption(f"{total_attempts} attempt(s) searchable. Enter a term above.")

# ── IP search ─────────────────────────────────────────────────────────────
theme.section("Search attacker IPs",
              "Substring match — enter a partial address to sweep a whole range.")

ip_pattern = st.text_input("IP contains…", placeholder="e.g. 35.227")
if ip_pattern:
    attackers = data.attackers(ip_pattern)
    if attackers:
        theme.table(pd.DataFrame(attackers),
                    columns=("ip_address", "country", "isp", "asn", "threat_score",
                             "verdict", "total_connections", "last_seen"))
        st.caption(f"{len(attackers)} matching source(s).")
    else:
        theme.empty_state("🕳️", "No matching IPs",
                          "No captured source address contains that string.")

# ── Multi-service ─────────────────────────────────────────────────────────
theme.section(
    "Multi-service attackers",
    "IPs that hit two or more honeypot services within a short window — the "
    "clearest signal separating a deliberate actor from a single-port scanner.",
)

multi_service_alerts = [a for a in _d["alerts"] if a["alert_type"] == "multi_service"]
if multi_service_alerts:
    theme.table(pd.DataFrame(multi_service_alerts),
                columns=("created_at", "ip_address", "severity", "evidence"))
else:
    theme.empty_state(
        "🧭",
        "Empty by design on this deployment",
        "This detector needs two or more exposed services to correlate across. Only "
        "the HTTP honeypot is deployed — SSH, FTP and Telnet are built and tested "
        "but not exposed — so it cannot fire yet. A known scope decision, not a fault.",
    )

# ── Campaigns ─────────────────────────────────────────────────────────────
theme.section("ASN campaigns",
              "Three or more IPs from the same network active within one window.")

campaigns = _d["campaigns"]
if campaigns:
    theme.table(pd.DataFrame(campaigns),
                columns=("asn", "attacker_count", "total_connections",
                         "campaign_start", "campaign_end", "severity"))
    st.caption("Full member breakdown, with per-IP enrichment, is on the Campaigns page.")
else:
    theme.empty_state(
        "🎪",
        "No campaigns detected",
        "Needs three or more IPs from one ASN active inside the campaign window. "
        "Distributed scanning from a single cloud provider is the usual trigger.",
    )
