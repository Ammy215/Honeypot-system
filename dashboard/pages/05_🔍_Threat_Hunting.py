"""
Threat Hunting — credential/IP search, multi-service attackers, campaign preview.

SECURITY: search results render attacker-supplied username/password values
pulled straight from login_attempts. Rendered exclusively via st.dataframe,
which treats cell contents as plain text — never markdown, never
unsafe_allow_html — per HONEYSHIELD_PROJECT.md section 6 point 3.

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

from dashboard import theme
from dashboard import data
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

# Why this page exists, stated up front. Without it the page reads as three
# empty search boxes, which is exactly the complaint it should pre-empt.
with st.expander("How to use this page", expanded=False):
    st.markdown(
        """
**Search captured credentials** — every username and password submitted to the
honeypot is stored verbatim. Search it to answer questions like:

- *Is a password from a known breach being sprayed at me?* Search the password.
- *Is anyone targeting a real account name from my org?* Search the username.
- *What is the most common credential pair?* Leave the box empty and browse.

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

# ── Credential search ─────────────────────────────────────────────────────
theme.section(
    "Search captured credentials",
    "Substring match across captured usernames and passwords. Values are shown "
    "exactly as received and are never interpreted as markup.",
)

# An empty substring matches every row, which is how we report the size of the
# searchable corpus — "no matches" and "nothing to search" are different
# answers and the empty states below distinguish them.
_d = data.hunting_context()
total_attempts = _d["total_attempts"]
pattern = st.text_input("Username or password contains…", placeholder="e.g. admin, root, 123456")

if pattern:
    results = data.credential_search(pattern)
    if results:
        theme.table(pd.DataFrame(results), height=380)
        st.caption(f"{len(results)} matching login attempt(s).")
    else:
        theme.empty_state("🕳️", "No matches",
                          f"No captured credential contains that string. "
                          f"{total_attempts} login attempt(s) have been captured in total.")
elif total_attempts == 0:
    theme.empty_state(
        "🔑",
        "No credentials captured yet — nothing to hunt through",
        "This search becomes useful the moment something tries to log in. So far "
        "every visitor has connected and left without submitting a credential, "
        "which is reconnaissance rather than intrusion.",
    )
else:
    st.caption(f"{total_attempts} login attempt(s) available to search. Enter a term above.")

# ── IP search ─────────────────────────────────────────────────────────────
theme.section("Search attacker IPs",
              "Substring match — enter a partial address to sweep a whole range.")

ip_pattern = st.text_input("IP contains…", placeholder="e.g. 35.227")
if ip_pattern:
    attackers = data.attackers(ip_pattern)
    if attackers:
        adf = pd.DataFrame(attackers)
        cols = [c for c in ("ip_address", "country", "isp", "asn", "threat_score",
                            "verdict", "total_connections", "last_seen") if c in adf.columns]
        theme.table(adf[cols])
        st.caption(f"{len(attackers)} matching attacker(s).")
    else:
        theme.empty_state("🕳️", "No matching IPs", "No captured source address contains that string.")

# ── Multi-service ─────────────────────────────────────────────────────────
theme.section(
    "Multi-service attackers",
    "IPs that hit two or more honeypot services within a short window — the "
    "clearest signal separating a deliberate actor from a single-port scanner.",
)

all_alerts = _d["alerts"]
multi_service_alerts = [a for a in all_alerts if a["alert_type"] == "multi_service"]
if multi_service_alerts:
    theme.table(pd.DataFrame([{"ip_address": a["ip_address"], "created_at": a["created_at"],
                       "evidence": a["evidence"]} for a in multi_service_alerts]))
else:
    theme.empty_state(
        "🧭",
        "Empty by design on this deployment",
        "This detector needs two or more exposed services to correlate across. Only "
        "the HTTP honeypot is deployed on the current platform — SSH, FTP and Telnet "
        "are built and tested but not exposed — so it cannot fire yet. This is a "
        "known scope decision, not a fault.",
    )

# ── Campaigns ─────────────────────────────────────────────────────────────
theme.section("ASN campaigns",
              "Three or more IPs from the same network active within one window.")

campaigns = _d["campaigns"]
if campaigns:
    theme.table(pd.DataFrame(campaigns)[["asn", "attacker_count", "campaign_start",
                                 "campaign_end", "severity"]])
    st.caption("Full member breakdown, with per-IP enrichment, is on the Campaigns page.")
else:
    theme.empty_state(
        "🎪",
        "No campaigns detected",
        "Needs three or more IPs from one ASN active inside the campaign window. "
        "Distributed scanning from a single cloud provider is the usual trigger.",
    )
