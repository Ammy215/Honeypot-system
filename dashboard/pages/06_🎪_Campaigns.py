"""
Campaigns — coordinated activity grouped by ASN.

All values are computed by the correlation engine or come from enrichment
lookups; no attacker-supplied text is rendered as markup.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

_ROOT = str(Path(__file__).parent.parent.parent)
if _ROOT not in sys.path:  # guarded: this line runs on every rerun
    sys.path.insert(0, _ROOT)

import config
from dashboard import theme
from dashboard.login import require_auth

st.set_page_config(page_title="HoneyShield — Campaigns", page_icon="🎪", layout="wide")
require_auth("🎪", "Campaigns")

# Heavy imports sit below the auth gate on purpose — see dashboard/login.py.
import pandas as pd  # noqa: E402
from dashboard import data  # noqa: E402

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

campaigns = data.campaigns(window_hours * 3600, min_attackers)


def _as_dt(ts):
    """
    Coerce a timestamp to an aware datetime, or None.

    The backends disagree — asyncpg returns a datetime, sqlite3 a string — so
    anything that formats a timestamp has to handle both or it silently works
    on one and fails on the other.
    """
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _span(start, end) -> str:
    """Human duration between two campaign timestamps."""
    a, b = _as_dt(start), _as_dt(end)
    if not a or not b:
        return "—"
    mins = max(0, int((b - a).total_seconds() // 60))
    if mins < 60:
        return f"{mins}m"
    if mins < 2880:
        return f"{mins // 60}h {mins % 60}m"
    return f"{mins // 1440}d"


if not campaigns:
    theme.empty_state(
        "🎪",
        "No campaigns at this threshold",
        f"Nothing meets {min_attackers}+ distinct IPs from one ASN active within "
        f"{window_hours}h. Loosen either slider to widen the search — dropping the "
        f"minimum to 2 is the usual way to see whether anything is forming.",
    )
    st.stop()

total_ips = sum(c["attacker_count"] for c in campaigns)
total_conns = sum(c["total_connections"] for c in campaigns)
ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
worst = max(campaigns,
            key=lambda c: ORDER.index(c["severity"]) if c["severity"] in ORDER else 0)

theme.kpis([
    {"label": "Campaigns", "value": len(campaigns), "note": "ASN groups", "tone": theme.ACCENT},
    {"label": "IPs involved", "value": total_ips, "note": "across all campaigns",
     "tone": "#4A9EFF"},
    {"label": "Sessions", "value": total_conns, "note": "attributable to campaigns",
     "tone": theme.MUTED},
    {"label": "Highest severity", "value": worst["severity"], "note": "any campaign",
     "tone": theme.severity_tone(worst["severity"]), "dot": True},
])

# ── Detected campaigns ────────────────────────────────────────────────────
theme.section(
    "Detected campaigns",
    "One row per network. Severity here is the campaign's spread — HIGH at five or "
    "more distinct IPs — not the individual threat scores of its members.",
)
theme.table(pd.DataFrame(campaigns),
            columns=("asn", "attacker_count", "total_connections",
                     "campaign_start", "campaign_end", "severity"))

# ── Detail ────────────────────────────────────────────────────────────────
theme.section("Campaign detail", "Member IPs and their individual enrichment.")

selected_asn = st.selectbox("Select an ASN to inspect", [c["asn"] for c in campaigns])
campaign = next(c for c in campaigns if c["asn"] == selected_asn)

theme.badge(campaign["severity"], detail=f"{campaign['asn']} · "
            f"{campaign['attacker_count']} IPs · {campaign['total_connections']} sessions")

left, right = st.columns([1, 1], gap="medium")

with left:
    theme.subsection("Campaign window")
    theme.facts({
        "Network": campaign["asn"],
        "First activity": campaign["campaign_start"],
        "Last activity": campaign["campaign_end"],
        "Duration": _span(campaign["campaign_start"], campaign["campaign_end"]),
        "Distinct IPs": campaign["attacker_count"],
        "Sessions": campaign["total_connections"],
    })

with right:
    theme.subsection("Members by threat score")
    members = data.campaign_members(tuple(campaign["ip_addresses"]))
    if members:
        counts = {}
        for m in members:
            counts[(m.get("verdict") or "UNSCORED").upper()] = \
                counts.get((m.get("verdict") or "UNSCORED").upper(), 0) + 1
        theme.composition([
            {"label": v.title(), "value": counts[v],
             "color": theme.SEVERITY.get(v, theme.MUTED)}
            for v in ORDER + ["UNSCORED"] if counts.get(v)
        ])
        st.caption(
            "A campaign is a spread finding: many low-scoring IPs from one network "
            "can matter more than a single high-scoring host, because the spread is "
            "the tactic.")
    else:
        theme.empty_state("👥", "No member enrichment",
                          "The campaign was detected but member profiles could not "
                          "be loaded.")

theme.section("Member profiles", f"The {campaign['attacker_count']} source(s) "
                                 f"attributed to {campaign['asn']}.")
if members:
    theme.table(pd.DataFrame(members),
                columns=("ip_address", "country", "city", "isp", "threat_score",
                         "verdict", "total_connections", "last_seen"))
else:
    theme.empty_state("👥", "No member detail available",
                      "The campaign was detected but member enrichment could not be "
                      "loaded — the attacker rows may have been removed since.")
