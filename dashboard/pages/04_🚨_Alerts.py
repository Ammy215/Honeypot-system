"""
Alerts — triage queue for detector output.

`evidence` is detector-generated JSON, but may embed attacker-supplied values
(usernames tried, paths probed), so it is rendered via st.code / theme.table —
both inert — and never as markdown or through a raw-HTML helper.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard import data, theme
from dashboard.async_bridge import run as bridge_run
from dashboard.login import require_auth
from database.db_async import db

st.set_page_config(page_title="HoneyShield — Alerts", page_icon="🚨", layout="wide")
require_auth("🚨", "Alerts")

theme.page_header(
    "",
    "Alerts",
    "Detections raised by the brute-force, credential-stuffing and correlation "
    "engines. Acknowledge one once you have triaged it — the count of unhandled "
    "alerts is the number that matters on this page.",
    eyebrow="Triage",
)

with st.sidebar:
    st.markdown("**Alert filters**")
    severity_filter = st.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    ack_filter = st.selectbox("Status", ["All", "Unacknowledged", "Acknowledged"])

severity = None if severity_filter == "All" else severity_filter
acknowledged = {"All": None, "Unacknowledged": False, "Acknowledged": True}[ack_filter]

_d = data.alerts(severity, acknowledged)
alerts, all_alerts = _d["filtered"], _d["all"]


def _as_dt(ts):
    """
    Coerce a timestamp to an aware datetime, or None.

    Necessary because the two backends disagree: asyncpg returns a datetime,
    sqlite3 returns a string. Guarding on `hasattr(ts, "tzinfo")` therefore
    silently discarded every SQLite row — "Oldest open" rendered "—" with two
    alerts open — while working correctly against Postgres. Backend-dependent
    behaviour like that hides until someone runs the other backend.
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


def _age(ts) -> str:
    """Relative age. A raw timestamp makes the reader do the arithmetic."""
    when = _as_dt(ts)
    if when is None:
        return str(ts)
    secs = (datetime.now(timezone.utc) - when).total_seconds()
    if secs < 90:
        return f"{int(secs)}s ago"
    if secs < 5400:
        return f"{int(secs // 60)}m ago"
    if secs < 172800:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


# ── Headline ──────────────────────────────────────────────────────────────
# Counts are over ALL alerts, not the filtered view: a severity filter should
# not change the totals it is filtering against.
counts = {lvl: sum(1 for a in all_alerts if a.get("severity") == lvl)
          for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
open_alerts = [a for a in all_alerts if not a.get("acknowledged")]
_open_times = [t for t in (_as_dt(a.get("created_at")) for a in open_alerts) if t]
oldest_open = min(_open_times, default=None)

theme.kpis([
    {"label": "Unacknowledged", "value": len(open_alerts), "note": "awaiting triage",
     "tone": theme.SEVERITY["HIGH"] if open_alerts else theme.SEVERITY["LOW"]},
    {"label": "Critical", "value": counts["CRITICAL"], "note": "all time",
     "tone": theme.SEVERITY["CRITICAL"] if counts["CRITICAL"] else theme.MUTED},
    {"label": "High", "value": counts["HIGH"], "note": "all time",
     "tone": theme.SEVERITY["HIGH"] if counts["HIGH"] else theme.MUTED},
    {"label": "Oldest open", "note": "longest untriaged", "tone": theme.MUTED,
     "value": _age(oldest_open) if oldest_open else "—"},
])

if not alerts:
    if all_alerts:
        theme.empty_state(
            "🎯", "No alerts match this filter",
            f"{len(all_alerts)} alert(s) exist, but none match the current severity "
            "and status selection. Reset the filters in the sidebar.",
        )
    else:
        theme.empty_state(
            "🔔",
            "No alerts raised — and that is a finding, not a blank page",
            "Detectors fire on brute-force thresholds, credential stuffing and "
            "multi-service probing. None has triggered, meaning every visitor so far "
            "connected without attempting a login. That is reconnaissance, not an "
            "intrusion attempt.",
        )
    st.stop()

# ── Queue ─────────────────────────────────────────────────────────────────
theme.section("Queue", f"{len(alerts)} alert(s) matching the current filter, newest first.")

for alert in alerts:
    with st.container(border=True):
        head, action = st.columns([5, 1], vertical_alignment="center")
        with head:
            # A severity pill from the shared palette, not a coloured emoji:
            # MEDIUM here is the same amber as MEDIUM in a table or a meter.
            theme.badge(str(alert.get("severity", "UNKNOWN")),
                        detail=str(alert.get("alert_type", "")).replace("_", " "))
            st.caption(f"{alert['ip_address']} · {_age(alert.get('created_at'))} "
                       f"· {alert.get('created_at')}")

            evidence = alert.get("evidence")
            if evidence:
                with st.expander("Evidence"):
                    # Pretty-printed so a nested payload is readable, but still
                    # st.code — evidence can embed attacker-supplied usernames
                    # and paths, and st.code renders them inert.
                    try:
                        pretty = json.dumps(json.loads(evidence), indent=2, sort_keys=True)
                    except (ValueError, TypeError):
                        pretty = str(evidence)
                    st.code(pretty, language="json")

        with action:
            if bool(alert.get("acknowledged")):
                # theme.badge rather than page-level HTML: only theme.py may
                # interpolate into a raw-HTML sink (tests/test_dashboard_security).
                theme.badge("ACKNOWLEDGED", level="LOW")
            elif st.button("Acknowledge", key=f"ack_{alert['id']}", width="stretch"):
                bridge_run(db.acknowledge_alert(alert["id"]))
                data.refresh()   # the cached alert list is now stale
                st.rerun()

# ── Table ─────────────────────────────────────────────────────────────────
theme.section("Table view", "The same alerts, sortable and exportable.")
theme.table(pd.DataFrame(alerts),
            columns=("created_at", "severity", "alert_type", "ip_address",
                     "acknowledged", "evidence", "id"))
