"""
AI Analysis — Gemini-written threat reports built strictly from captured rows.

Report text is model output derived from stored data and is rendered as
markdown by design. The anti-hallucination constraint lives in the prompt and
is verified in tests/test_ai_analyst.py, which asserts the model states gaps as
gaps rather than inventing detail to fill them.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

_ROOT = str(Path(__file__).parent.parent.parent)
if _ROOT not in sys.path:  # guarded: this line runs on every rerun
    sys.path.insert(0, _ROOT)

from dashboard import data, theme
from dashboard.async_bridge import run as bridge_run
from dashboard.login import require_auth
from honeypot.ai.async_analyst import RETRY_DELAYS, generate_attacker_report, is_available

st.set_page_config(page_title="HoneyShield — AI Analysis", page_icon="🤖", layout="wide")
require_auth("🤖", "AI Analysis")

theme.page_header(
    "",
    "AI Threat Analyst",
    "Writes an assessment of one attacker from its captured record only. The model "
    "is instructed to state gaps as gaps rather than fill them, so a sparse attacker "
    "yields a short report rather than an invented profile.",
    eyebrow="Gemini",
)


def _as_dt(ts):
    """Coerce a timestamp to an aware datetime, or None (asyncpg returns a
    datetime, sqlite3 a string — see dashboard/pages/04 for the bug this fixes)."""
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


if not is_available():
    st.warning(
        "AI analyst unavailable — GEMINI_API_KEY is not set in .env. Reports remain "
        "requestable below and will return a clear message rather than crashing."
    )

attackers = data.attackers(None)
if not attackers:
    theme.empty_state(
        "🤖",
        "Nothing to analyse yet",
        "Reports are built from captured rows, so at least one attacker must exist. "
        "Once a connection lands, its profile becomes selectable here.",
    )
    st.stop()

# ── Subject selection ─────────────────────────────────────────────────────
theme.section(
    "Subject",
    "Pick a captured source. The report is written from that source's record "
    "alone — connections, credentials, enrichment and alerts — and nothing else.",
    rule=False,
)

labels = {
    a["ip_address"]: f"{a['ip_address']} · {a.get('verdict') or 'UNSCORED'} "
                     f"· {a.get('threat_score', 0)}/100 · {a.get('country') or 'unknown'}"
    for a in attackers
}
selected_ip = st.selectbox("Select an attacker", list(labels),
                           format_func=lambda ip: labels[ip])
attacker = next(a for a in attackers if a["ip_address"] == selected_ip)
verdict = attacker.get("verdict") or "UNSCORED"

theme.kpis([
    {"label": "Threat score", "value": f"{attacker.get('threat_score', 0)}/100",
     "note": verdict, "tone": theme.severity_tone(verdict)},
    {"label": "Sessions", "value": attacker.get("total_connections") or 0,
     "note": "captured connections", "tone": "#4A9EFF"},
    {"label": "OTX pulses", "value": attacker.get("otx_pulse_count") or 0,
     "note": "threat-feed mentions",
     "tone": theme.SEVERITY["MEDIUM"] if attacker.get("otx_pulse_count") else theme.MUTED},
    {"label": "Origin", "value": attacker.get("country") or "unknown",
     "note": attacker.get("isp") or "network unknown", "tone": theme.MUTED},
])

# ── Generate ──────────────────────────────────────────────────────────────
reports = data.reports_for(selected_ip)

theme.section(
    "Generate assessment",
    f"Calls Gemini once for {selected_ip}. Transient provider errors are retried "
    f"automatically on a {'/'.join(str(d) for d in RETRY_DELAYS)}s backoff before "
    f"anything surfaces here.",
)

col_action, col_meta = st.columns([1, 3], vertical_alignment="center")
with col_action:
    generate = st.button("Generate report", type="primary", width="stretch",
                         icon=":material/auto_awesome:")
with col_meta:
    if reports:
        st.caption(f"{len(reports)} previous assessment(s) · most recent "
                   f"{_age(reports[0].get('generated_at'))}")
    else:
        st.caption("No assessment has been generated for this source yet.")

if generate:
    with st.spinner(f"Analysing {selected_ip} — retries automatically if Gemini is busy…"):
        result = bridge_run(generate_attacker_report(selected_ip))
    data.refresh()   # a new report invalidates the cached history

    if result["error"]:
        # Transient conditions were already retried inside the analyst, so by
        # the time one reaches here it deserves a softer treatment than a
        # hard failure: nothing is wrong with the data or the key.
        if result.get("transient"):
            st.warning(result["report_text"])
        else:
            st.error(result["report_text"])
    else:
        theme.badge("GENERATED", level="LOW",
                    detail=str(result.get("model", "unknown model")))
        with st.container(border=True):
            st.markdown(result["report_text"])
        reports = data.reports_for(selected_ip)

# ── History ───────────────────────────────────────────────────────────────
theme.section(
    "Assessment history",
    "Every report is stored, so you can compare how a source's assessment changes "
    "as more of its activity is captured.",
)

if reports:
    for i, r in enumerate(reports):
        when = r.get("generated_at")
        with st.expander(f"{_age(when)}  ·  {when}", expanded=(i == 0)):
            st.markdown(r["report_text"])
else:
    theme.empty_state(
        "📄",
        "No assessments yet for this source",
        "Generate one above. Reports are written only from what has actually been "
        "captured, so a source with a single connection and no credentials will "
        "produce a short report — that is the model behaving correctly, not "
        "failing.",
    )
