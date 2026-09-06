"""
AI Analysis — Gemini-written threat reports built strictly from captured rows.

Report text is model output derived from stored data, rendered as markdown by
design. The anti-hallucination constraint lives in the prompt and is verified
in tests/test_ai_analyst.py.
"""

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard import theme
from dashboard.async_bridge import run as bridge_run
from dashboard.login import require_auth
from database.db_async import db
from honeypot.ai.async_analyst import generate_attacker_report, is_available

st.set_page_config(page_title="HoneyShield — AI Analysis", page_icon="🤖", layout="wide")
require_auth("🤖", "AI Analysis")

theme.page_header(
    "",
    "AI Threat Analyst",
    "Generates a written assessment for one attacker from its captured record only. "
    "The model is instructed to state gaps as gaps rather than fill them — a sparse "
    "attacker yields a short report, not an invented profile.",
    eyebrow="Gemini",
)

if not is_available():
    st.warning(
        "AI analyst unavailable — GEMINI_API_KEY is not set in .env. Reports remain "
        "requestable below and will return a clear message rather than crashing."
    )

attackers = bridge_run(db.list_attackers(limit=200))
if not attackers:
    theme.empty_state(
        "🤖",
        "Nothing to analyse yet",
        "Reports are built from captured rows, so at least one attacker must exist. "
        "Once a connection lands, its profile becomes selectable here.",
    )
    st.stop()

labels = {
    a["ip_address"]: f"{a['ip_address']} · {a.get('verdict') or 'UNSCORED'} "
                     f"· {a.get('threat_score', 0)}/100 · {a.get('country') or 'unknown'}"
    for a in attackers
}
selected_ip = st.selectbox(
    "Select an attacker", list(labels), format_func=lambda ip: labels[ip]
)
attacker = next(a for a in attackers if a["ip_address"] == selected_ip)

theme.kpis([
    {"label": "Threat score", "value": f"{attacker.get('threat_score', 0)}/100",
     "note": attacker.get("verdict") or "unscored",
     "tone": theme.severity_tone(attacker.get("verdict"))},
    {"label": "Connections", "value": attacker.get("total_connections") or 0,
     "note": "captured sessions", "tone": "#4A9EFF"},
    {"label": "OTX pulses", "value": attacker.get("otx_pulse_count") or 0,
     "note": "threat-feed mentions", "tone": theme.MUTED},
    {"label": "Origin", "value": attacker.get("country") or "unknown",
     "note": attacker.get("isp") or "ISP unknown", "tone": theme.MUTED},
])

if st.button("Generate threat report", type="primary"):
    with st.spinner(f"Analysing {selected_ip} — retries automatically if Gemini is busy…"):
        result = bridge_run(generate_attacker_report(selected_ip))

    if result["error"]:
        # Transient provider conditions are retried inside the analyst; by the
        # time one surfaces here it has already been retried and is worth a
        # softer treatment than a hard failure.
        if result.get("transient"):
            st.warning(result["report_text"])
        else:
            st.error(result["report_text"])
    else:
        st.success(f"Report generated · {result.get('model', 'unknown model')}")
        with st.container(border=True):
            st.markdown(result["report_text"])

theme.section("Report history", f"Previous assessments generated for {selected_ip}.")

reports = bridge_run(db.list_ai_reports_for_ip(selected_ip, limit=10))
if reports:
    for r in reports:
        with st.expander(f"Report from {r['generated_at']}"):
            st.markdown(r["report_text"])
else:
    theme.empty_state(
        "📄",
        "No reports yet for this IP",
        "Generate one above. Each report is stored, so you can compare how an "
        "attacker's assessment changes as more activity is captured.",
    )
