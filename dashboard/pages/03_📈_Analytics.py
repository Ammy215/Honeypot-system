"""
Analytics — aggregate views over captured traffic.

All values are counts computed in SQL; nothing here renders attacker text.
"""

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard import theme
from dashboard.async_bridge import run as bridge_run
from dashboard.login import require_auth
from database.db_async import db

st.set_page_config(page_title="HoneyShield — Analytics", page_icon="📈", layout="wide")
require_auth("📈", "Analytics")

theme.page_header(
    "",
    "Analytics",
    "Volume, composition and severity of captured traffic over time.",
    eyebrow="Aggregates",
)

with st.sidebar:
    st.markdown("**Analytics controls**")
    hours = st.slider("Timeline window (hours)", 1, 168, 24)

# ── Timeline ──────────────────────────────────────────────────────────────
theme.section("Connections over time",
              f"Captured sessions per bucket across the last {hours} hour(s).", rule=False)

timeline = bridge_run(db.connections_timeline(hours=hours))
if timeline:
    df = pd.DataFrame(timeline)
    fig = px.area(df, x="bucket", y="cnt", labels={"bucket": "", "cnt": "Connections"})
    fig.update_traces(
        line=dict(color=theme.ACCENT, width=2),
        fillcolor="rgba(245,165,36,.13)",
        hovertemplate="%{x}<br>%{y} connection(s)<extra></extra>",
    )
    st.plotly_chart(theme.style_chart(fig, height=300), width="stretch")
else:
    theme.empty_state(
        "📉",
        "No connections in this window",
        "Widen the timeline window in the sidebar, or wait for traffic. On a free "
        "PaaS tier the service sleeps when idle, so gaps are expected.",
    )

# ── Composition ───────────────────────────────────────────────────────────
theme.section("Composition", "How captured traffic breaks down by service and by verdict.")

left, right = st.columns(2)

with left:
    st.markdown("##### By service")
    services = bridge_run(db.service_breakdown())
    if services:
        fig = px.pie(pd.DataFrame(services), names="service", values="cnt", hole=.58)
        fig.update_traces(textinfo="label+percent",
                          marker=dict(line=dict(color=theme.BG, width=2)))
        st.plotly_chart(theme.style_chart(fig, height=290), width="stretch")
        st.caption("Only the HTTP honeypot is deployed on the current platform; SSH, "
                   "FTP and Telnet are built but not exposed.")
    else:
        theme.empty_state("🧩", "No service data", "No connections have been captured yet.")

with right:
    st.markdown("##### By verdict")
    verdicts = bridge_run(db.verdict_breakdown())
    if verdicts:
        vdf = pd.DataFrame(verdicts)
        fig = px.bar(vdf, x="verdict", y="cnt", color="verdict",
                     color_discrete_map={k: v for k, v in theme.SEVERITY.items()},
                     labels={"verdict": "", "cnt": "Attackers"})
        fig.update_layout(showlegend=False)
        fig.update_traces(hovertemplate="%{x}: %{y}<extra></extra>")
        st.plotly_chart(theme.style_chart(fig, height=290), width="stretch")
        st.caption("Verdict is derived from the weighted threat score: "
                   "LOW < 25 ≤ MEDIUM < 50 ≤ HIGH < 80 ≤ CRITICAL.")
    else:
        theme.empty_state("⚖️", "No scored attackers", "Scoring runs as soon as an IP is captured.")

# ── Volume leaders ────────────────────────────────────────────────────────
theme.section("Most active sources", "Attackers ranked by number of captured sessions.")

attackers = bridge_run(db.list_attackers(limit=10))
if attackers:
    adf = pd.DataFrame(attackers).sort_values("total_connections", ascending=True)
    fig = px.bar(adf, x="total_connections", y="ip_address", orientation="h",
                 hover_data=["country", "verdict"],
                 labels={"total_connections": "Connections", "ip_address": ""})
    fig.update_traces(marker_color=theme.ACCENT)
    st.plotly_chart(theme.style_chart(fig, height=max(240, 44 * len(adf))), width="stretch")
else:
    theme.empty_state("🏷️", "No attackers yet", "Nothing has reached the honeypot so far.")
