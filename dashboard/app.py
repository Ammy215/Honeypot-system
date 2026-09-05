"""
HoneyShield v2 dashboard — main entry point.

Reads from the v2 async database (database/db_async.py) through
dashboard/async_bridge.py, since Streamlit pages are plain synchronous
scripts. That bridge owns one event loop for the process — see its module
docstring for why per-call asyncio.run() was silently broken here.
Bound to 127.0.0.1 only — see .streamlit/config.toml.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent))

from dashboard import theme
from dashboard.async_bridge import run as bridge_run
from dashboard.login import require_auth
from database.db_async import db

st.set_page_config(
    page_title="HoneyShield — Overview",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="expanded",
)

require_auth("🍯", "Overview")

theme.page_header(
    "🍯",
    "Operations Overview",
    "Live state of the deployed HTTP honeypot. Capture volume is expected to be "
    "low — this is a single unadvertised host, so a quiet feed is a normal "
    "reading rather than a fault.",
    eyebrow="HoneyShield SOC",
)

summary = bridge_run(db.summary_counts())
filtered = bridge_run(db.filtered_connection_stats())

theme.kpis([
    {"label": "Attackers", "value": summary["total_attackers"],
     "note": "distinct source IPs", "tone": theme.ACCENT},
    {"label": "Connections", "value": summary["total_connections"],
     "note": "captured sessions", "tone": "#4A9EFF"},
    {"label": "Active alerts", "value": summary["active_alerts"],
     "note": "awaiting triage",
     "tone": theme.SEVERITY["HIGH"] if summary["active_alerts"] else theme.MUTED},
    {"label": "Critical threats", "value": summary["critical_attackers"],
     "note": "score ≥ 80",
     "tone": theme.SEVERITY["CRITICAL"] if summary["critical_attackers"] else theme.MUTED},
])

# ── Sensor health ─────────────────────────────────────────────────────────
# The single most valuable thing this page can answer is "is the sensor alive?"
# Without it, an empty feed is ambiguous: genuinely quiet, or silently down.
# Platform health checks arrive on a fixed cadence, so their freshness is a
# reliable liveness signal that is independent of attacker traffic.
theme.section(
    "Sensor health",
    "Filtered probes are the platform's own health checks. They arrive on a fixed "
    "cadence, so their freshness tells you the honeypot is alive and reachable — "
    "independently of whether any attacker has found it.",
)

latest = filtered.get("latest")
if latest is not None:
    if latest.tzinfo is None:
        latest = latest.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - latest).total_seconds()
    if age < 300:
        status, tone, note = "ONLINE", theme.SEVERITY["LOW"], f"last probe {int(age)}s ago"
    elif age < 3600:
        status, tone, note = "IDLE", theme.SEVERITY["MEDIUM"], f"last probe {int(age // 60)}m ago"
    else:
        status, tone, note = "STALE", theme.SEVERITY["CRITICAL"], f"last probe {int(age // 3600)}h ago"
else:
    status, tone, note = "NO SIGNAL", theme.MUTED, "no probes recorded yet"

theme.kpis([
    {"label": "Sensor status", "value": status, "note": note, "tone": tone},
    {"label": "Probes filtered", "value": filtered["total"],
     "note": "kept out of capture data", "tone": theme.MUTED},
    {"label": "Last hour", "value": filtered["last_hour"], "note": "health checks", "tone": theme.MUTED},
    {"label": "Last 24h", "value": filtered["last_24h"], "note": "health checks", "tone": theme.MUTED},
])

if status == "STALE":
    st.warning(
        "No health-check probe in over an hour. On Render's free tier the service "
        "sleeps after ~15 minutes idle, so this is usually expected — but if it "
        "persists, check the deployment."
    )

# ── Recent activity ───────────────────────────────────────────────────────
theme.section("Recent activity", "The five most recent captured connections.")

recent = bridge_run(db.list_recent_connections(limit=5))
if recent:
    df = pd.DataFrame(recent)
    keep = [c for c in ("connected_at", "ip_address", "country", "service", "port",
                        "threat_score", "verdict") if c in df.columns]
    st.dataframe(df[keep], width="stretch", hide_index=True)
    st.page_link("pages/01_🔴_Live_Feed.py", label="Open the full live feed", icon="🔴")
else:
    theme.empty_state(
        "📡",
        "No connections captured yet",
        "The honeypot is listening but nothing has reached it. New hosts are "
        "typically found within minutes via Certificate Transparency logs, so "
        "the first arrivals are usually automated scanners.",
    )

# ── Top attackers ─────────────────────────────────────────────────────────
theme.section("Highest-scoring attackers", "Ranked by weighted threat score out of 100.")

top = bridge_run(db.list_attackers(limit=5))
if top:
    tdf = pd.DataFrame(top)
    keep = [c for c in ("ip_address", "country", "isp", "threat_score", "verdict",
                        "total_connections", "last_seen") if c in tdf.columns]
    st.dataframe(tdf[keep], width="stretch", hide_index=True)
    st.page_link("pages/02_🌍_Attacker_Intel.py", label="Open attacker intelligence", icon="🌍")
else:
    theme.empty_state(
        "🌍",
        "No attackers profiled yet",
        "Once a connection is captured, its source IP is enriched with "
        "geolocation, AbuseIPDB reputation and AlienVault OTX pulse data, then "
        "scored across 14 weighted factors.",
    )
