"""
Cached, concurrent data access for the dashboard.

WHY THIS EXISTS — measured, not assumed.
The database is a Supabase pooler in us-east-1; from here the round-trip
latency floor is ~214ms. Pages issued their queries one after another through
separate bridge calls, so the Overview page cost 4.3s of almost pure waiting:
1.9s of that was summary_counts alone (four queries in a loop, since collapsed
into one), and the rest was three more sequential trips.

Two changes, both aimed at the round trips rather than the queries:

1. GATHER. A page's queries are independent, so they run concurrently on the
   bridge's loop. The same four Overview calls measured 4305ms sequentially and
   1117ms gathered — the page now waits roughly one round trip instead of eight.

2. CACHE. Streamlit re-executes the entire script on EVERY interaction — a
   checkbox, a dropdown, a slider — so without caching each click paid the full
   page cost again. `st.cache_data` keys on the arguments and holds results for
   TTL seconds, which turns a re-render into a dictionary lookup.

The TTL is deliberately short: this is live security data, and showing a stale
attacker count is worse than waiting. `refresh()` clears everything for an
immediate re-read, wired to the sidebar's Refresh button.
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

import streamlit as st
from streamlit.runtime.scriptrunner import add_script_run_ctx, get_script_run_ctx

from dashboard import perf, sensor
from dashboard.async_bridge import run as bridge_run
from database.db_async import db
from honeypot.detectors.async_correlation import detect_asn_campaigns, get_campaign_members

# Long enough that clicking around a page is instant, short enough that the
# feed still reads as live. The sidebar Refresh button bypasses it entirely.
TTL = 20


def refresh() -> None:
    """Drop every cached bundle so the next render re-reads the database."""
    st.cache_data.clear()


def concurrently(*readers: Callable[[], object]) -> list:
    """
    Run independent cached readers at the same time; results in call order.

    For reads that do not share an event loop — Overview's database bundle and
    its HTTP health probe were running back to back, so a cache miss cost their
    SUM. Overlapped, it costs the slower of the two.

    Each worker is given the calling script's run context, which st.cache_data
    needs to behave exactly as it does on the script thread. The executor is
    per call, not shared: worker threads die with it, so one browser session's
    context can never linger on a thread that later serves another session.
    Exceptions surface here, unchanged, as if the reader had been called directly.
    """
    ctx = get_script_run_ctx()

    def _call(reader):
        if ctx is not None:
            add_script_run_ctx(None, ctx)
        return reader()

    with ThreadPoolExecutor(max_workers=len(readers), thread_name_prefix="hs-read") as ex:
        futures = [ex.submit(_call, r) for r in readers]
        return [f.result() for f in futures]


# ── Sensor liveness ───────────────────────────────────────────────────────
# Longer than TTL: this is a network round trip to another continent, not a
# database read, and liveness does not change meaningfully between two page
# clicks. Still short enough that a sensor going down surfaces within half a
# minute. Cached here rather than in sensor.py so the sidebar's Refresh button,
# which clears this module's caches, forces a genuine re-probe.
SENSOR_TTL = 30


@st.cache_data(ttl=SENSOR_TTL, show_spinner=False)
def _sensor_status_cached() -> dict:
    perf.note_miss()
    return sensor.probe()


def sensor_status() -> dict:
    """
    Probe the honeypot's health endpoint (see dashboard/sensor.py), cached.

    Split from the cached function only so that, with DASHBOARD_PERF_LOG on,
    each call is logged as a cache HIT or MISS with its latency — the body of a
    cached function runs only on a miss, which is what note_miss() records.
    """
    started = time.perf_counter()
    perf.begin()
    result = _sensor_status_cached()
    perf.record("sensor_status", started)
    return result


# ── Overview ──────────────────────────────────────────────────────────────
@st.cache_data(ttl=TTL, show_spinner=False)
def overview() -> dict:
    async def _load():
        summary, filtered, recent, top = await asyncio.gather(
            db.summary_counts(),
            db.filtered_connection_stats(),
            db.list_recent_connections(limit=5),
            db.list_attackers(limit=5),
        )
        return {"summary": summary, "filtered": filtered, "recent": recent, "top": top}

    return bridge_run(_load())


# ── Live Feed ─────────────────────────────────────────────────────────────
@st.cache_data(ttl=TTL, show_spinner=False)
def live_feed(service: Optional[str]) -> dict:
    async def _load():
        summary, connections, filtered, alerts = await asyncio.gather(
            db.summary_counts(),
            db.list_recent_connections(limit=100, service=service),
            db.filtered_connection_stats(),
            db.list_alerts(limit=10),
        )
        return {"summary": summary, "connections": connections,
                "filtered": filtered, "alerts": alerts}

    return bridge_run(_load())


# ── Attacker Intel ────────────────────────────────────────────────────────
@st.cache_data(ttl=TTL, show_spinner=False)
def attackers(search: Optional[str]) -> list:
    return bridge_run(db.list_attackers(limit=200, search_ip=search or None))


@st.cache_data(ttl=TTL, show_spinner=False)
def login_attempts_for(ip: str) -> list:
    return bridge_run(db.list_login_attempts_for_ip(ip, limit=50))


# ── Analytics ─────────────────────────────────────────────────────────────
@st.cache_data(ttl=TTL, show_spinner=False)
def analytics(hours: int) -> dict:
    async def _load():
        timeline, services, verdicts, top = await asyncio.gather(
            db.connections_timeline(hours=hours),
            # Windowed to match the timeline. Left unwindowed, the composition
            # panels silently reported all time while the chart beside them
            # reported `hours`, and the slider appeared to do nothing to them.
            db.service_breakdown(hours),
            db.verdict_breakdown(hours),
            db.list_attackers(limit=10),
        )
        return {"timeline": timeline, "services": services,
                "verdicts": verdicts, "top": top}

    return bridge_run(_load())


# ── Alerts ────────────────────────────────────────────────────────────────
@st.cache_data(ttl=TTL, show_spinner=False)
def alerts(severity: Optional[str], acknowledged: Optional[bool]) -> dict:
    async def _load():
        filtered, everything = await asyncio.gather(
            db.list_alerts(limit=200, severity=severity, acknowledged=acknowledged),
            db.list_alerts(limit=500),
        )
        return {"filtered": filtered, "all": everything}

    return bridge_run(_load())


# ── Threat Hunting ────────────────────────────────────────────────────────
@st.cache_data(ttl=TTL, show_spinner=False)
def hunting_context() -> dict:
    async def _load():
        # credential_stats replaces count_login_attempts here: it returns the
        # same total plus the aggregates the page needs to show what is
        # searchable, in the same single round trip.
        creds, all_alerts, campaigns = await asyncio.gather(
            db.credential_stats(),
            db.list_alerts(limit=500),
            detect_asn_campaigns(),
        )
        return {"credentials": creds, "total_attempts": creds["total"],
                "alerts": all_alerts, "campaigns": campaigns}

    return bridge_run(_load())


@st.cache_data(ttl=TTL, show_spinner=False)
def credential_search(pattern: str) -> list:
    return bridge_run(db.search_login_attempts(pattern, limit=200))


# ── Campaigns ─────────────────────────────────────────────────────────────
@st.cache_data(ttl=TTL, show_spinner=False)
def campaigns(window_seconds: int, min_attackers: int) -> list:
    return bridge_run(
        detect_asn_campaigns(window_seconds=window_seconds, min_attackers=min_attackers)
    )


@st.cache_data(ttl=TTL, show_spinner=False)
def campaign_members(ip_addresses: tuple) -> list:
    # tuple, not list: st.cache_data hashes its arguments and a list is
    # unhashable. Callers pass tuple(ips).
    return bridge_run(get_campaign_members(list(ip_addresses)))


# ── AI Analysis ───────────────────────────────────────────────────────────
@st.cache_data(ttl=TTL, show_spinner=False)
def reports_for(ip: str) -> list:
    return bridge_run(db.list_ai_reports_for_ip(ip, limit=10))
