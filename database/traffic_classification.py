"""
Tell the platform's own restart probes apart from captured attacker traffic.

WHAT THIS IS ABOUT
Every deploy or restart of the Render service is followed, a second or so
later, by exactly one HTTP request that the honeypot records as an attacker:

    GET /   Go-http-client/2.0   from Google Cloud, The Dalles (Oregon)

Render's Oregon region runs on Google Cloud, so the probe originates from the
platform's own network and arrives through the public edge like any visitor.
Fourteen of these have been captured; the correlation with deploys is exact.
Established two ways, and the second is the one that matters:

  - retrospectively: every push to main is followed by one such row 65-78 s
    later (that gap is Render's build-and-deploy time), and with the instance
    awake and no restarts, 49 hours passed with no rows at all;
  - prospectively: on 2026-09-12 the arrival was PREDICTED before pushing and
    then observed — boot marker at push + 78.3 s, probe 1.1 s after it.

These rows are real data about a real phenomenon. They are not the phenomenon
this project exists to capture, and left unlabelled they inflate every
attacker count on the dashboard. They are labelled, never deleted.

THE BOOT MARKER
The restart timestamps are in the database already. When a Render instance
starts, something inside the container requests `HEAD /` from 127.0.0.1 — a
port check. It carries no forwarding header, so it lands in
`filtered_connections` rather than `connections`, and it is the most precise
restart signal available: it survived the switch to /_health (unlike the
platform's health checks, which now hit an endpoint that records nothing) and
it catches restarts that were never pushes, such as an environment-variable
change.
"""

from bisect import bisect_right
from datetime import datetime, timezone
from typing import Optional, Sequence

# How long after an instance boots a probe may arrive and still be attributed
# to it. Every observation so far is 1-10 s; 30 s is deliberately generous, and
# still far below the interval between restarts.
RESTART_WINDOW_SECONDS = 30

# The request the probe makes, exactly.
PROBE_METHOD = "GET"
PROBE_PATH = "/"
PROBE_USER_AGENT_PREFIX = "Go-http-client"

# Google Cloud's Oregon presence, which is where Render's Oregon region runs.
PROBE_ASN = "AS396982"
PROBE_CITY = "The Dalles"

CLASS_PROBE = "restart_probe"
CLASS_LIKELY = "restart_probe_likely"

CLASS_LABELS = {
    CLASS_PROBE: "Render restart probe",
    CLASS_LIKELY: "Likely restart probe",
    None: "Unclassified",
}


def _as_utc(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def preceding_marker(when: datetime, markers: Sequence[datetime]) -> Optional[datetime]:
    """The newest boot marker at or before `when`, if any. `markers` must be sorted."""
    index = bisect_right(markers, when)
    return markers[index - 1] if index else None


def matches_origin(row: dict) -> bool:
    """Google Cloud, Oregon — by ASN, or by ISP and city together."""
    asn = (row.get("asn") or "")
    isp = (row.get("isp") or "").lower()
    city = (row.get("city") or "")
    return PROBE_ASN in asn or ("google" in isp and city == PROBE_CITY)


def matches_request(row: dict) -> bool:
    return (
        (row.get("method") or "") == PROBE_METHOD
        and (row.get("path") or "") == PROBE_PATH
        and (row.get("user_agent") or "").startswith(PROBE_USER_AGENT_PREFIX)
    )


def request_unrecorded(row: dict) -> bool:
    """
    True when the row carries no request detail at all.

    Rows captured before request logging existed (2026-09-06 and earlier) have
    NULL method/path/user_agent. Their request can never be checked, so they
    cannot be confirmed — only judged on timing and origin.
    """
    return not any(row.get(field) for field in ("method", "path", "user_agent"))


def classify(row: dict, markers: Sequence[datetime], window_seconds: int = RESTART_WINDOW_SECONDS):
    """
    Classify one connection row. Returns (traffic_class, note).

    traffic_class is CLASS_PROBE when timing, origin AND request all match;
    CLASS_LIKELY when timing and origin match but the request was never
    recorded; otherwise None — meaning "not shown to be a restart probe",
    which is the side to err on: an unlabelled row stays countable as
    potentially organic rather than being quietly written off.
    """
    when = _as_utc(row.get("connected_at"))
    if when is None:
        return None, None

    marker = preceding_marker(when, markers)
    if marker is None:
        return None, "no instance-start marker recorded before this connection"

    delta = (when - marker).total_seconds()
    if delta > window_seconds:
        return None, (f"nearest instance start was {delta:.0f}s earlier "
                      f"(outside the {window_seconds}s window)")

    if not matches_origin(row):
        return None, "origin is not Google Cloud / Oregon"

    where = f"{row.get('isp') or '?'} {row.get('city') or '?'}"
    timing = (f"{delta:.1f}s after instance start {marker:%Y-%m-%d %H:%M:%S} UTC; "
              f"origin {where}")

    if matches_request(row):
        return CLASS_PROBE, (f"{PROBE_METHOD} {PROBE_PATH} "
                             f"{row.get('user_agent')}; {timing}")
    if request_unrecorded(row):
        return CLASS_LIKELY, (f"timing and origin match; request detail was not "
                              f"recorded for this row (predates request logging); {timing}")
    return None, (f"request does not match the probe "
                  f"({row.get('method')} {row.get('path')} {row.get('user_agent')!r})")


def attacker_class(connection_classes: Sequence[Optional[str]]) -> Optional[str]:
    """
    The class for a source IP, from the classes of all its connections.

    Labelled only when EVERY connection from that IP is a probe: one organic
    request is enough to make the source worth looking at, and cloud IPs are
    reassigned, so a source that probed once could genuinely scan later.
    """
    classes = list(connection_classes)
    if not classes or any(c is None for c in classes):
        return None
    return CLASS_PROBE if all(c == CLASS_PROBE for c in classes) else CLASS_LIKELY


def boot_markers_query(backend: str) -> str:
    """SQL returning instance-start markers, newest last."""
    if backend == "postgres":
        return ("SELECT filtered_at FROM filtered_connections "
                "WHERE host(peer_ip) = '127.0.0.1' ORDER BY filtered_at")
    return ("SELECT filtered_at FROM filtered_connections "
            "WHERE peer_ip = '127.0.0.1' ORDER BY filtered_at")


__all__ = [
    "CLASS_PROBE", "CLASS_LIKELY", "CLASS_LABELS", "RESTART_WINDOW_SECONDS",
    "classify", "attacker_class", "preceding_marker", "matches_origin",
    "matches_request", "request_unrecorded", "boot_markers_query",
]
