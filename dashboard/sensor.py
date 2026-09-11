"""
Is the honeypot actually alive? Ask it, don't infer it.

WHY THIS EXISTS — a regression worth not repeating.
Sensor health used to be derived from the freshness of `filtered_connections`:
the platform's health checker hit a decoy path every few seconds, those probes
were filtered, and a recent filtered row therefore implied a live listener. It
worked, and it was fragile in a way that was invisible until it broke.

Adding HEALTH_CHECK_PATH pointed that checker at an endpoint that deliberately
records nothing. The noise source went silent by design, the table froze, and
Overview began reporting a permanently STALE sensor — in critical red, with a
"check the deployment" banner — for a service that was healthy and being pinged
every five minutes. Nothing detected it, because the panel still rendered fine;
it was simply rendering a lie.

The lesson is the design: a liveness signal must test the property it claims to
report. Reading a side effect of some *other* system's behaviour couples your
truth to their configuration, and they will change it without telling you. So
this module performs the actual request and reports what actually happened.
"""

import threading
import time
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import config

# Long enough to ride out a free-tier cold start (~30s observed), because a
# sleeping instance is not a dead one and must not be reported as down. Split
# from the connect timeout so a genuinely unreachable host still fails fast
# instead of freezing the page for the full read budget.
CONNECT_TIMEOUT_SECONDS = 5.0

# One persistent session, reused across probes. Measured from this machine:
#   requests.get(), new connection every call ...... 1,138 ms median
#   Session, connection kept alive .................   269 ms  (315 ms after 31 s idle)
#   curl, fresh connection, for reference ..........  ~350 ms
# The endpoint was never the slow part. A bare requests.get() builds a new SSL
# context and re-reads the CA bundle on every call, which costs ~0.8 s on
# Windows before a single byte is sent. Keeping one session skips all of that.
#
# One retry, on CONNECT failures only: a kept-alive socket the far end has
# quietly closed fails at connect time, and a single retry on a fresh socket is
# the correct response. Read timeouts are deliberately NOT retried — a
# genuinely hung origin must surface after one timeout, not two.
_SESSION = requests.Session()
_SESSION.mount("https://", HTTPAdapter(max_retries=Retry(
    total=1, connect=1, read=0, status=0, other=0, allowed_methods=["GET"])))
_LOCK = threading.Lock()

ONLINE = "online"
WAKING = "waking"
DEGRADED = "degraded"
UNREACHABLE = "unreachable"
UNCONFIGURED = "unconfigured"


def probe_url() -> Optional[str]:
    """The full URL this module would probe, or None when not configured."""
    if not config.HONEYPOT_PUBLIC_URL or not config.HEALTH_CHECK_PATH:
        return None
    return f"{config.HONEYPOT_PUBLIC_URL}{config.HEALTH_CHECK_PATH}"


def probe() -> dict:
    """
    Request the health endpoint once and classify the outcome.

    Returns a dict of facts, never raises: a dashboard panel reporting on
    reachability must not itself go down when the thing is unreachable. The
    caller decides how to present these; keeping presentation out of here means
    the classification can be tested without rendering anything.

    state:
      online       — answered 200 promptly
      waking       — answered 200, but slowly enough that it was cold-starting
      degraded     — answered, but not with 200 (reachable, misbehaving)
      unreachable  — no usable answer: DNS, connection refused, or timeout
      unconfigured — HONEYPOT_PUBLIC_URL is not set; nothing was probed
    """
    url = probe_url()
    if url is None:
        return {"state": UNCONFIGURED, "url": None, "latency_ms": None,
                "http_status": None, "detail": "HONEYPOT_PUBLIC_URL is not set"}

    started = time.monotonic()
    try:
        with _LOCK:
            response = _SESSION.get(
                url,
                timeout=(CONNECT_TIMEOUT_SECONDS, config.SENSOR_PROBE_TIMEOUT_SECONDS),
                headers={"User-Agent": "HoneyShield-Console/1.0 (sensor probe)"},
            )
    except requests.exceptions.Timeout:
        return {"state": UNREACHABLE, "url": url,
                "latency_ms": int((time.monotonic() - started) * 1000),
                "http_status": None,
                "detail": f"no response within {config.SENSOR_PROBE_TIMEOUT_SECONDS:.0f}s"}
    except requests.exceptions.RequestException as exc:
        return {"state": UNREACHABLE, "url": url,
                "latency_ms": int((time.monotonic() - started) * 1000),
                "http_status": None, "detail": type(exc).__name__}

    elapsed = time.monotonic() - started
    latency_ms = int(elapsed * 1000)

    if response.status_code != 200:
        return {"state": DEGRADED, "url": url, "latency_ms": latency_ms,
                "http_status": response.status_code,
                "detail": f"answered HTTP {response.status_code}, expected 200"}

    if elapsed >= config.SENSOR_WAKING_THRESHOLD_SECONDS:
        return {"state": WAKING, "url": url, "latency_ms": latency_ms,
                "http_status": 200,
                "detail": f"answered after {elapsed:.1f}s — cold start"}

    return {"state": ONLINE, "url": url, "latency_ms": latency_ms,
            "http_status": 200, "detail": f"answered in {latency_ms}ms"}
