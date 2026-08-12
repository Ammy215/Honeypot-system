"""
Resolve the real client IP when running behind a reverse proxy / PaaS load balancer.

Why this exists: asyncio's socket peer address is whoever opened the TCP
connection. On a VPS that's the attacker. Behind a PaaS load balancer (Option A
— see README "Future Work") it's the *balancer*, identically for every
connection. Recording that would collapse every attacker in the world into one
row: geolocation would resolve to the hosting provider's datacenter, AbuseIPDB
would be queried once, brute-force and credential-stuffing detection would fire
permanently against a single phantom IP, and campaign detection would see one
ASN containing the entire internet. The data would look structurally fine and
be entirely worthless.

The anti-spoofing part matters here more than in a normal web app, because the
clients are hostile by definition and forging a source IP is exactly the kind
of thing they try.

X-Forwarded-For is a list that proxies **append** to:

    attacker sends nothing        -> "<attacker>"
    attacker sends "1.2.3.4"      -> "1.2.3.4, <attacker>"
    attacker sends "1.2.3.4, 5.6" -> "1.2.3.4, 5.6, <attacker>"

Anything the attacker writes gets pushed *leftward* by the hop that appends the
address it actually received the connection from. So the trustworthy entry is
counted from the **right**, one position per proxy hop we control — never the
leftmost, which is the value the attacker chose. Naive implementations take the
first entry and hand attackers a free source-IP forgery.

A single-value header the platform sets itself (CF-Connecting-IP and friends)
is preferred where available, since it isn't a list and can't be polluted at
all. Configure it as TRUSTED_CLIENT_IP_HEADER.
"""

import ipaddress
import logging
from typing import Dict, Optional, Tuple

import config

logger = logging.getLogger("honeypot.client_ip")


def _parse_ip(token: str) -> Optional[str]:
    """
    Validate one X-Forwarded-For entry, tolerating the forms proxies emit:
    a bare address, an IPv4 address with a port, or a bracketed IPv6 address
    with or without a port. Returns the normalized address, or None if the
    token isn't a valid IP at all.
    """
    token = token.strip()
    if not token:
        return None

    # "[2001:db8::1]:443" or "[2001:db8::1]"
    if token.startswith("["):
        closing = token.find("]")
        if closing == -1:
            return None
        token = token[1:closing]
    # "192.0.2.1:443" — but not bare IPv6, which is full of colons
    elif token.count(":") == 1:
        token = token.split(":", 1)[0]

    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def resolve_client_ip(headers: Dict[str, str], peer_ip: str) -> Tuple[str, Optional[str]]:
    """
    Work out the real client IP for a request.

    `headers` must be lower-cased keys. Returns (client_ip, raw_header_value),
    where raw_header_value is the untouched header text for storage as evidence
    — a spoofed X-Forwarded-For is itself worth capturing as attacker intel —
    or None when no proxy header was involved.

    Falls back to `peer_ip` whenever the headers can't be trusted or parsed, so
    this can never fail closed into recording nothing.
    """
    if not config.TRUST_PROXY_HEADERS:
        # Direct exposure: the peer address IS the attacker, and any forwarding
        # header present is attacker-supplied noise that must not be believed.
        return peer_ip, None

    # 1. Platform-set single-value header, if one is configured. Not a list,
    #    so there is no left/right ambiguity to get wrong.
    if config.TRUSTED_CLIENT_IP_HEADER:
        raw_single = headers.get(config.TRUSTED_CLIENT_IP_HEADER)
        if raw_single:
            parsed = _parse_ip(raw_single)
            if parsed:
                return parsed, raw_single
            logger.warning(
                f"{config.TRUSTED_CLIENT_IP_HEADER} present but unparseable "
                f"({raw_single!r}); falling back to {config.FORWARDED_IP_HEADER}"
            )

    # 2. X-Forwarded-For, counted from the right.
    raw = headers.get(config.FORWARDED_IP_HEADER)
    if not raw:
        # Trust is enabled but the proxy sent no header — either a direct
        # connection that bypassed the balancer, or a misconfiguration. The
        # peer address is the only thing we actually observed.
        return peer_ip, None

    entries = [part for part in (p.strip() for p in raw.split(",")) if part]
    if not entries:
        return peer_ip, raw

    hops = max(1, config.TRUSTED_PROXY_HOPS)
    index = len(entries) - hops

    if index < 0:
        # Fewer entries than hops we expect to control. Something is wrong with
        # the hop count or the request bypassed a proxy; the leftmost entry is
        # the least-bad guess, but it is NOT trustworthy, so say so loudly.
        logger.warning(
            f"{config.FORWARDED_IP_HEADER} has {len(entries)} entries but "
            f"TRUSTED_PROXY_HOPS={hops}; value may be attacker-controlled: {raw!r}"
        )
        index = 0

    candidate = _parse_ip(entries[index])
    if candidate is None:
        logger.warning(
            f"Unparseable entry in {config.FORWARDED_IP_HEADER} ({raw!r}); "
            f"falling back to peer address {peer_ip}"
        )
        return peer_ip, raw

    return candidate, raw
