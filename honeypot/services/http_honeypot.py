"""
Fake HTTP honeypot — HoneyShield v2 (asyncio).

Serves fake admin/WordPress-style login forms and a phpMyAdmin decoy.
Any other path is treated as reconnaissance and gets a 404. POSTed
credentials are captured as inert text only, never interpreted.
"""

import asyncio
import time
from typing import Dict, Tuple, Optional
from urllib.parse import unquote_plus

import config
from honeypot.core.async_base_service import AsyncHoneypotService
from honeypot.core.client_ip import resolve_client_ip
from database.db_async import db
from honeypot.detectors.async_detection import check_and_alert, check_connection_patterns
from honeypot.intelligence.async_enrichment import enrich_and_score

SERVER_HEADER = "Apache/2.4.41 (Ubuntu)"

# Caps for the attacker-controlled request details stored on each connection.
# recv_safe already bounds the read at 8192 bytes, so these are not the only
# limit — but without them a client could fill the column with 8KB of padding
# on every request and use the capture table as a cheap write amplifier. The
# values are generous against real traffic: normal paths and User-Agent strings
# sit far below them, so nothing legitimate is lost, while a deliberately
# oversized value is still recorded (truncated) rather than dropped, because
# the attempt itself is intel.
MAX_METHOD_LEN = 16
MAX_PATH_LEN = 2048
MAX_USER_AGENT_LEN = 512


class HTTPHoneypot(AsyncHoneypotService):
    """Fake HTTP service honeypot — simulates admin panels"""

    def __init__(self, port: int = None, host: str = None):
        # config.HTTP_PORT is $PORT when the platform injects one (PaaS routes
        # exactly one port and picks it), else the local-dev port from SERVICES.
        super().__init__(port or config.HTTP_PORT, "HTTP", host)

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, address: Tuple[str, int]
    ):
        peer_ip = address[0]
        start_time = time.monotonic()

        # Read the request before recording anything: behind a load balancer the
        # real client IP arrives in a header, and every downstream consumer
        # (enrichment, detection, scoring) must key off the resolved address
        # rather than the balancer's. recv_safe has its own short timeout, so
        # this still returns promptly for a client that never sends a byte —
        # the idle-client case that broke logging in Phase 1 stays covered.
        request_data = await self.recv_safe(reader, 8192)
        headers = self._parse_headers(request_data) if request_data else {}
        ip_address, forwarded_raw = resolve_client_ip(headers, peer_ip)

        # Infrastructure noise: behind a proxy, anything arriving without a
        # forwarding header bypassed the load balancer, which in practice means
        # a platform health check. Recording those in attackers/connections would
        # swamp the real signal — but dropping them with no trace at all makes
        # "genuinely low traffic" and "traffic being filtered" indistinguishable
        # from outside. Logged to the separate filtered_connections table instead:
        # same response to the client, same untouched attackers/connections tables,
        # just visible rather than invisible. Fire-and-forget (spawn_background),
        # not awaited — a synchronous DB round-trip on every health-check ping
        # would add latency to exactly the path this exists to keep lightweight,
        # and could risk delaying the health check response itself.
        if (
            config.TRUST_PROXY_HEADERS
            and config.IGNORE_UNFORWARDED_CONNECTIONS
            and not forwarded_raw
        ):
            filtered_method, filtered_path = None, None
            if request_data:
                first_line = request_data.split("\n", 1)[0].strip().split()
                if len(first_line) >= 2:
                    filtered_method, filtered_path = first_line[0].upper(), first_line[1]

            self.spawn_background(db.record_filtered_connection(
                peer_ip=peer_ip, service="http", port=self.port,
                method=filtered_method, path=filtered_path,
            ))
            self.logger.debug(
                f"Filtered unforwarded connection from {peer_ip} "
                f"(method={filtered_method}, path={filtered_path})"
            )
            await self._send_html(writer, 200, self._not_found_html())
            return

        if forwarded_raw and ip_address != peer_ip:
            self.logger.info(f"HTTP connection from {ip_address} (via proxy {peer_ip})")
        else:
            self.logger.info(f"HTTP connection from {ip_address}:{address[1]}")

        # Parse the request line here, before the connection row is written, so
        # what was actually asked for is stored on the row itself. Recording only
        # that someone connected cannot distinguish a scanner fingerprinting the
        # host from one hunting for an exposed `.env` or a known CMS exploit
        # path — and that distinction is most of the intel value.
        req_method, req_path = self._request_line(request_data)
        req_user_agent = self._clip(headers.get("user-agent"), MAX_USER_AGENT_LEN)

        connection_id = await db.record_connection(
            ip_address=ip_address, service="http", port=self.port,
            forwarded_for_raw=forwarded_raw,
            method=req_method, path=req_path, user_agent=req_user_agent,
        )
        self.spawn_background(enrich_and_score(ip_address))
        await check_connection_patterns(ip_address)

        if not request_data:
            self._log_closed(ip_address, start_time, "no request")
            return

        self.logger.debug(f"HTTP request from {ip_address}: {request_data[:200]!r}")

        # Reuse the values already parsed for the connection row rather than
        # parsing a second time — two parsers on the same untrusted input is how
        # they drift apart, and the stored row would stop matching the routing.
        if req_method is None or req_path is None:
            self._log_closed(ip_address, start_time, "malformed request")
            return

        method, path = req_method, req_path
        user_agent = req_user_agent or "Unknown"
        self.logger.info(f"HTTP {method} {path} from {ip_address} | UA: {user_agent}")

        if path.startswith("/admin"):
            await self._handle_login_form(
                writer, connection_id, ip_address, method, request_data,
                login_html=self._admin_login_html, failure_html=self._admin_failure_html,
            )
        elif path.startswith("/phpmyadmin"):
            await self._handle_phpmyadmin(writer, ip_address)
        elif path.startswith("/wp-admin") or path.startswith("/wp-login"):
            await self._handle_login_form(
                writer, connection_id, ip_address, method, request_data,
                login_html=self._wordpress_login_html, failure_html=self._wordpress_failure_html,
            )
        else:
            self.logger.warning(f"HTTP path reconnaissance from {ip_address}: {path}")
            await self._send_html(writer, 404, self._not_found_html())

        self._log_closed(ip_address, start_time)

    def _log_closed(self, ip_address: str, start_time: float, note: str = ""):
        duration = time.monotonic() - start_time
        suffix = f" ({note})" if note else ""
        self.logger.info(f"HTTP connection from {ip_address} closed after {duration:.2f}s{suffix}")

    async def _handle_login_form(self, writer, connection_id, ip_address, method, request_data, login_html, failure_html):
        if method == "POST":
            username, password = self._parse_post_credentials(request_data)
            if username or password:
                self.logger.warning(f"HTTP login attempt from {ip_address}: user={username}, pass={password}")
                await db.record_login_attempt(connection_id, ip_address, username, password)
                await check_and_alert(ip_address, "http")
            await self._send_html(writer, 200, failure_html())
        else:
            await self._send_html(writer, 200, login_html())

    async def _handle_phpmyadmin(self, writer, ip_address: str):
        self.logger.warning(f"phpMyAdmin access attempt from {ip_address}")
        html = (
            "<!DOCTYPE html><html><head><title>phpMyAdmin</title></head>"
            "<body><h1>phpMyAdmin</h1><p>Access denied. This system is monitored.</p></body></html>"
        )
        await self._send_html(writer, 403, html)

    async def _send_html(self, writer: asyncio.StreamWriter, status: int, html: str):
        reason = {200: "OK", 403: "Forbidden", 404: "Not Found"}.get(status, "OK")
        body = html.encode("utf-8")
        response = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Server: {SERVER_HEADER}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("utf-8") + body
        await self.send_safe(writer, response)

    @staticmethod
    def _clip(value: Optional[str], limit: int) -> Optional[str]:
        """Bound an attacker-controlled string. None stays None, so 'absent' and
        'empty' remain distinguishable in the stored row."""
        if value is None:
            return None
        value = value.strip()
        return value[:limit] if value else None

    @classmethod
    def _request_line(cls, request_data: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract (method, path) from the request line, or (None, None).

        None means no usable request line arrived — a bare TCP probe or a
        malformed request — which is a meaningful distinction to preserve
        rather than flatten into an empty string.
        """
        if not request_data:
            return None, None
        parts = request_data.split("\n", 1)[0].strip().split()
        if len(parts) < 2:
            return None, None
        return cls._clip(parts[0].upper(), MAX_METHOD_LEN), cls._clip(parts[1], MAX_PATH_LEN)

    @staticmethod
    def _parse_headers(request_data: str) -> Dict[str, str]:
        """
        Header name -> value, names lower-cased. Duplicate names keep the last
        occurrence, matching how proxies fold repeated headers. Parsing only —
        no value here is trusted without going through resolve_client_ip.
        """
        headers: Dict[str, str] = {}
        for line in request_data.split("\n")[1:]:
            if not line.strip():
                break  # end of the header block; body starts here
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        return headers

    @staticmethod
    def _parse_post_credentials(request_data: str) -> Tuple[Optional[str], Optional[str]]:
        username = password = None
        if "\r\n\r\n" in request_data:
            body = request_data.split("\r\n\r\n", 1)[1]
        elif "\n\n" in request_data:
            body = request_data.split("\n\n", 1)[1]
        else:
            return username, password

        for pair in body.split("&"):
            if "=" not in pair:
                continue
            key, value = pair.split("=", 1)
            value = unquote_plus(value)
            if key in ("username", "log"):
                username = value
            elif key in ("password", "pwd"):
                password = value
        return username, password

    @staticmethod
    def _admin_login_html() -> str:
        return """<!DOCTYPE html>
<html><head><title>Admin Login</title></head>
<body>
<h2>Admin Login</h2>
<form method="POST" action="/admin">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Login</button>
</form>
</body></html>"""

    @staticmethod
    def _admin_failure_html() -> str:
        return """<!DOCTYPE html>
<html><head><title>Login Failed</title></head>
<body><h2>Login Failed</h2><p>Invalid credentials. Please try again.</p>
<a href="/admin">&larr; Back to Login</a></body></html>"""

    @staticmethod
    def _wordpress_login_html() -> str:
        return """<!DOCTYPE html>
<html><head><title>Log In &lsaquo; WordPress</title></head>
<body id="login">
<form name="loginform" id="loginform" method="POST" action="/wp-login.php">
<input type="text" name="log" id="user_login" placeholder="Username or Email Address">
<input type="password" name="pwd" id="user_pass" placeholder="Password">
<button type="submit" name="wp-submit" id="wp-submit">Log In</button>
</form>
</body></html>"""

    @staticmethod
    def _wordpress_failure_html() -> str:
        return """<!DOCTYPE html>
<html><head><title>Log In &lsaquo; WordPress</title></head>
<body id="login">
<div id="login_error"><strong>Error:</strong> Invalid username or incorrect password.</div>
<form name="loginform" id="loginform" method="POST" action="/wp-login.php">
<input type="text" name="log" id="user_login">
<input type="password" name="pwd" id="user_pass">
<button type="submit" name="wp-submit" id="wp-submit">Log In</button>
</form>
</body></html>"""

    @staticmethod
    def _not_found_html() -> str:
        return """<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>"""
