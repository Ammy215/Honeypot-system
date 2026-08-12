"""
Fake HTTP honeypot — HoneyShield v2 (asyncio).

Serves fake admin/WordPress-style login forms and a phpMyAdmin decoy.
Any other path is treated as reconnaissance and gets a 404. POSTed
credentials are captured as inert text only, never interpreted.
"""

import asyncio
import time
from typing import Tuple, Optional
from urllib.parse import unquote_plus

import config
from honeypot.core.async_base_service import AsyncHoneypotService
from database.db_async import db
from honeypot.detectors.async_detection import check_and_alert, check_connection_patterns
from honeypot.intelligence.async_enrichment import enrich_and_score

SERVER_HEADER = "Apache/2.4.41 (Ubuntu)"


class HTTPHoneypot(AsyncHoneypotService):
    """Fake HTTP service honeypot — simulates admin panels"""

    def __init__(self, port: int = None, host: str = None):
        super().__init__(port or config.SERVICES["HTTP"]["port"], "HTTP", host)

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, address: Tuple[str, int]
    ):
        ip_address = address[0]
        start_time = time.monotonic()

        self.logger.info(f"HTTP connection from {ip_address}:{address[1]}")

        # Log the connection unconditionally before attempting to read the
        # request, so an idle client that never sends a byte still shows up.
        connection_id = await db.record_connection(ip_address=ip_address, service="http", port=self.port)
        self.spawn_background(enrich_and_score(ip_address))
        await check_connection_patterns(ip_address)

        request_data = await self.recv_safe(reader, 8192)
        if not request_data:
            self._log_closed(ip_address, start_time, "no request")
            return

        self.logger.debug(f"HTTP request from {ip_address}: {request_data[:200]!r}")

        lines = request_data.split("\n")
        parts = lines[0].strip().split() if lines else []
        if len(parts) < 2:
            self._log_closed(ip_address, start_time, "malformed request")
            return

        method, path = parts[0].upper(), parts[1]

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        user_agent = headers.get("user-agent", "Unknown")
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
