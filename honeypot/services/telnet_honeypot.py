"""
Fake Telnet honeypot — HoneyShield v2 (asyncio).

Ubuntu-style login prompt, up to 2 username/password attempts per
connection (matching real `login` retry behavior), each logged as an
inert login attempt.
"""

import asyncio
import time
from typing import Tuple

import config
from honeypot.core.async_base_service import AsyncHoneypotService
from database.db_async import db
from honeypot.detectors.async_detection import check_and_alert, check_connection_patterns
from honeypot.intelligence.async_enrichment import enrich_and_score

MAX_ATTEMPTS_PER_SESSION = 2


class TelnetHoneypot(AsyncHoneypotService):
    """Fake Telnet service honeypot"""

    def __init__(self, port: int = None, host: str = None):
        super().__init__(port or config.SERVICES["Telnet"]["port"], "Telnet", host)
        self.banner = config.BANNERS["Telnet"]

    def get_banner(self) -> bytes:
        return self.banner.encode("utf-8")

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, address: Tuple[str, int]
    ):
        ip_address = address[0]
        start_time = time.monotonic()

        self.logger.info(f"Telnet connection from {ip_address}:{address[1]}")

        # Log the connection unconditionally, before the login exchange, so an
        # idle client that never sends a byte still shows up.
        connection_id = await db.record_connection(ip_address=ip_address, service="telnet", port=self.port)
        self.spawn_background(enrich_and_score(ip_address))
        await check_connection_patterns(ip_address)

        if not await self.send_safe(writer, self.get_banner()):
            return

        login_attempts = 0

        for attempt in range(1, MAX_ATTEMPTS_PER_SESSION + 1):
            if attempt > 1 and not await self.send_safe(writer, self.get_banner()):
                break

            username_data = await self.recv_safe(reader, 1024)
            if not username_data:
                break  # client disconnected, or went idle past recv_safe's timeout
            username = username_data.strip()
            self.logger.info(f"Telnet username from {ip_address}: {username}")

            if not await self.send_safe(writer, b"Password: "):
                break

            password_data = await self.recv_safe(reader, 1024)
            if not password_data:
                break
            password = password_data.strip()
            login_attempts += 1

            self.logger.warning(
                f"Telnet login attempt #{login_attempts} from {ip_address}: user={username}, pass={password}"
            )

            await db.record_login_attempt(connection_id, ip_address, username, password)
            await check_and_alert(ip_address, "telnet")

            await asyncio.sleep(2)  # frustrate automated tools
            if not await self.send_safe(writer, b"\r\nLogin incorrect\r\n\r\n"):
                break

        duration = time.monotonic() - start_time
        self.logger.info(
            f"Telnet connection from {ip_address} closed after {duration:.2f}s ({login_attempts} login attempts)"
        )
