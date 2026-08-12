"""
Fake FTP honeypot — HoneyShield v2 (asyncio).

Speaks just enough FTP to look real: banner, USER/PASS, SYST/HELP/QUIT.
Every USER/PASS pair is logged as a login attempt; credentials are stored
as inert text only, never interpreted. Closes after 3 failed logins,
matching real FTP server behavior.
"""

import asyncio
import time
from typing import Tuple

import config
from honeypot.core.async_base_service import AsyncHoneypotService
from database.db_async import db
from honeypot.detectors.async_detection import check_and_alert
from honeypot.intelligence.async_enrichment import enrich_and_score

MAX_ATTEMPTS_BEFORE_CLOSE = 3


class FTPHoneypot(AsyncHoneypotService):
    """Fake FTP service honeypot"""

    def __init__(self, port: int = None, host: str = None):
        super().__init__(port or config.SERVICES["FTP"]["port"], "FTP", host)
        self.banner = config.BANNERS["FTP"]

    def get_banner(self) -> bytes:
        return f"{self.banner}\r\n".encode("utf-8")

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, address: Tuple[str, int]
    ):
        ip_address = address[0]
        start_time = time.monotonic()

        self.logger.info(f"FTP connection from {ip_address}:{address[1]}")

        # Log the connection unconditionally, before anything else can fail or
        # time out, so an idle client that never sends a byte still shows up.
        connection_id = await db.record_connection(ip_address=ip_address, service="ftp", port=self.port)
        self.spawn_background(enrich_and_score(ip_address))

        if not await self.send_safe(writer, self.get_banner()):
            return

        login_attempts = 0
        username = None

        while login_attempts < config.MAX_LOGIN_ATTEMPTS_PER_SESSION:
            data = await self.recv_safe(reader, 4096)
            if not data:
                break  # client disconnected, or went idle past recv_safe's timeout

            command = data.strip().upper()
            self.logger.debug(f"FTP command from {ip_address}: {command}")

            if command.startswith("USER "):
                username = data.strip()[5:].strip()
                self.logger.info(f"FTP USER attempt from {ip_address}: {username}")
                await self.send_safe(writer, f"331 Password required for {username}\r\n".encode("utf-8"))

            elif command.startswith("PASS "):
                password = data.strip()[5:].strip()
                login_attempts += 1

                self.logger.warning(
                    f"FTP login attempt #{login_attempts} from {ip_address}: user={username}, pass={password}"
                )

                await db.record_login_attempt(connection_id, ip_address, username, password)
                await check_and_alert(ip_address, "ftp")

                await asyncio.sleep(2)  # frustrate automated tools

                if login_attempts >= MAX_ATTEMPTS_BEFORE_CLOSE:
                    await self.send_safe(writer, b"421 Too many login failures. Connection closing.\r\n")
                    break
                await self.send_safe(writer, b"530 Login incorrect.\r\n")

            elif command.startswith("QUIT"):
                await self.send_safe(writer, b"221 Goodbye.\r\n")
                break

            elif command.startswith("SYST"):
                await self.send_safe(writer, b"215 UNIX Type: L8\r\n")

            elif command.startswith("HELP"):
                await self.send_safe(
                    writer, b"214 The following commands are recognized:\r\n USER PASS QUIT SYST HELP\r\n214 Help OK.\r\n"
                )

            else:
                await self.send_safe(writer, b"500 Unknown command.\r\n")

        duration = time.monotonic() - start_time
        self.logger.info(
            f"FTP connection from {ip_address} closed after {duration:.2f}s ({login_attempts} login attempts)"
        )
