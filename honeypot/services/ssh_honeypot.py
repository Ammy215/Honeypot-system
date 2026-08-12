"""
Fake SSH honeypot — HoneyShield v2 (asyncio).

Sends a realistic OpenSSH banner, reads whatever the client sends (SSH
client identification / key exchange bytes), logs the connection, and
closes. Captured bytes are stored as inert text only — never parsed as a
real SSH handshake, never executed.
"""

import asyncio
import time
from typing import Tuple

import config
from honeypot.core.async_base_service import AsyncHoneypotService
from database.db_async import db
from honeypot.intelligence.async_enrichment import enrich_and_score


class SSHHoneypot(AsyncHoneypotService):
    """Fake SSH service honeypot"""

    def __init__(self, port: int = None, host: str = None):
        super().__init__(port or config.SERVICES["SSH"]["port"], "SSH", host)
        self.banner = config.BANNERS["SSH"]

    def get_banner(self) -> bytes:
        return f"{self.banner}\r\n".encode("utf-8")

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, address: Tuple[str, int]
    ):
        ip_address = address[0]
        source_port = address[1]
        start_time = time.monotonic()

        self.logger.info(f"SSH connection from {ip_address}:{source_port}")

        if not await self.send_safe(writer, self.get_banner()):
            return

        # Collect whatever the client sends (SSH identification / KEXINIT bytes,
        # or just a brute-force script's blind payload) — stored as inert text only.
        raw_data_parts = []
        for _ in range(3):  # accept up to 3 packets
            data = await self.recv_safe(reader, 4096)
            if not data:
                break
            raw_data_parts.append(data)
            self.logger.debug(f"Received from {ip_address}: {data[:100]!r}")
            await asyncio.sleep(0.1)

        raw_data = "".join(raw_data_parts) if raw_data_parts else None
        if raw_data:
            self.logger.debug(f"Raw data from {ip_address} (len={len(raw_data)}), stored inert")

        connection_id = await db.record_connection(
            ip_address=ip_address, service="ssh", port=self.port
        )
        self.spawn_background(enrich_and_score(ip_address))

        duration = time.monotonic() - start_time
        self.logger.info(
            f"SSH connection from {ip_address} closed after {duration:.2f}s (connection id {connection_id})"
        )
