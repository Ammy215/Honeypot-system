"""
Asyncio base class for HoneyShield v2 honeypot services.

Replaces the thread-per-connection model (honeypot/core/base_service.py) with
asyncio.start_server, per HONEYSHIELD_PROJECT.md sections 3 and 9. The v1
FTP/HTTP/Telnet services still use the threaded base until they're converted
to asyncio in Phase 2 — this class is only used by the new SSH service so far.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Tuple

import config


class AsyncHoneypotService(ABC):
    """Abstract base for asyncio-based honeypot services."""

    def __init__(self, port: int, service_name: str, host: str = None):
        self.port = port
        self.service_name = service_name
        self.host = host or config.HONEYPOT_HOST
        self.logger = logging.getLogger(f"honeypot.{service_name}")
        self._server: asyncio.base_events.Server = None
        self._active_by_ip: Dict[str, int] = {}
        self._active_total = 0

    async def start(self):
        """Start listening. Blocks (serve_forever) until stop() is called."""
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self.logger.info(f"{self.service_name} honeypot listening on {self.host}:{self.port}")
        async with self._server:
            await self._server.serve_forever()

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self.logger.info(f"{self.service_name} honeypot stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        address: Tuple[str, int] = peer if peer else ("unknown", 0)
        ip_address = address[0]

        if not self._register_connection(ip_address):
            self.logger.warning(f"Rejected connection from {ip_address}: connection limit reached")
            writer.close()
            await writer.wait_closed()
            return

        try:
            await asyncio.wait_for(
                self.handle_connection(reader, writer, address),
                timeout=config.CONNECTION_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            self.logger.info(f"Connection from {ip_address} timed out")
        except (ConnectionResetError, BrokenPipeError):
            self.logger.info(f"Connection from {ip_address} reset by peer")
        except Exception as e:
            self.logger.error(f"Connection handler error from {ip_address}: {e}")
        finally:
            self._release_connection(ip_address)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _register_connection(self, ip: str) -> bool:
        """Enforce the per-IP and global connection caps (spec section 6, point 5)."""
        if self._active_total >= config.MAX_TOTAL_CONNECTIONS:
            return False
        count = self._active_by_ip.get(ip, 0)
        if count >= config.MAX_CONNECTIONS_PER_IP:
            return False
        self._active_by_ip[ip] = count + 1
        self._active_total += 1
        return True

    def _release_connection(self, ip: str):
        count = self._active_by_ip.get(ip, 0)
        if count <= 1:
            self._active_by_ip.pop(ip, None)
        else:
            self._active_by_ip[ip] = count - 1
        self._active_total = max(0, self._active_total - 1)

    @staticmethod
    async def send_safe(writer: asyncio.StreamWriter, data: bytes) -> bool:
        try:
            writer.write(data)
            await writer.drain()
            return True
        except Exception:
            return False

    @staticmethod
    async def recv_safe(reader: asyncio.StreamReader, buffer_size: int = 4096, timeout: float = 5.0) -> str:
        """Read with its own short timeout, so a client that goes idle after the
        first packet doesn't hold the whole connection hostage until the outer
        per-connection watchdog fires (which would skip logging entirely)."""
        try:
            data = await asyncio.wait_for(reader.read(buffer_size), timeout=timeout)
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @abstractmethod
    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, address: Tuple[str, int]
    ):
        """Handle one client connection — must be implemented by subclass."""
        ...
