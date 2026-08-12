#!/usr/bin/env python3
"""
HoneyShield Intelligence Platform — v2 (asyncio rebuild)
Entry point for the async honeypot core.

Which listeners start is controlled by ENABLED_SERVICES (config.py), defaulting
to all four locally. The deployed environment sets ENABLED_SERVICES=HTTP.
"""

import asyncio
import logging
import sys
from pathlib import Path
from rich.logging import RichHandler
from rich.console import Console

import config
from database.db_async import db
from honeypot.services.ssh_honeypot import SSHHoneypot
from honeypot.services.ftp_honeypot import FTPHoneypot
from honeypot.services.telnet_honeypot import TelnetHoneypot
from honeypot.services.http_honeypot import HTTPHoneypot

console = Console()


def setup_logging():
    Path(config.LOG_DIR).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=config.LOG_LEVEL,
        format=config.LOG_FORMAT,
        handlers=[
            RichHandler(console=console, rich_tracebacks=True, tracebacks_show_locals=True),
            logging.FileHandler(Path(config.LOG_DIR) / "honeypot.log", mode="a", encoding="utf-8"),
        ],
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║            🍯  HoneyShield Intelligence Platform  🛡️          ║
    ║                    v2 — asyncio rebuild                     ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


async def run():
    logger = logging.getLogger("honeypot.main")
    logger.info("HoneyShield v2 starting up...")

    console.print("\n[yellow]Connecting to database...[/yellow]")
    await db.connect()
    await db.init_schema()
    console.print(f"[green]✓[/green] Database ready ({db.backend})\n")

    # All four services stay wired up unconditionally; ENABLED_SERVICES only
    # gates which ones actually listen. Production runs HTTP alone because free
    # PaaS tiers route HTTP and not raw TCP — see README "Future Work". Local
    # dev defaults to all four.
    available = {
        "SSH": SSHHoneypot,
        "FTP": FTPHoneypot,
        "TELNET": TelnetHoneypot,
        "HTTP": HTTPHoneypot,
    }

    unknown = [name for name in config.ENABLED_SERVICES if name not in available]
    if unknown:
        raise ValueError(
            f"ENABLED_SERVICES contains unknown service(s): {', '.join(unknown)}. "
            f"Valid values: {', '.join(available)}"
        )

    services = [available[name]() for name in config.ENABLED_SERVICES]
    if not services:
        raise ValueError("ENABLED_SERVICES is empty — nothing to listen on.")

    console.print("[bold cyan]Starting services:[/bold cyan]")
    for service in services:
        console.print(f"  • [green]{service.service_name}[/green] on port [yellow]{service.port}[/yellow]")

    skipped = [name for name in available if name not in config.ENABLED_SERVICES]
    if skipped:
        console.print(
            f"  [dim]Not started (ENABLED_SERVICES): {', '.join(skipped)} — "
            f"built and tested, gated for this deployment[/dim]"
        )

    console.print("\n[bold green]All systems operational![/bold green]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    try:
        await asyncio.gather(*(service.start() for service in services))
    finally:
        for service in services:
            await service.stop()
        await db.close()


def main():
    print_banner()
    setup_logging()
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutdown initiated by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Fatal error:[/bold red] {e}")
        logging.exception("Fatal error in main")
        sys.exit(1)


if __name__ == "__main__":
    main()
