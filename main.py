#!/usr/bin/env python3
"""
HoneyShield Intelligence Platform — v2 (asyncio rebuild)
Entry point for the async honeypot core. Per HONEYSHIELD_PROJECT.md,
Phase 1 starts only the SSH listener; FTP/HTTP/Telnet are converted to
asyncio in Phase 2.
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

    services = [SSHHoneypot()]

    console.print("[bold cyan]Starting services:[/bold cyan]")
    for service in services:
        console.print(f"  • [green]{service.service_name}[/green] on port [yellow]{service.port}[/yellow]")

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
