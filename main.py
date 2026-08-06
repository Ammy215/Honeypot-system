#!/usr/bin/env python3
"""
HoneyShield Intelligence Platform
Main entry point for the honeypot system
"""

import sys
import logging
from pathlib import Path
from rich.logging import RichHandler
from rich.console import Console
import config
from database.db import init_db
from honeypot.core.server import HoneypotServer

# Setup rich console
console = Console()


def setup_logging():
    """Configure logging with Rich handler and file output"""
    # Create logs directory
    Path(config.LOG_DIR).mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    logging.basicConfig(
        level=config.LOG_LEVEL,
        format=config.LOG_FORMAT,
        handlers=[
            # Console handler with Rich
            RichHandler(
                console=console,
                rich_tracebacks=True,
                tracebacks_show_locals=True
            ),
            # File handler
            logging.FileHandler(
                Path(config.LOG_DIR) / "honeypot.log",
                mode='a',
                encoding='utf-8'
            )
        ]
    )
    
    # Set specific log levels for noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def print_banner():
    """Print startup banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║            🍯  HoneyShield Intelligence Platform  🛡️          ║
    ║                                                               ║
    ║          Advanced Honeypot Trap & Threat Intelligence         ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def main():
    """Main entry point"""
    try:
        # Print banner
        print_banner()
        
        # Setup logging
        setup_logging()
        logger = logging.getLogger("honeypot.main")
        logger.info("HoneyShield starting up...")
        
        # Initialize database
        console.print("\n[yellow]Initializing database...[/yellow]")
        init_db()
        console.print("[green]✓[/green] Database initialized\n")
        
        # Create and initialize server
        console.print("[yellow]Initializing honeypot services...[/yellow]")
        server = HoneypotServer()
        server.initialize_services()
        console.print(f"[green]✓[/green] {len(server.services)} service(s) initialized\n")
        
        # Display service status
        console.print("[bold cyan]Active Services:[/bold cyan]")
        for service in server.services:
            console.print(f"  • [green]{service.service_name}[/green] on port [yellow]{service.port}[/yellow]")
        
        console.print("\n[bold green]All systems operational![/bold green]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")
        
        # Start server (blocks until stopped)
        server.start()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutdown initiated by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Fatal error:[/bold red] {e}")
        logging.exception("Fatal error in main")
        sys.exit(1)


if __name__ == "__main__":
    main()
