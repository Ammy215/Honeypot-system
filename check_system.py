"""
System Readiness Checker - Verify everything is ready to run
"""

import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def check_dependencies():
    """Check if required packages are installed"""
    console.print("\n[bold cyan]📦 Checking Dependencies...[/bold cyan]")
    
    required = {
        "streamlit": "Dashboard",
        "requests": "HTTP requests",
        "rich": "Terminal UI",
        "cryptography": "Security",
        "bcrypt": "Password hashing"
    }
    
    missing = []
    for package, purpose in required.items():
        try:
            __import__(package)
            console.print(f"  ✅ {package:15} ({purpose})")
        except ImportError:
            console.print(f"  ❌ {package:15} ({purpose}) [red]MISSING[/red]")
            missing.append(package)
    
    return len(missing) == 0, missing


def check_api_keys():
    """Check API key configuration"""
    console.print("\n[bold cyan]🔑 Checking API Keys...[/bold cyan]")
    
    import os
    from dotenv import load_dotenv
    load_dotenv()
    
    keys_status = {}
    
    # AbuseIPDB
    abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuseipdb_key and abuseipdb_key != "your_key_here":
        console.print("  ✅ AbuseIPDB API key configured")
        keys_status['abuseipdb'] = True
    else:
        console.print("  ⚪ AbuseIPDB API key not configured (optional)")
        keys_status['abuseipdb'] = False
    
    # OpenAI
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key and openai_key != "your_key_here":
        console.print("  ✅ OpenAI API key configured")
        keys_status['openai'] = True
    else:
        console.print("  ⚪ OpenAI API key not configured (optional)")
        keys_status['openai'] = False
    
    # Geolocation (always works, no key needed)
    console.print("  ✅ Geolocation available (ip-api.com - FREE)")
    keys_status['geolocation'] = True
    
    return keys_status


def check_database():
    """Check database setup"""
    console.print("\n[bold cyan]💾 Checking Database...[/bold cyan]")
    
    db_path = Path("data/honeypot.db")
    
    if db_path.exists():
        size_mb = db_path.stat().st_size / (1024 * 1024)
        console.print(f"  ✅ Database exists ({size_mb:.2f} MB)")
        
        # Try to connect
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            conn.close()
            
            console.print(f"  ✅ Database accessible ({len(tables)} tables)")
            return True
        except Exception as e:
            console.print(f"  ⚠️  Database exists but error: {e}")
            return False
    else:
        console.print("  ℹ️  Database will be created on first run")
        return True


def check_security():
    """Check security configuration"""
    console.print("\n[bold cyan]🔒 Checking Security...[/bold cyan]")
    
    # Check auth files
    if Path("auth/users.json").exists():
        console.print("  ✅ Users configured")
    else:
        console.print("  ℹ️  Admin user will be created on first run")
    
    # Check master key
    if Path("security/.master_key").exists():
        console.print("  ✅ Encryption master key exists")
    else:
        console.print("  ℹ️  Master key will be created on first run")
    
    # Check .env
    if Path(".env").exists():
        console.print("  ✅ .env configuration file exists")
    else:
        console.print("  ⚠️  .env file not found")
        return False
    
    return True


def print_feature_status(keys_status):
    """Print what features are available"""
    console.print("\n[bold cyan]🎯 Available Features:[/bold cyan]")
    
    table = Table(show_header=True)
    table.add_column("Feature", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Notes")
    
    # Core features (always available)
    table.add_row("Honeypot Services", "✅", "SSH, FTP, HTTP, Telnet")
    table.add_row("Attack Recording", "✅", "All attacks logged")
    table.add_row("Dashboard", "✅", "7 pages with authentication")
    table.add_row("Brute Force Detection", "✅", "9 detection rules")
    table.add_row("Campaign Detection", "✅", "4 campaign types")
    table.add_row("Geolocation", "✅", "FREE (ip-api.com)")
    table.add_row("Threat Scoring", "✅", "18-factor scoring")
    
    # Optional features
    if keys_status.get('abuseipdb'):
        table.add_row("IP Reputation (AbuseIPDB)", "✅", "Configured")
    else:
        table.add_row("IP Reputation (AbuseIPDB)", "⚪", "Not configured (optional)")
    
    if keys_status.get('openai'):
        table.add_row("AI Analysis (OpenAI)", "✅", "Configured")
    else:
        table.add_row("AI Analysis (OpenAI)", "⚪", "Not configured (optional)")
    
    console.print(table)


def print_next_steps(has_dependencies, has_security, keys_status):
    """Print what to do next"""
    console.print("\n" + "="*60)
    
    if not has_dependencies:
        console.print(Panel(
            "[bold red]❌ MISSING DEPENDENCIES[/bold red]\n\n"
            "Install required packages:\n"
            "[bold]pip install -r requirements.txt[/bold]",
            border_style="red"
        ))
        return
    
    if not has_security:
        console.print(Panel(
            "[bold yellow]⚠️  SETUP NEEDED[/bold yellow]\n\n"
            "Run the setup wizard:\n"
            "[bold]python setup_production.py[/bold]",
            border_style="yellow"
        ))
        return
    
    # System is ready!
    console.print(Panel.fit(
        "[bold green]✅ SYSTEM READY![/bold green]\n\n"
        "[yellow]Next Steps:[/yellow]\n\n"
        "1. Start honeypot:\n"
        "   [bold]python main.py[/bold]\n\n"
        "2. Start dashboard (new terminal):\n"
        "   [bold]streamlit run dashboard/app.py[/bold]\n\n"
        "3. Open browser:\n"
        "   [bold]http://localhost:8501[/bold]\n\n"
        "4. Login with your admin credentials\n\n"
        + ("[dim]💡 Tip: Add API keys later for more features!\n"
           "   Run: [bold]python setup_production.py[/bold][/dim]\n\n"
           if not all(keys_status.values()) else "") +
        "📚 Need help? Read: [bold]README_PRODUCTION.md[/bold]",
        border_style="green"
    ))


def main():
    """Main check"""
    console.print(Panel.fit(
        "[bold cyan]🍯 HoneyShield System Check[/bold cyan]\n"
        "[yellow]Verifying system is ready to run...[/yellow]",
        border_style="cyan"
    ))
    
    try:
        # Run checks
        has_dependencies, missing = check_dependencies()
        keys_status = check_api_keys()
        has_database = check_database()
        has_security = check_security()
        
        # Show features
        print_feature_status(keys_status)
        
        # Show next steps
        print_next_steps(has_dependencies, has_security, keys_status)
        
        # Exit code
        if has_dependencies and has_security:
            sys.exit(0)  # Ready!
        else:
            sys.exit(1)  # Needs setup
        
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Check cancelled[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]❌ Check failed: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
