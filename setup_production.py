"""
Production Setup Script - Configure HoneyShield for production deployment
"""

import os
import sys
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table

console = Console()


def print_banner():
    """Print setup banner"""
    console.print(Panel.fit(
        "[bold cyan]🔒 HoneyShield Production Setup[/bold cyan]\n"
        "[yellow]Secure your honeypot deployment[/yellow]",
        border_style="cyan"
    ))


def check_requirements():
    """Check if required packages are installed"""
    console.print("\n[bold]Checking requirements...[/bold]")
    
    required = [
        "streamlit",
        "cryptography",
        "bcrypt",
        "requests",
        "openai",
        "rich"
    ]
    
    missing = []
    for package in required:
        try:
            __import__(package)
            console.print(f"  ✅ {package}")
        except ImportError:
            console.print(f"  ❌ {package} [red](missing)[/red]")
            missing.append(package)
    
    if missing:
        console.print(f"\n[red]Missing packages: {', '.join(missing)}[/red]")
        console.print("Run: [bold]pip install -r requirements.txt[/bold]")
        return False
    
    return True


def setup_api_keys():
    """Setup and encrypt API keys"""
    console.print("\n[bold cyan]📦 API Key Configuration[/bold cyan]")
    
    from security.api_key_manager import api_key_manager
    
    # Check if keys already exist
    existing_keys = api_key_manager.list_keys()
    
    if existing_keys:
        console.print("\n[yellow]Existing API keys found:[/yellow]")
        for key_info in existing_keys:
            console.print(f"  • {key_info['service']} ({'active' if key_info['active'] else 'inactive'})")
        
        if not Confirm.ask("\nDo you want to add/update API keys?"):
            return
    
    # AbuseIPDB
    console.print("\n[bold]AbuseIPDB API Key[/bold]")
    console.print("Get your key from: https://www.abuseipdb.com/api")
    
    if Confirm.ask("Configure AbuseIPDB?"):
        api_key = Prompt.ask("Enter AbuseIPDB API key", password=True)
        if api_key and api_key != "":
            api_key_manager.add_key(
                "abuseipdb",
                api_key,
                "AbuseIPDB Threat Intelligence",
                rate_limit=1000,
                rate_period="day"
            )
            console.print("  ✅ AbuseIPDB key saved")
    
    # OpenAI
    console.print("\n[bold]OpenAI API Key[/bold]")
    console.print("Get your key from: https://platform.openai.com/api-keys")
    
    if Confirm.ask("Configure OpenAI?"):
        api_key = Prompt.ask("Enter OpenAI API key", password=True)
        if api_key and api_key != "":
            api_key_manager.add_key(
                "openai",
                api_key,
                "OpenAI GPT API",
                rate_limit=10000,
                rate_period="day"
            )
            console.print("  ✅ OpenAI key saved")
    
    # AlienVault OTX (optional)
    console.print("\n[bold]AlienVault OTX API Key[/bold] (Optional)")
    
    if Confirm.ask("Configure AlienVault OTX?", default=False):
        api_key = Prompt.ask("Enter OTX API key", password=True)
        if api_key and api_key != "":
            api_key_manager.add_key(
                "otx",
                api_key,
                "AlienVault OTX",
                rate_limit=10000,
                rate_period="hour"
            )
            console.print("  ✅ OTX key saved")
    
    console.print("\n[green]✅ API keys encrypted and saved![/green]")


def setup_authentication():
    """Setup admin user and authentication"""
    console.print("\n[bold cyan]🔐 Authentication Setup[/bold cyan]")
    
    from auth.auth_manager import auth_manager
    
    # Check if admin user exists
    users = auth_manager.list_users()
    admin_exists = any(u['username'] == 'admin' for u in users)
    
    if admin_exists:
        console.print("\n[yellow]Admin user already exists[/yellow]")
        
        if Confirm.ask("Do you want to change the admin password?"):
            old_password = Prompt.ask("Enter current admin password", password=True)
            new_password = Prompt.ask("Enter new admin password", password=True)
            confirm_password = Prompt.ask("Confirm new admin password", password=True)
            
            if new_password != confirm_password:
                console.print("[red]❌ Passwords don't match![/red]")
                return
            
            if auth_manager.change_password("admin", old_password, new_password):
                console.print("[green]✅ Admin password changed![/green]")
                
                # Delete default credentials file
                default_creds = Path("auth/default_credentials.txt")
                if default_creds.exists():
                    default_creds.unlink()
                    console.print("  • Default credentials file removed")
            else:
                console.print("[red]❌ Failed to change password (incorrect old password?)[/red]")
        
        return
    
    # Create new admin user
    console.print("\n[bold]Create Admin User[/bold]")
    console.print("The admin user will have full access to the system")
    
    username = Prompt.ask("Admin username", default="admin")
    password = Prompt.ask("Admin password", password=True)
    confirm_password = Prompt.ask("Confirm password", password=True)
    
    if password != confirm_password:
        console.print("[red]❌ Passwords don't match![/red]")
        return
    
    if len(password) < 8:
        console.print("[yellow]⚠️  Warning: Password is too short (minimum 8 characters recommended)[/yellow]")
        if not Confirm.ask("Continue anyway?"):
            return
    
    email = Prompt.ask("Admin email (optional)", default="")
    
    if auth_manager.create_user(username, password, "admin", email):
        console.print(f"\n[green]✅ Admin user '{username}' created![/green]")
        
        # Delete default credentials file
        default_creds = Path("auth/default_credentials.txt")
        if default_creds.exists():
            default_creds.unlink()
            console.print("  • Default credentials file removed")
    else:
        console.print("[red]❌ Failed to create admin user![/red]")


def setup_database():
    """Setup database configuration"""
    console.print("\n[bold cyan]💾 Database Configuration[/bold cyan]")
    
    from database.db_production import db_production
    
    # Check database integrity
    console.print("\nChecking database...")
    
    if db_production.check_integrity():
        console.print("  ✅ Database integrity: OK")
    else:
        console.print("  ❌ Database integrity: FAILED")
        if Confirm.ask("Do you want to continue anyway?", default=False):
            pass
        else:
            return
    
    # Get statistics
    stats = db_production.get_statistics()
    
    console.print(f"\n[bold]Database Statistics:[/bold]")
    console.print(f"  • Total queries: {stats['total_queries']}")
    console.print(f"  • Errors: {stats['errors']}")
    console.print(f"  • Success rate: {stats['success_rate']:.2f}%")
    
    if 'tables' in stats:
        console.print("\n[bold]Table Counts:[/bold]")
        for table, count in stats['tables'].items():
            console.print(f"  • {table}: {count} rows")
    
    # Backup option
    if Confirm.ask("\nCreate database backup?", default=True):
        from datetime import datetime
        backup_path = f"data/honeypot_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        
        if db_production.backup_database(backup_path):
            console.print(f"[green]✅ Backup created: {backup_path}[/green]")
        else:
            console.print("[red]❌ Backup failed![/red]")
    
    # Optimize option
    if Confirm.ask("Optimize database (VACUUM)?", default=False):
        if db_production.vacuum_database():
            console.print("[green]✅ Database optimized![/green]")
        else:
            console.print("[red]❌ Optimization failed![/red]")


def setup_env_file():
    """Setup .env file"""
    console.print("\n[bold cyan]⚙️  Environment Configuration[/bold cyan]")
    
    env_file = Path(".env")
    
    if env_file.exists():
        console.print("\n[yellow].env file already exists[/yellow]")
        if not Confirm.ask("Do you want to update it?"):
            return
    
    # Read .env.example as template
    example_file = Path(".env.example")
    if example_file.exists():
        with open(example_file, 'r') as f:
            template = f.read()
    else:
        template = ""
    
    # Configuration options
    enable_auth = Confirm.ask("Enable authentication?", default=True)
    use_prod_db = Confirm.ask("Use production database manager?", default=True)
    enable_audit = Confirm.ask("Enable audit logging?", default=True)
    
    # Write .env
    with open(env_file, 'w') as f:
        f.write("# HoneyShield Production Configuration\n\n")
        f.write(f"ENABLE_AUTHENTICATION={'true' if enable_auth else 'false'}\n")
        f.write("SESSION_TIMEOUT_HOURS=8\n\n")
        f.write(f"USE_PRODUCTION_DB={'true' if use_prod_db else 'false'}\n")
        f.write("DB_POOL_SIZE=5\n\n")
        f.write(f"ENABLE_AUDIT_LOGGING={'true' if enable_audit else 'false'}\n")
        f.write("ENABLE_RATE_LIMITING=true\n")
        f.write("DASHBOARD_RATE_LIMIT=100\n\n")
        f.write("# API Keys (managed by APIKeyManager - these are legacy)\n")
        f.write("ABUSEIPDB_API_KEY=managed_by_security\n")
        f.write("OPENAI_API_KEY=managed_by_security\n")
        f.write("OTX_API_KEY=managed_by_security\n")
    
    console.print("[green]✅ .env file created![/green]")


def show_summary():
    """Show setup summary"""
    console.print("\n" + "="*60)
    console.print(Panel.fit(
        "[bold green]✅ Production Setup Complete![/bold green]\n\n"
        "[yellow]Next Steps:[/yellow]\n"
        "1. Run honeypot: [bold]python main.py[/bold]\n"
        "2. Run dashboard: [bold]streamlit run dashboard/app.py[/bold]\n"
        "3. Login with your admin credentials\n"
        "4. Monitor security logs in [bold]logs/audit.log[/bold]\n\n"
        "[red]⚠️  Important Security Notes:[/red]\n"
        "• Keep [bold]security/.master_key[/bold] backed up securely\n"
        "• Never commit [bold].env[/bold] to version control\n"
        "• Change default passwords immediately\n"
        "• Enable HTTPS for production deployment\n"
        "• Regularly backup your database\n"
        "• Review audit logs frequently",
        border_style="green"
    ))


def main():
    """Main setup flow"""
    print_banner()
    
    # Check requirements
    if not check_requirements():
        console.print("\n[red]❌ Setup cannot continue. Install missing packages first.[/red]")
        sys.exit(1)
    
    console.print("\n[green]✅ All requirements satisfied![/green]")
    
    # Setup flow
    try:
        # 1. Environment file
        setup_env_file()
        
        # 2. API Keys
        setup_api_keys()
        
        # 3. Authentication
        setup_authentication()
        
        # 4. Database
        setup_database()
        
        # Summary
        show_summary()
        
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Setup cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]❌ Setup error: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
