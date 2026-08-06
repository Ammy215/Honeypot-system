"""
Complete System Test Suite - Test all components
"""

import sys
import os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import time

console = Console()

class TestResults:
    def __init__(self):
        self.passed = []
        self.failed = []
        self.warnings = []
    
    def add_pass(self, test_name, details=""):
        self.passed.append((test_name, details))
    
    def add_fail(self, test_name, error):
        self.failed.append((test_name, str(error)))
    
    def add_warning(self, test_name, warning):
        self.warnings.append((test_name, warning))
    
    def print_summary(self):
        console.print("\n" + "="*60)
        
        table = Table(title="Test Results Summary", show_header=True)
        table.add_column("Category", style="cyan")
        table.add_column("Count", justify="center")
        table.add_column("Status", justify="center")
        
        total = len(self.passed) + len(self.failed)
        pass_rate = (len(self.passed) / total * 100) if total > 0 else 0
        
        table.add_row("✅ Passed", str(len(self.passed)), f"{pass_rate:.1f}%", style="green")
        table.add_row("❌ Failed", str(len(self.failed)), "", style="red")
        table.add_row("⚠️  Warnings", str(len(self.warnings)), "", style="yellow")
        table.add_row("Total Tests", str(total), "", style="bold")
        
        console.print(table)
        
        # Show failures
        if self.failed:
            console.print("\n[bold red]Failed Tests:[/bold red]")
            for test, error in self.failed:
                console.print(f"  ❌ {test}: {error}")
        
        # Show warnings
        if self.warnings:
            console.print("\n[bold yellow]Warnings:[/bold yellow]")
            for test, warning in self.warnings:
                console.print(f"  ⚠️  {test}: {warning}")
        
        # Final verdict
        console.print("\n" + "="*60)
        if not self.failed:
            console.print(Panel(
                "[bold green]✅ ALL TESTS PASSED![/bold green]\n\n"
                "System is ready for deployment!",
                border_style="green"
            ))
            return True
        else:
            console.print(Panel(
                f"[bold red]❌ {len(self.failed)} TEST(S) FAILED[/bold red]\n\n"
                "Fix the issues before deployment.",
                border_style="red"
            ))
            return False


def test_dependencies(results):
    """Test 1: Check all required packages"""
    console.print("\n[bold cyan]Test 1: Dependencies[/bold cyan]")
    
    required = {
        "streamlit": "Dashboard framework",
        "requests": "HTTP client",
        "rich": "Terminal UI",
        "cryptography": "Encryption",
        "bcrypt": "Password hashing",
        "pandas": "Data processing",
        "plotly": "Charts",
        "openai": "AI features"
    }
    
    for package, purpose in required.items():
        try:
            __import__(package)
            console.print(f"  ✅ {package}")
            results.add_pass(f"Dependency: {package}")
        except ImportError:
            console.print(f"  ❌ {package}")
            results.add_fail(f"Dependency: {package}", "Not installed")


def test_configuration(results):
    """Test 2: Check configuration files"""
    console.print("\n[bold cyan]Test 2: Configuration Files[/bold cyan]")
    
    # Check .env
    if Path(".env").exists():
        console.print("  ✅ .env file exists")
        results.add_pass("Config: .env file")
    else:
        console.print("  ❌ .env file missing")
        results.add_fail("Config: .env file", "File not found")
    
    # Check config.py
    try:
        import config
        console.print("  ✅ config.py loads")
        results.add_pass("Config: config.py")
    except Exception as e:
        console.print(f"  ❌ config.py error: {e}")
        results.add_fail("Config: config.py", str(e))


def test_api_keys(results):
    """Test 3: Check API keys"""
    console.print("\n[bold cyan]Test 3: API Keys[/bold cyan]")
    
    try:
        from security.api_key_manager import api_key_manager
        
        keys = api_key_manager.list_keys()
        
        if not keys:
            console.print("  ⚠️  No API keys configured")
            results.add_warning("API Keys", "No keys configured")
        else:
            for key_info in keys:
                service = key_info['service']
                active = key_info['active']
                if active:
                    console.print(f"  ✅ {service}: Active")
                    results.add_pass(f"API Key: {service}")
                else:
                    console.print(f"  ⚠️  {service}: Inactive")
                    results.add_warning(f"API Key: {service}", "Inactive")
        
        # Test if keys work
        if any(k['service'] == 'abuseipdb' and k['active'] for k in keys):
            console.print("  ✅ AbuseIPDB key configured")
        else:
            console.print("  ⚠️  AbuseIPDB key not configured")
            results.add_warning("API Key: AbuseIPDB", "Not configured (optional)")
        
    except Exception as e:
        console.print(f"  ❌ API key check failed: {e}")
        results.add_fail("API Keys", str(e))


def test_authentication(results):
    """Test 4: Check authentication system"""
    console.print("\n[bold cyan]Test 4: Authentication System[/bold cyan]")
    
    try:
        from auth.auth_manager import auth_manager
        
        # Check users
        users = auth_manager.list_users()
        
        if not users:
            console.print("  ❌ No users configured")
            results.add_fail("Auth: Users", "No users found")
        else:
            console.print(f"  ✅ {len(users)} user(s) configured")
            results.add_pass("Auth: Users")
            
            # Check for admin
            admins = [u for u in users if u['role'] == 'admin']
            if admins:
                console.print(f"  ✅ {len(admins)} admin(s)")
                results.add_pass("Auth: Admin user")
            else:
                console.print("  ❌ No admin users")
                results.add_fail("Auth: Admin", "No admin user found")
        
        # Test password hashing
        test_hash = auth_manager.hash_password("test123")
        if auth_manager.verify_password("test123", test_hash):
            console.print("  ✅ Password hashing works")
            results.add_pass("Auth: Password hashing")
        else:
            console.print("  ❌ Password hashing failed")
            results.add_fail("Auth: Password hashing", "Verification failed")
        
    except Exception as e:
        console.print(f"  ❌ Auth system error: {e}")
        results.add_fail("Auth: System", str(e))


def test_database(results):
    """Test 5: Check database"""
    console.print("\n[bold cyan]Test 5: Database[/bold cyan]")
    
    try:
        import sqlite3
        import config
        
        db_path = Path(config.DATABASE_PATH)
        
        if db_path.exists():
            console.print(f"  ✅ Database exists: {db_path}")
            results.add_pass("Database: File exists")
            
            # Test connection
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            console.print(f"  ✅ {len(tables)} tables found")
            results.add_pass("Database: Tables")
            
            # Check key tables
            table_names = [t[0] for t in tables]
            required_tables = ['attackers', 'connections', 'login_attempts', 'alerts']
            
            for table in required_tables:
                if table in table_names:
                    # Get count
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    console.print(f"  ✅ Table '{table}': {count} rows")
                    results.add_pass(f"Database: {table} table")
                else:
                    console.print(f"  ❌ Table '{table}': Missing")
                    results.add_fail(f"Database: {table}", "Table not found")
            
            conn.close()
        else:
            console.print("  ℹ️  Database will be created on first run")
            results.add_warning("Database", "Will be created automatically")
        
    except Exception as e:
        console.print(f"  ❌ Database error: {e}")
        results.add_fail("Database", str(e))


def test_security(results):
    """Test 6: Check security components"""
    console.print("\n[bold cyan]Test 6: Security Components[/bold cyan]")
    
    # Master key
    master_key = Path("security/.master_key")
    if master_key.exists():
        console.print("  ✅ Master encryption key exists")
        results.add_pass("Security: Master key")
    else:
        console.print("  ⚠️  Master key will be created on first run")
        results.add_warning("Security: Master key", "Will be created")
    
    # Audit logger
    try:
        from security.audit_logger import audit_logger
        console.print("  ✅ Audit logger available")
        results.add_pass("Security: Audit logger")
    except Exception as e:
        console.print(f"  ❌ Audit logger error: {e}")
        results.add_fail("Security: Audit logger", str(e))


def test_honeypot_services(results):
    """Test 7: Check honeypot services"""
    console.print("\n[bold cyan]Test 7: Honeypot Services[/bold cyan]")
    
    services = {
        "SSH": "honeypot/services/ssh_honeypot.py",
        "FTP": "honeypot/services/ftp_honeypot.py",
        "HTTP": "honeypot/services/http_honeypot.py",
        "Telnet": "honeypot/services/telnet_honeypot.py"
    }
    
    for service, path in services.items():
        if Path(path).exists():
            console.print(f"  ✅ {service} honeypot exists")
            results.add_pass(f"Service: {service}")
        else:
            console.print(f"  ❌ {service} honeypot missing")
            results.add_fail(f"Service: {service}", "File not found")


def test_detection_engines(results):
    """Test 8: Check detection engines"""
    console.print("\n[bold cyan]Test 8: Detection Engines[/bold cyan]")
    
    engines = {
        "Brute Force": "honeypot/detectors/brute_force.py",
        "Campaign": "honeypot/detectors/campaign_detector.py",
        "Correlation": "honeypot/detectors/correlation_engine.py"
    }
    
    for engine, path in engines.items():
        if Path(path).exists():
            console.print(f"  ✅ {engine} detector exists")
            results.add_pass(f"Detection: {engine}")
        else:
            console.print(f"  ❌ {engine} detector missing")
            results.add_fail(f"Detection: {engine}", "File not found")


def test_intelligence(results):
    """Test 9: Check intelligence modules"""
    console.print("\n[bold cyan]Test 9: Intelligence Modules[/bold cyan]")
    
    modules = {
        "Geolocation": "honeypot/intelligence/geolocation.py",
        "AbuseIPDB": "honeypot/intelligence/abuseipdb.py",
        "Threat Scorer": "honeypot/intelligence/threat_scorer.py"
    }
    
    for module, path in modules.items():
        if Path(path).exists():
            console.print(f"  ✅ {module} exists")
            results.add_pass(f"Intelligence: {module}")
        else:
            console.print(f"  ❌ {module} missing")
            results.add_fail(f"Intelligence: {module}", "File not found")


def test_dashboard(results):
    """Test 10: Check dashboard"""
    console.print("\n[bold cyan]Test 10: Dashboard[/bold cyan]")
    
    # Main dashboard
    if Path("dashboard/app.py").exists():
        console.print("  ✅ Main dashboard exists")
        results.add_pass("Dashboard: Main app")
    else:
        console.print("  ❌ Main dashboard missing")
        results.add_fail("Dashboard: Main app", "File not found")
    
    # Dashboard pages
    pages = [
        "01_🔴_Live_Feed.py",
        "02_🌍_Attacker_Intel.py",
        "03_📈_Analytics.py",
        "04_🚨_Alerts.py",
        "05_🔍_Threat_Hunting.py",
        "06_🎪_Campaigns.py",
        "07_🤖_AI_Analysis.py"
    ]
    
    for page in pages:
        path = Path(f"dashboard/pages/{page}")
        if path.exists():
            console.print(f"  ✅ {page}")
            results.add_pass(f"Dashboard: {page}")
        else:
            console.print(f"  ❌ {page}")
            results.add_fail(f"Dashboard: {page}", "File not found")


def test_imports(results):
    """Test 11: Test critical imports"""
    console.print("\n[bold cyan]Test 11: Critical Imports[/bold cyan]")
    
    imports_to_test = [
        ("config", "Configuration"),
        ("database.db", "Database manager"),
        ("auth.auth_manager", "Auth manager"),
        ("security.api_key_manager", "API key manager"),
        ("security.audit_logger", "Audit logger")
    ]
    
    for module, name in imports_to_test:
        try:
            __import__(module)
            console.print(f"  ✅ {name}")
            results.add_pass(f"Import: {name}")
        except Exception as e:
            console.print(f"  ❌ {name}: {e}")
            results.add_fail(f"Import: {name}", str(e))


def test_ports_available(results):
    """Test 12: Check if ports are available"""
    console.print("\n[bold cyan]Test 12: Port Availability[/bold cyan]")
    
    import socket
    
    ports = {
        2222: "SSH Honeypot",
        2121: "FTP Honeypot",
        8080: "HTTP Honeypot",
        2323: "Telnet Honeypot",
        8501: "Dashboard"
    }
    
    for port, service in ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        
        if result != 0:
            console.print(f"  ✅ Port {port} ({service}): Available")
            results.add_pass(f"Port: {port} - {service}")
        else:
            console.print(f"  ⚠️  Port {port} ({service}): In use")
            results.add_warning(f"Port: {port}", f"{service} port already in use")


def main():
    """Run all tests"""
    console.print(Panel.fit(
        "[bold cyan]🧪 HoneyShield Complete System Test[/bold cyan]\n"
        "[yellow]Testing all components...[/yellow]",
        border_style="cyan"
    ))
    
    results = TestResults()
    
    try:
        # Run all tests
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Running tests...", total=12)
            
            test_dependencies(results)
            progress.advance(task)
            
            test_configuration(results)
            progress.advance(task)
            
            test_api_keys(results)
            progress.advance(task)
            
            test_authentication(results)
            progress.advance(task)
            
            test_database(results)
            progress.advance(task)
            
            test_security(results)
            progress.advance(task)
            
            test_honeypot_services(results)
            progress.advance(task)
            
            test_detection_engines(results)
            progress.advance(task)
            
            test_intelligence(results)
            progress.advance(task)
            
            test_dashboard(results)
            progress.advance(task)
            
            test_imports(results)
            progress.advance(task)
            
            test_ports_available(results)
            progress.advance(task)
        
        # Print results
        success = results.print_summary()
        
        # Exit code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Testing cancelled[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]❌ Testing error: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
