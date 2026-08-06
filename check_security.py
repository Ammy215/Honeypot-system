"""
Security Status Checker - Verify production security configuration
"""

import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def check_authentication():
    """Check authentication configuration"""
    console.print("\n[bold cyan]🔐 Authentication System[/bold cyan]")
    
    issues = []
    
    try:
        from auth.auth_manager import auth_manager
        import config
        
        # Check if enabled
        if not config.ENABLE_AUTHENTICATION:
            issues.append(("❌ CRITICAL", "Authentication is DISABLED!", "Enable in .env"))
        else:
            console.print("  ✅ Authentication enabled")
        
        # Check users
        users = auth_manager.list_users()
        if not users:
            issues.append(("❌ CRITICAL", "No users configured", "Run setup_production.py"))
        else:
            console.print(f"  ✅ {len(users)} user(s) configured")
            
            # Check for admins
            admins = [u for u in users if u['role'] == 'admin']
            if not admins:
                issues.append(("⚠️  WARNING", "No admin users", "Create admin user"))
            else:
                console.print(f"  ✅ {len(admins)} admin(s)")
        
        # Check for default credentials file
        default_creds = Path("auth/default_credentials.txt")
        if default_creds.exists():
            issues.append(("⚠️  WARNING", "Default credentials file exists", "Change password and delete file"))
        else:
            console.print("  ✅ No default credentials file")
        
        # Check session timeout
        if config.SESSION_TIMEOUT_HOURS < 1:
            issues.append(("⚠️  WARNING", "Session timeout too short", "Increase SESSION_TIMEOUT_HOURS"))
        elif config.SESSION_TIMEOUT_HOURS > 24:
            issues.append(("ℹ️  INFO", "Session timeout very long (>24h)", "Consider shorter timeout for security"))
        else:
            console.print(f"  ✅ Session timeout: {config.SESSION_TIMEOUT_HOURS} hours")
        
    except Exception as e:
        issues.append(("❌ ERROR", f"Failed to check authentication: {e}", "Check installation"))
    
    return issues


def check_api_keys():
    """Check API key configuration"""
    console.print("\n[bold cyan]🔑 API Key Management[/bold cyan]")
    
    issues = []
    
    try:
        from security.api_key_manager import api_key_manager
        
        # Check master key
        master_key = Path("security/.master_key")
        if not master_key.exists():
            issues.append(("❌ CRITICAL", "Master key not found", "Run setup_production.py"))
        else:
            console.print("  ✅ Master encryption key exists")
            
            # Check permissions (Unix-like systems)
            try:
                import os
                import stat
                st = os.stat(master_key)
                if stat.S_IMODE(st.st_mode) != 0o600:
                    issues.append(("⚠️  WARNING", "Master key has weak permissions", f"Run: chmod 600 {master_key}"))
                else:
                    console.print("  ✅ Master key has secure permissions")
            except:
                pass
        
        # Check API keys
        keys = api_key_manager.list_keys()
        if not keys:
            issues.append(("⚠️  WARNING", "No API keys configured", "Run setup_production.py"))
        else:
            console.print(f"  ✅ {len(keys)} API key(s) configured")
            
            # Check specific services
            services = {k['service'] for k in keys}
            
            if 'abuseipdb' not in services:
                issues.append(("ℹ️  INFO", "AbuseIPDB key not configured", "Optional but recommended"))
            
            if 'openai' not in services:
                issues.append(("ℹ️  INFO", "OpenAI key not configured", "Optional but required for AI features"))
            
            # Check for inactive keys
            inactive = [k for k in keys if not k['active']]
            if inactive:
                console.print(f"  ℹ️  {len(inactive)} inactive key(s)")
        
    except Exception as e:
        issues.append(("❌ ERROR", f"Failed to check API keys: {e}", "Check installation"))
    
    return issues


def check_database():
    """Check database configuration"""
    console.print("\n[bold cyan]💾 Database Configuration[/bold cyan]")
    
    issues = []
    
    try:
        import config
        
        # Check if production DB is enabled
        if not config.USE_PRODUCTION_DB:
            issues.append(("⚠️  WARNING", "Production DB not enabled", "Set USE_PRODUCTION_DB=true in .env"))
        else:
            console.print("  ✅ Production database enabled")
        
        # Check database file
        db_path = Path(config.DATABASE_PATH)
        if not db_path.exists():
            issues.append(("⚠️  WARNING", "Database file not found", "Will be created on first run"))
        else:
            console.print(f"  ✅ Database exists: {db_path}")
            
            # Check size
            size_mb = db_path.stat().st_size / (1024 * 1024)
            console.print(f"  ℹ️  Database size: {size_mb:.2f} MB")
        
        # Test connection
        try:
            from database.db_production import db_production as db
            
            # Check integrity
            if db.check_integrity():
                console.print("  ✅ Database integrity: OK")
            else:
                issues.append(("❌ CRITICAL", "Database integrity check failed", "Restore from backup"))
            
            # Get stats
            stats = db.get_statistics()
            console.print(f"  ℹ️  Total queries: {stats['total_queries']}")
            console.print(f"  ℹ️  Success rate: {stats['success_rate']:.2f}%")
            
            if stats['success_rate'] < 95:
                issues.append(("⚠️  WARNING", "Low database success rate", "Check logs for errors"))
        
        except Exception as e:
            issues.append(("❌ ERROR", f"Database connection failed: {e}", "Check database file"))
        
        # Check backups
        backup_dir = Path("data")
        backups = list(backup_dir.glob("honeypot_backup_*.db"))
        if not backups:
            issues.append(("⚠️  WARNING", "No backups found", "Create regular backups"))
        else:
            console.print(f"  ✅ {len(backups)} backup(s) found")
        
    except Exception as e:
        issues.append(("❌ ERROR", f"Failed to check database: {e}", "Check installation"))
    
    return issues


def check_audit_logging():
    """Check audit logging configuration"""
    console.print("\n[bold cyan]📊 Audit Logging[/bold cyan]")
    
    issues = []
    
    try:
        import config
        from security.audit_logger import audit_logger
        
        # Check if enabled
        if not config.ENABLE_AUDIT_LOGGING:
            issues.append(("⚠️  WARNING", "Audit logging disabled", "Enable in .env"))
        else:
            console.print("  ✅ Audit logging enabled")
        
        # Check log files
        audit_log = Path("logs/audit.log")
        audit_json = Path("logs/audit.json")
        
        if not audit_log.exists():
            issues.append(("ℹ️  INFO", "Audit log not found", "Will be created on first event"))
        else:
            size_kb = audit_log.stat().st_size / 1024
            console.print(f"  ✅ Audit log exists ({size_kb:.2f} KB)")
        
        if audit_json.exists():
            # Query recent events
            try:
                events = audit_logger.query_events(limit=10)
                console.print(f"  ℹ️  Recent events: {len(events)}")
                
                # Check for failed logins
                failed = audit_logger.get_failed_logins(limit=100)
                if len(failed) > 50:
                    issues.append(("⚠️  WARNING", f"Many failed logins ({len(failed)})", "Investigate potential attacks"))
                
                # Check for suspicious activity
                suspicious = audit_logger.get_suspicious_activity()
                if suspicious:
                    issues.append(("❌ ALERT", f"{len(suspicious)} suspicious events", "Review immediately"))
            
            except Exception as e:
                issues.append(("⚠️  WARNING", f"Cannot query audit log: {e}", "Check log file"))
        
    except Exception as e:
        issues.append(("❌ ERROR", f"Failed to check audit logging: {e}", "Check installation"))
    
    return issues


def check_environment():
    """Check environment configuration"""
    console.print("\n[bold cyan]⚙️  Environment Configuration[/bold cyan]")
    
    issues = []
    
    # Check .env file
    env_file = Path(".env")
    if not env_file.exists():
        issues.append(("❌ CRITICAL", ".env file not found", "Run setup_production.py"))
    else:
        console.print("  ✅ .env file exists")
    
    # Check .env in .gitignore
    gitignore = Path(".gitignore")
    if gitignore.exists():
        with open(gitignore, 'r') as f:
            content = f.read()
            if '.env' in content:
                console.print("  ✅ .env in .gitignore")
            else:
                issues.append(("❌ CRITICAL", ".env not in .gitignore", "Add to .gitignore immediately!"))
    else:
        issues.append(("⚠️  WARNING", ".gitignore not found", "Create .gitignore and add .env"))
    
    # Check required directories
    required_dirs = ['data', 'logs', 'auth', 'security', 'reports']
    for dir_name in required_dirs:
        if Path(dir_name).exists():
            console.print(f"  ✅ {dir_name}/ directory exists")
        else:
            issues.append(("ℹ️  INFO", f"{dir_name}/ directory not found", "Will be created automatically"))
    
    return issues


def check_network_security():
    """Check network security settings"""
    console.print("\n[bold cyan]🌐 Network Security[/bold cyan]")
    
    issues = []
    
    try:
        import config
        
        # Check rate limiting
        if not config.ENABLE_RATE_LIMITING:
            issues.append(("⚠️  WARNING", "Rate limiting disabled", "Enable in .env"))
        else:
            console.print("  ✅ Rate limiting enabled")
            console.print(f"  ℹ️  Dashboard limit: {config.DASHBOARD_RATE_LIMIT} req/min")
        
        # Check honeypot host
        if config.HONEYPOT_HOST == "0.0.0.0":
            issues.append(("ℹ️  INFO", "Honeypot listening on all interfaces", "Expected for honeypot"))
        
        # HTTPS check (coming soon)
        issues.append(("⚠️  WARNING", "HTTPS not configured", "Setup SSL/TLS for production"))
        
    except Exception as e:
        issues.append(("❌ ERROR", f"Failed to check network security: {e}", "Check configuration"))
    
    return issues


def print_summary(all_issues):
    """Print summary of issues"""
    console.print("\n" + "="*60)
    
    critical = [i for i in all_issues if "CRITICAL" in i[0]]
    warnings = [i for i in all_issues if "WARNING" in i[0]]
    info = [i for i in all_issues if "INFO" in i[0]]
    errors = [i for i in all_issues if "ERROR" in i[0]]
    
    # Create summary table
    table = Table(title="Security Status Summary", box=box.ROUNDED)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="center")
    
    if critical:
        table.add_row("❌ Critical", str(len(critical)), style="bold red")
    if errors:
        table.add_row("❌ Errors", str(len(errors)), style="red")
    if warnings:
        table.add_row("⚠️  Warnings", str(len(warnings)), style="yellow")
    if info:
        table.add_row("ℹ️  Info", str(len(info)), style="cyan")
    
    if not all_issues:
        table.add_row("✅ All Clear", "0", style="bold green")
    
    console.print(table)
    
    # Print detailed issues
    if all_issues:
        console.print("\n[bold]Detailed Issues:[/bold]\n")
        
        for severity, issue, solution in all_issues:
            console.print(f"{severity} [bold]{issue}[/bold]")
            console.print(f"  💡 Solution: {solution}\n")
    
    # Overall status
    console.print("="*60)
    
    if critical or errors:
        console.print(Panel(
            "[bold red]❌ SECURITY ISSUES FOUND![/bold red]\n\n"
            "Critical issues must be resolved before production deployment.\n"
            "Run: [bold]python setup_production.py[/bold]",
            border_style="red"
        ))
        return False
    elif warnings:
        console.print(Panel(
            "[bold yellow]⚠️  WARNINGS DETECTED[/bold yellow]\n\n"
            "System is functional but has security warnings.\n"
            "Address warnings for optimal security.",
            border_style="yellow"
        ))
        return True
    else:
        console.print(Panel(
            "[bold green]✅ SECURITY CHECK PASSED![/bold green]\n\n"
            "All security components are properly configured.\n"
            "System is ready for production deployment.",
            border_style="green"
        ))
        return True


def main():
    """Main security check"""
    console.print(Panel.fit(
        "[bold cyan]🔒 HoneyShield Security Status Check[/bold cyan]\n"
        "[yellow]Verifying production security configuration...[/yellow]",
        border_style="cyan"
    ))
    
    all_issues = []
    
    try:
        # Run all checks
        all_issues.extend(check_environment())
        all_issues.extend(check_authentication())
        all_issues.extend(check_api_keys())
        all_issues.extend(check_database())
        all_issues.extend(check_audit_logging())
        all_issues.extend(check_network_security())
        
        # Print summary
        success = print_summary(all_issues)
        
        # Exit code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Check cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]❌ Check failed: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
