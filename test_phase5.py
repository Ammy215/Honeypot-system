"""
Phase 5 Test Suite - Correlation Engine & Advanced Hunting
"""

import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

from database.db import db
from honeypot.detectors.campaign_detector import campaign_detector
from honeypot.detectors.correlation_engine import correlation_engine

console = Console()


def test_campaign_detector():
    """Test campaign detection functionality"""
    
    console.print("\n[cyan]═══ Test 1: Campaign Detector ═══[/cyan]")
    
    try:
        # Detect campaigns
        campaigns = campaign_detector.detect_campaigns(time_window_hours=24)
        
        console.print(f"✓ Campaign detection executed")
        console.print(f"  Detected [yellow]{len(campaigns)}[/yellow] campaigns")
        
        if campaigns:
            # Show campaign types
            type_counts = {}
            for c in campaigns:
                type_counts[c['type']] = type_counts.get(c['type'], 0) + 1
            
            table = Table(title="Campaign Types")
            table.add_column("Type", style="cyan")
            table.add_column("Count", style="yellow")
            
            for ctype, count in type_counts.items():
                table.add_row(ctype, str(count))
            
            console.print(table)
            
            # Show first campaign details
            console.print(f"\n[cyan]Sample Campaign:[/cyan]")
            sample = campaigns[0]
            console.print(f"  Type: {sample['type']}")
            console.print(f"  Severity: {sample.get('severity', 'N/A')}")
            console.print(f"  Attackers: {sample.get('attacker_count', 'N/A')}")
            console.print(f"  Description: {sample.get('description', 'N/A')}")
        
        return True
    
    except Exception as e:
        console.print(f"✗ Campaign detector failed: {e}", style="red")
        return False


def test_campaign_summary():
    """Test campaign summary generation"""
    
    console.print("\n[cyan]═══ Test 2: Campaign Summary ═══[/cyan]")
    
    try:
        summary = campaign_detector.get_campaign_summary()
        
        console.print(f"✓ Campaign summary generated")
        console.print(f"  Total campaigns: [yellow]{summary['total_campaigns']}[/yellow]")
        
        if summary['by_type']:
            console.print("\n  By Type:")
            for ctype, count in summary['by_type'].items():
                console.print(f"    {ctype}: {count}")
        
        if summary['by_severity']:
            console.print("\n  By Severity:")
            for severity, count in summary['by_severity'].items():
                console.print(f"    {severity}: {count}")
        
        return True
    
    except Exception as e:
        console.print(f"✗ Campaign summary failed: {e}", style="red")
        return False


def test_correlation_engine():
    """Test correlation engine"""
    
    console.print("\n[cyan]═══ Test 3: Correlation Engine ═══[/cyan]")
    
    try:
        # Get an attacker with login attempts
        query = """
            SELECT ip_address 
            FROM attackers 
            WHERE total_login_attempts > 0 
            LIMIT 1
        """
        results = db.execute_query(query)
        
        if not results:
            console.print("⊘ No attackers with login attempts yet (skipping)", style="yellow")
            return True
        
        test_ip = results[0]['ip_address']
        
        # Correlate behavior
        analysis = correlation_engine.correlate_attacker_behavior(test_ip)
        
        console.print(f"✓ Behavior correlation completed for {test_ip}")
        console.print(f"  Behavioral score: [yellow]{analysis['behavioral_score']}[/yellow]")
        console.print(f"  Attack sequence length: {len(analysis['attack_sequence'])}")
        
        # Service correlation
        if analysis['service_correlation']:
            sc = analysis['service_correlation']
            console.print(f"  Services targeted: {sc.get('service_count', 0)}")
            console.print(f"  Is scanning: {sc.get('is_scanning', False)}")
        
        # Credential patterns
        if analysis['credential_patterns']:
            cp = analysis['credential_patterns']
            console.print(f"  Credential attack type: {cp.get('attack_type', 'N/A')}")
            console.print(f"  Total attempts: {cp.get('total_attempts', 0)}")
        
        return True
    
    except Exception as e:
        console.print(f"✗ Correlation engine failed: {e}", style="red")
        import traceback
        console.print(traceback.format_exc())
        return False


def test_attack_chains():
    """Test attack chain detection"""
    
    console.print("\n[cyan]═══ Test 4: Attack Chain Detection ═══[/cyan]")
    
    try:
        chains = correlation_engine.detect_attack_chains(time_window_minutes=60)
        
        console.print(f"✓ Attack chain detection executed")
        console.print(f"  Detected [yellow]{len(chains)}[/yellow] attack chains")
        
        if chains:
            # Show statistics
            avg_length = sum(c['length'] for c in chains) / len(chains)
            max_length = max(c['length'] for c in chains)
            
            console.print(f"  Average chain length: {avg_length:.1f}")
            console.print(f"  Longest chain: {max_length} events")
            
            # Show sample chain
            console.print(f"\n[cyan]Sample Chain:[/cyan]")
            sample = chains[0]
            console.print(f"  IP: {sample['ip_address']}")
            console.print(f"  Length: {sample['length']} events")
            console.print(f"  Duration: {sample['duration_minutes']:.1f} minutes")
            console.print(f"  Services: {sample['unique_services']}")
            console.print(f"  Severity: {sample.get('severity', 'N/A')}")
        
        return True
    
    except Exception as e:
        console.print(f"✗ Attack chain detection failed: {e}", style="red")
        return False


def test_similar_attackers():
    """Test finding similar attackers"""
    
    console.print("\n[cyan]═══ Test 5: Similar Attacker Detection ═══[/cyan]")
    
    try:
        # Get an attacker
        query = """
            SELECT ip_address 
            FROM attackers 
            WHERE total_login_attempts > 5 
            LIMIT 1
        """
        results = db.execute_query(query)
        
        if not results:
            console.print("⊘ No suitable attackers yet (skipping)", style="yellow")
            return True
        
        test_ip = results[0]['ip_address']
        
        # Find similar (with lower threshold for testing)
        similar = correlation_engine.find_similar_attackers(test_ip, threshold=0.5)
        
        console.print(f"✓ Similar attacker search completed for {test_ip}")
        console.print(f"  Found [yellow]{len(similar)}[/yellow] similar attackers")
        
        if similar:
            console.print("\n  Top 3 similar:")
            for ip, score in similar[:3]:
                console.print(f"    {ip}: {score:.3f}")
        
        return True
    
    except Exception as e:
        console.print(f"✗ Similar attacker detection failed: {e}", style="red")
        return False


def test_database_queries():
    """Test that all required database tables exist"""
    
    console.print("\n[cyan]═══ Test 6: Database Schema ═══[/cyan]")
    
    try:
        required_tables = [
            'attackers',
            'connections',
            'login_attempts',
            'alerts'
        ]
        
        for table in required_tables:
            query = f"SELECT COUNT(*) as count FROM {table}"
            results = db.execute_query(query)
            count = results[0]['count']
            console.print(f"✓ Table '{table}': {count} rows")
        
        return True
    
    except Exception as e:
        console.print(f"✗ Database check failed: {e}", style="red")
        return False


def main():
    """Run all Phase 5 tests"""
    
    console.print(Panel.fit(
        "[bold cyan]Phase 5 Test Suite[/bold cyan]\n"
        "Correlation Engine & Advanced Hunting",
        border_style="cyan"
    ))
    
    tests = [
        ("Database Schema", test_database_queries),
        ("Campaign Detector", test_campaign_detector),
        ("Campaign Summary", test_campaign_summary),
        ("Correlation Engine", test_correlation_engine),
        ("Attack Chains", test_attack_chains),
        ("Similar Attackers", test_similar_attackers),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            passed = test_func()
            results.append((test_name, passed))
        except Exception as e:
            console.print(f"\n[red]Error in {test_name}: {e}[/red]")
            results.append((test_name, False))
    
    # Summary
    console.print("\n" + "═" * 60)
    console.print("[bold]Test Results Summary[/bold]")
    console.print("═" * 60)
    
    passed_count = sum(1 for _, passed in results if passed)
    total_count = len(results)
    
    table = Table()
    table.add_column("Test", style="cyan")
    table.add_column("Result", style="bold")
    
    for test_name, passed in results:
        status = "[green]✓ PASS[/green]" if passed else "[red]✗ FAIL[/red]"
        table.add_row(test_name, status)
    
    console.print(table)
    
    console.print(f"\n[bold]Total: {passed_count}/{total_count} tests passed[/bold]")
    
    if passed_count == total_count:
        console.print("\n[green bold]✓ All Phase 5 tests passed![/green bold]")
        console.print("\n[cyan]Phase 5 features:[/cyan]")
        console.print("  • Campaign detection (ASN, credential, timing, target)")
        console.print("  • Behavior correlation engine")
        console.print("  • Attack chain detection")
        console.print("  • Similar attacker identification")
        console.print("  • Advanced threat hunting tools")
    else:
        console.print(f"\n[yellow]⚠ {total_count - passed_count} test(s) failed[/yellow]")


if __name__ == "__main__":
    main()
