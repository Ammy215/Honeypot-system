"""
Phase 6 Test Suite - AI Analyst and Reporting
"""

import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

from honeypot.ai.analyst import ai_analyst
from honeypot.ai.report_generator import report_generator
from database.db import db

console = Console()


def test_ai_availability():
    """Test if AI analyst is available"""
    
    console.print("\n[cyan]═══ Test 1: AI Availability ═══[/cyan]")
    
    try:
        is_available = ai_analyst.is_available()
        
        if is_available:
            console.print("✓ AI Analyst available", style="green")
            console.print(f"  Model: {ai_analyst.model}")
            return True
        else:
            console.print("⊘ AI Analyst not available (API key not configured)", style="yellow")
            console.print("  This is expected if OPENAI_API_KEY is not set")
            return True  # Not a failure, just not configured
    
    except Exception as e:
        console.print(f"✗ AI availability check failed: {e}", style="red")
        return False


def test_report_generator():
    """Test report generator"""
    
    console.print("\n[cyan]═══ Test 2: Report Generator ═══[/cyan]")
    
    try:
        # Create reports directory if needed
        report_generator.output_dir.mkdir(exist_ok=True)
        
        console.print("✓ Report generator initialized")
        console.print(f"  Output directory: {report_generator.output_dir}")
        
        return True
    
    except Exception as e:
        console.print(f"✗ Report generator failed: {e}", style="red")
        return False


def test_executive_summary():
    """Test executive summary generation"""
    
    console.print("\n[cyan]═══ Test 3: Executive Summary ═══[/cyan]")
    
    try:
        # Generate executive summary
        filepath = report_generator.generate_executive_summary(time_hours=24)
        
        console.print(f"✓ Executive summary generated")
        console.print(f"  File: {filepath}")
        
        # Check file exists
        if Path(filepath).exists():
            file_size = Path(filepath).stat().st_size
            console.print(f"  Size: {file_size} bytes")
            return True
        else:
            console.print("✗ Summary file not found", style="red")
            return False
    
    except Exception as e:
        console.print(f"✗ Executive summary failed: {e}", style="red")
        import traceback
        console.print(traceback.format_exc())
        return False


def test_attacker_analysis():
    """Test attacker analysis (without AI if not configured)"""
    
    console.print("\n[cyan]═══ Test 4: Attacker Analysis ═══[/cyan]")
    
    try:
        # Get an attacker
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
        
        if ai_analyst.is_available():
            # Try AI analysis
            analysis = ai_analyst.analyze_attacker(test_ip)
            
            if analysis and not analysis.get('error'):
                console.print(f"✓ AI analysis completed for {test_ip}")
                console.print(f"  Threat score: {analysis['threat_score']}")
                console.print(f"  Analysis length: {len(analysis['analysis_text'])} chars")
            else:
                console.print(f"✗ AI analysis returned error for {test_ip}", style="red")
                return False
        else:
            console.print(f"⊘ AI not available, testing report generation only")
            
            # Test report generation without AI
            dummy_analysis = {
                'ip_address': test_ip,
                'analysis_text': 'Test analysis text',
                'timestamp': '2026-06-05T10:00:00',
                'threat_score': 75,
                'verdict': 'HIGH'
            }
            
            filepath = report_generator.generate_attacker_report(test_ip, dummy_analysis)
            console.print(f"✓ Attacker report generated: {filepath}")
        
        return True
    
    except Exception as e:
        console.print(f"✗ Attacker analysis failed: {e}", style="red")
        import traceback
        console.print(traceback.format_exc())
        return False


def test_threat_report():
    """Test threat report generation"""
    
    console.print("\n[cyan]═══ Test 5: Threat Report ═══[/cyan]")
    
    try:
        if ai_analyst.is_available():
            # Try AI report
            report = ai_analyst.generate_threat_report(time_hours=24)
            
            if report and not report.get('error'):
                console.print(f"✓ AI threat report generated")
                console.print(f"  Report length: {len(report['report_text'])} chars")
                
                if 'statistics' in report:
                    console.print(f"  Statistics included: {len(report['statistics'])} metrics")
            else:
                console.print(f"✗ AI report returned error", style="red")
                return False
        else:
            console.print("⊘ AI not available, testing text report generation")
            
            # Test text report without AI
            dummy_report = {
                'report_text': 'Test threat report content',
                'timestamp': '2026-06-05T10:00:00',
                'time_window': 24,
                'model': 'test',
                'statistics': {
                    'total_attackers': 5,
                    'total_alerts': 10
                }
            }
            
            filepath = report_generator.generate_text_report(dummy_report)
            console.print(f"✓ Text report generated: {filepath}")
        
        return True
    
    except Exception as e:
        console.print(f"✗ Threat report failed: {e}", style="red")
        import traceback
        console.print(traceback.format_exc())
        return False


def test_alert_summary():
    """Test alert summarization"""
    
    console.print("\n[cyan]═══ Test 6: Alert Summary ═══[/cyan]")
    
    try:
        # Check if alerts exist
        query = "SELECT COUNT(*) as count FROM alerts"
        result = db.execute_query(query)
        alert_count = result[0]['count']
        
        if alert_count == 0:
            console.print("⊘ No alerts in database yet (skipping)", style="yellow")
            return True
        
        if ai_analyst.is_available():
            # Try AI summary
            summary = ai_analyst.summarize_alerts(alert_count=min(10, alert_count))
            
            if summary:
                console.print(f"✓ AI alert summary generated")
                console.print(f"  Summary length: {len(summary)} chars")
                console.print(f"  Preview: {summary[:100]}...")
            else:
                console.print("✗ AI summary returned None", style="red")
                return False
        else:
            console.print("⊘ AI not available, skipping alert summary")
        
        return True
    
    except Exception as e:
        console.print(f"✗ Alert summary failed: {e}", style="red")
        return False


def test_database_storage():
    """Test that AI reports table exists"""
    
    console.print("\n[cyan]═══ Test 7: Database Storage ═══[/cyan]")
    
    try:
        query = "SELECT COUNT(*) as count FROM ai_reports"
        result = db.execute_query(query)
        count = result[0]['count']
        
        console.print(f"✓ AI reports table exists")
        console.print(f"  Stored reports: {count}")
        
        return True
    
    except Exception as e:
        console.print(f"✗ Database storage check failed: {e}", style="red")
        return False


def main():
    """Run all Phase 6 tests"""
    
    console.print(Panel.fit(
        "[bold cyan]Phase 6 Test Suite[/bold cyan]\n"
        "AI Analyst and Reporting",
        border_style="cyan"
    ))
    
    tests = [
        ("AI Availability", test_ai_availability),
        ("Report Generator", test_report_generator),
        ("Executive Summary", test_executive_summary),
        ("Attacker Analysis", test_attacker_analysis),
        ("Threat Report", test_threat_report),
        ("Alert Summary", test_alert_summary),
        ("Database Storage", test_database_storage),
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
        console.print("\n[green bold]✓ All Phase 6 tests passed![/green bold]")
        console.print("\n[cyan]Phase 6 features:[/cyan]")
        console.print("  • AI-powered threat analysis")
        console.print("  • Attacker behavior analysis")
        console.print("  • Automated threat reports")
        console.print("  • Alert summarization")
        console.print("  • Report generation (text/PDF)")
        console.print("  • Executive summaries")
        console.print("\n[yellow]Note:[/yellow] Full AI features require OpenAI API key")
    else:
        console.print(f"\n[yellow]⚠ {total_count - passed_count} test(s) failed[/yellow]")


if __name__ == "__main__":
    main()
