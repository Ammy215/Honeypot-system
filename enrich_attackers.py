#!/usr/bin/env python3
"""
Manual enrichment script for existing attackers
"""

import sys
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from honeypot.intelligence.enrichment import (
    enrich_recent_attackers, 
    get_enrichment_status,
    display_enrichment_status
)
from honeypot.intelligence.threat_scorer import recalculate_all_scores

console = Console()


def main():
    console.print("\n[bold cyan]HoneyShield Threat Intelligence Enrichment[/bold cyan]\n")
    
    # Show current status
    console.print("[yellow]Current Enrichment Status:[/yellow]")
    display_enrichment_status()
    
    # Get user choice
    console.print("\n[cyan]Options:[/cyan]")
    console.print("  1. Enrich recent attackers (10)")
    console.print("  2. Enrich all unenriched attackers")
    console.print("  3. Recalculate all threat scores")
    console.print("  4. Full enrichment (geo + reputation + scores)")
    console.print("  5. Exit")
    
    choice = input("\nSelect option (1-5): ").strip()
    
    if choice == "1":
        console.print("\n[yellow]Enriching 10 most recent attackers...[/yellow]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Enriching...", total=None)
            enrich_recent_attackers(limit=10, skip_enriched=True)
            progress.update(task, description="✓ Complete")
        
        console.print("\n[green]✓ Enrichment complete![/green]")
        display_enrichment_status()
    
    elif choice == "2":
        console.print("\n[yellow]Enriching all unenriched attackers...[/yellow]")
        
        # Get count first
        from database.db import db
        query = """
            SELECT COUNT(*) as cnt FROM attackers 
            WHERE geo_enriched = 0 OR intel_enriched = 0
        """
        result = db.execute_query(query)
        count = result[0]['cnt'] if result else 0
        
        if count == 0:
            console.print("[green]All attackers already enriched![/green]")
            return
        
        console.print(f"Found {count} attackers to enrich")
        confirm = input(f"This will make {count}+ API calls. Continue? (y/n): ")
        
        if confirm.lower() == 'y':
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"Enriching {count} attackers...", total=None)
                enrich_recent_attackers(limit=count, skip_enriched=True)
                progress.update(task, description="✓ Complete")
            
            console.print("\n[green]✓ Enrichment complete![/green]")
            display_enrichment_status()
        else:
            console.print("[yellow]Cancelled[/yellow]")
    
    elif choice == "3":
        console.print("\n[yellow]Recalculating all threat scores...[/yellow]")
        
        from database.db import db
        query = "SELECT COUNT(*) as cnt FROM attackers"
        result = db.execute_query(query)
        count = result[0]['cnt'] if result else 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Scoring {count} attackers...", total=None)
            recalculate_all_scores()
            progress.update(task, description="✓ Complete")
        
        console.print("\n[green]✓ Threat scores updated![/green]")
        display_enrichment_status()
    
    elif choice == "4":
        console.print("\n[yellow]Full enrichment starting...[/yellow]")
        console.print("This will:")
        console.print("  • Get geolocation for all IPs")
        console.print("  • Check AbuseIPDB reputation (if API key configured)")
        console.print("  • Calculate threat scores")
        console.print()
        
        from database.db import db
        query = "SELECT COUNT(*) as cnt FROM attackers"
        result = db.execute_query(query)
        count = result[0]['cnt'] if result else 0
        
        confirm = input(f"Enrich {count} attackers? (y/n): ")
        
        if confirm.lower() == 'y':
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Full enrichment...", total=None)
                
                # Enrich all
                enrich_recent_attackers(limit=count, skip_enriched=False)
                
                # Recalculate scores
                recalculate_all_scores()
                
                progress.update(task, description="✓ Complete")
            
            console.print("\n[green]✓ Full enrichment complete![/green]")
            display_enrichment_status()
        else:
            console.print("[yellow]Cancelled[/yellow]")
    
    elif choice == "5":
        console.print("[cyan]Goodbye![/cyan]")
        sys.exit(0)
    
    else:
        console.print("[red]Invalid choice[/red]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)
