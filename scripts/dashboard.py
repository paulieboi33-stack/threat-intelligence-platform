#!/usr/bin/env python3
"""
Terminal Dashboard - Text-based dashboard for threat intelligence platform
==========================================

Run this script to see a text-based dashboard of your platform status
"""

import sys
import sqlite3
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich import print as rprint

console = Console()

# Database connection
db_path = "/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/data/threats.db"

def get_dashboard():
    """Get dashboard data"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_threats,
                SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) as low,
                MAX(collected_at) as last_collection
            FROM threats
        """)
        stats = cursor.fetchone()
        
        # Get recent threats
        cursor.execute("""
            SELECT cve_id, severity, cvss_score, title
            FROM threats 
            ORDER BY collected_at DESC 
            LIMIT 5
        """)
        recent = cursor.fetchall()
        
        # Get threat breakdown
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM threats 
            GROUP BY severity
            ORDER BY count DESC
        """)
        breakdown = cursor.fetchall()
        
        conn.close()
        
        return stats, recent, breakdown
        
    except Exception as e:
        console.print(f"[red]✗ Database error: {str(e)}[/red]")
        return (0, 0, 0, 0, 0, ""), [], []

def print_dashboard():
    """Print dashboard to console"""
    
    console.print(Panel.fit(
        "[bold blue]🛡️ Threat Intelligence Dashboard[/bold blue]\n"
        "Real-time status of your multi-agent platform",
        border_style="blue"
    ))
    
    # Get data
    stats, recent, breakdown = get_dashboard()
    
    if not stats[0]:
        console.print("[yellow]⚠️  No data yet - platform will start collecting soon[/yellow]")
        return
    
    # Print statistics
    console.print("\n[bold]📊 Statistics[/bold]")
    console.print(f"[green]Total Threats: {stats[0]}[/green]")
    console.print(f"[red]Critical: {stats[1]}[/red]")
    console.print(f"[orange1]High: {stats[2]}[/orange1]")
    console.print(f"[yellow]Medium: {stats[3]}[/yellow]")
    console.print(f"[green]Low: {stats[4]}[/green]")
    console.print(f"[cyan]Last Collection: {stats[5] or 'Never'}[/cyan]")
    
    # Print breakdown
    console.print("\n[bold]📈 Severity Breakdown[/bold]")
    table = Table(title="Threat Distribution")
    table.add_column("Severity", justify="center")
    table.add_column("Count", justify="center")
    
    for severity, count in breakdown:
        table.add_row(severity, str(count))
    
    console.print(table)
    
    # Print recent threats
    console.print("\n[bold]📋 Recent Threats[/bold]")
    
    if recent:
        table = Table(title="Latest Discoveries")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Severity", justify="center")
        table.add_column("CVSS", justify="right")
        table.add_column("Title (Truncated)")
        
        for threat in recent:
            title = threat[3][:40] + "..." if len(threat[3]) > 40 else threat[3]
            table.add_row(
                threat[0],
                threat[1],
                str(threat[2]),
                title
            )
        
        console.print(table)
    else:
        console.print("[yellow]No recent threats[/yellow]")

def main():
    """Main function"""
    print_dashboard()

if __name__ == "__main__":
    main()
