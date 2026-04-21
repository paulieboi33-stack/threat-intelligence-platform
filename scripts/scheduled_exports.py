#!/usr/bin/env python3
"""
Scheduled Exports Script - Threat Intelligence Platform
===================
Automates daily/weekly report generation and data maintenance
"""

import sys
import os
from datetime import datetime, timedelta
from rich.console import Console

console = Console()

# Add path
sys.path.insert(0, '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/agents')

from data.persistence import ThreatDatabase
from data.export import DataExporter
from main import ThreatIntelPipeline

class ScheduledExporter:
    """Automated scheduled export and maintenance"""
    
    def __init__(self):
        self.db = ThreatDatabase()
        self.exporter = DataExporter(self.db)
        self.pipeline = ThreatIntelPipeline()
    
    def daily_export(self):
        """Export daily threat report"""
        date = datetime.now().date()
        console.print(f"[yellow]📅 Daily Export - {date}[/yellow]")
        
        filename = self.exporter.export_daily_report(date=date)
        
        if filename:
            # Also create markdown summary
            markdown_filename = filename.replace('.json', '.md')
            self._create_markdown_summary(filename, markdown_filename)
        
        console.print(f"[green]✓ Daily export complete[/green]")
    
    def weekly_export(self):
        """Export weekly summary report"""
        console.print("[yellow]📊 Weekly Export[/yellow]")
        
        filename = self.pipeline.export_weekly_report()
        
        console.print(f"[green]✓ Weekly export complete[/green]")
    
    def monthly_export(self):
        """Export monthly summary report"""
        console.print("[yellow]📈 Monthly Export[/yellow]")
        
        threats = self.db.get_all_threats()
        stats = self.db.get_statistics()
        
        # Create monthly summary
        summary = {
            'generated_at': datetime.now().isoformat(),
            'month': datetime.now().strftime('%Y-%m'),
            'total_threats': len(threats),
            'critical_count': len([t for t in threats if t['severity'] == 'Critical']),
            'high_count': len([t for t in threats if t['severity'] == 'High']),
            'medium_count': len([t for t in threats if t['severity'] == 'Medium']),
            'low_count': len([t for t in threats if t['severity'] == 'Low']),
            'unique_vendors': len(set(t.get('vendor', '') for t in threats)),
            'days_tracked': len(set(datetime.fromisoformat(t['collected_at']).date() for t in threats))
        }
        
        filename = f"/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/monthly_summary_{datetime.now().strftime('%Y-%m')}.json"
        
        with open(filename, 'w') as f:
            import json
            json.dump(summary, f, indent=2)
        
        console.print(f"[green]✓ Monthly export complete: {filename}[/green]")
    
    def _create_markdown_summary(self, json_file, markdown_file):
        """Create markdown summary from JSON data"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Create markdown
            with open(markdown_file, 'w') as f:
                f.write(f"# Threat Report - {datetime.now().strftime('%Y-%m-%d')}\n\n")
                f.write(f"**Generated**: {data.get('generated_at', 'N/A')}\n\n")
                f.write(f"**Total Threats**: {data.get('total_threats', 0)}\n")
                f.write(f"**Critical**: {data.get('critical_count', 0)}\n")
                f.write(f"**High**: {data.get('high_count', 0)}\n\n")
            
            console.print(f"[green]✓ Markdown summary: {markdown_file}[/green]")
            
        except Exception as e:
            console.print(f"[red]✗ Error creating markdown: {str(e)}[/red]")
    
    def maintenance(self):
        """Run maintenance tasks"""
        console.print("[yellow]🔧 Running maintenance...[/yellow]")
        
        # Cleanup old data
        deleted = self.db.cleanup_old_data(days_to_keep=90)
        
        # Check storage
        threats = self.db.get_all_threats()
        current_count = len(threats)
        
        console.print(f"[green]✓ Cleaned up {deleted} old threats[/green]")
        console.print(f"[green]✓ Current threat count: {current_count}[/green]")
        
        # Export latest summary
        self.exporter.export_summary()
        
        console.print("[green]✓ Maintenance complete[/green]")

def run_scheduled_exports():
    """Run scheduled exports"""
    console.print("[yellow]📅 Scheduled Exports Script[/yellow]")
    console.print("")
    
    exporter = ScheduledExporter()
    
    # Ask what to export
    console.print("[cyan]Select export type:[/cyan]")
    console.print("  1. Daily report")
    console.print("  2. Weekly summary")
    console.print("  3. Monthly summary")
    console.print("  4. Maintenance only")
    console.print("  5. All reports")
    console.print("")
    
    choice = input("Enter choice (1-5): ")
    
    if choice == '1':
        exporter.daily_export()
    elif choice == '2':
        exporter.weekly_export()
    elif choice == '3':
        exporter.monthly_export()
    elif choice == '4':
        exporter.maintenance()
    elif choice == '5':
        exporter.daily_export()
        exporter.weekly_export()
        exporter.monthly_export()
        exporter.maintenance()
    else:
        console.print("[yellow]⚠️  Invalid choice[/yellow]")

if __name__ == "__main__":
    run_scheduled_exports()
