#!/usr/bin/env python3
"""
Main Orchestrator - Threat Intelligence Pipeline with Database & Retention
=================================
Runs all agents in pipeline: API Scout → Analyst → Watchdog → Reporter
With database persistence, retention policies, and scheduled exports
"""

import sys
import os
from datetime import datetime, timedelta
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress

console = Console()

# Add agents to path
sys.path.insert(0, '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/agents')

try:
    from api_integration import ThreatAPI
    from additional_feeds import AdditionalThreatFeeds
    from reporter import ReporterAgent
    from watchdog import WatchdogAgent
    from analyst import AnalystAgent
    from data.persistence import ThreatDatabase
    from data.export import DataExporter
except ImportError as e:
    console.print(f"[red]Import error: {str(e)}[/red]")
    console.print("[yellow]Using sample data for demo...[/yellow]")
    from scout import load_sample_threats
    ThreatDatabase = None
    DataExporter = None
    AnalystAgent = None

class ThreatIntelPipeline:
    """Main threat intelligence pipeline orchestrator with database & retention"""
    
    def __init__(self):
        self.api = ThreatAPI()
        self.additional_feeds = AdditionalThreatFeeds()
        self.reporter = ReporterAgent()
        self.watchdog = WatchdogAgent()
        self.analyst = AnalystAgent() if AnalystAgent else None
        self.db = ThreatDatabase() if ThreatDatabase else None
        self.exporter = DataExporter(self.db) if DataExporter else None
        
        # Data retention settings
        self.retention_days = 90  # Keep threats for 90 days
        self.max_threats = 1000   # Maximum threats to keep
    
    def run_pipeline(self):
        """Run complete threat intelligence pipeline with database persistence"""
        
        console.print(Panel(
            "[bold white]🚀 Starting Threat Intelligence Pipeline with Database[/bold white]\n"
            "📥 API Scout → 🧠 Analyst → 🐶 Watchdog → 📊 Reporter → 💾 Database",
            title="🔒 Threat Intelligence System (Database Mode)",
            border_style="blue"
        ))
        
        console.print("\n[green]📦 Phase 1: Collection (API & Additional Feeds)[/green]")
        
        # Phase 1: Collect threats from ALL sources
        all_threats = []
        
        # Fetch from main APIs
        console.print("[yellow]📥 Fetching from primary sources (CISA, NVD, MalwareBazaar)...[/yellow]")
        primary_threats = self.api.combine_all_threats()
        all_threats.extend(primary_threats)
        
        # Fetch from additional sources
        console.print("[yellow]📥 Fetching from additional feeds (GitHub, Exploit-DB, VulnLookup)...[/yellow]")
        additional_threats = self.additional_feeds.fetch_all_additional_feeds()
        all_threats.extend(additional_threats)
        
        console.print(f"\n[green]✓ Total threats collected: {len(all_threats)}[/green]")
        console.print(f"[green]  - Primary sources: {len(primary_threats)}[/green]")
        console.print(f"[green]  - Additional feeds: {len(additional_threats)}[/green]")
        
        if not all_threats:
            console.print("[yellow]⚠️  No threats collected, falling back to sample data[/yellow]")
            threats = load_sample_threats()
            all_threats = threats
        
        # Phase 2: AI Analysis
        console.print("\n[blue]🧠 Phase 2: AI Analysis (Analyst Agent — powered by qwen2.5:32b)[/blue]")
        if self.analyst and self.analyst.available:
            enriched_threats = self.analyst.analyze_batch(all_threats, limit=20)
            self.analyst.save_analysis_to_db(enriched_threats)
            # Print sample of first critical threat
            criticals = [t for t in enriched_threats if t.get('severity') == 'Critical']
            if criticals:
                self.analyst.print_sample_analysis(criticals[0])
        else:
            enriched_threats = []
            for threat in all_threats:
                enriched_threat = {
                    **threat,
                    'analyzed_at': datetime.now().isoformat(),
                    'ai_summary': f"CVSS {threat.get('cvss_score', 'N/A')} {threat.get('severity', '')} vulnerability."
                }
                enriched_threats.append(enriched_threat)

        console.print(f"[green]✓ Analyzed {len(enriched_threats)} threats[/green]")
        
        # Save to database
        if self.db:
            console.print("[yellow]💾 Saving threats to database...[/yellow]")
            # Fix: Pass enriched_threats not all_threats
            self.db.save_threat_batch(enriched_threats, source='API Collection')
        
        # Phase 3: Watchdog filtering
        console.print("\n[blue]🐶 Phase 3: Alerting (Watchdog Agent)[/blue]")
        console.print("[yellow]🐶 Monitoring for threats affecting our environment...[/yellow]")
        self.watchdog.generate_alerts(enriched_threats)
        
        # Phase 4: Generate reports
        console.print("\n[blue]📊 Phase 4: Reporting (Reporter Agent)[/blue]")
        console.print("[cyan]📄 Generating reports (HTML, Console, Markdown)...[/cyan]")
        
        html_path = self.reporter.generate_html_report(enriched_threats)
        self.reporter.generate_console_report(enriched_threats)
        self.reporter.generate_markdown_report(enriched_threats)
        
        # Phase 5: Apply retention policy
        if self.db:
            console.print("\n[blue]🗑️  Phase 5: Data Retention Policy[/blue]")
            cleanup_count = self.db.cleanup_old_data(days_to_keep=self.retention_days)
            current_count = len(self.db.get_all_threats())
            
            console.print(f"[green]✓ Cleaned up {cleanup_count} old threats (>{self.retention_days} days)[/green]")
            console.print(f"[green]✓ Current threat count in database: {current_count}[/green]")
            console.print(f"[cyan]📊 Retention: Keeping threats for {self.retention_days} days[/cyan]")
        
        console.print("\n[green]✓ Alerting complete[/green]")
        
        console.print("\n[blue]📊 Phase 5: Data Management[/blue]")
        
        # Phase 5: Apply data retention and limits
        if self.db:
            self._apply_retention_policies(enriched_threats)
        
        # Phase 6: Generate trend analysis
        if self.db and len(self.db.get_all_threats()) > 5:
            console.print("\n[blue]📈 Phase 6: Trend Analysis[/blue]")
            trend_analysis = self._generate_trend_analysis()
            console.print(trend_analysis)
        
        console.print("\n[green]✓ Reports generated![/green]")
        console.print(f"[cyan]📂 HTML Report: {html_path}[/cyan]")
        
        console.print("\n╔═════════════════════════════════════════════════════╗")
        console.print("║   Pipeline Complete! Reports Ready for Review       ║")
        console.print("╚══════════════════════════════════════════════════════╝")
        
        return enriched_threats
    
    def _generate_ai_summary(self, threat):
        """Generate AI summary for threat"""
        summary = f"This {threat['severity'].lower()} severity vulnerability affects {threat.get('product', 'unknown software')}. "
        summary += f"CVSS Score: {threat['cvss_score']}. "
        if threat.get('exploit_available'):
            summary += "Exploit is available - immediate patching required."
        else:
            summary += "Exploit not yet known - monitor for updates."
        
        return summary
    
    def _apply_retention_policies(self, threats):
        """Apply data retention and limits"""
        if not self.db:
            return
        
        # Get current count
        current_count = len(self.db.get_all_threats())
        
        # Apply maximum threat limit
        if current_count + len(threats) > self.max_threats:
            console.print(f"[yellow]⚠️  Approaching maximum threat limit ({self.max_threats})[/yellow]")
            console.print(f"[yellow]🗑️  Automatically removing oldest threats to stay under limit[/yellow]")
            
            # Get oldest threats to remove
            all_threats = self.db.get_all_threats()
            sorted_threats = sorted(all_threats, key=lambda x: x['collected_at'])
            threats_to_remove = sorted_threats[:len(threats_to_remove) - len(threats)]
            
            for threat in threats_to_remove:
                self.db._delete_threat(threat['id'])
    
    def _generate_trend_analysis(self):
        """Generate trend analysis from database"""
        threats = self.db.get_all_threats()
        
        if len(threats) < 3:
            return "[yellow]⚠️  Need at least 3 threats for trend analysis[/yellow]"
        
        # Group by date
        from datetime import datetime
        daily_counts = {}
        for threat in threats:
            try:
                date = datetime.fromisoformat(threat['collected_at']).date()
                daily_counts[date] = daily_counts.get(date, 0) + 1
            except:
                pass
        
        if len(daily_counts) < 2:
            return "[yellow]⚠️  Need threats collected over multiple days[/yellow]"
        
        # Convert to list
        dates = sorted(daily_counts.keys())
        counts = [daily_counts[d] for d in dates]
        
        # Create analysis
        analysis = []
        analysis.append("[green]📈 TREND ANALYSIS[/green]")
        analysis.append("")
        analysis.append(f"Analysis Period: {dates[0]} to {dates[-1]}")
        analysis.append(f"Total threats analyzed: {len(threats)}")
        analysis.append("")
        analysis.append(f"📊 Daily Average: {sum(counts) / len(dates):.1f} threats/day")
        analysis.append(f"📈 Peak Day: {max(daily_counts, key=daily_counts.get)} ({max(counts)} threats)")
        analysis.append("")
        analysis.append("📈 Threat Discovery Trend:")
        
        # Add trend indicators
        if len(dates) >= 3:
            first_half = sum(counts[:len(counts)//2])
            second_half = sum(counts[len(counts)//2:])
            
            if second_half > first_half * 1.2:
                analysis.append("[green]✓ Threat volume is increasing[/green]")
            elif second_half < first_half * 0.8:
                analysis.append("[red]⚠️  Threat volume is decreasing[/red]")
            else:
                analysis.append("[yellow]→ Threat volume is stable[/yellow]")
        
        analysis.append("")
        analysis.append("📊 Severity Distribution Over Time:")
        
        # Get severity trends
        critical_count = len([t for t in threats if t['severity'] == 'Critical'])
        high_count = len([t for t in threats if t['severity'] == 'High'])
        
        analysis.append(f"  Critical threats: {critical_count}")
        analysis.append(f"  High severity threats: {high_count}")
        
        if critical_count > len(threats) * 0.1:  # More than 10% critical
            analysis.append("[red]⚠️  High percentage of critical threats![/red]")
        
        analysis.append("")
        analysis.append("[green]✓ Trend analysis complete[/green]")
        
        return "\n".join(analysis)
    
    def export_daily_report(self, date=None):
        """Export daily threat report"""
        if not date:
            date = datetime.now().date()
        
        threats = self.db.get_all_threats()
        daily_threats = [
            t for t in threats 
            if datetime.fromisoformat(t['collected_at']).date() == date
        ]
        
        if daily_threats:
            filename = f"/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/daily_report_{date.strftime('%Y-%m-%d')}.json"
            return self.exporter.export_to_file(daily_threats, filename, 'json')
        else:
            console.print(f"[yellow]⚠️  No threats collected on {date}[/yellow]")
            return None
    
    def export_weekly_report(self):
        """Export weekly summary report"""
        threats = self.db.get_all_threats()
        stats = self.db.get_statistics()
        
        # Create weekly summary
        summary = {
            'generated_at': datetime.now().isoformat(),
            'week_start': (datetime.now() - timedelta(days=7)).isoformat(),
            'week_end': datetime.now().isoformat(),
            'total_threats': len(threats),
            'critical_count': len([t for t in threats if t['severity'] == 'Critical']),
            'high_count': len([t for t in threats if t['severity'] == 'High']),
            'medium_count': len([t for t in threats if t['severity'] == 'Medium']),
            'low_count': len([t for t in threats if t['severity'] == 'Low']),
            'database_size': len(threats),
            'retention_days': self.retention_days
        }
        
        filename = f"/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/weekly_summary_{datetime.now().strftime('%Y-%m-%d')}.json"
        
        with open(filename, 'w') as f:
            import json
            json.dump(summary, f, indent=2)
        
        console.print(f"[green]✓ Weekly report generated: {filename}[/green]")
        return filename


def main():
    """Main entry point"""
    console.print("\n[yellow]🔌 Connecting to threat intelligence APIs...[/yellow]")
    pipeline = ThreatIntelPipeline()
    pipeline.run_pipeline()

if __name__ == "__main__":
    main()
