#!/usr/bin/env python3
"""
Simplified Visualizer Agent - Unified Rendering
==========================
One agent handles all chart types
"""

from rich.console import Console
from datetime import datetime
import json

console = Console()

class SimpleVisualizer:
    """Unified visualization agent"""
    
    def __init__(self):
        self.output_dir = '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs'
    
    def visualize(self, threats, chart_type='auto'):
        """Generate appropriate visualization"""
        
        # Auto-detect chart type based on data
        if chart_type == 'auto':
            critical_count = len([t for t in threats if t['severity'] == 'Critical'])
            if critical_count > len(threats) * 0.5:
                chart_type = 'critical_alerts'
            elif len(threats) < 5:
                chart_type = 'simple_list'
            else:
                chart_type = 'severity_distribution'
        
        # Generate appropriate visualization
        if chart_type == 'simple_list':
            self._simple_list(threats)
        elif chart_type == 'severity_distribution':
            self._severity_chart(threats)
        elif chart_type == 'critical_alerts':
            self._critical_alerts(threats)
        elif chart_type == 'trend':
            self._trend_chart(threats)
    
    def _simple_list(self, threats):
        """Simple list for small datasets"""
        console.print("[green]📊 Simple Threat List:[/green]")
        for i, threat in enumerate(threats, 1):
            console.print(f"  {i}. {threat['cve_id']}: {threat['severity']} (CVSS: {threat['cvss_score']})")
    
    def _severity_chart(self, threats):
        """Severity distribution"""
        console.print("[green]📊 Severity Distribution:[/green]")
        
        # Count by severity
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for threat in threats:
            sev = threat.get('severity', 'Low')
            if sev in counts:
                counts[sev] += 1
        
        console.print(f"  Critical: {counts['Critical']}")
        console.print(f"  High: {counts['High']}")
        console.print(f"  Medium: {counts['Medium']}")
        console.print(f"  Low: {counts['Low']}")
    
    def _critical_alerts(self, threats):
        """Critical alerts dashboard"""
        critical = [t for t in threats if t['severity'] == 'Critical']
        
        console.print("[red]🚨 CRITICAL ALERTS[/red]")
        for threat in critical:
            console.print(f"[red]  ✗ {threat['cve_id']} - {threat['title']}[/red]")
    
    def _trend_chart(self, threats):
        """Simple trend visualization"""
        console.print("[green]📈 Threat Trend (simplified):[/green]")
        
        # Group by date
        daily = {}
        for threat in threats:
            try:
                date = datetime.fromisoformat(threat['collected_at']).date()
                daily[date] = daily.get(date, 0) + 1
            except:
                pass
        
        if daily:
            dates = sorted(daily.keys())
            console.print(f"  Period: {dates[0]} to {dates[-1]}")
            console.print(f"  Total threats: {sum(daily.values())}")
            console.print(f"  Daily average: {sum(daily.values()) / len(dates):.1f}")
    
    def generate_summary(self, threats):
        """Generate simple summary"""
        if not threats:
            return ""
        
        summary = f"""
📊 Threat Intelligence Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Threats: {len(threats)}
Critical: {len([t for t in threats if t['severity'] == 'Critical'])}
High: {len([t for t in threats if t['severity'] == 'High'])}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}
"""
        return summary
