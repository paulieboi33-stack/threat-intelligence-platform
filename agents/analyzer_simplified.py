#!/usr/bin/env python3
"""
Simplified Analyzer Agent - Unified Analysis
================
Combines analysis and alerting into one simple function
"""

from rich.console import Console
from rich.table import Table

console = Console()

class SimpleAnalyzer:
    """Unified analysis and alerting"""
    
    def __init__(self, org_profile=None):
        self.org_profile = org_profile or {}
        self.alert_threshold = org_profile.get('alert_threshold', 7.5) if org_profile else 7.5
    
    def analyze(self, threats):
        """Analyze and alert in one pass"""
        console.print("[yellow]🔍 Analyzing threats...[/yellow]")
        
        analyzed = []
        alerts = []
        
        for threat in threats:
            # Simplified analysis
            threat_with_summary = {
                **threat,
                'ai_summary': f"Vulnerability in {threat.get('vendor', 'unknown')}: {threat.get('title', '')} requires attention."
            }
            analyzed.append(threat_with_summary)
            
            # Simple alert logic
            if threat['cvss_score'] >= self.alert_threshold:
                alert = {
                    'cve_id': threat['cve_id'],
                    'severity': threat['severity'],
                    'title': threat['title'],
                    'reason': f"CVSS score {threat['cvss_score']} exceeds threshold {self.alert_threshold}"
                }
                alerts.append(alert)
        
        # Generate alerts if any
        if alerts:
            console.print("\n[yellow]🚨 ALERTS GENERATED[/yellow]")
            table = Table(title="Critical Alerts")
            table.add_column("CVE ID")
            table.add_column("Severity")
            table.add_column("Alert Reason")
            
            for alert in alerts[:5]:  # Show top 5
                table.add_row(
                    alert['cve_id'],
                    alert['severity'],
                    alert['reason'][:50] + "..." if len(alert['reason']) > 50 else alert['reason']
                )
            
            console.print(table)
        
        return analyzed
    
    def get_statistics(self, threats):
        """Get simple statistics"""
        if not threats:
            return {'total': 0, 'critical': 0, 'high': 0}
        
        critical = len([t for t in threats if t['severity'] == 'Critical'])
        high = len([t for t in threats if t['severity'] == 'High'])
        
        return {
            'total': len(threats),
            'critical': critical,
            'high': high
        }
