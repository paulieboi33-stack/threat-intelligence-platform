#!/usr/bin/env python3
"""
Watchdog Agent - Alerting System
=======================
Monitors for threats matching target environment profile
"""

import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class WatchdogAgent:
    """Target environment alerting agent"""
    
    def __init__(self, org_profile_path=None):
        self.org_profile_path = org_profile_path
        self.org_profile = self._load_org_profile()
    
    def _load_org_profile(self):
        """Load organization profile"""
        if self.org_profile_path:
            try:
                with open(self.org_profile_path, 'r') as f:
                    profile = json.load(f)
                    return profile
            except:
                # Default profile
                return {
                    'org_name': 'DemoCorp',
                    'tech_stack': ['Apache', 'Linux', 'WordPress', 'MySQL', 'Python'],
                    'industry': 'small_business',
                    'alert_threshold': 7.5
                }
        else:
            # Default profile
            return {
                'org_name': 'DemoCorp',
                'tech_stack': ['Apache', 'Linux', 'WordPress', 'MySQL', 'Python'],
                'industry': 'small_business',
                'alert_threshold': 7.5
            }
    
    def assess_threat_relevance(self, threat):
        """Assess if threat is relevant to target environment"""
        tech_stack = self.org_profile.get('tech_stack', [])
        threat_keywords = threat.get('title', '').lower() + ' ' + threat.get('description', '').lower()
        
        # Check if threat affects our tech stack
        relevant_products = []
        for product in tech_stack:
            if product.lower() in threat_keywords or any(word in threat_keywords for word in product.lower().split()):
                relevant_products.append(product)
        
        return {
            'is_relevant': len(relevant_products) > 0,
            'relevant_products': relevant_products,
            'reason': f"Affects: {', '.join(relevant_products)}" if relevant_products else "No match to tech stack"
        }
    
    def filter_critical_threats(self, threats):
        """Filter threats based on alert threshold"""
        threshold = self.org_profile.get('alert_threshold', 7.5)
        critical_threats = []
        
        for threat in threats:
            assessment = self.assess_threat_relevance(threat)
            if threat['cvss_score'] >= threshold or assessment['is_relevant']:
                critical_threats.append({
                    **threat,
                    'alert_reason': assessment['reason']
                })
        
        return critical_threats
    
    def generate_alerts(self, threats):
        """Generate alerts for critical threats"""
        console.print("\n[yellow]🐶 Watchdog Agent - Monitoring Target Environment[/yellow]")
        console.print(f"[cyan]📋 Organization Profile: {self.org_profile.get('org_name', 'Unknown')}[/cyan]")
        console.print(f"[cyan]🛡️ Tech Stack: {', '.join(self.org_profile.get('tech_stack', ['N/A']))}[/cyan]\n")
        
        # Filter and assess threats
        critical_threats = self.filter_critical_threats(threats)
        
        # Create alert table
        table = Table(title="🚨 ALERTS - Threats Affecting Our Environment")
        table.add_column("CVE ID")
        table.add_column("Severity")
        table.add_column("Threat Score")
        table.add_column("Alert Reason")
        
        for threat in critical_threats[:5]:  # Show top 5 alerts
            table.add_row(
                threat['cve_id'],
                threat['severity'],
                str(threat['cvss_score']),
                threat.get('alert_reason', 'High risk')
            )
        
        console.print(table)
        
        console.print(f"\n[bold]📊 Watchdog Summary:[/bold]")
        console.print(f"Total threats assessed: {len(threats)}")
        console.print(f"Critical alerts generated: {len(critical_threats)}")
        
        if len(critical_threats) > 0:
            console.print(Panel(
                f"⚠️  {len(critical_threats)} threats require immediate attention!\n"
                f"Most critical: {max(critical_threats, key=lambda x: x['cvss_score'])['cve_id']}",
                title="🚨 IMMEDIATE ACTION REQUIRED",
                border_style="red"
            ))
        else:
            console.print(Panel(
                "✅ All threats are within acceptable risk levels",
                title="🟢 NO CRITICAL ALERTS",
                border_style="green"
            ))
    
    def simulate_alert_notification(self, threat):
        """Simulate sending alert notification"""
        alert = f"""
🚨 SECURITY ALERT

Organization: {self.org_profile.get('org_name')}
CVE ID: {threat['cve_id']}
Severity: {threat['severity']}
Threat Score: {threat['cvss_score']}

Reason: {threat.get('alert_reason', 'High priority')}

Recommended Action: Review and apply security patches immediately.
        """
        console.print(Panel(alert, title="📧 Simulated Alert Notification", border_style="yellow"))

if __name__ == "__main__":
    console.print("[yellow]🐶 Watchdog Agent - Target Environment Monitoring[/yellow]")
    
    # Sample threats
    threats = [
        {'cve_id': 'CVE-2024-1001', 'severity': 'Critical', 'cvss_score': 9.8, 'title': 'Windows SMB RCE', 'description': 'Windows Server SMB protocol vulnerability'},
        {'cve_id': 'CVE-2024-2001', 'severity': 'High', 'cvss_score': 7.5, 'title': 'Linux Kernel Memory', 'description': 'Linux kernel networking stack'},
        {'cve_id': 'CVE-2024-3001', 'severity': 'High', 'cvss_score': 8.1, 'title': 'Docker Escaping', 'description': 'Docker container security'},
        {'cve_id': 'CVE-2024-4001', 'severity': 'Critical', 'cvss_score': 10.0, 'title': 'Apache Log4Shell', 'description': 'Apache Log4j vulnerability'},
    ]
    
    # Create watchdog with default profile
    watchdog = WatchdogAgent()
    
    # Generate alerts
    watchdog.generate_alerts(threats)
