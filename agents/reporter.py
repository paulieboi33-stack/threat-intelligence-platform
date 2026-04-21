#!/usr/bin/env python3
"""
Reporter Agent - Threat Intelligence Reporting
=====================
Generates HTML dashboard, console output, and markdown reports
"""

import jinja2
from rich.console import Console
from rich.panel import Panel
from datetime import datetime

console = Console()

class ReporterAgent:
    """Threat intelligence reporting agent"""
    
    def __init__(self, template_path=None):
        self.template = template_path or '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/templates/report.html'
    
    def generate_console_report(self, threats):
        """Generate console summary output"""
        console.print("\n[bold cyan]╔════════════════════════════════════════════╗")
        console.print("[bold cyan]║   SECURITY THREAT INTELLIGENCE REPORT      ║")
        console.print("[bold cyan]╚════════════════════════════════════════════╝\n")
        
        # Executive summary
        critical = len([t for t in threats if t['severity'] == 'Critical'])
        high = len([t for t in threats if t['severity'] == 'High'])
        medium = len([t for t in threats if t['severity'] == 'Medium'])
        low = len([t for t in threats if t['severity'] == 'Low'])
        
        console.print(Panel(
            f"📊 EXECUTIVE SUMMARY\n"
            f"Total Threats Analyzed: {len(threats)}\n"
            f"Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}\n"
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="🎯 Executive Summary",
            border_style="blue"
        ))
        
        # Top threats
        top_threats = sorted(threats, key=lambda x: x['cvss_score'], reverse=True)[:3]
        console.print("\n[bold red]🚨 TOP THREATS:\n")
        
        for i, threat in enumerate(top_threats, 1):
            console.print(f"[bold red]#{i}[/] {threat['cve_id']} - {threat['severity']} (CVSS: {threat['cvss_score']})")
            console.print(f"    [yellow]{threat['title']}[/]")
            console.print()
    
    def generate_html_report(self, threats, org_profile=None):
        """Generate HTML dashboard report"""
        # Prepare data for template
        html_data = {
            'total_threats': len(threats),
            'critical_count': len([t for t in threats if t['severity'] == 'Critical']),
            'high_count': len([t for t in threats if t['severity'] == 'High']),
            'avg_score': round(sum(t['cvss_score'] for t in threats) / len(threats), 1) if threats else 0,
            'highest_threat': max(threats, key=lambda x: x['cvss_score']) if threats else {'cve_id': 'N/A'},
            'now': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'threats': sorted(threats, key=lambda x: x['cvss_score'], reverse=True)[:10]  # Top 10
        }
        
        # Read template
        try:
            with open(self.template, 'r') as f:
                template_content = f.read()
        except FileNotFoundError:
            console.print(f"[red]Template not found: {self.template}[/red]")
            return ""
        
        # Render template
        try:
            # Simple string replacement (not using full Jinja2 in this demo)
            html_content = template_content
            for key, value in html_data.items():
                html_content = html_content.replace(f"{{{{{key}}}}}", str(value))
            
            # Write output file
            output_path = '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/report.html'
            with open(output_path, 'w') as f:
                f.write(html_content)
            
            console.print(f"\n[green]✓ HTML report generated: {output_path}[/green]")
            return output_path
            
        except Exception as e:
            console.print(f"[red]✗ Error generating HTML report: {str(e)}[/red]")
            return ""
    
    def generate_markdown_report(self, threats):
        """Generate markdown report for documentation"""
        md_lines = [
            "# 🔒 Threat Intelligence Report",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## 📊 Executive Summary",
            f"- **Total Threats**: {len(threats)}",
            f"- **Critical**: {len([t for t in threats if t['severity'] == 'Critical'])}",
            f"- **High**: {len([t for t in threats if t['severity'] == 'High'])}",
            "",
            "## 🚨 Critical Threats",
            "",
        ]
        
        for threat in sorted(threats, key=lambda x: x['cvss_score'], reverse=True)[:5]:
            md_lines.extend([
                f"### {threat['cve_id']}",
                f"- **Severity**: {threat['severity']}",
                f"- **CVSS Score**: {threat['cvss_score']}",
                f"- **Product**: {threat.get('product', threat.get('title', 'Various'))}",
                f"- **Title**: {threat['title']}",
                "",
                f"**Description**:",
                f"{threat['description']}",
                "",
            ])
        
        markdown = '\n'.join(md_lines)
        
        # Write markdown file
        output_path = '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/report.md'
        with open(output_path, 'w') as f:
            f.write(markdown)
        
        console.print(f"[green]✓ Markdown report generated: {output_path}[/green]")
        return output_path

if __name__ == "__main__":
    console.print("[yellow]📝 Reporter Agent - Generating Reports[/yellow]")
    
    # Sample threats
    threats = [
        {'cve_id': 'CVE-2024-1001', 'severity': 'Critical', 'cvss_score': 9.8, 'title': 'Windows SMB RCE', 'product': 'Windows Server', 'description': 'Remote code execution'},
        {'cve_id': 'CVE-2024-2001', 'severity': 'High', 'cvss_score': 7.5, 'title': 'Linux Kernel Memory', 'product': 'Linux Kernel', 'description': 'Memory corruption'},
        {'cve_id': 'CVE-2024-3001', 'severity': 'High', 'cvss_score': 8.1, 'title': 'Docker Escaping', 'product': 'Docker Engine', 'description': 'Container breakout'},
    ]
    
    reporter = ReporterAgent()
    
    # Generate console report
    reporter.generate_console_report(threats)
    
    # Generate HTML report
    html_path = reporter.generate_html_report(threats)
    
    # Generate markdown report
    md_path = reporter.generate_markdown_report(threats)
