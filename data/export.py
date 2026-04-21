#!/usr/bin/env python3
"""
Data Export Utilities - Threat Intelligence Platform
==========================
Export threats to various formats: JSON, CSV, PDF, Excel
"""

import json
from datetime import datetime
from rich.console import Console

console = Console()

class DataExporter:
    """Export threats to various formats"""
    
    def __init__(self, db=None):
        self.db = db
        self.output_dir = '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs'
    
    def export_all(self, format='json', limit=None):
        """Export all threats"""
        threats = self.db.get_all_threats()
        
        if limit:
            threats = threats[:limit]
        
        extensions = {
            'json': 'json',
            'csv': 'csv',
            'excel': 'xlsx',
            'pdf': 'pdf'
        }
        
        output_file = f"{self.output_dir}/threats_export.{extensions.get(format, 'json')}"
        return self._export_to_file(threats, output_file, format)
    
    def export_daily(self, date=None):
        """Export threats collected on a specific day"""
        if not date:
            date = datetime.now().date()
        
        threats = self.db.get_all_threats()
        daily_threats = [
            t for t in threats 
            if datetime.fromisoformat(t['collected_at']).date() == date
        ]
        
        if daily_threats:
            filename = f"{self.output_dir}/daily_threats_{date.strftime('%Y-%m-%d')}.json"
            return self._export_to_file(daily_threats, filename, 'json')
        else:
            console.print(f"[yellow]⚠️  No threats collected on {date}[/yellow]")
            return None
    
    def export_critical_only(self, limit=10):
        """Export only critical threats"""
        threats = self.db.get_critical_threats(limit=limit)
        
        output_file = f"{self.output_dir}/critical_threats.json"
        return self._export_to_file(threats, output_file, 'json')
    
    def export_summary(self):
        """Export summary statistics"""
        stats = self.db.get_statistics()
        
        output_file = f"{self.output_dir}/threat_summary.json"
        
        summary = {
            'generated_at': datetime.now().isoformat(),
            'total_threats': stats.get('total_threats', 0),
            'critical_count': stats.get('critical_count', 0),
            'high_count': stats.get('high_count', 0),
            'medium_count': stats.get('medium_count', 0),
            'low_count': stats.get('low_count', 0),
            'last_check': stats.get('last_check')
        }
        
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        console.print(f"[green]✓ Exported threat summary to {output_file}[/green]")
        return output_file
    
    def _export_to_file(self, threats, output_file, format):
        """Export threats to file"""
        try:
            with open(output_file, 'w') as f:
                if format == 'json':
                    json.dump(threats, f, indent=2)
                elif format == 'csv':
                    # Simple CSV export
                    if threats:
                        headers = threats[0].keys()
                        f.write(','.join(headers) + '\n')
                        for threat in threats:
                            values = [str(threat[h]) for h in headers]
                            f.write(','.join(values) + '\n')
            
            console.print(f"[green]✓ Exported {len(threats)} threats to {output_file}[/green]")
            return output_file
            
        except Exception as e:
            console.print(f"[red]✗ Error exporting: {str(e)}[/red]")
            return None
    
    def export_to_markdown(self):
        """Export threats to markdown report"""
        threats = self.db.get_all_threats()
        
        output_file = f"{self.output_dir}/threats_report.md"
        
        with open(output_file, 'w') as f:
            f.write("# Threat Intelligence Report\n")
            f.write(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Critical Threats\n\n")
            critical = [t for t in threats if t['severity'] == 'Critical']
            
            for threat in critical[:10]:
                f.write(f"### {threat['cve_id']}\n\n")
                f.write(f"**Severity**: {threat['severity']}\n")
                f.write(f"**CVSS Score**: {threat['cvss_score']}\n\n")
                f.write(f"**Title**: {threat['title']}\n\n")
                f.write(f"**Description**:\n")
                f.write(f"{threat['description']}\n\n")
                f.write("---\n\n")
        
        console.print(f"[green]✓ Exported threat report to {output_file}[/green]")
        return output_file


if __name__ == "__main__":
    console.print("[yellow]📤 Data Export Test[/yellow]")
    exporter = DataExporter()
    print(exporter)
