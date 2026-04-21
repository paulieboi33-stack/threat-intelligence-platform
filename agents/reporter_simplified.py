#!/usr/bin/env python3
"""
Simplified Reporter Agent - Auto Format Detection
===============
One function handles all export formats
"""

from rich.console import Console
from datetime import datetime

console = Console()

class SimpleReporter:
    """Unified report generation"""
    
    def report(self, threats, format='auto'):
        """Generate report in detected or specified format"""
        
        # Detect format from output file or parameter
        output_file = self._get_output_path(threats, format)
        
        if format == 'html' or format == 'auto':
            self._generate_html(threats, output_file)
        elif format == 'csv':
            self._generate_csv(threats, output_file)
        elif format == 'markdown':
            self._generate_markdown(threats, output_file)
        elif format == 'json':
            self._generate_json(threats, output_file)
        
        console.print(f"[green]✓ Report generated: {output_file}[/green]")
        return output_file
    
    def _get_output_path(self, threats, format):
        """Get output file path"""
        import os
        output_dir = '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs'
        os.makedirs(output_dir, exist_ok=True)
        
        date = datetime.now().strftime('%Y-%m-%d_%H-%M')
        
        if format == 'auto':
            # Default to HTML
            return f"{output_dir}/report_{date}.html"
        else:
            return f"{output_dir}/report_{date}.{format}"
    
    def _generate_html(self, threats, output_file):
        """Generate HTML report"""
        # Simplified HTML generation
        html = f"""<!DOCTYPE html>
<html>
<head><title>Threat Report</title></head>
<body>
    <h1>Threat Intelligence Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    <p>Total Threats: {len(threats)}</p>
    <h2>Critical Threats:</h2>
    <ul>
"""
        for threat in threats:
            html += f"        <li><strong>{threat['cve_id']}</strong> - {threat['severity']} (CVSS: {threat['cvss_score']})</li>\n"
        html += """    </ul>
</body>
</html>"""
        
        with open(output_file, 'w') as f:
            f.write(html)
    
    def _generate_csv(self, threats, output_file):
        """Generate CSV report"""
        import csv
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['cve_id', 'severity', 'cvss_score', 'title'])
            writer.writeheader()
            for threat in threats:
                writer.writerow({
                    'cve_id': threat['cve_id'],
                    'severity': threat['severity'],
                    'cvss_score': threat['cvss_score'],
                    'title': threat['title']
                })
    
    def _generate_markdown(self, threats, output_file):
        """Generate markdown report"""
        with open(output_file, 'w') as f:
            f.write(f"# Threat Report\n\n")
            for threat in threats:
                f.write(f"## {threat['cve_id']}\n\n")
                f.write(f"**Severity**: {threat['severity']}\n")
                f.write(f"**CVSS**: {threat['cvss_score']}\n\n")
    
    def _generate_json(self, threats, output_file):
        """Generate JSON report"""
        import json
        with open(output_file, 'w') as f:
            json.dump(threats, f, indent=2)
