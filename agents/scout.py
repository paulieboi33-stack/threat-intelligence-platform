#!/usr/bin/env python3
"""
Scout Agent - Threat Collection
===========================
Gathers raw threat intelligence from open-source feeds
"""

import requests
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

class ScoutAgent:
    """Threat collection agent"""
    
    def __init__(self):
        self.api_keys = {}
        self.data_sources = {
            'nvd': {
                'name': 'NVD CVE API',
                'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
                'enabled': True
            },
            'cisa': {
                'name': 'CISA KEV Catalog',
                'url': 'https://www.cisa.gov/know-your-attacker',
                'enabled': False  # Requires authentication
            },
            'malwarebazaar': {
                'name': 'MalwareBazaar',
                'url': 'https://firewall-mon.surge.sh/feed/urlhaus',
                'enabled': False
            }
        }
    
    def fetch_nvd_threats(self, cve_ids=None, limit=10):
        """Fetch threats from NVD API"""
        console.print("[yellow]📥 Fetching from NVD CVE API...[/yellow]")
        
        try:
            # Simplified NVD call
            response = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves?api_key={self.api_keys.get('nvd', 'demo')}",
                params={'resultsPerPage': limit},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                threats = []
                
                for cve in data.get('vulnerabilities', [])[:limit]:
                    threat = {
                        'id': cve.get('id', 'Unknown'),
                        'cve_id': cve.get('cve', {}).get('id'),
                        'title': cve.get('cve', {}).get('description', {}).get('shortName'),
                        'description': cve.get('cve', {}).get('description', {}).get('descriptions', [{}])[0].get('value', ''),
                        'cvss_score': float(cve.get('cve', {}).get('metrics', {}).get('metrics', [{}])[0].get('cvssV3_1', {}).get('score', 5.0)),
                        'published_date': cve.get('cve', {}).get('published', ''),
                        'modified_date': cve.get('cve', {}).get('lastModified', ''),
                        'vendor': cve.get('cve', {}).get('references', {}).get('references', [{}])[0].get('name', ''),
                        'product': 'Various',
                        'severity': self._calculate_severity(cve.get('cve', {}).get('cvssV3_1', {}).get('baseScore', 0)),
                        'exploit_available': cve.get('cve', {}).get('exploitAvailable', False),
                        'known_exploit': cve.get('cve', {}).get('exploitAvailable', False),
                        'references': cve.get('cve', {}).get('references', {}).get('references', [])
                    }
                    threats.append(threat)
                
                console.print(f"[green]✓ Retrieved {len(threats)} threats from NVD[/green]")
                return threats
            else:
                console.print(f"[red]✗ NVD API error: {response.status_code}[/red]")
                return []
                
        except Exception as e:
            console.print(f"[red]✗ Error fetching NVD data: {str(e)}[/red]")
            return []
    
    def _calculate_severity(self, cvss_score):
        """Calculate severity from CVSS score"""
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        else:
            return "Low"
    
    def enrich_threats(self, threats):
        """Mark threats as collected"""
        enriched = []
        for threat in threats:
            enriched.append({
                'collected_at': datetime.now().isoformat(),
                **threat
            })
        return enriched

    def display_threats(self, threats):
        """Display collected threats in table format"""
        if not threats:
            return
        
        table = Table(title="📥 Collected Threat Intelligence")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Severity", justify="center")
        table.add_column("CVSS Score")
        table.add_column("Exploit", justify="center")
        table.add_column("Title (Truncated)")
        
        for threat in threats[:5]:  # Show first 5
            title = threat.get('title', 'Unknown')[:50] + "..." if len(threat.get('title', '')) > 50 else threat.get('title', 'Unknown')
            table.add_row(
                threat.get('cve_id', 'Unknown'),
                threat.get('severity', 'Unknown'),
                str(threat.get('cvss_score', 'N/A')),
                "⚠️" if threat.get('exploit_available') else "✓",
                title
            )
        
        console.print(table)

def load_sample_threats():
    """Load sample CVE data for demo"""
    return [
        {
            'id': 'CVE-2024-1001',
            'cve_id': 'CVE-2024-1001',
            'title': 'Windows SMB Remote Code Execution',
            'description': 'Remote code execution vulnerability in Windows Server SMB protocol allows attackers to execute arbitrary code',
            'cvss_score': 9.8,
            'published_date': '2024-04-01T00:00:00',
            'modified_date': '2024-04-01T00:00:00',
            'vendor': 'Microsoft',
            'product': 'Windows Server',
            'severity': 'Critical',
            'exploit_available': True,
            'known_exploit': True,
            'references': ['https://msrc.microsoft.com']
        },
        {
            'id': 'CVE-2024-2001',
            'cve_id': 'CVE-2024-2001',
            'title': 'Linux Kernel Memory Corruption',
            'description': 'Memory corruption in Linux kernel networking stack',
            'cvss_score': 7.5,
            'published_date': '2024-04-05T00:00:00',
            'modified_date': '2024-04-06T00:00:00',
            'vendor': 'Linux Foundation',
            'product': 'Linux Kernel',
            'severity': 'High',
            'exploit_available': False,
            'known_exploit': False,
            'references': ['https://lwn.net']
        },
        {
            'id': 'CVE-2024-3001',
            'cve_id': 'CVE-2024-3001',
            'title': 'Docker Container Escaping',
            'description': 'Container escape vulnerability allowing breakout from containers',
            'cvss_score': 8.1,
            'published_date': '2024-04-02T00:00:00',
            'modified_date': '2024-04-03T00:00:00',
            'vendor': 'Docker',
            'product': 'Docker Engine',
            'severity': 'High',
            'exploit_available': True,
            'known_exploit': False,
            'references': ['https://hub.docker.com']
        }
    ]

if __name__ == "__main__":
    console.print("[yellow]🔍 Scout Agent - Threat Collection System[/yellow]")
    console.print("[green]📦 Loading sample threat data...[/green]")
    
    # Load sample threats
    threats = load_sample_threats()
    
    # Display collected threats
    scout = ScoutAgent()
    scout.display_threats(threats)
    
    console.print(f"\n[blue]📊 Total threats collected: {len(threats)}[/blue]")
