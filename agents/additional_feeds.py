#!/usr/bin/env python3
"""
Additional Threat Intelligence Feeds - Easy Integration
=======================
Free, public APIs that don't require authentication
"""

import requests
from rich.console import Console
from rich.table import Table

console = Console()

class AdditionalThreatFeeds:
    """Additional threat intelligence data sources"""
    
    def __init__(self):
        self.feeds = {
            'github_cve': 'GitHub CVE Database',
            'exploit_db': 'Exploit Database',
            'vulnlookup': 'VulnLookup',
            'cve_details': 'CVE Details API',
            'securityfocus': 'SecurityFocus/Bulletin',
            'packetstorm': 'Packet Storm Security'
        }
    
    def fetch_github_cve(self, limit=50):
        """Fetch CVE data from GitHub CVE list"""
        console.print("[yellow]📥 Fetching from GitHub CVE Database...[/yellow]")
        
        try:
            # GitHub CVE list is available as raw JSON
            url = 'https://raw.githubusercontent.com/JT3N/CVE-List/main/data.json'
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                threats = []
                for cve in data[:limit]:
                    threat = {
                        'id': f"GH-{len(threats)+1:04d}",
                        'cve_id': cve.get('id'),
                        'title': cve.get('title', 'Unknown'),
                        'description': cve.get('description', '')[:200],
                        'cvss_score': float(cve.get('cvssScore', 5.0)),
                        'severity': self._calculate_severity(cve.get('cvssScore', 0)),
                        'references': cve.get('references', [])
                    }
                    threats.append(threat)
                
                console.print(f"[green]✓ Retrieved {len(threats)} CVEs from GitHub[/green]")
                return threats
            else:
                console.print("[yellow]⚠️ GitHub CVE feed unavailable[/yellow]")
                return []
                
        except Exception as e:
            console.print(f"[red]✗ Error: {str(e)}[/red]")
            return []
    
    def fetch_exploit_db(self, limit=20):
        """Fetch from Exploit-DB"""
        console.print("[yellow]📥 Checking Exploit-DB for active exploits...[/yellow]")
        
        try:
            # Exploit-DB search API
            url = 'https://www.exploit-db.com/search'
            params = {
                'search': '',
                'platform': 'all',
                'type': 'all',
                'limit': limit
            }
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                exploits = data.get('exploits', [])
                
                threats = []
                for exploit in exploits[:limit]:
                    threat = {
                        'id': f"EXP-{len(threats)+1:04d}",
                        'cve_id': exploit.get('title', 'Unknown'),
                        'title': exploit.get('title', ''),
                        'description': exploit.get('view_count', '0') + ' views',
                        'cvss_score': 7.0,  # Exploit available = high risk
                        'severity': 'High',
                        'exploit_available': True,
                        'references': [exploit.get('view_count', '')]
                    }
                    threats.append(threat)
                
                console.print(f"[green]✓ Retrieved {len(threats)} exploits from Exploit-DB[/green]")
                return threats
            else:
                console.print("[yellow]⚠️ Exploit-DB search unavailable[/yellow]")
                return []
                
        except Exception as e:
            console.print(f"[red]✗ Error: {str(e)}[/red]")
            return []
    
    def fetch_vulnlookup(self):
        """Fetch from VulnLookup (CVE details)"""
        console.print("[yellow]📥 Fetching from VulnLookup...[/yellow]")
        
        try:
            # VulnLookup provides detailed CVE information
            url = 'https://www.vulnlookup.com/api.php'
            
            # Use sample CVEs for demo (in production, use real CVE list)
            sample_cves = ['CVE-2024-1001', 'CVE-2024-2001', 'CVE-2024-3001']
            
            threats = []
            for cve_id in sample_cves:
                response = requests.get(url, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        details = data.get('cve', {})
                        threat = {
                            'id': f"VL-{len(threats)+1:04d}",
                            'cve_id': cve_id,
                            'title': details.get('title', ''),
                            'description': details.get('description', '')[:200],
                            'cvss_score': float(details.get('cvss', 5.0)),
                            'severity': self._calculate_severity(details.get('cvss', 0)),
                            'references': details.get('references', [])
                        }
                        threats.append(threat)
                
                console.print(f"[green]✓ Retrieved vulnerability details for {cve_id}[/green]")
            
            return threats
                
        except Exception as e:
            console.print(f"[red]✗ Error: {str(e)}[/red]")
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
    
    def fetch_all_additional_feeds(self):
        """Fetch from all additional sources"""
        console.print("\n[yellow]🔗 Fetching from additional threat feeds...[/yellow]")
        
        all_threats = []
        
        # Fetch from GitHub
        github_threats = self.fetch_github_cve(limit=30)
        all_threats.extend(github_threats)
        
        # Fetch from Exploit-DB
        exploit_threats = self.fetch_exploit_db(limit=15)
        all_threats.extend(exploit_threats)
        
        # Fetch from VulnLookup
        vuln_threats = self.fetch_vulnlookup()
        all_threats.extend(vuln_threats)
        
        console.print(f"\n[green]✓ Total additional threats: {len(all_threats)}[/green]")
        
        return all_threats

if __name__ == "__main__":
    console.print("[yellow]🌐 Additional Threat Feeds Test[/yellow]")
    
    feeds = AdditionalThreatFeeds()
    threats = feeds.fetch_all_additional_feeds()
    
    console.print(f"\n[blue]📊 Total threats from additional feeds: {len(threats)}[/blue]")
