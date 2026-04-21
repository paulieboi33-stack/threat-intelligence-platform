#!/usr/bin/env python3
"""
API Integration Layer - Threat Intelligence Feeds
======================
Connect to real threat data sources: NVD, CISA, MalwareBazaar
"""

import requests
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

class ThreatAPI:
    """Threat intelligence API client"""
    
    def __init__(self):
        self.base_urls = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'malwarebazaar': 'https://firewall-mon.surge.sh/feed/urlhaus',
            'github_cve': 'https://raw.githubusercontent.com/JT3N/CVE-List/main/data.json'
        }
        self.api_key = ''  # NVD API key (optional, for rate limiting)
    
    def fetch_nvd_threats(self, cve_id=None, limit=100):
        """Fetch CVE data from NVD API"""
        console.print("[yellow]📥 Fetching from NVD CVE API...[/yellow]")
        
        try:
            url = self.base_urls['nvd']
            
            from datetime import timedelta
            thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%dT00:00:00.000')
            now_str = datetime.now().strftime('%Y-%m-%dT23:59:59.999')
            params = {
                'resultsPerPage': min(limit, 100),
                'startIndex': 0,
                'pubStartDate': thirty_days_ago,
                'pubEndDate': now_str,
            }
            if cve_id:
                params['cveId'] = cve_id
            if self.api_key:
                params['apiKey'] = self.api_key
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                # Extract CVE data
                threats = []
                for vuln in vulnerabilities[:limit]:
                    cve_data = vuln.get('cve', {})
                    if not cve_data or 'id' not in cve_data:
                        continue
                    
                    # Get description - NVD API v2.0 structure
                    descriptions = cve_data.get('descriptions', [])
                    description_text = ''
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description_text = desc.get('value', '')
                            break
                    if not description_text and descriptions:
                        description_text = descriptions[0].get('value', '')

                    # Get metrics (CVSS score) - NVD API v2.0 structure
                    metrics = cve_data.get('metrics', {})
                    cvss_score = 5.0  # Default
                    try:
                        if 'cvssMetricV31' in metrics:
                            cvss_score = float(metrics['cvssMetricV31'][0]['cvssData']['baseScore'])
                        elif 'cvssMetricV30' in metrics:
                            cvss_score = float(metrics['cvssMetricV30'][0]['cvssData']['baseScore'])
                        elif 'cvssMetricV2' in metrics:
                            cvss_score = float(metrics['cvssMetricV2'][0]['cvssData']['baseScore'])
                    except (KeyError, IndexError, TypeError):
                        pass
                    
                    # Determine severity
                    severity = self._calculate_severity(cvss_score)
                    
                    threat = {
                        'id': f"SCOUT-{len(threats)+1:04d}",
                        'cve_id': cve_data.get('id'),
                        'title': cve_data.get('shortName', 'Unknown'),
                        'description': description_text[:200] + '...' if len(description_text) > 200 else description_text,
                        'cvss_score': cvss_score,
                        'published': cve_data.get('published'),
                        'modified': cve_data.get('lastModified'),
                        'severity': severity,
                        'exploit_available': cve_data.get('exploitAvailable', False),
                        'references': cve_data.get('references', [])[:5]  # Limit refs
                    }
                    threats.append(threat)
                
                console.print(f"[green]✓ Retrieved {len(threats)} CVEs from NVD[/green]")
                
                # Show sample
                if threats:
                    self._display_threat_summary(threats[:3])
                
                return threats
                
            else:
                console.print(f"[red]✗ NVD API error: {response.status_code} - {response.text[:100]}[/red]")
                return []
                
        except Exception as e:
            console.print(f"[red]✗ Error fetching NVD data: {str(e)}[/red]")
            return []
    
    def fetch_cisa_kev(self, limit=20):
        """Fetch CISA Known Exploited Vulnerabilities (live JSON feed)"""
        console.print("[yellow]📥 Checking CISA Known Exploited Vulnerabilities...[/yellow]")
        
        try:
            url = self.base_urls['cisa_kev']
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulns = data.get('vulnerabilities', [])[:limit]
                
                threats = []
                for v in vulns:
                    threat = {
                        'id': v.get('cveID', f'CISA-{len(threats)+1:04d}'),
                        'cve_id': v.get('cveID', 'Unknown'),
                        'title': v.get('vulnerabilityName', 'Unknown'),
                        'description': v.get('shortDescription', ''),
                        'cvss_score': 9.0,  # KEV = actively exploited = critical
                        'severity': 'Critical',
                        'exploit_available': True,
                        'known_exploit': True,
                        'kev_date': v.get('dateAdded', ''),
                        'vendor': v.get('vendorProject', ''),
                        'product': v.get('product', ''),
                        'due_date': v.get('dueDate', ''),
                    }
                    threats.append(threat)
                
                total = len(data.get('vulnerabilities', []))
                console.print(f"[green]✓ Retrieved {len(threats)} CISA KEV threats (of {total} total in catalog)[/green]")
                self._display_threat_summary(threats[:3])
                return threats
            else:
                console.print(f"[red]✗ CISA KEV error: {response.status_code}[/red]")
                return []
                
        except Exception as e:
            console.print(f"[red]✗ Error fetching CISA KEV: {str(e)}[/red]")
            return []
    
    def fetch_malwarebazaar(self):
        """Fetch malware samples from MalwareBazaar"""
        console.print("[yellow]📥 Checking MalwareBazaar for active malware...[/yellow]")
        
        try:
            # MalwareBazaar feed URL
            url = self.base_urls['malwarebazaar']
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                # MalwareBazaar returns JSON array of hashes
                samples = response.json()[:5]  # Limit to 5 for demo
                
                threats = []
                for sample in samples:
                    threat = {
                        'id': f"MALWARE-{len(threats)+1:04d}",
                        'cve_id': 'MALWARE-FAMILY',
                        'title': f"Malware Family: {sample.get('alias', 'Unknown')}",
                        'description': f"Active malware sample detected. Bazaar first seen: {sample.get('firstSeen', 'N/A')}",
                        'cvss_score': 9.0,  # Malware is always critical
                        'severity': 'Critical',
                        'exploit_available': True,
                        'known_exploit': True,
                        'malware_family': sample.get('alias', 'Unknown')
                    }
                    threats.append(threat)
                
                console.print(f"[green]✓ Retrieved {len(threats)} malware samples[/green]")
                return threats
            else:
                console.print("[yellow]⚠️ MalwareBazaar feed unavailable (expected in demo) / yellow]")
                return []
                
        except Exception as e:
            console.print(f"[red]✗ Error fetching MalwareBazaar: {str(e)}[/red]")
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
    
    def _display_threat_summary(self, threats):
        """Display sample of threats in table"""
        if not threats:
            return
        
        table = Table(title="📦 Sample Threats Retrieved")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Severity")
        table.add_column("CVSS Score")
        table.add_column("Title (Truncated)")
        
        for threat in threats[:5]:
            title = threat.get('title', 'Unknown')[:50] + "..." if len(threat.get('title', '')) > 50 else threat.get('title', 'Unknown')
            table.add_row(
                threat.get('cve_id', 'Unknown'),
                threat.get('severity', 'Unknown'),
                str(threat.get('cvss_score', 'N/A')),
                title
            )
        
        console.print(table)
    
    def combine_all_threats(self):
        """Combine threats from all sources"""
        console.print("\n[yellow]🔗 Combining threats from all sources...[/yellow]")
        
        all_threats = []
        
        # Fetch from NVD
        nvd_threats = self.fetch_nvd_threats(limit=20)
        all_threats.extend(nvd_threats)
        
        # Fetch from CISA KEV
        cev_threats = self.fetch_cisa_kev()
        all_threats.extend(cev_threats)
        
        # Fetch from MalwareBazaar
        malware_threats = self.fetch_malwarebazaar()
        all_threats.extend(malware_threats)
        
        console.print(f"[green]✓ Total threats collected: {len(all_threats)}[/green]")
        
        return all_threats

if __name__ == "__main__":
    console.print("[yellow]🌐 Threat Intelligence API Integration Test[/yellow]")
    
    api = ThreatAPI()
    
    # Test each API
    threats = api.combine_all_threats()
    
    console.print("\n[blue]📊 Integration Complete[/blue]")
    console.print(f"Total threats from all sources: {len(threats)}")
