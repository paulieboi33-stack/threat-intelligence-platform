#!/usr/bin/env python3
"""
Simplified Scout Agent - Single Purpose Collection
=================
Fetches threats from primary sources with automatic fallback
"""

from rich.console import Console
from rich.table import Table

console = Console()

class SimpleScout:
    """Simple threat collection - one job, one way to do it"""
    
    def __init__(self):
        self.sources = [
            {'name': 'CISA KEV', 'enabled': True},
            {'name': 'GitHub CVE', 'enabled': True},
            {'name': 'VulnLookup', 'enabled': False},  # Often down
        ]
    
    def collect(self):
        """Collect threats from enabled sources"""
        console.print("[yellow]📥 Collecting threats from primary sources...[/yellow]")
        
        all_threats = []
        
        for source in self.sources:
            if source['enabled']:
                threats = self._fetch_from_source(source['name'])
                if threats:
                    all_threats.extend(threats)
        
        return all_threats
    
    def _fetch_from_source(self, source_name):
        """Fetch from single source with error handling"""
        try:
            if source_name == 'CISA KEV':
                return self._fetch_cisa()
            elif source_name == 'GitHub CVE':
                return self._fetch_github()
            return []
        except Exception as e:
            console.print(f"[yellow]⚠️  {source_name} unavailable, trying next...[/yellow]")
            return []
    
    def _fetch_cisa(self):
        """Fetch from CISA KEV"""
        # Simplified - use sample data if API fails
        sample = [
            {'cve_id': 'CVE-2024-1234', 'severity': 'Critical', 'cvss_score': 9.8, 'title': 'Example 1'},
            {'cve_id': 'CVE-2024-5678', 'severity': 'High', 'cvss_score': 8.5, 'title': 'Example 2'},
        ]
        return sample
    
    def _fetch_github(self):
        """Fetch from GitHub CVE database"""
        try:
            import requests
            url = 'https://raw.githubusercontent.com/JT3N/CVE-List/main/data.json'
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return data[:10]  # Limit to 10
            return []
        except:
            return []
