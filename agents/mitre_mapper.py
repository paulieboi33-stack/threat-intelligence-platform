#!/usr/bin/env python3
"""
MITRE ATT&CK Mapper Agent
=========================
Maps CVEs to MITRE ATT&CK tactics and techniques.
Uses keyword-based mapping against the ATT&CK Enterprise framework.
Reference: https://attack.mitre.org/
"""

import sqlite3
import json
import os
import re
from rich.console import Console
from rich.table import Table

console = Console()

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'threats.db')

# ─── MITRE ATT&CK Mapping Rules ───────────────────────────────────────────────
# Maps keywords in CVE descriptions to ATT&CK Tactics + Techniques
# Source: https://attack.mitre.org/tactics/enterprise/

MITRE_MAPPINGS = [
    # Initial Access
    {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "keywords": ["remote code execution", "rce", "unauthenticated", "public-facing",
                     "web application", "api endpoint", "exposed service", "path traversal",
                     "directory traversal", "file inclusion", "sql injection", "sqli"],
        "color": "#e74c3c"
    },
    {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Phishing",
        "technique_id": "T1566",
        "keywords": ["phishing", "email", "attachment", "malicious document", "macro",
                     "spear phishing", "office document"],
        "color": "#e74c3c"
    },
    # Execution
    {
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique": "Command and Scripting Interpreter",
        "technique_id": "T1059",
        "keywords": ["command injection", "shell", "powershell", "bash", "script injection",
                     "code injection", "eval", "exec", "arbitrary command", "os command"],
        "color": "#e67e22"
    },
    {
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique": "Exploitation for Client Execution",
        "technique_id": "T1203",
        "keywords": ["client-side", "browser", "javascript", "cross-site scripting", "xss",
                     "dom", "flash", "pdf reader", "adobe reader", "acrobat"],
        "color": "#e67e22"
    },
    # Persistence
    {
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique": "Server Software Component",
        "technique_id": "T1505",
        "keywords": ["webshell", "web shell", "backdoor", "persistent", "plugin",
                     "extension", "module", "wordpress", "cms plugin"],
        "color": "#9b59b6"
    },
    # Privilege Escalation
    {
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique": "Exploitation for Privilege Escalation",
        "technique_id": "T1068",
        "keywords": ["privilege escalation", "elevat", "root", "administrator",
                     "unauthorized actor", "privileged api", "sudo", "setuid",
                     "improper authorization", "incorrect privilege"],
        "color": "#f39c12"
    },
    {
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique": "Access Token Manipulation",
        "technique_id": "T1134",
        "keywords": ["token", "oauth", "jwt", "session", "cookie", "authentication bypass",
                     "improper authentication", "auth bypass"],
        "color": "#f39c12"
    },
    # Defense Evasion
    {
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "Exploitation for Defense Evasion",
        "technique_id": "T1211",
        "keywords": ["bypass", "evade", "antivirus", "security control", "filter bypass",
                     "sandbox", "detection evasion"],
        "color": "#1abc9c"
    },
    # Credential Access
    {
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "keywords": ["brute force", "password", "credential", "authentication", "login",
                     "account lockout", "weak password", "default credential"],
        "color": "#3498db"
    },
    {
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Steal or Forge Authentication Certificates",
        "technique_id": "T1649",
        "keywords": ["certificate", "ssl", "tls", "x.509", "private key", "crypto",
                     "cryptographic", "certificate validation"],
        "color": "#3498db"
    },
    # Discovery
    {
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "keywords": ["information disclosure", "information exposure", "sensitive information",
                     "data exposure", "leak", "disclosure", "enumerate", "scan"],
        "color": "#2ecc71"
    },
    # Lateral Movement
    {
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique": "Exploitation of Remote Services",
        "technique_id": "T1210",
        "keywords": ["lateral movement", "remote service", "smb", "rdp", "ssh",
                     "network share", "remote desktop", "winrm"],
        "color": "#16a085"
    },
    # Collection
    {
        "tactic": "Collection",
        "tactic_id": "TA0009",
        "technique": "Data from Local System",
        "technique_id": "T1005",
        "keywords": ["file read", "arbitrary file", "local file", "read file",
                     "directory listing", "file access", "data collection"],
        "color": "#8e44ad"
    },
    # Exfiltration
    {
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "technique": "Exfiltration Over Web Service",
        "technique_id": "T1567",
        "keywords": ["exfiltrat", "data theft", "data exfiltration", "send data",
                     "upload", "transmit", "covert channel"],
        "color": "#c0392b"
    },
    # Impact
    {
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Data Destruction",
        "technique_id": "T1485",
        "keywords": ["denial of service", "dos", "ddos", "crash", "resource exhaustion",
                     "memory corruption", "buffer overflow", "heap overflow", "stack overflow",
                     "use-after-free", "null pointer", "out-of-bounds"],
        "color": "#e74c3c"
    },
    {
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Defacement",
        "technique_id": "T1491",
        "keywords": ["defacement", "ransomware", "encrypt", "wiper", "destructive"],
        "color": "#e74c3c"
    },
    # Command and Control
    {
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique": "Application Layer Protocol",
        "technique_id": "T1071",
        "keywords": ["c2", "command and control", "remote access", "trojan", "rat",
                     "botnet", "malware", "implant", "beacon"],
        "color": "#d35400"
    },
]


class MitreMapper:
    """Maps CVEs to MITRE ATT&CK tactics and techniques"""

    def __init__(self):
        self.mappings = MITRE_MAPPINGS

    def map_threat(self, threat: dict) -> list:
        """Map a single threat to ATT&CK techniques"""
        text = f"{threat.get('title', '')} {threat.get('description', '')} {threat.get('ai_summary', '')}".lower()

        matched = []
        seen_techniques = set()

        for mapping in self.mappings:
            for keyword in mapping['keywords']:
                if keyword.lower() in text and mapping['technique_id'] not in seen_techniques:
                    matched.append({
                        'tactic': mapping['tactic'],
                        'tactic_id': mapping['tactic_id'],
                        'technique': mapping['technique'],
                        'technique_id': mapping['technique_id'],
                        'color': mapping['color'],
                        'url': f"https://attack.mitre.org/techniques/{mapping['technique_id']}/"
                    })
                    seen_techniques.add(mapping['technique_id'])
                    break

        # Default if no match
        if not matched:
            matched.append({
                'tactic': 'Exploitation',
                'tactic_id': 'TA0000',
                'technique': 'Exploit Public-Facing Application',
                'technique_id': 'T1190',
                'color': '#e74c3c',
                'url': 'https://attack.mitre.org/techniques/T1190/'
            })

        return matched

    def map_all_threats(self, threats: list) -> list:
        """Map all threats and return enriched list"""
        console.print("\n[yellow]🎯 MITRE ATT&CK Mapper — mapping threats to tactics...[/yellow]")
        enriched = []
        for threat in threats:
            mappings = self.map_threat(threat)
            threat['mitre_mappings'] = mappings
            threat['mitre_tactics'] = list(set(m['tactic'] for m in mappings))
            threat['mitre_techniques'] = [f"{m['technique_id']}: {m['technique']}" for m in mappings]
            enriched.append(threat)

        console.print(f"[green]✓ Mapped {len(enriched)} threats to ATT&CK framework[/green]")
        return enriched

    def save_to_db(self, threats: list):
        """Save MITRE mappings to database"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Add columns if needed
        for col in ['mitre_tactics', 'mitre_techniques', 'mitre_mappings']:
            try:
                cursor.execute(f"ALTER TABLE threats ADD COLUMN {col} TEXT")
            except sqlite3.OperationalError:
                pass

        updated = 0
        for threat in threats:
            if 'mitre_mappings' in threat:
                cursor.execute("""
                    UPDATE threats SET
                        mitre_tactics = ?,
                        mitre_techniques = ?,
                        mitre_mappings = ?
                    WHERE cve_id = ?
                """, (
                    json.dumps(threat.get('mitre_tactics', [])),
                    json.dumps(threat.get('mitre_techniques', [])),
                    json.dumps(threat.get('mitre_mappings', [])),
                    threat.get('cve_id', '')
                ))
                updated += cursor.rowcount

        conn.commit()
        conn.close()
        console.print(f"[green]✓ Saved MITRE mappings for {updated} threats[/green]")

    def get_tactic_summary(self, threats: list) -> dict:
        """Get count of threats per tactic"""
        tactic_counts = {}
        for threat in threats:
            for tactic in threat.get('mitre_tactics', []):
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        return dict(sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True))

    def print_summary(self, threats: list):
        """Print MITRE mapping summary table"""
        tactic_counts = self.get_tactic_summary(threats)

        table = Table(title="🎯 MITRE ATT&CK Tactic Distribution")
        table.add_column("Tactic", style="cyan")
        table.add_column("Threats", justify="center")
        table.add_column("ATT&CK ID", style="dim")

        tactic_ids = {m['tactic']: m['tactic_id'] for m in MITRE_MAPPINGS}
        for tactic, count in tactic_counts.items():
            bar = "█" * min(count, 20)
            table.add_row(tactic, f"{count} {bar}", tactic_ids.get(tactic, ""))

        console.print(table)


if __name__ == "__main__":
    # Test the mapper
    console.print("[bold yellow]🎯 Testing MITRE ATT&CK Mapper[/bold yellow]\n")

    mapper = MitreMapper()

    # Load from DB
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threats ORDER BY cvss_score DESC LIMIT 30")
    threats = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # Map them
    enriched = mapper.map_all_threats(threats)
    mapper.save_to_db(enriched)
    mapper.print_summary(enriched)

    # Show sample
    console.print("\n[bold]Sample mappings:[/bold]")
    for t in enriched[:5]:
        console.print(f"\n[cyan]{t['cve_id']}[/cyan] — {(t.get('title') or '')[:50]}")
        for m in t.get('mitre_mappings', [])[:2]:
            console.print(f"  → [{m['tactic_id']}] {m['tactic']} :: [{m['technique_id']}] {m['technique']}")
