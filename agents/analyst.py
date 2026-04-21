#!/usr/bin/env python3
"""
Analyst Agent - AI-Powered Threat Intelligence
==============================================
Uses local Ollama (qwen2.5:32b) to generate plain-English threat summaries,
attack scenario analysis, and remediation recommendations for each CVE.
"""

import requests
import json
import sqlite3
import os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:32b"
FALLBACK_MODEL = "llama3.1:8b"  # Fast fallback, always loaded

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'threats.db')


class AnalystAgent:
    """AI-powered threat analyst using local LLM"""

    def __init__(self, model=MODEL):
        self.model = model
        self.available = self._check_ollama()

    def _check_ollama(self):
        """Check if Ollama is running"""
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=3)
            if r.status_code == 200:
                models = [m['name'] for m in r.json().get('models', [])]
                # Use fast reliable model by default; 32b needs manual override
                if any(FALLBACK_MODEL in m for m in models):
                    self.model = FALLBACK_MODEL
                    console.print(f"[cyan]   Using {FALLBACK_MODEL} for fast analysis[/cyan]")
                console.print(f"[green]✓ Ollama connected — using {self.model}[/green]")
                return True
        except Exception:
            pass
        console.print("[yellow]⚠️  Ollama not available — skipping AI analysis[/yellow]")
        return False

    def analyze_threat(self, threat: dict) -> dict:
        """Generate AI analysis for a single threat"""
        if not self.available:
            return self._basic_analysis(threat)

        cve_id = threat.get('cve_id', 'Unknown')
        title = threat.get('title', 'Unknown vulnerability')
        description = threat.get('description', 'No description available')
        cvss_score = threat.get('cvss_score', 5.0)
        severity = threat.get('severity', 'Medium')
        exploit_available = threat.get('exploit_available', False)

        prompt = f"""You are a senior cybersecurity analyst. Analyze this vulnerability and provide a concise threat intelligence report.

CVE ID: {cve_id}
Title: {title}
CVSS Score: {cvss_score} ({severity})
Exploit Available: {exploit_available}
Description: {description}

Provide a JSON response with exactly these fields:
{{
  "plain_english": "2-3 sentence explanation a non-technical manager can understand",
  "attack_scenario": "1-2 sentences describing how an attacker would exploit this",
  "affected_systems": "comma-separated list of affected system types",
  "remediation": "1-2 sentences on how to fix or mitigate this",
  "priority": "Patch Immediately / Patch This Week / Monitor / Low Priority",
  "threat_actor_interest": "High / Medium / Low"
}}

Respond with valid JSON only, no other text."""

        try:
            response = requests.post(
                OLLAMA_URL,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                        "num_predict": 400,
                    }
                },
                timeout=120
            )
            # If 32b times out or returns empty, fall back to llama
            if response.status_code == 200 and not response.json().get('response', '').strip():
                self.model = FALLBACK_MODEL
                response = requests.post(
                    OLLAMA_URL,
                    json={"model": FALLBACK_MODEL, "prompt": prompt, "stream": False,
                          "options": {"temperature": 0.2, "num_predict": 400}},
                    timeout=60
                )

            if response.status_code == 200:
                raw = response.json().get('response', '').strip()
                # Extract JSON from response
                start = raw.find('{')
                end = raw.rfind('}') + 1
                if start >= 0 and end > start:
                    analysis = json.loads(raw[start:end])
                    analysis['ai_analyzed'] = True
                    analysis['model_used'] = self.model
                    return analysis

        except json.JSONDecodeError:
            pass
        except Exception as e:
            console.print(f"[red]✗ AI analysis error for {cve_id}: {str(e)[:50]}[/red]")

        return self._basic_analysis(threat)

    def _basic_analysis(self, threat: dict) -> dict:
        """Fallback rule-based analysis when AI unavailable"""
        score = threat.get('cvss_score', 5.0)
        severity = threat.get('severity', 'Medium')
        exploit = threat.get('exploit_available', False)

        if score >= 9.0 or exploit:
            priority = "Patch Immediately"
            interest = "High"
        elif score >= 7.0:
            priority = "Patch This Week"
            interest = "Medium"
        elif score >= 4.0:
            priority = "Monitor"
            interest = "Low"
        else:
            priority = "Low Priority"
            interest = "Low"

        return {
            "plain_english": f"A {severity.lower()} severity vulnerability with CVSS score {score}. {'An exploit is publicly available.' if exploit else 'No public exploit known.'}",
            "attack_scenario": "Attacker could exploit this vulnerability to compromise affected systems.",
            "affected_systems": "Systems running vulnerable software versions",
            "remediation": "Apply vendor patches and security updates as soon as available.",
            "priority": priority,
            "threat_actor_interest": interest,
            "ai_analyzed": False,
            "model_used": "rule-based"
        }

    def analyze_batch(self, threats: list, limit: int = 20) -> list:
        """Analyze a batch of threats"""
        console.print(f"\n[yellow]🧠 AI Analyst processing {min(len(threats), limit)} threats...[/yellow]")
        console.print(f"[cyan]   Model: {self.model}[/cyan]")

        results = []
        to_analyze = threats[:limit]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing...", total=len(to_analyze))

            for threat in to_analyze:
                cve_id = threat.get('cve_id', 'Unknown')
                progress.update(task, description=f"Analyzing {cve_id}...")

                analysis = self.analyze_threat(threat)
                threat['ai_analysis'] = analysis
                threat['ai_summary'] = analysis.get('plain_english', '')
                threat['priority'] = analysis.get('priority', 'Monitor')
                threat['threat_actor_interest'] = analysis.get('threat_actor_interest', 'Low')
                results.append(threat)

                progress.advance(task)

        ai_count = sum(1 for t in results if t.get('ai_analysis', {}).get('ai_analyzed', False))
        console.print(f"[green]✓ Analysis complete — {ai_count}/{len(results)} analyzed by AI[/green]")
        return results

    def save_analysis_to_db(self, threats: list):
        """Save AI analysis results back to database"""
        if not threats:
            return

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Add ai_summary column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE threats ADD COLUMN ai_summary TEXT")
            cursor.execute("ALTER TABLE threats ADD COLUMN priority TEXT")
            cursor.execute("ALTER TABLE threats ADD COLUMN threat_actor_interest TEXT")
            cursor.execute("ALTER TABLE threats ADD COLUMN ai_full_analysis TEXT")
        except sqlite3.OperationalError:
            pass  # Columns already exist

        updated = 0
        for threat in threats:
            if 'ai_analysis' in threat:
                cursor.execute("""
                    UPDATE threats SET
                        ai_summary = ?,
                        priority = ?,
                        threat_actor_interest = ?,
                        ai_full_analysis = ?,
                        processed = 1
                    WHERE cve_id = ?
                """, (
                    threat.get('ai_summary', ''),
                    threat.get('priority', ''),
                    threat.get('threat_actor_interest', ''),
                    json.dumps(threat.get('ai_analysis', {})),
                    threat.get('cve_id', '')
                ))
                updated += cursor.rowcount

        conn.commit()
        conn.close()
        console.print(f"[green]✓ Saved AI analysis for {updated} threats to database[/green]")

    def print_sample_analysis(self, threat: dict):
        """Pretty print a sample analysis"""
        analysis = threat.get('ai_analysis', {})
        if not analysis:
            return

        cve_id = threat.get('cve_id', 'Unknown')
        severity = threat.get('severity', 'Unknown')
        score = threat.get('cvss_score', 0)

        color = {
            'Critical': 'red', 'High': 'orange3',
            'Medium': 'yellow', 'Low': 'green'
        }.get(severity, 'white')

        panel_content = f"""
[bold]{cve_id}[/bold] | [{color}]{severity} (CVSS {score})[/{color}] | Priority: [bold]{analysis.get('priority', 'N/A')}[/bold]

[bold cyan]📋 Plain English:[/bold cyan]
{analysis.get('plain_english', 'N/A')}

[bold red]⚔️  Attack Scenario:[/bold red]
{analysis.get('attack_scenario', 'N/A')}

[bold green]🛡️  Remediation:[/bold green]
{analysis.get('remediation', 'N/A')}

[bold yellow]🎯 Threat Actor Interest:[/bold yellow] {analysis.get('threat_actor_interest', 'N/A')}
[bold]🖥️  Affected Systems:[/bold] {analysis.get('affected_systems', 'N/A')}
[dim]Model: {analysis.get('model_used', 'N/A')}[/dim]
"""
        console.print(Panel(panel_content, title="🧠 AI Threat Analysis", border_style=color))


if __name__ == "__main__":
    # Test the analyst
    console.print("[bold yellow]🧠 Testing AI Analyst Agent[/bold yellow]\n")

    analyst = AnalystAgent()

    test_threats = [
        {
            'cve_id': 'CVE-2026-20122',
            'title': 'Cisco Catalyst SD-WAN Manager Incorrect Use of Privileged APIs',
            'description': 'A vulnerability in Cisco Catalyst SD-WAN Manager allows an authenticated remote attacker to gain elevated privileges on an affected system due to incorrect use of privileged APIs.',
            'cvss_score': 9.9,
            'severity': 'Critical',
            'exploit_available': True
        },
        {
            'cve_id': 'CVE-2025-2749',
            'title': 'Kentico Xperience Path Traversal Vulnerability',
            'description': 'Kentico Xperience contains a path traversal vulnerability that allows remote attackers to read arbitrary files on the server.',
            'cvss_score': 7.5,
            'severity': 'High',
            'exploit_available': True
        }
    ]

    results = analyst.analyze_batch(test_threats, limit=2)

    console.print("\n[bold]Sample AI Analysis Output:[/bold]\n")
    for threat in results:
        analyst.print_sample_analysis(threat)
