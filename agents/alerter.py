#!/usr/bin/env python3
"""
Alerter Agent - Email Notifications for Critical Threats
=========================================================
Sends Gmail alerts when Critical CVEs are detected.
Uses the gog CLI (already configured for leonaeger2026@gmail.com).
"""

import subprocess
import sqlite3
import json
import os
from datetime import datetime, timedelta
from rich.console import Console

console = Console()

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'threats.db')
ALERT_STATE_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alert_state.json')
ALERT_EMAIL = "paulnaeger@protonmail.com"


def load_alert_state():
    """Load record of already-alerted CVEs to avoid duplicates"""
    if os.path.exists(ALERT_STATE_PATH):
        with open(ALERT_STATE_PATH) as f:
            return json.load(f)
    return {"alerted_cves": [], "last_alert_run": None}


def save_alert_state(state):
    with open(ALERT_STATE_PATH, 'w') as f:
        json.dump(state, f, indent=2)


def get_new_critical_threats(state):
    """Get Critical threats not yet alerted on"""
    already_alerted = set(state.get("alerted_cves", []))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get critical threats from last 24 hours that we haven't alerted on
    since = (datetime.now() - timedelta(hours=24)).isoformat()
    cursor.execute("""
        SELECT cve_id, title, description, cvss_score, severity,
               ai_summary, priority, threat_actor_interest, collected_at
        FROM threats
        WHERE severity = 'Critical'
        AND collected_at >= ?
        ORDER BY cvss_score DESC
    """, (since,))

    threats = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # Filter out already alerted
    new_threats = [t for t in threats if t['cve_id'] not in already_alerted]
    return new_threats


def build_email_body(threats):
    """Build HTML email body for critical threat alert"""
    count = len(threats)
    now = datetime.now().strftime("%B %d, %Y at %I:%M %p")

    threat_rows = ""
    for t in threats[:10]:  # Cap at 10 per email
        title = t.get('title') or t.get('description', '')[:80]
        ai_summary = t.get('ai_summary', '')
        priority = t.get('priority', 'Unknown')

        threat_rows += f"""
        <tr>
            <td style="padding:8px; border-bottom:1px solid #333; color:#ff4444; font-weight:bold;">{t['cve_id']}</td>
            <td style="padding:8px; border-bottom:1px solid #333;">{title[:60]}</td>
            <td style="padding:8px; border-bottom:1px solid #333; text-align:center;">{t['cvss_score']}</td>
            <td style="padding:8px; border-bottom:1px solid #333; color:#ff8800;">{priority}</td>
        </tr>
        <tr>
            <td colspan="4" style="padding:8px 8px 16px 8px; border-bottom:1px solid #222; color:#aaa; font-size:0.9em;">
                🧠 {ai_summary if ai_summary else 'No AI summary available.'}
            </td>
        </tr>
        """

    return f"""
<html>
<body style="background:#0d1117; color:#e6edf3; font-family:Arial,sans-serif; padding:20px;">

<div style="max-width:700px; margin:0 auto;">

<div style="background:#161b22; border:1px solid #ff4444; border-radius:8px; padding:20px; margin-bottom:20px;">
    <h1 style="color:#ff4444; margin:0;">🚨 Critical Threat Alert</h1>
    <p style="color:#aaa; margin:8px 0 0 0;">{count} new Critical CVE{'s' if count > 1 else ''} detected · {now}</p>
</div>

<div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px; margin-bottom:20px;">
    <h2 style="color:#58a6ff; margin-top:0;">📊 Summary</h2>
    <p>Your Threat Intelligence Platform has detected <strong style="color:#ff4444;">{count} new Critical severity vulnerabilities</strong> in the last 24 hours.</p>
    <p>These require <strong>immediate attention</strong> — review and patch affected systems as soon as possible.</p>
</div>

<div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px; margin-bottom:20px;">
    <h2 style="color:#58a6ff; margin-top:0;">🔴 Critical Threats</h2>
    <table style="width:100%; border-collapse:collapse;">
        <thead>
            <tr style="background:#21262d;">
                <th style="padding:8px; text-align:left; color:#8b949e;">CVE ID</th>
                <th style="padding:8px; text-align:left; color:#8b949e;">Title</th>
                <th style="padding:8px; text-align:center; color:#8b949e;">CVSS</th>
                <th style="padding:8px; text-align:left; color:#8b949e;">Priority</th>
            </tr>
        </thead>
        <tbody>
            {threat_rows}
        </tbody>
    </table>
</div>

<div style="background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px;">
    <h2 style="color:#58a6ff; margin-top:0;">🛡️ Recommended Actions</h2>
    <ol style="color:#e6edf3; line-height:1.8;">
        <li>Review each CVE at <a href="https://nvd.nist.gov/vuln" style="color:#58a6ff;">nvd.nist.gov</a></li>
        <li>Check if your systems run affected software</li>
        <li>Apply vendor patches immediately for CVSS ≥ 9.0</li>
        <li>Monitor CISA KEV for exploit confirmation</li>
    </ol>
</div>

<p style="color:#555; font-size:0.8em; margin-top:20px; text-align:center;">
    Threat Intelligence Platform · <a href="https://github.com/paulieboi33-stack/threat-intelligence-platform" style="color:#58a6ff;">GitHub</a> · Powered by NVD + CISA KEV + llama3.1:8b
</p>

</div>
</body>
</html>
"""


def send_alert_email(threats):
    """Send alert email via gog CLI"""
    if not threats:
        return False

    count = len(threats)
    cve_list = ", ".join(t['cve_id'] for t in threats[:5])
    if count > 5:
        cve_list += f" (+{count-5} more)"

    subject = f"🚨 [{count} Critical CVE{'s' if count > 1 else ''}] Threat Alert — {cve_list}"
    body = build_email_body(threats)

    # Build plain text fallback
    plain_body = f"CRITICAL THREAT ALERT — {count} new Critical CVE(s) detected\n\n"
    for t in threats[:10]:
        plain_body += f"• {t['cve_id']} (CVSS {t['cvss_score']}): {(t.get('title') or '')[:60]}\n"
        if t.get('ai_summary'):
            plain_body += f"  → {t['ai_summary'][:120]}\n"
        plain_body += "\n"
    plain_body += "View full platform: https://github.com/paulieboi33-stack/threat-intelligence-platform"

    try:
        result = subprocess.run(
            ["gog", "gmail", "send",
             "--to", ALERT_EMAIL,
             "--subject", subject,
             "--body", plain_body,
             "--body-html", body],
            capture_output=True, text=True, timeout=60
        )

        if result.returncode == 0:
            console.print(f"[green]✅ Alert email sent to {ALERT_EMAIL}[/green]")
            return True
        else:
            console.print(f"[red]✗ Email failed: {result.stderr[:150]}[/red]")
            return False

    except subprocess.TimeoutExpired:
        console.print("[red]✗ Email timed out — gog may need re-auth[/red]")
        return False
    except Exception as e:
        console.print(f"[red]✗ Email error: {str(e)}[/red]")
        return False


def run_alerts():
    """Main alert runner — check for new criticals and send email"""
    console.print("\n[yellow]📧 Alerter Agent — Checking for critical threats...[/yellow]")

    state = load_alert_state()
    new_threats = get_new_critical_threats(state)

    if not new_threats:
        console.print("[green]✓ No new critical threats to alert on[/green]")
        state["last_alert_run"] = datetime.now().isoformat()
        save_alert_state(state)
        return 0

    console.print(f"[red]🚨 {len(new_threats)} new critical threat(s) found![/red]")
    for t in new_threats:
        console.print(f"   • {t['cve_id']} (CVSS {t['cvss_score']}) — {(t.get('title') or '')[:50]}")

    sent = send_alert_email(new_threats)

    if sent:
        # Mark as alerted so we don't spam
        state["alerted_cves"].extend(t['cve_id'] for t in new_threats)
        # Keep only last 500 to prevent unbounded growth
        state["alerted_cves"] = state["alerted_cves"][-500:]
        state["last_alert_run"] = datetime.now().isoformat()
        save_alert_state(state)

    return len(new_threats)


if __name__ == "__main__":
    count = run_alerts()
    console.print(f"\n[bold]Alert run complete — {count} threat(s) alerted[/bold]")
