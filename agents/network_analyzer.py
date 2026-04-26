#!/usr/bin/env python3
"""
Network Traffic Analyzer Agent
================================
Reads captured mitmproxy flows, extracts domains/IPs, analyzes them
for threats, trackers, and suspicious behavior, then saves to the
threat intel database for display on the dashboard.
"""

import subprocess
import json
import os
import sqlite3
import re
from datetime import datetime
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
FLOWS_FILE = os.path.join(BASE_DIR, "data", "network", "flows.mitm")
FLOWS_JSON = os.path.join(BASE_DIR, "data", "network", "flows_export.json")
OUTPUT_JSON = os.path.join(BASE_DIR, "data", "network", "network_analysis.json")
EXPORT_SCRIPT = "/tmp/export_flows.py"
DB_PATH = os.path.join(BASE_DIR, "data", "threats.db")

# ── Known tracker / ad / data-broker domains ─────────────────────────────────
TRACKERS = {
    "doubleclick.net":      ("TRACKER", "Google ad/tracking network"),
    "googlesyndication.com":("TRACKER", "Google ad syndication"),
    "google-analytics.com": ("TRACKER", "Google Analytics"),
    "googletagmanager.com": ("TRACKER", "Google Tag Manager"),
    "facebook.com":         ("TRACKER", "Facebook tracking pixel"),
    "graph.facebook.com":   ("TRACKER", "Facebook data collection API"),
    "connect.facebook.net": ("TRACKER", "Facebook Connect SDK"),
    "analytics.twitter.com":("TRACKER", "Twitter analytics"),
    "ads.twitter.com":      ("TRACKER", "Twitter ad network"),
    "amplitude.com":        ("TRACKER", "Amplitude user analytics"),
    "mixpanel.com":         ("TRACKER", "Mixpanel analytics"),
    "segment.io":           ("TRACKER", "Segment data pipeline"),
    "segment.com":          ("TRACKER", "Segment data pipeline"),
    "appsflyer.com":        ("TRACKER", "AppsFlyer mobile attribution"),
    "adjust.com":           ("TRACKER", "Adjust mobile attribution"),
    "branch.io":            ("TRACKER", "Branch deep link / attribution"),
    "kochava.com":          ("TRACKER", "Kochava mobile attribution"),
    "flurry.com":           ("TRACKER", "Flurry analytics (Yahoo)"),
    "crashlytics.com":      ("TRACKER", "Firebase Crashlytics"),
    "firebase.com":         ("TRACKER", "Firebase app analytics"),
    "firebaseio.com":       ("TRACKER", "Firebase real-time database"),
    "app-measurement.com":  ("TRACKER", "Google/Firebase measurement"),
    "moengage.com":         ("TRACKER", "MoEngage push/analytics"),
    "braze.com":            ("TRACKER", "Braze customer engagement"),
    "onesignal.com":        ("TRACKER", "OneSignal push notifications"),
    "intercom.io":          ("TRACKER", "Intercom user tracking"),
    "hotjar.com":           ("TRACKER", "Hotjar session recording"),
    "datadog-browser-agent.com": ("TRACKER", "Datadog RUM"),
    "sentry.io":            ("TRACKER", "Sentry error tracking"),
    "newrelic.com":         ("TRACKER", "New Relic performance monitoring"),
    "memfault.com":         ("TRACKER", "Memfault device diagnostics (silent)"),
    "scorecardresearch.com":("TRACKER", "ComScore audience measurement"),
    "quantserve.com":       ("TRACKER", "Quantcast audience data"),
    "moatads.com":          ("TRACKER", "Oracle Moat ad measurement"),
    "adnxs.com":            ("TRACKER", "Xandr/AppNexus ad exchange"),
    "criteo.com":           ("TRACKER", "Criteo retargeting ads"),
    "taboola.com":          ("TRACKER", "Taboola content ads"),
    "outbrain.com":         ("TRACKER", "Outbrain content recommendation"),
    "rubiconproject.com":   ("TRACKER", "Magnite/Rubicon ad exchange"),
    "pubmatic.com":         ("TRACKER", "PubMatic ad exchange"),
    "openx.com":            ("TRACKER", "OpenX ad exchange"),
    "spotxchange.com":      ("TRACKER", "SpotX video ad exchange"),
}

SUSPICIOUS = {
    "memfault.com":      ("HIGH",   "Silent device telemetry to 3rd party — not disclosed to users"),
    "adcolony.com":      ("MEDIUM", "Aggressive mobile ad SDK with location access"),
    "mopub.com":         ("MEDIUM", "Twitter MoPub ad SDK — collects device identifiers"),
    "inmobi.com":        ("MEDIUM", "InMobi ad SDK — known for location data harvesting"),
    "chartboost.com":    ("MEDIUM", "Chartboost gaming ads — collects behavioral data"),
    "vungle.com":        ("MEDIUM", "Vungle video ads — fingerprinting SDK"),
    "ironsrc.com":       ("MEDIUM", "IronSource ad mediation — aggressive data collection"),
    "startapp.com":      ("HIGH",   "StartApp — flagged for unauthorized location data sales"),
    "zedge.net":         ("MEDIUM", "Zedge CDN — wallpaper app with broad permissions"),
}

KNOWN_SAFE = {
    "apple.com", "icloud.com", "mzstatic.com", "apple-dns.net",
    "aaplimg.com", "cdn-apple.com", "akadns.net", "appattest.apple.com",
    "gstatic.com", "googleapis.com", "google.com",
    "amazonaws.com", "cloudfront.net", "fastly.net",
    "akamaized.net", "akamai.net", "edgekey.net",
    "twimg.com", "twitter.com", "x.com",
    "instagram.com", "cdninstagram.com",
    "starbucks.com", "zoom.us",
}


def domain_root(host):
    """Extract root domain (e.g. sub.example.com → example.com)."""
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def export_flows_via_mitmdump():
    """Use mitmdump binary (v12) to export flows to JSON."""
    export_script = """
import json
from mitmproxy import http

flows_out = []

def request(flow: http.HTTPFlow):
    flows_out.append({
        "host": flow.request.host,
        "path": flow.request.path[:80],
        "method": flow.request.method,
        "scheme": flow.request.scheme,
    })

def done():
    import json
    with open("%s", "w") as f:
        json.dump(flows_out, f)
""" % FLOWS_JSON

    with open(EXPORT_SCRIPT, "w") as f:
        f.write(export_script)

    result = subprocess.run(
        ["mitmdump", "-r", FLOWS_FILE, "--mode", "regular@8083", "-q", "-s", EXPORT_SCRIPT],
        capture_output=True, text=True, timeout=30
    )
    return os.path.exists(FLOWS_JSON)


def read_flows():
    """Read flows from exported JSON or export fresh from .mitm file."""
    if not os.path.exists(FLOWS_FILE):
        console.print(f"[red]No flows file found at {FLOWS_FILE}[/red]")
        return []

    # Try to export via mitmdump if JSON doesn't exist or is older than .mitm
    mitm_mtime = os.path.getmtime(FLOWS_FILE)
    json_mtime = os.path.getmtime(FLOWS_JSON) if os.path.exists(FLOWS_JSON) else 0

    if not os.path.exists(FLOWS_JSON) or mitm_mtime > json_mtime:
        console.print("[cyan]Exporting flows via mitmdump...[/cyan]")
        export_flows_via_mitmdump()

    if os.path.exists(FLOWS_JSON):
        try:
            with open(FLOWS_JSON) as f:
                return json.load(f)
        except Exception as e:
            console.print(f"[red]Error reading flows JSON: {e}[/red]")
            return []

    return []


def analyze_flows(flows):
    """Analyze flows for trackers, suspicious domains, data leakage."""
    domain_counts = defaultdict(int)
    findings = []
    seen_domains = set()

    for flow in flows:
        host = flow.get("host", "")
        if not host:
            continue
        root = domain_root(host)
        domain_counts[root] += 1

        if root in seen_domains:
            continue
        seen_domains.add(root)

        # Check suspicious
        for pattern, (risk, reason) in SUSPICIOUS.items():
            if pattern in host:
                findings.append({
                    "type": "SUSPICIOUS",
                    "host": host,
                    "root": root,
                    "risk": risk,
                    "reason": reason,
                    "count": domain_counts[root],
                })
                break

        # Check trackers
        for pattern, (ttype, reason) in TRACKERS.items():
            if pattern in host:
                if not any(f["host"] == host and f["type"] == "TRACKER" for f in findings):
                    findings.append({
                        "type": "TRACKER",
                        "host": host,
                        "root": root,
                        "risk": "LOW",
                        "reason": reason,
                        "count": domain_counts[root],
                    })
                break

    return findings, domain_counts


def save_to_db(findings):
    """Save network findings to the threat intel database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Create network_findings table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT,
                root_domain TEXT,
                type TEXT,
                risk TEXT,
                reason TEXT,
                request_count INTEGER,
                collected_at TEXT
            )
        """)

        # Clear old network findings
        cursor.execute("DELETE FROM network_findings")

        now = datetime.now().isoformat()
        for f in findings:
            cursor.execute("""
                INSERT INTO network_findings (host, root_domain, type, risk, reason, request_count, collected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (f["host"], f["root"], f["type"], f["risk"], f["reason"], f["count"], now))

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        console.print(f"[red]DB error: {e}[/red]")
        return False


def run():
    console.print(Panel("[bold cyan]📡 Network Traffic Analyzer[/bold cyan]", expand=False))

    flows = read_flows()
    if not flows:
        console.print("[red]No flows captured yet. Make sure mitmproxy is running and iPhone proxy is set.[/red]")
        return

    console.print(f"[green]✅ {len(flows)} flows captured[/green]")

    findings, domain_counts = analyze_flows(flows)

    suspicious = [f for f in findings if f["type"] == "SUSPICIOUS"]
    trackers = [f for f in findings if f["type"] == "TRACKER"]

    # Summary
    console.print(f"\n[bold]📊 Analysis Summary[/bold]")
    console.print(f"  Total requests captured: {len(flows)}")
    console.print(f"  Unique domains contacted: {len(domain_counts)}")
    console.print(f"  Suspicious findings: [red]{len(suspicious)}[/red]")
    console.print(f"  Trackers detected: [yellow]{len(trackers)}[/yellow]")

    # Top domains by request count
    console.print(f"\n[bold]🔝 Most Active Domains[/bold]")
    top = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    t = Table(show_header=True, header_style="bold cyan")
    t.add_column("Domain", style="white")
    t.add_column("Requests", justify="right", style="yellow")
    for domain, count in top:
        t.add_row(domain, str(count))
    console.print(t)

    if suspicious:
        console.print(f"\n[bold red]⚠️  Suspicious Connections[/bold red]")
        for f in suspicious:
            console.print(f"  🔴 [{f['risk']}] {f['host']}")
            console.print(f"      {f['reason']}\n")

    if trackers:
        console.print(f"\n[bold yellow]📡 Trackers Detected[/bold yellow]")
        for f in trackers[:20]:
            console.print(f"  🟡 {f['host']} — {f['reason']}")

    # Save
    save_to_db(findings)
    result = {
        "collected_at": datetime.now().isoformat(),
        "total_flows": len(flows),
        "unique_domains": len(domain_counts),
        "findings": findings,
        "top_domains": [{"domain": d, "count": c} for d, c in top],
    }
    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    with open(OUTPUT_JSON, "w") as f:
        json.dump(result, f, indent=2)

    console.print(f"\n[green]✅ Saved to {OUTPUT_JSON} and threat database[/green]")
    return result


if __name__ == "__main__":
    run()
