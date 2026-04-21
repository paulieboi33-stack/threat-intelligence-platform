#!/usr/bin/env python3
"""
Create Beautiful Visualizations - Threat Intelligence Platform
===========================================
Uses Plotly, Matplotlib, and Seaborn for data visualization
"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from rich.console import Console

console = Console()

def create_threat_heatmap(threats):
    """Create MITRE ATT&CK-style heatmap"""
    
    # Group threats by severity and tactic
    if not threats:
        console.print("[yellow]⚠️  No threats to visualize[/yellow]")
        return
    
    # Simplified tactic mapping
    tactic_mapping = {
        'Initial Access': [],
        'Execution': [],
        'Persistence': [],
        'Privilege Escalation': [],
        'Defense Evasion': [],
        'Credential Access': [],
        'Discovery': [],
        'Lateral Movement': [],
        'Collection': [],
        'Exfiltration': [],
        'Impact': []
    }
    
    # Count threats by severity
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    }
    
    for threat in threats:
        tactic = threat.get('tactic', 'Unknown')
        if tactic in tactic_mapping:
            tactic_mapping[tactic].append(threat.get('cve_id', ''))
    
    severity_counts[threat.get('severity', 'Low')] += 1
    
    # Create heatmap
    fig = go.Figure(data=[
        go.Heatmap(
            z=[len(v) for v in tactic_mapping.values()],
            x=['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 
               'Defense Evasion', 'Credential Access', 'Discovery', 
               'Lateral Movement', 'Collection', 'Exfiltration', 'Impact'],
            y=['Total Threats'],
            colorscale='Blues'
        )
    ])
    
    fig.update_layout(
        title='MITRE ATT&CK Technique Distribution',
        xaxis_title='Attack Tactic',
        yaxis_title='Number of Threats',
        height=400
    )
    
    # Save to HTML
    output_file = '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/heatmap.html'
    fig.write_html(output_file)
    
    console.print(f"[green]✓ Heatmap saved to {output_file}[/green]")
    return output_file


def create_severity_distribution(threats):
    """Create severity distribution chart"""
    
    if not threats:
        console.print("[yellow]⚠️  No threats to visualize[/yellow]")
        return
    
    # Create DataFrame
    df = pd.DataFrame([
        {'Severity': t['severity'], 'Count': 1} 
        for t in threats
    ])
    
    # Count by severity
    counts = df['Severity'].value_counts().sort_index()
    
    # Create pie chart
    fig = px.pie(
        values=counts,
        names=counts.index,
        title='Threat Severity Distribution',
        hole=0.4
    )
    
    # Save
    output_file = '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/severity_pie.html'
    fig.write_html(output_file)
    
    console.print(f"[green]✓ Severity pie chart saved to {output_file}[/green]")
    return output_file


def create_trend_chart(threats):
    """Create threat trend over time"""
    
    if len(threats) < 2:
        console.print("[yellow]⚠️  Need at least 2 threats for trend chart[/yellow]")
        return
    
    # Create DataFrame
    df = pd.DataFrame(threats)
    df['collected_at'] = pd.to_datetime(df['collected_at'])
    df['Date'] = df['collected_at'].dt.date
    
    # Group by date
    daily = df.groupby('Date').size()
    
    # Create line chart
    fig = px.line(
        x=daily.index,
        y=daily.values,
        title='Threat Discovery Trend',
        markers=True
    )
    
    # Save
    output_file = '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/trend_chart.html'
    fig.write_html(output_file)
    
    console.print(f"[green]✓ Trend chart saved to {output_file}[/green]")
    return output_file


def create_top_vendors_chart(threats):
    """Create top affected vendors chart"""
    
    if not threats:
        console.print("[yellow]⚠️  No threats to visualize[/yellow]")
        return
    
    # Create simple vendor mapping
    vendor_counts = {}
    for threat in threats:
        vendor = threat.get('vendor', 'Unknown') or 'Unknown'
        vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
    
    # Sort by count
    sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Create bar chart
    vendors = [v[0] for v in sorted_vendors]
    counts = [v[1] for v in sorted_vendors]
    
    fig = px.bar(
        x=vendors,
        y=counts,
        title='Top 5 Most Affected Vendors',
        color=counts,
        color_continuous_scale='Blues'
    )
    
    # Save
    output_file = '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/vendor_chart.html'
    fig.write_html(output_file)
    
    console.print(f"[green]✓ Vendor chart saved to {output_file}[/green]")
    return output_file


def main():
    """Run all visualizations"""
    
    console.print("[yellow]📊 Creating Threat Intelligence Visualizations[/yellow]")
    
    # Sample threats (load from database or use sample)
    from data.persistence import ThreatDatabase
    from api_integration import ThreatAPI
    
    api = ThreatAPI()
    threats = api.fetch_nvd_threats(limit=30)
    
    if not threats:
        console.print("[yellow]⚠️  No threats to visualize - using sample data[/yellow]")
        threats = [
            {'cve_id': 'CVE-2024-1001', 'severity': 'Critical', 'tactic': 'Initial Access', 'collected_at': '2024-04-01'},
            {'cve_id': 'CVE-2024-1002', 'severity': 'High', 'tactic': 'Execution', 'collected_at': '2024-04-02'},
            {'cve_id': 'CVE-2024-1003', 'severity': 'Medium', 'tactic': 'Persistence', 'collected_at': '2024-04-03'},
            {'cve_id': 'CVE-2024-1004', 'severity': 'High', 'tactic': 'Privilege Escalation', 'collected_at': '2024-04-04'},
            {'cve_id': 'CVE-2024-1005', 'severity': 'Critical', 'tactic': 'Defense Evasion', 'collected_at': '2024-04-05'},
        ]
    
    # Create all visualizations
    create_threat_heatmap(threats)
    create_severity_distribution(threats)
    create_top_vendors_chart(threats)
    create_trend_chart(threats)
    
    console.print("\n[blue]📊 All visualizations created successfully![/blue]")


if __name__ == "__main__":
    main()
