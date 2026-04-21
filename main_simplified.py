#!/usr/bin/env python3
"""
Main Orchestrator - Simplified Version
========================
Uses simplified agents but keeps all functionality
"""

import sys
import os
from datetime import datetime
from rich.console import Console

console = Console()

# Add simplified agents
sys.path.insert(0, '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/agents')

# Import simplified agents
try:
    from scout_simplified import SimpleScout
    from analyzer_simplified import SimpleAnalyzer
    from reporter_simplified import SimpleReporter
    from visualizer_simplified import SimpleVisualizer
    console.print("[green]✅ Using simplified agents[/green]")
except ImportError:
    console.print("[yellow]⚠️  Using original agents (simplified not available)[/yellow]")

class ThreatIntelSimple:
    """Simplified threat intelligence pipeline"""
    
    def __init__(self):
        self.scout = SimpleScout()
        self.analyzer = SimpleAnalyzer()
        self.reporter = SimpleReporter()
        self.visualizer = SimpleVisualizer()
        self.retention_days = 90
    
    def run(self):
        """Run simplified pipeline"""
        
        console.print("[blue]🚀 Simplified Threat Intelligence Pipeline[/blue]")
        
        # Phase 1: Collect
        threats = self.scout.collect()
        console.print(f"[green]✓ Collected {len(threats)} threats[/green]")
        
        # Phase 2: Analyze & Alert
        analyzed = self.analyzer.analyze(threats)
        stats = self.analyzer.get_statistics(analyzed)
        console.print(f"[green]✓ Analysis complete - {stats['critical']} critical, {stats['high']} high[/green]")
        
        # Phase 3: Report (auto-detect format)
        self.reporter.report(analyzed, format='auto')
        
        # Phase 4: Visualize
        self.visualizer.visualize(analyzed, chart_type='auto')
        
        # Phase 5: Summary
        console.print(self.visualizer.generate_summary(analyzed))
        
        # Phase 6: Retention
        self._apply_retention()
        
        return analyzed
    
    def _apply_retention(self):
        """Simple retention logic"""
        import sqlite3
        conn = sqlite3.connect('/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/data/threats.db')
        cursor = conn.cursor()
        
        cutoff = (datetime.now() - __import__('datetime').timedelta(days=self.retention_days)).isoformat()
        cursor.execute('DELETE FROM threats WHERE collected_at < ?', (cutoff,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        if deleted > 0:
            console.print(f"[yellow]🗑️  Cleaned up {deleted} old threats[/yellow]")
