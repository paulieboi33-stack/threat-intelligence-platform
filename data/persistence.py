#!/usr/bin/env python3
"""
Data Persistence Layer - Threat Intelligence Platform
========================
Stores and manages threat data with proper data retention policies
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from rich.console import Console
from rich.progress import Progress

console = Console()

class ThreatDatabase:
    """SQLite database for threat intelligence storage"""
    
    def __init__(self, db_path=None):
        self.db_path = db_path or '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/data/threats.db'
        self.db_dir = Path(self.db_path).parent
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self._create_database()
    
    def _create_database(self):
        """Create SQLite database schema"""
        console.print("[yellow]🗄️  Creating threat database...[/yellow]")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                cve_id TEXT UNIQUE NOT NULL,
                title TEXT,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                exploit_available INTEGER,
                published_date TEXT,
                modified_date TEXT,
                ai_summary TEXT,
                tactic TEXT,
                collected_at TEXT DEFAULT CURRENT_TIMESTAMP,
                processed INTEGER DEFAULT 0
            )
        ''')
        
        # Processing log
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processing_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_size INTEGER,
                source TEXT,
                processed_count INTEGER,
                start_time TEXT,
                end_time TEXT,
                success INTEGER
            )
        ''')
        
        # Statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY,
                last_check TEXT,
                total_threats INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER
            )
        ''')
        
        # Insert initial statistics row
        cursor.execute('''
            INSERT OR REPLACE INTO statistics (id, last_check, total_threats, critical_count, high_count, medium_count, low_count)
            VALUES (1, ?, 0, 0, 0, 0, 0)
        ''', (datetime.now().isoformat(),))
        
        conn.commit()
        conn.close()
        
        console.print("[green]✓ Threat database created[/green]")
    
    def save_threat(self, threat):
        """Save a single threat to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO threats 
                (source, cve_id, title, description, cvss_score, severity, 
                 exploit_available, published_date, modified_date, ai_summary, 
                 tactic, collected_at, processed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat.get('source', 'unknown'),
                threat.get('cve_id'),
                threat.get('title'),
                threat.get('description', ''),
                threat.get('cvss_score', 0),
                threat.get('severity'),
                1 if threat.get('exploit_available') else 0,
                threat.get('published_date'),
                threat.get('modified_date'),
                threat.get('ai_summary'),
                threat.get('tactic'),
                datetime.now().isoformat(),
                1
            ))
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            console.print(f"[red]✗ Error saving threat: {str(e)}[/red]")
            return False
    
    def save_threat_batch(self, threats, source):
        """Save batch of threats to database"""
        console.print(f"[yellow]💾 Saving {len(threats)} threats to database...[/yellow]")
        
        with Progress() as progress:
            task = progress.add_task("Saving threats...", total=len(threats))
            
            success_count = 0
            for threat in threats:
                if self.save_threat(threat):
                    success_count += 1
                progress.update(task, advance=1)
        
        # Update statistics - pass the actual threats list
        self._update_statistics(threats, source)
        console.print(f"[green]✓ Saved {success_count} threats[/green]")
        
        return success_count
    
    def _update_statistics(self, threats, source):
        """Update statistics table"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get current counts
            cursor.execute('SELECT critical_count, high_count, medium_count, low_count FROM statistics WHERE id=1')
            row = cursor.fetchone()
            
            critical = row[0] if row else 0
            high = row[1] if row else 0
            medium = row[2] if row else 0
            low = row[3] if row else 0
            
            # Add new threats to counts
            for threat in threats:
                severity = threat.get('severity', 'Low')
                if severity == 'Critical':
                    critical += 1
                elif severity == 'High':
                    high += 1
                elif severity == 'Medium':
                    medium += 1
                else:
                    low += 1
            
            total = critical + high + medium + low
            
            # Update statistics
            cursor.execute('''
                UPDATE statistics SET 
                    last_check = ?, 
                    total_threats = ?,
                    critical_count = ?,
                    high_count = ?,
                    medium_count = ?,
                    low_count = ?
                WHERE id = 1
            ''', (datetime.now().isoformat(), total, critical, high, medium, low))
            
            conn.commit()
            
        except Exception as e:
            console.print(f"[red]✗ Error updating statistics: {str(e)}[/red]")
            if "threats" in str(e):
                # This is an expected error when threats list is not passed, ignore it
                pass
    
    def get_all_threats(self):
        """Get all threats from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM threats ORDER BY cvss_score DESC
            ''')
            
            threats = []
            for row in cursor.fetchall():
                threat = {
                    'id': row[0],
                    'source': row[1],
                    'cve_id': row[2],
                    'title': row[3],
                    'description': row[4],
                    'cvss_score': row[5],
                    'severity': row[6],
                    'exploit_available': bool(row[7]),
                    'published_date': row[8],
                    'modified_date': row[9],
                    'ai_summary': row[10],
                    'tactic': row[11],
                    'collected_at': row[12],
                    'processed': bool(row[13])
                }
                threats.append(threat)
            
            conn.close()
            return threats
            
        except Exception as e:
            console.print(f"[red]✗ Error retrieving threats: {str(e)}[/red]")
            return []
    
    def get_critical_threats(self, limit=10):
        """Get critical threats"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM threats 
                WHERE severity = 'Critical' 
                ORDER BY cvss_score DESC
                LIMIT ?
            ''', (limit,))
            
            threats = []
            for row in cursor.fetchall():
                threat = {
                    'id': row[0],
                    'source': row[1],
                    'cve_id': row[2],
                    'title': row[3],
                    'description': row[4],
                    'cvss_score': row[5],
                    'severity': row[6],
                    'exploit_available': bool(row[7]),
                    'published_date': row[8],
                    'modified_date': row[9],
                    'ai_summary': row[10],
                    'tactic': row[11],
                    'collected_at': row[12],
                    'processed': bool(row[13])
                }
                threats.append(threat)
            
            conn.close()
            return threats
            
        except Exception as e:
            console.print(f"[red]✗ Error retrieving critical threats: {str(e)}[/red]")
            return []
    
    def get_statistics(self):
        """Get current statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM statistics WHERE id=1')
            row = cursor.fetchone()
            
            stats = {
                'total_threats': row[2],
                'critical_count': row[3],
                'high_count': row[4],
                'medium_count': row[5],
                'low_count': row[6],
                'last_check': row[1]
            }
            
            conn.close()
            return stats
            
        except Exception as e:
            console.print(f"[red]✗ Error retrieving statistics: {str(e)}[/red]")
            return None
    
    def cleanup_old_data(self, days_to_keep=90):
        """Cleanup old data beyond retention period"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
            
            cursor.execute('''
                DELETE FROM threats WHERE collected_at < ?
            ''', (cutoff_date,))
            
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            
            console.print(f"[yellow]🗑️  Cleaned up {deleted} old threats (older than {days_to_keep} days)[/yellow]")
            return deleted
            
        except Exception as e:
            console.print(f"[red]✗ Error cleaning up data: {str(e)}[/red]")
            return 0
    
    def export_threats(self, output_file=None, format='json'):
        """Export threats to file"""
        threats = self.get_all_threats()
        
        if not output_file:
            output_file = '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/threats_export.json'
        
        try:
            with open(output_file, 'w') as f:
                json.dump(threats, f, indent=2)
            
            console.print(f"[green]✓ Exported {len(threats)} threats to {output_file}[/green]")
            return output_file
            
        except Exception as e:
            console.print(f"[red]✗ Error exporting threats: {str(e)}[/red]")
            return None


class ThreatJSONStorage:
    """Simple JSON file-based storage for quick reference"""
    
    def __init__(self, storage_path=None):
        self.storage_path = storage_path or '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/data/threats.json'
        self.storage_dir = Path(self.storage_path).parent
        self.storage_dir.mkdir(parents=True, exist_ok=True)
    
    def save_threat(self, threat):
        """Save threat to JSON file"""
        try:
            with open(self.storage_path, 'a') as f:
                threat['collected_at'] = datetime.now().isoformat()
                f.write(json.dumps(threat) + '\n')
            
            return True
        except Exception as e:
            console.print(f"[red]✗ Error saving threat: {str(e)}[/red]")
            return False
    
    def load_threats(self, limit=None):
        """Load threats from JSON file"""
        try:
            threats = []
            with open(self.storage_path, 'r') as f:
                for line in f:
                    if limit and len(threats) >= limit:
                        break
                    threat = json.loads(line.strip())
                    threats.append(threat)
            
            return threats
        except Exception as e:
            console.print(f"[red]✗ Error loading threats: {str(e)}[/red]")
            return []
    
    def load_threat(self, cve_id):
        """Load specific threat by CVE ID"""
        threats = self.load_threats()
        for threat in threats:
            if threat.get('cve_id') == cve_id:
                return threat
        return None
    
    def export_csv(self, output_file=None):
        """Export threats to CSV"""
        threats = self.load_threats()
        
        if not output_file:
            output_file = '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/threats.csv'
        
        try:
            # Simple CSV export
            with open(output_file, 'w') as f:
                if threats:
                    headers = threats[0].keys()
                    f.write(','.join(headers) + '\n')
                    for threat in threats:
                        values = [str(threat[h]) for h in headers]
                        f.write(','.join(values) + '\n')
            
            console.print(f"[green]✓ Exported {len(threats)} threats to CSV[/green]")
            return output_file
        except Exception as e:
            console.print(f"[red]✗ Error exporting CSV: {str(e)}[/red]")
            return None
