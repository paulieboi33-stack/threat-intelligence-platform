#!/usr/bin/env python3
"""
Threat Intelligence REST API
=============================
Flask API exposing threat data and platform controls.
Run: python3 api.py
Access from phone: http://10.0.0.60:5001/api/threats
"""

from flask import Flask, jsonify, request, send_from_directory
import sqlite3
import json
import os
import subprocess
import threading
from datetime import datetime

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'threats.db')
BASE_DIR = os.path.dirname(__file__)

# Track pipeline run state
pipeline_state = {
    "running": False,
    "last_run": None,
    "last_result": None
}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/control')
def control_panel():
    """Mobile control panel"""
    return send_from_directory(
        os.path.join(BASE_DIR, 'templates'),
        'control.html'
    )

@app.route('/')
def index():
    """API root — list all endpoints"""
    return jsonify({
        "name": "Threat Intelligence Platform API",
        "version": "1.0",
        "built_by": "Paul Naeger | Lone Star College AI & ML",
        "endpoints": {
            "GET  /api/status":          "Platform status and stats",
            "GET  /api/threats":         "All threats (supports ?severity=Critical&limit=20)",
            "GET  /api/threats/<cve_id>":"Single threat by CVE ID",
            "GET  /api/mitre":           "MITRE ATT&CK tactic summary",
            "GET  /api/critical":        "Critical threats only",
            "POST /api/run":             "Trigger a collection run",
            "GET  /api/run/status":      "Check if pipeline is running",
        },
        "github": "https://github.com/paulieboi33-stack/threat-intelligence-platform",
        "dashboard": "https://threat-intelligence-platform-hwlwosewldz68jyv8f8wbn.streamlit.app"
    })


@app.route('/api/status')
def status():
    """Platform status and statistics"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity='High' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity='Medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END) as low,
                MAX(collected_at) as last_collection,
                SUM(CASE WHEN ai_summary IS NOT NULL AND ai_summary != '' THEN 1 ELSE 0 END) as ai_analyzed,
                SUM(CASE WHEN mitre_tactics IS NOT NULL AND mitre_tactics != '' THEN 1 ELSE 0 END) as mitre_mapped
            FROM threats
        """)
        row = dict(cursor.fetchone())
        conn.close()

        return jsonify({
            "status": "operational",
            "timestamp": datetime.now().isoformat(),
            "threats": row,
            "pipeline": {
                "running": pipeline_state["running"],
                "last_run": pipeline_state["last_run"],
                "schedule": "Every 6 hours (auto)",
            },
            "agents": {
                "scout": "active",
                "analyst": "active (llama3.1:8b)",
                "watchdog": "active",
                "reporter": "active",
                "mitre_mapper": "active",
                "alerter": "active"
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/threats')
def get_threats():
    """Get threats with optional filtering"""
    severity = request.args.get('severity')
    limit = min(int(request.args.get('limit', 50)), 200)
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'severity')  # severity | cvss | date

    try:
        conn = get_db()
        cursor = conn.cursor()

        query = """
            SELECT cve_id, severity, cvss_score, title, description,
                   ai_summary, priority, threat_actor_interest,
                   mitre_tactics, mitre_techniques, collected_at
            FROM threats
            WHERE 1=1
        """
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if search:
            query += " AND (cve_id LIKE ? OR title LIKE ? OR description LIKE ?)"
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

        if sort == 'cvss':
            query += " ORDER BY cvss_score DESC"
        elif sort == 'date':
            query += " ORDER BY collected_at DESC"
        else:
            query += " ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END, cvss_score DESC"

        query += f" LIMIT {limit}"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        threats = []
        for row in rows:
            t = dict(row)
            # Parse JSON fields
            for field in ['mitre_tactics', 'mitre_techniques']:
                if t.get(field):
                    try:
                        t[field] = json.loads(t[field])
                    except:
                        pass
            threats.append(t)

        return jsonify({
            "count": len(threats),
            "filters": {"severity": severity, "search": search, "sort": sort},
            "threats": threats
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/threats/<cve_id>')
def get_threat(cve_id):
    """Get a single threat by CVE ID"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threats WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return jsonify({"error": f"{cve_id} not found"}), 404

        t = dict(row)
        for field in ['mitre_tactics', 'mitre_techniques', 'mitre_mappings', 'ai_full_analysis']:
            if t.get(field):
                try:
                    t[field] = json.loads(t[field])
                except:
                    pass

        return jsonify(t)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/critical')
def get_critical():
    """Get critical threats only — quick endpoint for phone alerts"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cve_id, severity, cvss_score, title, ai_summary,
                   priority, mitre_tactics, collected_at
            FROM threats
            WHERE severity = 'Critical'
            ORDER BY cvss_score DESC
            LIMIT 20
        """)
        rows = cursor.fetchall()
        conn.close()

        threats = []
        for row in rows:
            t = dict(row)
            if t.get('mitre_tactics'):
                try:
                    t['mitre_tactics'] = json.loads(t['mitre_tactics'])
                except:
                    pass
            threats.append(t)

        return jsonify({
            "count": len(threats),
            "severity": "Critical",
            "threats": threats
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/mitre')
def get_mitre():
    """MITRE ATT&CK tactic distribution"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cve_id, severity, mitre_tactics, mitre_mappings
            FROM threats
            WHERE mitre_tactics IS NOT NULL AND mitre_tactics != '' AND mitre_tactics != '[]'
        """)
        rows = cursor.fetchall()
        conn.close()

        tactic_counts = {}
        technique_counts = {}
        tactic_ids = {
            "Initial Access":"TA0001","Execution":"TA0002","Persistence":"TA0003",
            "Privilege Escalation":"TA0004","Defense Evasion":"TA0005",
            "Credential Access":"TA0006","Discovery":"TA0007","Lateral Movement":"TA0008",
            "Collection":"TA0009","Exfiltration":"TA0010","Command and Control":"TA0011",
            "Impact":"TA0040"
        }

        for row in rows:
            try:
                tactics = json.loads(row['mitre_tactics'])
                for t in tactics:
                    tactic_counts[t] = tactic_counts.get(t, 0) + 1

                mappings = json.loads(row['mitre_mappings']) if row['mitre_mappings'] else []
                for m in mappings:
                    tid = m.get('technique_id', '')
                    tname = m.get('technique', '')
                    key = f"{tid}: {tname}"
                    technique_counts[key] = technique_counts.get(key, 0) + 1
            except:
                pass

        tactics_output = [
            {
                "tactic": tactic,
                "tactic_id": tactic_ids.get(tactic, ""),
                "count": count,
                "url": f"https://attack.mitre.org/tactics/{tactic_ids.get(tactic, '')}/"
            }
            for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        techniques_output = [
            {"technique": tech, "count": count}
            for tech, count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        return jsonify({
            "total_mapped": len(rows),
            "tactic_distribution": tactics_output,
            "top_techniques": techniques_output,
            "framework": "MITRE ATT&CK Enterprise",
            "reference": "https://attack.mitre.org"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def run_pipeline_background():
    """Run the pipeline in a background thread"""
    pipeline_state["running"] = True
    pipeline_state["last_run"] = datetime.now().isoformat()
    try:
        result = subprocess.run(
            ["python3", "main.py"],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=600
        )
        pipeline_state["last_result"] = {
            "success": result.returncode == 0,
            "output": result.stdout[-500:] if result.stdout else "",
            "error": result.stderr[-200:] if result.stderr else ""
        }
    except subprocess.TimeoutExpired:
        pipeline_state["last_result"] = {"success": False, "error": "Timed out after 10 minutes"}
    except Exception as e:
        pipeline_state["last_result"] = {"success": False, "error": str(e)}
    finally:
        pipeline_state["running"] = False


@app.route('/api/run', methods=['POST'])
def trigger_run():
    """Trigger a manual collection run"""
    if pipeline_state["running"]:
        return jsonify({
            "status": "already_running",
            "message": "Pipeline is already running. Check /api/run/status",
            "started_at": pipeline_state["last_run"]
        }), 409

    thread = threading.Thread(target=run_pipeline_background, daemon=True)
    thread.start()

    return jsonify({
        "status": "started",
        "message": "Pipeline started! Takes 2-3 minutes. Check /api/run/status for progress.",
        "started_at": pipeline_state["last_run"],
        "check_status": "/api/run/status"
    })


@app.route('/api/run/status')
def run_status():
    """Check pipeline run status"""
    return jsonify({
        "running": pipeline_state["running"],
        "last_run": pipeline_state["last_run"],
        "last_result": pipeline_state["last_result"],
        "message": "Pipeline is running..." if pipeline_state["running"] else "Pipeline is idle"
    })


# ─── Start ────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n🛡️  Threat Intelligence Platform API")
    print("=" * 40)
    print(f"Local:   http://localhost:5001")
    print(f"Phone:   http://10.0.0.60:5001")
    print(f"Docs:    http://10.0.0.60:5001/")
    print("=" * 40)
    print("\nEndpoints:")
    print("  GET  /api/status      — Platform stats")
    print("  GET  /api/threats     — All threats")
    print("  GET  /api/critical    — Critical only")
    print("  GET  /api/mitre       — ATT&CK mapping")
    print("  POST /api/run         — Trigger collection")
    print("  GET  /api/run/status  — Run status")
    print("\nReady! ✅\n")

    app.run(host='0.0.0.0', port=5001, debug=False)
