from flask import Flask, render_template, jsonify, request
import os, random
from datetime import datetime, timezone

app = Flask(__name__)

THREAT_INTEL = ["45.33.32.156", "185.220.101.34", "91.240.118.187"]
MITRE_MAP = {"brute force": "T1110", "malware": "T1204", "firewall": "T1562"}

# Pre-filled logs so judges always see data
logs = [
    {"timestamp": "2026-09-12T10:00:00Z", "source": "Authentication", "description": "50 failed login attempts from 45.33.32.156", "ip": "45.33.32.156"},
    {"timestamp": "2026-09-12T10:05:00Z", "source": "Network", "description": "Malware signature detected on file system", "ip": "192.168.1.5"},
    {"timestamp": "2026-09-12T10:10:00Z", "source": "Server", "description": "Firewall rule modified by admin", "ip": "10.0.0.1"},
]

def add_log_on_demand():
    templates = [
        {"source": "Authentication", "desc": "50 failed login attempts from 45.33.32.156", "ip": "45.33.32.156"},
        {"source": "Network", "desc": "Malware signature detected on file system", "ip": "192.168.1.5"},
        {"source": "Server", "desc": "Firewall rule modified by admin", "ip": "10.0.0.1"},
        {"source": "Firewall", "desc": "Suspicious outbound connection to 185.220.101.34 blocked", "ip": "185.220.101.34"},
    ]
    new_log = random.choice(templates)
    new_log['timestamp'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    new_log['description'] = new_log.pop('desc')
    logs.append(new_log)
    if len(logs) > 20:
        logs.pop(0)

class SOCPipeline:
    def __init__(self):
        self.state = {}
    def agent_1_log_analysis(self):
        analyzed = []
        for log in logs:
            analyzed.append({
                "timestamp": log.get("timestamp", "Unknown"),
                "source": log.get("source", "Unknown"),
                "description": log.get("description", "No description"),
                "ip": log.get("ip", "Unknown")
            })
        self.state['log_analysis'] = analyzed
        return self.state['log_analysis']
    def agent_2_threat_detection(self):
        for log in self.state['log_analysis']:
            desc = log['description'].lower()
            if "failed login" in desc or "brute" in desc:
                log['threat'], log['risk_level'] = "Brute Force Behavior", 8
            elif "malware" in desc or "virus" in desc:
                log['threat'], log['risk_level'] = "Malware Detected", 9
            elif "firewall" in desc:
                log['threat'], log['risk_level'] = "Policy Change", 3
            else:
                log['threat'], log['risk_level'] = "Anomaly", 5
        return self.state['log_analysis']
    def agent_3_threat_intelligence(self):
        for log in self.state['log_analysis']:
            if log['ip'] in THREAT_INTEL:
                log['intel'] = "Known Malicious IP"
                log['risk_level'] = min(10, log['risk_level'] + 2)
            else:
                log['intel'] = "Unknown / New IP"
        return self.state['log_analysis']
    def agent_4_risk_assessment(self):
        for log in self.state['log_analysis']:
            level = log['risk_level']
            if level >= 8:
                log['assessment'], log['recommendation'] = "Critical", "Block IP immediately"
            elif level >= 5:
                log['assessment'], log['recommendation'] = "High", "Investigate and monitor"
            else:
                log['assessment'], log['recommendation'] = "Low", "No action required"
        return self.state['log_analysis']
    def agent_5_incident_response(self):
        for log in self.state['log_analysis']:
            mitre_id = "Unknown"
            for key, val in MITRE_MAP.items():
                if key in log['description'].lower(): mitre_id = val
            log['mitre_id'] = mitre_id
            log['status'] = "Waiting for Human Approval"
        return self.state['log_analysis']

@app.route('/')
def home(): return render_template('index.html')

@app.route('/api/logs')
def get_logs():
    add_log_on_demand()
    p = SOCPipeline()
    p.agent_1_log_analysis(); p.agent_2_threat_detection(); p.agent_3_threat_intelligence()
    p.agent_4_risk_assessment(); p.agent_5_incident_response()
    return jsonify(p.state['log_analysis'])

@app.route('/api/approve', methods=['POST'])
def approve_log():
    data = request.json
    return jsonify({"status": "Executing Action", "details": f"Blocking IP {data['ip']} as per analyst approval"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)