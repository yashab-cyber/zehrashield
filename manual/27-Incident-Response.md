# 27. Incident Response

![ZehraSec](https://img.shields.io/badge/🛡️-ZehraSec%20Incident%20Response-red?style=for-the-badge&logo=alert)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## 🚨 **Overview**

ZehraSec Advanced Firewall provides comprehensive incident response capabilities to help organizations quickly detect, analyze, contain, and recover from security incidents. This guide covers incident response procedures, automation, forensics, and recovery strategies.

---

## 📋 **Incident Response Framework**

### **Phase 1: Preparation**
- **Response Team**: Establish incident response team
- **Procedures**: Document response procedures
- **Tools**: Deploy incident response tools
- **Training**: Train response team members

### **Phase 2: Detection & Analysis**
- **Monitoring**: Continuous security monitoring
- **Alert Triage**: Classify and prioritize alerts
- **Investigation**: Detailed incident analysis
- **Documentation**: Record all findings

### **Phase 3: Containment**
- **Short-term**: Immediate threat containment
- **Long-term**: Sustained containment measures
- **Evidence**: Preserve forensic evidence
- **Communication**: Notify stakeholders

### **Phase 4: Eradication & Recovery**
- **Root Cause**: Eliminate incident cause
- **System Restoration**: Restore affected systems
- **Monitoring**: Enhanced monitoring post-incident
- **Validation**: Verify system integrity

### **Phase 5: Post-Incident**
- **Lessons Learned**: Document lessons learned
- **Process Improvement**: Update procedures
- **Training Updates**: Enhance team training
- **Reporting**: Submit final incident report

---

## 🔍 **Incident Detection**

### **Automated Detection**
```python
# incident_detector.py
import json
import time
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import List, Dict
from enum import Enum

class IncidentSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityIncident:
    id: str
    timestamp: datetime
    severity: IncidentSeverity
    category: str
    description: str
    affected_systems: List[str]
    indicators: Dict[str, str]
    status: str = "new"

class IncidentDetector:
    def __init__(self, config):
        self.config = config
        self.rules = self.load_detection_rules()
        self.incidents = []
    
    def load_detection_rules(self):
        """Load incident detection rules"""
        return {
            "malware_detection": {
                "pattern": r"malware.*detected",
                "severity": IncidentSeverity.HIGH,
                "category": "malware"
            },
            "intrusion_attempt": {
                "pattern": r"unauthorized.*access",
                "severity": IncidentSeverity.CRITICAL,
                "category": "intrusion"
            },
            "ddos_attack": {
                "pattern": r"high.*traffic.*volume",
                "severity": IncidentSeverity.HIGH,
                "category": "ddos"
            },
            "data_exfiltration": {
                "pattern": r"unusual.*data.*transfer",
                "severity": IncidentSeverity.CRITICAL,
                "category": "data_breach"
            }
        }
    
    def analyze_log_entry(self, log_entry):
        """Analyze log entry for potential incidents"""
        for rule_name, rule in self.rules.items():
            if self.match_pattern(log_entry, rule["pattern"]):
                incident = self.create_incident(log_entry, rule)
                self.incidents.append(incident)
                self.trigger_response(incident)
                return incident
        return None
    
    def create_incident(self, log_entry, rule):
        """Create incident from detection rule match"""
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        return SecurityIncident(
            id=incident_id,
            timestamp=datetime.now(),
            severity=rule["severity"],
            category=rule["category"],
            description=f"Detected {rule['category']} incident",
            affected_systems=self.extract_affected_systems(log_entry),
            indicators=self.extract_indicators(log_entry)
        )
    
    def trigger_response(self, incident):
        """Trigger automated incident response"""
        if incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]:
            self.send_alert(incident)
            self.initiate_containment(incident)
            self.collect_evidence(incident)
```

### **Detection Rules Configuration**
```json
{
  "detection_rules": {
    "malware_signatures": {
      "enabled": true,
      "severity": "high",
      "auto_response": ["isolate_host", "collect_sample"]
    },
    "network_anomalies": {
      "enabled": true,
      "thresholds": {
        "connection_rate": 1000,
        "bandwidth_usage": "90%",
        "failed_connections": 100
      },
      "severity": "medium",
      "auto_response": ["rate_limit", "log_enhanced"]
    },
    "authentication_failures": {
      "enabled": true,
      "threshold": 5,
      "window": "5m",
      "severity": "high",
      "auto_response": ["block_ip", "notify_admin"]
    },
    "privilege_escalation": {
      "enabled": true,
      "patterns": [
        "sudo.*NOPASSWD",
        "privilege.*escalation",
        "unauthorized.*admin"
      ],
      "severity": "critical",
      "auto_response": ["isolate_session", "emergency_alert"]
    }
  }
}
```

---

## 🚀 **Automated Response**

### **Response Automation Engine**
```python
# response_automation.py
import subprocess
import requests
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class ResponseAction:
    name: str
    description: str
    command: str
    parameters: Dict[str, str]
    rollback_command: str = None

class ResponseAutomation:
    def __init__(self, config):
        self.config = config
        self.response_actions = self.load_response_actions()
        self.executed_actions = []
    
    def load_response_actions(self):
        """Load available response actions"""
        return {
            "block_ip": ResponseAction(
                name="Block IP Address",
                description="Block malicious IP address",
                command="iptables -A INPUT -s {ip} -j DROP",
                parameters={"ip": ""},
                rollback_command="iptables -D INPUT -s {ip} -j DROP"
            ),
            "isolate_host": ResponseAction(
                name="Isolate Host",
                description="Isolate infected host from network",
                command="iptables -A INPUT -s {host_ip} -j DROP && iptables -A OUTPUT -d {host_ip} -j DROP",
                parameters={"host_ip": ""},
                rollback_command="iptables -D INPUT -s {host_ip} -j DROP && iptables -D OUTPUT -d {host_ip} -j DROP"
            ),
            "kill_process": ResponseAction(
                name="Kill Malicious Process",
                description="Terminate malicious process",
                command="kill -9 {pid}",
                parameters={"pid": ""}
            ),
            "disable_user": ResponseAction(
                name="Disable User Account",
                description="Disable compromised user account",
                command="usermod -L {username}",
                parameters={"username": ""},
                rollback_command="usermod -U {username}"
            ),
            "quarantine_file": ResponseAction(
                name="Quarantine File",
                description="Move malicious file to quarantine",
                command="mv {file_path} /quarantine/{filename}",
                parameters={"file_path": "", "filename": ""}
            )
        }
    
    def execute_response(self, incident, action_names: List[str]):
        """Execute automated response actions"""
        results = []
        
        for action_name in action_names:
            if action_name in self.response_actions:
                action = self.response_actions[action_name]
                result = self.execute_action(incident, action)
                results.append(result)
                
                if result["success"]:
                    self.executed_actions.append({
                        "incident_id": incident.id,
                        "action": action_name,
                        "timestamp": datetime.now(),
                        "parameters": result["parameters"]
                    })
        
        return results
    
    def execute_action(self, incident, action):
        """Execute single response action"""
        try:
            # Prepare parameters from incident data
            parameters = self.prepare_parameters(incident, action)
            
            # Format command with parameters
            command = action.command.format(**parameters)
            
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                "success": result.returncode == 0,
                "action": action.name,
                "command": command,
                "output": result.stdout,
                "error": result.stderr,
                "parameters": parameters
            }
            
        except Exception as e:
            return {
                "success": False,
                "action": action.name,
                "error": str(e),
                "parameters": {}
            }
    
    def rollback_actions(self, incident_id):
        """Rollback executed actions for incident"""
        rollback_results = []
        
        for action_record in self.executed_actions:
            if action_record["incident_id"] == incident_id:
                action = self.response_actions[action_record["action"]]
                
                if action.rollback_command:
                    try:
                        command = action.rollback_command.format(
                            **action_record["parameters"]
                        )
                        
                        result = subprocess.run(
                            command,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        
                        rollback_results.append({
                            "success": result.returncode == 0,
                            "action": action.name,
                            "command": command,
                            "output": result.stdout,
                            "error": result.stderr
                        })
                        
                    except Exception as e:
                        rollback_results.append({
                            "success": False,
                            "action": action.name,
                            "error": str(e)
                        })
        
        return rollback_results
```

---

## 🔍 **Forensic Analysis**

### **Evidence Collection**
```python
# forensics.py
import os
import shutil
import hashlib
import zipfile
from datetime import datetime
from pathlib import Path

class ForensicCollector:
    def __init__(self, evidence_dir="/evidence"):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(exist_ok=True)
    
    def collect_incident_evidence(self, incident):
        """Collect all relevant evidence for incident"""
        evidence_path = self.evidence_dir / f"incident_{incident.id}"
        evidence_path.mkdir(exist_ok=True)
        
        evidence_items = []
        
        # Collect system logs
        log_evidence = self.collect_logs(incident, evidence_path)
        evidence_items.extend(log_evidence)
        
        # Collect network data
        network_evidence = self.collect_network_data(incident, evidence_path)
        evidence_items.extend(network_evidence)
        
        # Collect file system evidence
        file_evidence = self.collect_file_evidence(incident, evidence_path)
        evidence_items.extend(file_evidence)
        
        # Collect memory dumps
        memory_evidence = self.collect_memory_dumps(incident, evidence_path)
        evidence_items.extend(memory_evidence)
        
        # Create evidence manifest
        self.create_evidence_manifest(incident, evidence_items, evidence_path)
        
        # Create evidence archive
        archive_path = self.create_evidence_archive(incident, evidence_path)
        
        return {
            "incident_id": incident.id,
            "evidence_path": str(evidence_path),
            "archive_path": str(archive_path),
            "items_collected": len(evidence_items),
            "collection_time": datetime.now().isoformat()
        }
    
    def collect_logs(self, incident, evidence_path):
        """Collect relevant log files"""
        log_dir = evidence_path / "logs"
        log_dir.mkdir(exist_ok=True)
        
        evidence_items = []
        log_sources = [
            "/logs/zehrasec.log",
            "/logs/security.log",
            "/logs/network.log",
            "/logs/system.log",
            "/var/log/auth.log",
            "/var/log/syslog"
        ]
        
        for log_source in log_sources:
            if os.path.exists(log_source):
                # Copy log file
                dest_path = log_dir / os.path.basename(log_source)
                shutil.copy2(log_source, dest_path)
                
                # Calculate hash
                file_hash = self.calculate_file_hash(dest_path)
                
                evidence_items.append({
                    "type": "log_file",
                    "source": log_source,
                    "destination": str(dest_path),
                    "hash": file_hash,
                    "collected_at": datetime.now().isoformat()
                })
        
        return evidence_items
    
    def collect_network_data(self, incident, evidence_path):
        """Collect network traffic and connection data"""
        network_dir = evidence_path / "network"
        network_dir.mkdir(exist_ok=True)
        
        evidence_items = []
        
        # Collect network connections
        connections_file = network_dir / "connections.txt"
        os.system(f"netstat -tulpn > {connections_file}")
        
        if connections_file.exists():
            evidence_items.append({
                "type": "network_connections",
                "source": "netstat",
                "destination": str(connections_file),
                "hash": self.calculate_file_hash(connections_file),
                "collected_at": datetime.now().isoformat()
            })
        
        # Collect ARP table
        arp_file = network_dir / "arp_table.txt"
        os.system(f"arp -a > {arp_file}")
        
        if arp_file.exists():
            evidence_items.append({
                "type": "arp_table",
                "source": "arp",
                "destination": str(arp_file),
                "hash": self.calculate_file_hash(arp_file),
                "collected_at": datetime.now().isoformat()
            })
        
        return evidence_items
    
    def collect_file_evidence(self, incident, evidence_path):
        """Collect suspicious files and directories"""
        files_dir = evidence_path / "files"
        files_dir.mkdir(exist_ok=True)
        
        evidence_items = []
        
        # Get suspicious file paths from incident indicators
        suspicious_files = incident.indicators.get("files", [])
        
        for file_path in suspicious_files:
            if os.path.exists(file_path):
                dest_path = files_dir / os.path.basename(file_path)
                shutil.copy2(file_path, dest_path)
                
                evidence_items.append({
                    "type": "suspicious_file",
                    "source": file_path,
                    "destination": str(dest_path),
                    "hash": self.calculate_file_hash(dest_path),
                    "collected_at": datetime.now().isoformat()
                })
        
        return evidence_items
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        hash_sha256 = hashlib.sha256()
        
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            return f"Error calculating hash: {e}"
    
    def create_evidence_manifest(self, incident, evidence_items, evidence_path):
        """Create evidence collection manifest"""
        manifest = {
            "incident_id": incident.id,
            "collection_time": datetime.now().isoformat(),
            "collector": "ZehraSec Forensic Collector v3.0.0",
            "total_items": len(evidence_items),
            "evidence_items": evidence_items
        }
        
        manifest_path = evidence_path / "manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        return manifest_path
```

---

## 📞 **Communication & Notification**

### **Notification System**
```python
# notification.py
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

class IncidentNotification:
    def __init__(self, config):
        self.config = config
        self.notification_channels = config.get("notification_channels", {})
    
    def send_incident_alert(self, incident):
        """Send incident alert through configured channels"""
        message = self.format_incident_message(incident)
        
        # Send email notifications
        if self.notification_channels.get("email", {}).get("enabled"):
            self.send_email_alert(incident, message)
        
        # Send Slack notifications
        if self.notification_channels.get("slack", {}).get("enabled"):
            self.send_slack_alert(incident, message)
        
        # Send SMS notifications
        if self.notification_channels.get("sms", {}).get("enabled"):
            self.send_sms_alert(incident, message)
        
        # Send webhook notifications
        if self.notification_channels.get("webhook", {}).get("enabled"):
            self.send_webhook_alert(incident, message)
    
    def format_incident_message(self, incident):
        """Format incident information for notifications"""
        return f"""
🚨 SECURITY INCIDENT ALERT 🚨

Incident ID: {incident.id}
Severity: {incident.severity.value.upper()}
Category: {incident.category}
Time: {incident.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

Description: {incident.description}

Affected Systems: {', '.join(incident.affected_systems)}

Indicators:
{chr(10).join([f"- {key}: {value}" for key, value in incident.indicators.items()])}

Status: {incident.status}

This is an automated alert from ZehraSec Advanced Firewall.
Please review and take appropriate action.
        """.strip()
    
    def send_email_alert(self, incident, message):
        """Send email alert"""
        try:
            email_config = self.notification_channels["email"]
            
            msg = MIMEMultipart()
            msg['From'] = email_config["from_address"]
            msg['To'] = ", ".join(email_config["recipients"])
            msg['Subject'] = f"[ZEHRASEC ALERT] {incident.severity.value.upper()} - {incident.category}"
            
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"])
            if email_config.get("use_tls"):
                server.starttls()
            if email_config.get("username") and email_config.get("password"):
                server.login(email_config["username"], email_config["password"])
            
            server.send_message(msg)
            server.quit()
            
        except Exception as e:
            print(f"Failed to send email alert: {e}")
    
    def send_slack_alert(self, incident, message):
        """Send Slack alert"""
        try:
            slack_config = self.notification_channels["slack"]
            
            payload = {
                "text": f"Security Incident Alert - {incident.severity.value.upper()}",
                "attachments": [
                    {
                        "color": self.get_severity_color(incident.severity),
                        "fields": [
                            {"title": "Incident ID", "value": incident.id, "short": True},
                            {"title": "Severity", "value": incident.severity.value.upper(), "short": True},
                            {"title": "Category", "value": incident.category, "short": True},
                            {"title": "Time", "value": incident.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'), "short": True},
                            {"title": "Description", "value": incident.description, "short": False},
                            {"title": "Affected Systems", "value": ", ".join(incident.affected_systems), "short": False}
                        ]
                    }
                ]
            }
            
            response = requests.post(slack_config["webhook_url"], json=payload)
            response.raise_for_status()
            
        except Exception as e:
            print(f"Failed to send Slack alert: {e}")
    
    def get_severity_color(self, severity):
        """Get color code for severity level"""
        colors = {
            IncidentSeverity.LOW: "good",
            IncidentSeverity.MEDIUM: "warning",
            IncidentSeverity.HIGH: "danger",
            IncidentSeverity.CRITICAL: "#ff0000"
        }
        return colors.get(severity, "warning")
```

---

## 📊 **Incident Tracking & Reporting**

### **Incident Database**
```python
# incident_database.py
import sqlite3
import json
from datetime import datetime
from typing import List, Optional

class IncidentDatabase:
    def __init__(self, db_path="incidents.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize incident database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                affected_systems TEXT,
                indicators TEXT,
                status TEXT DEFAULT 'new',
                assigned_to TEXT,
                resolution_notes TEXT,
                closed_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incident_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                action_data TEXT,
                executed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                executed_by TEXT,
                status TEXT DEFAULT 'completed',
                FOREIGN KEY (incident_id) REFERENCES incidents (id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def save_incident(self, incident):
        """Save incident to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO incidents 
            (id, timestamp, severity, category, description, affected_systems, 
             indicators, status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident.id,
            incident.timestamp.isoformat(),
            incident.severity.value,
            incident.category,
            incident.description,
            json.dumps(incident.affected_systems),
            json.dumps(incident.indicators),
            incident.status,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def get_incident(self, incident_id) -> Optional[dict]:
        """Retrieve incident by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()
        
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    def list_incidents(self, status=None, severity=None, limit=100) -> List[dict]:
        """List incidents with optional filters"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        conn.close()
        
        return [dict(row) for row in rows]
    
    def update_incident_status(self, incident_id, status, notes=None):
        """Update incident status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        update_fields = ["status = ?", "updated_at = ?"]
        params = [status, datetime.now().isoformat()]
        
        if notes:
            update_fields.append("resolution_notes = ?")
            params.append(notes)
        
        if status == "closed":
            update_fields.append("closed_at = ?")
            params.append(datetime.now().isoformat())
        
        params.append(incident_id)
        
        cursor.execute(f"""
            UPDATE incidents 
            SET {', '.join(update_fields)}
            WHERE id = ?
        """, params)
        
        conn.commit()
        conn.close()
```

---

## 📈 **Metrics & Reporting**

### **Incident Metrics**
```python
# incident_metrics.py
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import pandas as pd

class IncidentMetrics:
    def __init__(self, database):
        self.db = database
    
    def generate_incident_report(self, days=30):
        """Generate comprehensive incident report"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        incidents = self.db.list_incidents(limit=1000)
        
        # Filter incidents by date range
        filtered_incidents = [
            inc for inc in incidents 
            if datetime.fromisoformat(inc['timestamp']) >= start_date
        ]
        
        report = {
            "report_period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days
            },
            "summary": {
                "total_incidents": len(filtered_incidents),
                "by_severity": self.count_by_field(filtered_incidents, 'severity'),
                "by_category": self.count_by_field(filtered_incidents, 'category'),
                "by_status": self.count_by_field(filtered_incidents, 'status')
            },
            "trends": self.analyze_trends(filtered_incidents),
            "response_times": self.analyze_response_times(filtered_incidents),
            "top_affected_systems": self.analyze_affected_systems(filtered_incidents)
        }
        
        return report
    
    def count_by_field(self, incidents, field):
        """Count incidents by field value"""
        counts = {}
        for incident in incidents:
            value = incident.get(field, 'unknown')
            counts[value] = counts.get(value, 0) + 1
        return counts
    
    def analyze_trends(self, incidents):
        """Analyze incident trends over time"""
        daily_counts = {}
        
        for incident in incidents:
            date = datetime.fromisoformat(incident['timestamp']).date()
            daily_counts[str(date)] = daily_counts.get(str(date), 0) + 1
        
        return {
            "daily_incidents": daily_counts,
            "average_per_day": sum(daily_counts.values()) / len(daily_counts) if daily_counts else 0
        }
    
    def analyze_response_times(self, incidents):
        """Analyze incident response times"""
        response_times = []
        
        for incident in incidents:
            if incident['closed_at']:
                start_time = datetime.fromisoformat(incident['timestamp'])
                end_time = datetime.fromisoformat(incident['closed_at'])
                response_time = (end_time - start_time).total_seconds() / 3600  # hours
                response_times.append(response_time)
        
        if response_times:
            return {
                "average_hours": sum(response_times) / len(response_times),
                "min_hours": min(response_times),
                "max_hours": max(response_times),
                "total_resolved": len(response_times)
            }
        
        return {"message": "No resolved incidents in this period"}
```

---

## 🛠️ **Recovery Procedures**

### **System Recovery**
```bash
#!/bin/bash
# system_recovery.sh

echo "Starting ZehraSec system recovery..."

# Stop all ZehraSec services
systemctl stop zehrasec
systemctl stop zehrasec-web
systemctl stop zehrasec-api

# Backup current configuration
cp -r /etc/zehrasec /etc/zehrasec.backup.$(date +%Y%m%d-%H%M%S)

# Restore from known good configuration
if [ -f "/backups/zehrasec-config-latest.tar.gz" ]; then
    tar -xzf /backups/zehrasec-config-latest.tar.gz -C /etc/
    echo "Configuration restored from backup"
fi

# Reset firewall rules to safe defaults
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow essential services
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # SSH
iptables -A INPUT -p tcp --dport 443 -j ACCEPT # HTTPS

# Start services in safe mode
systemctl start zehrasec
sleep 5

# Verify service status
if systemctl is-active --quiet zehrasec; then
    echo "ZehraSec service restored successfully"
    
    # Start additional services
    systemctl start zehrasec-web
    systemctl start zehrasec-api
    
    echo "System recovery completed successfully"
else
    echo "ERROR: Failed to start ZehraSec service"
    echo "Manual intervention required"
    exit 1
fi
```

---

## 📋 **Best Practices**

### **Incident Response Best Practices**
1. **Preparation**
   - Maintain updated incident response procedures
   - Train response team regularly
   - Test response procedures quarterly
   - Keep emergency contact lists current

2. **Detection**
   - Implement continuous monitoring
   - Set appropriate alert thresholds
   - Reduce false positives
   - Document all detection methods

3. **Response**
   - Follow established procedures
   - Document all actions taken
   - Preserve evidence integrity
   - Communicate with stakeholders

4. **Recovery**
   - Verify system integrity before restoration
   - Monitor for recurring incidents
   - Update security controls
   - Document lessons learned

5. **Improvement**
   - Conduct post-incident reviews
   - Update procedures based on lessons learned
   - Enhance detection capabilities
   - Improve response automation

---

## 📞 **Emergency Contacts**

### **Internal Team**
- **Incident Commander**: incidents@zehrasec.com
- **Technical Lead**: tech-lead@zehrasec.com  
- **Security Team**: security@zehrasec.com
- **Management**: management@zehrasec.com

### **External Partners**
- **Law Enforcement**: [Local cybercrime unit]
- **Legal Counsel**: [Legal team contact]
- **Public Relations**: [PR team contact]
- **Insurance**: [Cyber insurance provider]

---

## 📞 **Support**

For incident response support:
- **Emergency**: emergency@zehrasec.com
- **24/7 Hotline**: +1-800-ZEHRASEC
- **Documentation**: https://docs.zehrasec.com/incident-response
- **Training**: https://training.zehrasec.com/incident-response

---

*ZehraSec Advanced Firewall - Comprehensive Incident Response*
