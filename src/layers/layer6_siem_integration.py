"""
ZehraShield Layer 6 - SIEM Integration
Copyright © 2025 ZehraSec - Yashab Alam

Implements Security Information and Event Management (SIEM) integration,
log aggregation, real-time alerting, incident response, and compliance reporting.
"""

import logging
import threading
import time
import json
import sqlite3
import csv
import gzip
import requests
import socket
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
import uuid

# Handle elasticsearch import gracefully
try:
    from elasticsearch import Elasticsearch
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    logging.warning("Elasticsearch not available - some SIEM features limited")
    ELASTICSEARCH_AVAILABLE = False

# Handle email imports gracefully
try:
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
    import smtplib
    EMAIL_AVAILABLE = True
except ImportError:
    logging.warning("Email modules not available - email alerts disabled")
    EMAIL_AVAILABLE = False
import smtplib
from core.logger import security_logger


@dataclass
class SecurityEvent:
    """Represents a security event for SIEM."""
    event_id: str
    timestamp: datetime
    source_layer: str
    event_type: str
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    action: str
    description: str
    raw_data: Dict[str, Any]
    threat_intelligence: Dict[str, Any]
    user_context: Dict[str, Any]
    device_context: Dict[str, Any]
    geo_location: Dict[str, Any]


@dataclass
class Incident:
    """Represents a security incident."""
    incident_id: str
    created_at: datetime
    updated_at: datetime
    title: str
    description: str
    severity: str
    status: str  # 'OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'
    assigned_to: str
    events: List[str]  # Event IDs
    tags: List[str]
    response_actions: List[Dict[str, Any]]
    resolution: str


class SIEMIntegrationLayer:
    """Layer 6: SIEM Integration with comprehensive logging and incident management."""
    
    def __init__(self, config):
        """Initialize the SIEM Integration layer."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.running = False
        
        # Database setup
        self.db_path = "data/siem.db"
        self._setup_database()
        
        # Event queue for real-time processing
        self.event_queue = []
        self.queue_lock = threading.Lock()
        
        # Incident management
        self.active_incidents: Dict[str, Incident] = {}
        
        # External integrations
        self.splunk_client = None
        self.elastic_client = None
        self._setup_integrations()
        
        # Configuration
        self.log_aggregation = config.get('log_aggregation', True)
        self.real_time_alerts = config.get('real_time_alerts', True)
        self.incident_response = config.get('incident_response', True)
        self.compliance_reporting = config.get('compliance_reporting', True)
        self.log_retention_days = config.get('log_retention_days', 90)
        self.export_formats = config.get('export_formats', ['json', 'csv', 'syslog'])
        
        # Processing threads
        self.event_processor_thread = None
        self.log_aggregator_thread = None
        self.incident_manager_thread = None
        self.compliance_reporter_thread = None
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'incidents_created': 0,
            'incidents_resolved': 0,
            'alerts_sent': 0,
            'compliance_reports': 0,
            'external_exports': 0,
            'database_size_mb': 0
        }
        
        # Alert thresholds
        self.alert_thresholds = {
            'failed_logins_per_hour': 10,
            'port_scans_per_hour': 5,
            'malware_detections_per_hour': 1,
            'data_exfiltration_mb_per_hour': 100,
            'concurrent_attacks': 3
        }
        
    def start(self):
        """Start the SIEM Integration layer."""
        if self.running:
            return
            
        self.logger.info("Starting SIEM Integration Layer...")
        self.running = True
        
        # Start processing threads
        if self.log_aggregation:
            self.event_processor_thread = threading.Thread(target=self._event_processor, daemon=True)
            self.event_processor_thread.start()
            
            self.log_aggregator_thread = threading.Thread(target=self._log_aggregator, daemon=True)
            self.log_aggregator_thread.start()
        
        if self.incident_response:
            self.incident_manager_thread = threading.Thread(target=self._incident_manager, daemon=True)
            self.incident_manager_thread.start()
        
        if self.compliance_reporting:
            self.compliance_reporter_thread = threading.Thread(target=self._compliance_reporter, daemon=True)
            self.compliance_reporter_thread.start()
        
        self.logger.info("✅ SIEM Integration Layer started")
        security_logger.info("SIEM Integration Layer activated")
        
    def stop(self):
        """Stop the SIEM Integration layer."""
        if not self.running:
            return
            
        self.logger.info("Stopping SIEM Integration Layer...")
        self.running = False
        
        # Wait for threads to finish
        threads = [
            self.event_processor_thread,
            self.log_aggregator_thread,
            self.incident_manager_thread,
            self.compliance_reporter_thread
        ]
        
        for thread in threads:
            if thread and thread.is_alive():
                thread.join(timeout=5)
        
        self.logger.info("SIEM Integration Layer stopped")
        
    def _setup_database(self):
        """Setup SQLite database for SIEM data."""
        Path("data").mkdir(exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_layer TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                action TEXT,
                description TEXT,
                raw_data TEXT,
                threat_intelligence TEXT,
                user_context TEXT,
                device_context TEXT,
                geo_location TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Incidents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                assigned_to TEXT,
                events TEXT,
                tags TEXT,
                response_actions TEXT,
                resolution TEXT
            )
        """)
        
        # Compliance reports table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_reports (
                report_id TEXT PRIMARY KEY,
                report_type TEXT NOT NULL,
                period_start TEXT NOT NULL,
                period_end TEXT NOT NULL,
                generated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                report_data TEXT,
                format TEXT,
                file_path TEXT
            )
        """)
        
        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source_layer ON events(source_layer)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")
        
        conn.commit()
        conn.close()
        
        self.logger.info("SIEM database initialized")
        
    def _setup_integrations(self):
        """Setup external SIEM integrations."""
        integrations = self.config.get('integrations', {})
        
        # Splunk integration
        splunk_config = integrations.get('splunk', {})
        if splunk_config.get('enabled', False):
            try:
                # Note: In a real implementation, you'd use the Splunk SDK
                self.splunk_client = {
                    'host': splunk_config.get('host'),
                    'port': splunk_config.get('port', 8088),
                    'token': splunk_config.get('token')
                }
                self.logger.info("Splunk integration configured")
            except Exception as e:
                self.logger.error(f"Failed to configure Splunk integration: {e}")
        
        # Elasticsearch integration
        elastic_config = integrations.get('elastic', {})
        if elastic_config.get('enabled', False):
            try:
                self.elastic_client = Elasticsearch([{
                    'host': elastic_config.get('host', 'localhost'),
                    'port': elastic_config.get('port', 9200)
                }])
                
                # Test connection
                if self.elastic_client.ping():
                    self.logger.info("Elasticsearch integration configured")
                else:
                    self.elastic_client = None
                    self.logger.warning("Elasticsearch connection test failed")
                    
            except Exception as e:
                self.logger.error(f"Failed to configure Elasticsearch integration: {e}")
                self.elastic_client = None
                
    def log_security_event(self, event_data: Dict[str, Any]) -> str:
        """Log a security event from any layer."""
        # Create security event
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            source_layer=event_data.get('source_layer', 'unknown'),
            event_type=event_data.get('event_type', 'unknown'),
            severity=event_data.get('severity', 'MEDIUM'),
            source_ip=event_data.get('source_ip', ''),
            destination_ip=event_data.get('destination_ip', ''),
            source_port=event_data.get('source_port', 0),
            destination_port=event_data.get('destination_port', 0),
            protocol=event_data.get('protocol', ''),
            action=event_data.get('action', ''),
            description=event_data.get('description', ''),
            raw_data=event_data.get('raw_data', {}),
            threat_intelligence=event_data.get('threat_intelligence', {}),
            user_context=event_data.get('user_context', {}),
            device_context=event_data.get('device_context', {}),
            geo_location=event_data.get('geo_location', {})
        )
        
        # Add to processing queue
        with self.queue_lock:
            self.event_queue.append(event)
        
        # Immediate processing for critical events
        if event.severity == 'CRITICAL':
            self._process_critical_event(event)
        
        return event.event_id
        
    def _event_processor(self):
        """Process events from the queue."""
        while self.running:
            try:
                events_to_process = []
                
                # Get events from queue
                with self.queue_lock:
                    if self.event_queue:
                        events_to_process = self.event_queue.copy()
                        self.event_queue.clear()
                
                # Process events
                for event in events_to_process:
                    self._process_event(event)
                    self.stats['events_processed'] += 1
                
                time.sleep(1)  # Process every second
                
            except Exception as e:
                self.logger.error(f"Error in event processor: {e}")
                time.sleep(5)
                
    def _process_event(self, event: SecurityEvent):
        """Process a single security event."""
        # Store in database
        self._store_event(event)
        
        # Send to external systems
        self._export_event(event)
        
        # Check for incident correlation
        self._correlate_incident(event)
        
        # Check alert thresholds
        if self.real_time_alerts:
            self._check_alert_thresholds(event)
        
        # Log to security logger
        security_logger.info(
            f"SIEM Event: {event.event_type} | "
            f"Severity: {event.severity} | "
            f"Source: {event.source_ip} | "
            f"Description: {event.description}"
        )
        
    def _store_event(self, event: SecurityEvent):
        """Store event in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO events (
                    event_id, timestamp, source_layer, event_type, severity,
                    source_ip, destination_ip, source_port, destination_port,
                    protocol, action, description, raw_data, threat_intelligence,
                    user_context, device_context, geo_location
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.timestamp.isoformat(),
                event.source_layer,
                event.event_type,
                event.severity,
                event.source_ip,
                event.destination_ip,
                event.source_port,
                event.destination_port,
                event.protocol,
                event.action,
                event.description,
                json.dumps(event.raw_data),
                json.dumps(event.threat_intelligence),
                json.dumps(event.user_context),
                json.dumps(event.device_context),
                json.dumps(event.geo_location)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing event in database: {e}")
            
    def _export_event(self, event: SecurityEvent):
        """Export event to external systems."""
        # Export to Elasticsearch
        if self.elastic_client:
            try:
                doc = asdict(event)
                doc['timestamp'] = event.timestamp.isoformat()
                
                self.elastic_client.index(
                    index=f"zehrashield-{datetime.now().strftime('%Y-%m')}",
                    body=doc
                )
                self.stats['external_exports'] += 1
                
            except Exception as e:
                self.logger.error(f"Error exporting to Elasticsearch: {e}")
        
        # Export to Splunk
        if self.splunk_client:
            try:
                event_data = {
                    'event': asdict(event),
                    'sourcetype': 'zehrashield:security',
                    'source': 'zehrashield',
                    'time': int(event.timestamp.timestamp())
                }
                
                # Send to Splunk HEC endpoint
                headers = {
                    'Authorization': f"Splunk {self.splunk_client['token']}",
                    'Content-Type': 'application/json'
                }
                
                url = f"https://{self.splunk_client['host']}:{self.splunk_client['port']}/services/collector"
                
                response = requests.post(
                    url,
                    headers=headers,
                    json=event_data,
                    verify=False,  # In production, use proper SSL verification
                    timeout=30
                )
                
                if response.status_code == 200:
                    self.stats['external_exports'] += 1
                else:
                    self.logger.warning(f"Splunk export failed: {response.status_code}")
                    
            except Exception as e:
                self.logger.error(f"Error exporting to Splunk: {e}")
                
    def _correlate_incident(self, event: SecurityEvent):
        """Correlate events to detect incidents."""
        # Simple correlation logic - could be much more sophisticated
        correlation_rules = [
            {
                'name': 'Multiple Failed Logins',
                'conditions': {
                    'event_type': 'authentication_failure',
                    'time_window': timedelta(minutes=15),
                    'count_threshold': 5
                },
                'severity': 'HIGH',
                'auto_response': True
            },
            {
                'name': 'Port Scan Detected',
                'conditions': {
                    'event_type': 'port_scan',
                    'time_window': timedelta(minutes=5),
                    'count_threshold': 1
                },
                'severity': 'MEDIUM',
                'auto_response': True
            },
            {
                'name': 'Malware Detection',
                'conditions': {
                    'event_type': 'malware_detected',
                    'time_window': timedelta(minutes=1),
                    'count_threshold': 1
                },
                'severity': 'CRITICAL',
                'auto_response': True
            }
        ]
        
        for rule in correlation_rules:
            if self._check_correlation_rule(event, rule):
                self._create_incident(event, rule)
                
    def _check_correlation_rule(self, event: SecurityEvent, rule: Dict) -> bool:
        """Check if an event matches a correlation rule."""
        conditions = rule['conditions']
        
        # Check event type
        if event.event_type != conditions.get('event_type'):
            return False
        
        # Check time window and count
        time_window = conditions.get('time_window', timedelta(minutes=10))
        count_threshold = conditions.get('count_threshold', 1)
        
        # Query recent events of same type from same source
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since_time = (datetime.now() - time_window).isoformat()
            
            cursor.execute("""
                SELECT COUNT(*) FROM events 
                WHERE event_type = ? AND source_ip = ? AND timestamp > ?
            """, (event.event_type, event.source_ip, since_time))
            
            count = cursor.fetchone()[0]
            conn.close()
            
            return count >= count_threshold
            
        except Exception as e:
            self.logger.error(f"Error checking correlation rule: {e}")
            return False
            
    def _create_incident(self, triggering_event: SecurityEvent, rule: Dict):
        """Create a new security incident."""
        incident_id = str(uuid.uuid4())
        
        incident = Incident(
            incident_id=incident_id,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            title=f"{rule['name']} - {triggering_event.source_ip}",
            description=f"Incident triggered by correlation rule: {rule['name']}",
            severity=rule['severity'],
            status='OPEN',
            assigned_to='auto-response',
            events=[triggering_event.event_id],
            tags=[rule['name'].lower().replace(' ', '_')],
            response_actions=[],
            resolution=''
        )
        
        self.active_incidents[incident_id] = incident
        self.stats['incidents_created'] += 1
        
        # Store in database
        self._store_incident(incident)
        
        # Send alert
        self._send_incident_alert(incident)
        
        # Auto-response if enabled
        if rule.get('auto_response', False):
            self._trigger_auto_response(incident, triggering_event)
        
        security_logger.critical(f"Security incident created: {incident.title} [{incident_id}]")
        
    def _store_incident(self, incident: Incident):
        """Store incident in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO incidents (
                    incident_id, created_at, updated_at, title, description,
                    severity, status, assigned_to, events, tags,
                    response_actions, resolution
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.incident_id,
                incident.created_at.isoformat(),
                incident.updated_at.isoformat(),
                incident.title,
                incident.description,
                incident.severity,
                incident.status,
                incident.assigned_to,
                json.dumps(incident.events),
                json.dumps(incident.tags),
                json.dumps(incident.response_actions),
                incident.resolution
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing incident in database: {e}")
            
    def _send_incident_alert(self, incident: Incident):
        """Send alert for new incident."""
        # Send email alert
        self._send_email_alert(incident)
        
        # Send Slack alert
        self._send_slack_alert(incident)
        
        # Send webhook alert
        self._send_webhook_alert(incident)
        
        self.stats['alerts_sent'] += 1
        
    def _send_email_alert(self, incident: Incident):
        """Send email alert for incident."""
        email_config = self.config.get('notifications', {}).get('email', {})
        
        if not email_config.get('enabled', False):
            return
        
        try:
            msg = MimeMultipart()
            msg['From'] = email_config.get('from_address')
            msg['To'] = ', '.join(email_config.get('to_addresses', []))
            msg['Subject'] = f"ZehraShield Security Alert: {incident.title}"
            
            body = f"""
Security Incident Alert - ZehraShield

Incident ID: {incident.incident_id}
Title: {incident.title}
Severity: {incident.severity}
Status: {incident.status}
Created: {incident.created_at}

Description:
{incident.description}

This is an automated alert from ZehraShield.
            """
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(email_config.get('smtp_server'), email_config.get('smtp_port', 587))
            server.starttls()
            server.login(email_config.get('username'), email_config.get('password'))
            
            text = msg.as_string()
            server.sendmail(msg['From'], email_config.get('to_addresses', []), text)
            server.quit()
            
        except Exception as e:
            self.logger.error(f"Error sending email alert: {e}")
            
    def _send_slack_alert(self, incident: Incident):
        """Send Slack alert for incident."""
        slack_config = self.config.get('notifications', {}).get('slack', {})
        
        if not slack_config.get('enabled', False):
            return
        
        try:
            webhook_url = slack_config.get('webhook_url')
            
            payload = {
                'text': f"🚨 ZehraShield Security Alert",
                'attachments': [{
                    'color': 'danger' if incident.severity in ['HIGH', 'CRITICAL'] else 'warning',
                    'fields': [
                        {'title': 'Incident ID', 'value': incident.incident_id, 'short': True},
                        {'title': 'Severity', 'value': incident.severity, 'short': True},
                        {'title': 'Title', 'value': incident.title, 'short': False},
                        {'title': 'Description', 'value': incident.description, 'short': False}
                    ],
                    'footer': 'ZehraShield SIEM',
                    'ts': int(incident.created_at.timestamp())
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=30)
            response.raise_for_status()
            
        except Exception as e:
            self.logger.error(f"Error sending Slack alert: {e}")
            
    def _send_webhook_alert(self, incident: Incident):
        """Send webhook alert for incident."""
        webhook_config = self.config.get('notifications', {}).get('webhook', {})
        
        if not webhook_config.get('enabled', False):
            return
        
        try:
            url = webhook_config.get('url')
            secret = webhook_config.get('secret')
            
            payload = {
                'type': 'security_incident',
                'incident': asdict(incident),
                'timestamp': datetime.now().isoformat(),
                'source': 'zehrashield'
            }
            
            headers = {'Content-Type': 'application/json'}
            if secret:
                headers['X-ZehraShield-Secret'] = secret
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
        except Exception as e:
            self.logger.error(f"Error sending webhook alert: {e}")
            
    def _trigger_auto_response(self, incident: Incident, triggering_event: SecurityEvent):
        """Trigger automated response actions."""
        response_actions = []
        
        # Auto-response based on event type
        if triggering_event.event_type == 'port_scan':
            action = {
                'type': 'ip_block',
                'target': triggering_event.source_ip,
                'duration': '1h',
                'timestamp': datetime.now().isoformat()
            }
            response_actions.append(action)
            
        elif triggering_event.event_type == 'malware_detected':
            action = {
                'type': 'quarantine_device',
                'target': triggering_event.source_ip,
                'timestamp': datetime.now().isoformat()
            }
            response_actions.append(action)
            
        elif triggering_event.event_type == 'authentication_failure':
            action = {
                'type': 'account_lockout',
                'target': triggering_event.user_context.get('username', 'unknown'),
                'duration': '30m',
                'timestamp': datetime.now().isoformat()
            }
            response_actions.append(action)
        
        incident.response_actions.extend(response_actions)
        
        # Log response actions
        for action in response_actions:
            security_logger.info(f"Auto-response triggered: {action['type']} for {action['target']}")
            
    def _process_critical_event(self, event: SecurityEvent):
        """Immediate processing for critical events."""
        # Log immediately
        security_logger.critical(f"CRITICAL EVENT: {event.description}")
        
        # Store immediately
        self._store_event(event)
        
        # Send immediate alert
        # This would trigger emergency notifications
        
    def _log_aggregator(self):
        """Aggregate and archive logs."""
        while self.running:
            try:
                # Clean old logs based on retention policy
                self._cleanup_old_logs()
                
                # Archive logs
                self._archive_logs()
                
                # Update database statistics
                self._update_db_stats()
                
                time.sleep(3600)  # Run every hour
                
            except Exception as e:
                self.logger.error(f"Error in log aggregator: {e}")
                time.sleep(3600)
                
    def _cleanup_old_logs(self):
        """Clean up old logs based on retention policy."""
        try:
            cutoff_date = (datetime.now() - timedelta(days=self.log_retention_days)).isoformat()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Delete old events
            cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_date,))
            deleted_events = cursor.rowcount
            
            # Delete old resolved incidents
            cursor.execute("""
                DELETE FROM incidents 
                WHERE status IN ('RESOLVED', 'CLOSED') AND created_at < ?
            """, (cutoff_date,))
            deleted_incidents = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            if deleted_events > 0 or deleted_incidents > 0:
                self.logger.info(f"Cleaned up {deleted_events} old events and {deleted_incidents} old incidents")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old logs: {e}")
            
    def _archive_logs(self):
        """Archive logs to compressed files."""
        # Implementation for log archiving
        pass
        
    def _update_db_stats(self):
        """Update database statistics."""
        try:
            db_file = Path(self.db_path)
            if db_file.exists():
                self.stats['database_size_mb'] = db_file.stat().st_size / (1024 * 1024)
        except Exception as e:
            self.logger.error(f"Error updating database stats: {e}")
            
    def _incident_manager(self):
        """Manage active incidents."""
        while self.running:
            try:
                # Auto-close old resolved incidents
                self._auto_close_incidents()
                
                # Update incident priorities
                self._update_incident_priorities()
                
                time.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in incident manager: {e}")
                time.sleep(300)
                
    def _auto_close_incidents(self):
        """Automatically close old resolved incidents."""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        for incident_id, incident in list(self.active_incidents.items()):
            if (incident.status == 'RESOLVED' and 
                incident.updated_at < cutoff_time):
                
                incident.status = 'CLOSED'
                incident.updated_at = datetime.now()
                
                # Update in database
                self._update_incident_status(incident_id, 'CLOSED')
                
                # Remove from active incidents
                del self.active_incidents[incident_id]
                
                self.stats['incidents_resolved'] += 1
                
    def _update_incident_priorities(self):
        """Update incident priorities based on age and activity."""
        # Implementation for dynamic priority adjustment
        pass
        
    def _update_incident_status(self, incident_id: str, status: str):
        """Update incident status in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE incidents 
                SET status = ?, updated_at = ? 
                WHERE incident_id = ?
            """, (status, datetime.now().isoformat(), incident_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error updating incident status: {e}")
            
    def _compliance_reporter(self):
        """Generate compliance reports."""
        while self.running:
            try:
                # Generate daily reports
                if datetime.now().hour == 2:  # 2 AM daily
                    self._generate_daily_report()
                
                # Generate weekly reports
                if datetime.now().weekday() == 0 and datetime.now().hour == 3:  # Monday 3 AM
                    self._generate_weekly_report()
                
                # Generate monthly reports
                if datetime.now().day == 1 and datetime.now().hour == 4:  # 1st of month 4 AM
                    self._generate_monthly_report()
                
                time.sleep(3600)  # Check every hour
                
            except Exception as e:
                self.logger.error(f"Error in compliance reporter: {e}")
                time.sleep(3600)
                
    def _generate_daily_report(self):
        """Generate daily compliance report."""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=1)
            
            report_data = self._get_compliance_data(start_time, end_time)
            
            report_id = str(uuid.uuid4())
            report_path = f"reports/daily_report_{end_time.strftime('%Y%m%d')}.json"
            
            # Save report
            Path("reports").mkdir(exist_ok=True)
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            # Store report metadata
            self._store_compliance_report(
                report_id,
                'daily',
                start_time,
                end_time,
                report_data,
                'json',
                report_path
            )
            
            self.stats['compliance_reports'] += 1
            self.logger.info(f"Generated daily compliance report: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating daily report: {e}")
            
    def _generate_weekly_report(self):
        """Generate weekly compliance report."""
        # Similar to daily report but with weekly scope
        pass
        
    def _generate_monthly_report(self):
        """Generate monthly compliance report."""
        # Similar to daily report but with monthly scope
        pass
        
    def _get_compliance_data(self, start_time: datetime, end_time: datetime) -> Dict:
        """Get compliance data for a time period."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get event statistics
            cursor.execute("""
                SELECT 
                    event_type,
                    severity,
                    COUNT(*) as count
                FROM events 
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY event_type, severity
            """, (start_time.isoformat(), end_time.isoformat()))
            
            event_stats = {}
            for row in cursor.fetchall():
                event_type, severity, count = row
                if event_type not in event_stats:
                    event_stats[event_type] = {}
                event_stats[event_type][severity] = count
            
            # Get incident statistics
            cursor.execute("""
                SELECT 
                    severity,
                    status,
                    COUNT(*) as count
                FROM incidents 
                WHERE created_at BETWEEN ? AND ?
                GROUP BY severity, status
            """, (start_time.isoformat(), end_time.isoformat()))
            
            incident_stats = {}
            for row in cursor.fetchall():
                severity, status, count = row
                if severity not in incident_stats:
                    incident_stats[severity] = {}
                incident_stats[severity][status] = count
            
            conn.close()
            
            return {
                'period': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat()
                },
                'event_statistics': event_stats,
                'incident_statistics': incident_stats,
                'total_events': sum(sum(severities.values()) for severities in event_stats.values()),
                'total_incidents': sum(sum(statuses.values()) for statuses in incident_stats.values()),
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting compliance data: {e}")
            return {}
            
    def _store_compliance_report(self, report_id: str, report_type: str, 
                                start_time: datetime, end_time: datetime,
                                report_data: Dict, format: str, file_path: str):
        """Store compliance report metadata."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO compliance_reports (
                    report_id, report_type, period_start, period_end,
                    report_data, format, file_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                report_type,
                start_time.isoformat(),
                end_time.isoformat(),
                json.dumps(report_data),
                format,
                file_path
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing compliance report: {e}")
            
    def _check_alert_thresholds(self, event: SecurityEvent):
        """Check if event triggers alert thresholds."""
        # Implementation for threshold-based alerting
        pass
        
    def get_recent_events(self, limit: int = 100, severity: str = None) -> List[Dict]:
        """Get recent security events."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = "SELECT * FROM events"
            params = []
            
            if severity:
                query += " WHERE severity = ?"
                params.append(severity)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            
            columns = [description[0] for description in cursor.description]
            events = []
            
            for row in cursor.fetchall():
                event_dict = dict(zip(columns, row))
                # Parse JSON fields
                for field in ['raw_data', 'threat_intelligence', 'user_context', 'device_context', 'geo_location']:
                    if event_dict[field]:
                        event_dict[field] = json.loads(event_dict[field])
                events.append(event_dict)
            
            conn.close()
            return events
            
        except Exception as e:
            self.logger.error(f"Error getting recent events: {e}")
            return []
            
    def get_active_incidents(self) -> List[Dict]:
        """Get all active incidents."""
        return [asdict(incident) for incident in self.active_incidents.values()]
        
    def get_statistics(self) -> Dict:
        """Get SIEM statistics."""
        return {
            **self.stats,
            'active_incidents': len(self.active_incidents),
            'queue_length': len(self.event_queue),
            'integrations': {
                'splunk_enabled': self.splunk_client is not None,
                'elasticsearch_enabled': self.elastic_client is not None
            }
        }
        
    def is_healthy(self) -> bool:
        """Check if the SIEM layer is healthy."""
        return (
            self.running and
            (self.event_processor_thread is None or self.event_processor_thread.is_alive()) and
            (self.log_aggregator_thread is None or self.log_aggregator_thread.is_alive()) and
            (self.incident_manager_thread is None or self.incident_manager_thread.is_alive()) and
            (self.compliance_reporter_thread is None or self.compliance_reporter_thread.is_alive())
        )
