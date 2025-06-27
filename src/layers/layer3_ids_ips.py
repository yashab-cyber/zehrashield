"""
Layer 3: Intrusion Detection & Prevention System (IDS/IPS)
Signature-based and anomaly detection with automated response
Copyright © 2025 ZehraSec - Yashab Alam
"""

import logging
import re
import json
import threading
import time
from typing import Dict, List, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib

from core.logger import security_logger


class IDSIPSLayer:
    """Layer 3: Intrusion Detection & Prevention System."""
    
    def __init__(self, config: dict, engine):
        """Initialize IDS/IPS layer."""
        self.config = config
        self.engine = engine
        self.logger = logging.getLogger(__name__)
        
        # Signature database
        self.signatures = self._load_signatures()
        self.custom_rules = self._load_custom_rules()
        
        # Anomaly detection
        self.baseline_traffic = {}
        self.anomaly_threshold = config.get('threat_threshold', 75)
        
        # Attack detection
        self.attack_patterns = self._load_attack_patterns()
        self.suspicious_activities = defaultdict(list)
        
        # Behavioral analysis
        self.user_profiles = defaultdict(dict)
        self.connection_patterns = defaultdict(deque)
        
        # IP reputation and whitelisting
        self.whitelist_ips = set(config.get('whitelist_ips', []))
        self.blacklist_ips = set(config.get('blacklist_ips', []))
        
        # Statistics
        self.stats = {
            'signatures_loaded': len(self.signatures),
            'threats_detected': 0,
            'attacks_blocked': 0,
            'anomalies_detected': 0,
            'false_positives': 0,
            'ips_blocked': 0
        }
        
        # Auto-blocking
        self.auto_block = config.get('auto_block', True)
        self.blocked_ips = set()
        self.temp_blocks = {}
        
        # Learning mode
        self.learning_mode = False
        self.learning_data = []
        
        self.logger.info(f"Layer 3 (IDS/IPS) initialized with {len(self.signatures)} signatures")
        
    def start(self):
        """Start the IDS/IPS layer."""
        # Start background tasks
        self._start_background_tasks()
        
        self.logger.info("✅ Layer 3 (IDS/IPS) started")
        
    def stop(self):
        """Stop the IDS/IPS layer."""
        self.logger.info("Layer 3 (IDS/IPS) stopped")
        
    def process_packet(self, packet_data: dict) -> dict:
        """Process a packet through Layer 3 IDS/IPS analysis."""
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        
        # Skip whitelisted IPs
        if src_ip in self.whitelist_ips:
            return {'allow': True, 'layer': 'ids_ips'}
            
        # Check blacklisted IPs
        if src_ip in self.blacklist_ips or src_ip in self.blocked_ips:
            return {'allow': False, 'reason': 'IP on blacklist'}
            
        # Signature-based detection
        signature_result = self._check_signatures(packet_data)
        if not signature_result['safe']:
            self._handle_detection('SIGNATURE_MATCH', packet_data, signature_result)
            return {'allow': False, 'reason': signature_result['reason']}
            
        # Anomaly detection
        anomaly_result = self._detect_anomalies(packet_data)
        if not anomaly_result['safe']:
            self._handle_detection('ANOMALY', packet_data, anomaly_result)
            # For anomalies, we might allow but log (depending on severity)
            if anomaly_result.get('severity', 5) > 7:
                return {'allow': False, 'reason': anomaly_result['reason']}
                
        # Behavioral analysis
        behavior_result = self._analyze_behavior(packet_data)
        if not behavior_result['safe']:
            self._handle_detection('BEHAVIORAL', packet_data, behavior_result)
            
        # Attack pattern detection
        attack_result = self._detect_attack_patterns(packet_data)
        if not attack_result['safe']:
            self._handle_detection('ATTACK_PATTERN', packet_data, attack_result)
            return {'allow': False, 'reason': attack_result['reason']}
            
        # Update learning data if in learning mode
        if self.learning_mode:
            self._update_learning_data(packet_data)
            
        return {'allow': True, 'layer': 'ids_ips'}
        
    def _check_signatures(self, packet_data: dict) -> dict:
        """Check packet against signature database."""
        # Construct packet content for signature matching
        content = self._construct_packet_content(packet_data)
        
        for sig_id, signature in self.signatures.items():
            if self._match_signature(content, signature, packet_data):
                self.stats['threats_detected'] += 1
                
                return {
                    'safe': False,
                    'reason': f"Signature match: {signature.get('name', sig_id)}",
                    'signature_id': sig_id,
                    'severity': signature.get('severity', 5)
                }
                
        return {'safe': True}
        
    def _detect_anomalies(self, packet_data: dict) -> dict:
        """Detect anomalies using statistical analysis."""
        src_ip = packet_data.get('src_ip')
        current_time = time.time()
        
        # Traffic volume anomaly
        if self._is_traffic_anomaly(src_ip, current_time):
            self.stats['anomalies_detected'] += 1
            return {
                'safe': False,
                'reason': 'Traffic volume anomaly',
                'severity': 6
            }
            
        # Port scanning detection
        if self._is_port_scan(src_ip, packet_data):
            self.stats['anomalies_detected'] += 1
            return {
                'safe': False,
                'reason': 'Port scanning detected',
                'severity': 8
            }
            
        # Time-based anomalies
        if self._is_time_anomaly(src_ip, current_time):
            self.stats['anomalies_detected'] += 1
            return {
                'safe': False,
                'reason': 'Unusual time-based activity',
                'severity': 5
            }
            
        return {'safe': True}
        
    def _analyze_behavior(self, packet_data: dict) -> dict:
        """Analyze behavioral patterns."""
        src_ip = packet_data.get('src_ip')
        
        # Update connection patterns
        self.connection_patterns[src_ip].append({
            'timestamp': time.time(),
            'dst_ip': packet_data.get('dst_ip'),
            'dst_port': packet_data.get('dst_port'),
            'protocol': packet_data.get('protocol')
        })
        
        # Keep only recent connections (last hour)
        cutoff_time = time.time() - 3600
        self.connection_patterns[src_ip] = deque([
            conn for conn in self.connection_patterns[src_ip]
            if conn['timestamp'] > cutoff_time
        ], maxlen=1000)
        
        # Behavioral analysis
        if self._is_behavioral_anomaly(src_ip):
            return {
                'safe': False,
                'reason': 'Behavioral anomaly detected',
                'severity': 6
            }
            
        return {'safe': True}
        
    def _detect_attack_patterns(self, packet_data: dict) -> dict:
        """Detect known attack patterns."""
        src_ip = packet_data.get('src_ip')
        
        # Check for specific attack patterns
        for pattern_name, pattern in self.attack_patterns.items():
            if self._match_attack_pattern(packet_data, pattern):
                self.stats['attacks_blocked'] += 1
                
                return {
                    'safe': False,
                    'reason': f"Attack pattern detected: {pattern_name}",
                    'pattern': pattern_name,
                    'severity': pattern.get('severity', 8)
                }
                
        return {'safe': True}
        
    def _construct_packet_content(self, packet_data: dict) -> str:
        """Construct packet content string for signature matching."""
        parts = []
        
        # Add IP information
        if packet_data.get('src_ip'):
            parts.append(f"src:{packet_data['src_ip']}")
        if packet_data.get('dst_ip'):
            parts.append(f"dst:{packet_data['dst_ip']}")
            
        # Add port information
        if packet_data.get('src_port'):
            parts.append(f"sport:{packet_data['src_port']}")
        if packet_data.get('dst_port'):
            parts.append(f"dport:{packet_data['dst_port']}")
            
        # Add protocol
        if packet_data.get('protocol'):
            parts.append(f"proto:{packet_data['protocol']}")
            
        # Add payload if available
        if packet_data.get('payload'):
            parts.append(f"payload:{packet_data['payload']}")
            
        return " ".join(parts)
        
    def _match_signature(self, content: str, signature: dict, packet_data: dict) -> bool:
        """Match content against a signature."""
        # Check signature conditions
        conditions = signature.get('conditions', [])
        
        for condition in conditions:
            if not self._evaluate_condition(condition, content, packet_data):
                return False
                
        return len(conditions) > 0
        
    def _evaluate_condition(self, condition: dict, content: str, packet_data: dict) -> bool:
        """Evaluate a single signature condition."""
        condition_type = condition.get('type')
        value = condition.get('value')
        
        if condition_type == 'regex':
            return bool(re.search(value, content, re.IGNORECASE))
        elif condition_type == 'string':
            return value.lower() in content.lower()
        elif condition_type == 'port':
            return packet_data.get('dst_port') == value
        elif condition_type == 'ip':
            return packet_data.get('src_ip') == value
        elif condition_type == 'protocol':
            return packet_data.get('protocol') == value
            
        return False
        
    def _is_traffic_anomaly(self, src_ip: str, current_time: float) -> bool:
        """Detect traffic volume anomalies."""
        # Simple rate-based anomaly detection
        if src_ip not in self.baseline_traffic:
            self.baseline_traffic[src_ip] = deque(maxlen=100)
            
        self.baseline_traffic[src_ip].append(current_time)
        
        # Check request rate
        minute_ago = current_time - 60
        recent_requests = [t for t in self.baseline_traffic[src_ip] if t > minute_ago]
        
        # Anomaly if more than 500 requests per minute
        return len(recent_requests) > 500
        
    def _is_port_scan(self, src_ip: str, packet_data: dict) -> bool:
        """Detect port scanning activity."""
        dst_port = packet_data.get('dst_port')
        if not dst_port:
            return False
            
        # Track unique ports accessed by this IP
        if src_ip not in self.suspicious_activities:
            self.suspicious_activities[src_ip] = []
            
        current_time = time.time()
        
        # Add current port
        self.suspicious_activities[src_ip].append({
            'port': dst_port,
            'timestamp': current_time
        })
        
        # Remove old entries (older than 5 minutes)
        self.suspicious_activities[src_ip] = [
            entry for entry in self.suspicious_activities[src_ip]
            if current_time - entry['timestamp'] < 300
        ]
        
        # Get unique ports in the time window
        unique_ports = set(entry['port'] for entry in self.suspicious_activities[src_ip])
        
        # Port scan if accessing more than 20 unique ports in 5 minutes
        return len(unique_ports) > 20
        
    def _is_time_anomaly(self, src_ip: str, current_time: float) -> bool:
        """Detect time-based anomalies."""
        # Check if activity is happening at unusual hours
        hour = datetime.fromtimestamp(current_time).hour
        
        # Activity between 2 AM and 5 AM might be suspicious
        if 2 <= hour <= 5:
            # Check if this IP usually operates during these hours
            if src_ip not in self.user_profiles:
                return True
                
        return False
        
    def _is_behavioral_anomaly(self, src_ip: str) -> bool:
        """Detect behavioral anomalies."""
        connections = list(self.connection_patterns[src_ip])
        
        if len(connections) < 10:
            return False
            
        # Check for unusual connection diversity
        unique_destinations = set(conn['dst_ip'] for conn in connections)
        unique_ports = set(conn['dst_port'] for conn in connections if conn['dst_port'])
        
        # Anomaly if connecting to too many different destinations
        if len(unique_destinations) > 50:
            return True
            
        # Anomaly if using too many different ports
        if len(unique_ports) > 30:
            return True
            
        return False
        
    def _match_attack_pattern(self, packet_data: dict, pattern: dict) -> bool:
        """Match packet against attack pattern."""
        # Simple pattern matching
        pattern_type = pattern.get('type')
        
        if pattern_type == 'syn_flood':
            return packet_data.get('tcp_flags') == 2  # SYN flag
        elif pattern_type == 'port_scan':
            return self._is_port_scan(packet_data.get('src_ip'), packet_data)
        elif pattern_type == 'dns_amplification':
            return (packet_data.get('dst_port') == 53 and 
                   packet_data.get('size', 0) > 512)
                   
        return False
        
    def _handle_detection(self, detection_type: str, packet_data: dict, result: dict):
        """Handle a threat detection."""
        src_ip = packet_data.get('src_ip')
        severity = result.get('severity', 5)
        
        # Log the detection
        security_logger.log_threat(
            detection_type,
            src_ip,
            {
                'packet_data': packet_data,
                'detection_result': result,
                'severity': severity
            }
        )
        
        # Auto-block high severity threats
        if self.auto_block and severity >= 8:
            self._auto_block_ip(src_ip, f"{detection_type}: {result.get('reason')}")
            
        # Notify engine about the threat
        self.engine.handle_threat({
            'type': detection_type,
            'source_ip': src_ip,
            'severity': severity,
            'details': result
        })
        
    def _auto_block_ip(self, ip: str, reason: str):
        """Automatically block an IP address."""
        if ip not in self.whitelist_ips:
            self.blocked_ips.add(ip)
            self.stats['ips_blocked'] += 1
            
            security_logger.log_block(ip, f"Auto-blocked: {reason}")
            
            # Also block at engine level
            self.engine.block_ip(ip, reason, 3600)  # 1 hour block
            
    def _load_signatures(self) -> dict:
        """Load threat signatures."""
        signatures = {
            'sig_001': {
                'name': 'SQL Injection Attempt',
                'conditions': [
                    {'type': 'regex', 'value': r'union.*select|select.*from'},
                    {'type': 'port', 'value': 80}
                ],
                'severity': 8
            },
            'sig_002': {
                'name': 'XSS Attempt',
                'conditions': [
                    {'type': 'regex', 'value': r'<script|javascript:|onload='},
                    {'type': 'port', 'value': 80}
                ],
                'severity': 7
            },
            'sig_003': {
                'name': 'Directory Traversal',
                'conditions': [
                    {'type': 'regex', 'value': r'\.\./|\.\.\\'},
                    {'type': 'port', 'value': 80}
                ],
                'severity': 6
            },
            'sig_004': {
                'name': 'Command Injection',
                'conditions': [
                    {'type': 'regex', 'value': r'(;|\||&|`)\s*(cat|ls|pwd|whoami|id)'},
                    {'type': 'port', 'value': 80}
                ],
                'severity': 9
            },
            'sig_005': {
                'name': 'Suspicious User Agent',
                'conditions': [
                    {'type': 'regex', 'value': r'(sqlmap|nikto|burp|nmap|masscan)'},
                ],
                'severity': 6
            }
        }
        
        return signatures
        
    def _load_custom_rules(self) -> dict:
        """Load custom rules."""
        # In a real implementation, this would load from a file or database
        return {}
        
    def _load_attack_patterns(self) -> dict:
        """Load attack patterns."""
        patterns = {
            'syn_flood': {
                'type': 'syn_flood',
                'description': 'SYN flood attack',
                'severity': 8
            },
            'port_scan': {
                'type': 'port_scan',
                'description': 'Port scanning activity',
                'severity': 7
            },
            'dns_amplification': {
                'type': 'dns_amplification',
                'description': 'DNS amplification attack',
                'severity': 8
            }
        }
        
        return patterns
        
    def _start_background_tasks(self):
        """Start background maintenance tasks."""
        def cleanup_task():
            while True:
                time.sleep(3600)  # Run every hour
                self._cleanup_old_data()
                
        cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
        cleanup_thread.start()
        
    def _cleanup_old_data(self):
        """Clean up old tracking data."""
        current_time = time.time()
        
        # Clean up suspicious activities
        for ip in list(self.suspicious_activities.keys()):
            self.suspicious_activities[ip] = [
                entry for entry in self.suspicious_activities[ip]
                if current_time - entry['timestamp'] < 86400  # 24 hours
            ]
            
            if not self.suspicious_activities[ip]:
                del self.suspicious_activities[ip]
                
    def _update_learning_data(self, packet_data: dict):
        """Update learning data for machine learning models."""
        if len(self.learning_data) < 10000:  # Limit learning data size
            self.learning_data.append({
                'timestamp': time.time(),
                'packet': packet_data
            })
            
    def block_ip(self, ip: str, reason: str, duration: int = None):
        """Block an IP address."""
        self.blocked_ips.add(ip)
        self.stats['ips_blocked'] += 1
        
        if duration:
            # Temporary block
            expiry = datetime.now() + timedelta(seconds=duration)
            self.temp_blocks[ip] = expiry
            
        security_logger.log_block(ip, reason)
        
    def unblock_ip(self, ip: str):
        """Unblock an IP address."""
        self.blocked_ips.discard(ip)
        self.temp_blocks.pop(ip, None)
        
    def add_signature(self, signature_id: str, signature: dict):
        """Add a new signature."""
        self.signatures[signature_id] = signature
        self.stats['signatures_loaded'] = len(self.signatures)
        self.logger.info(f"Added signature: {signature_id}")
        
    def remove_signature(self, signature_id: str):
        """Remove a signature."""
        if signature_id in self.signatures:
            del self.signatures[signature_id]
            self.stats['signatures_loaded'] = len(self.signatures)
            self.logger.info(f"Removed signature: {signature_id}")
            
    def get_stats(self) -> dict:
        """Get layer statistics."""
        stats = self.stats.copy()
        stats['blocked_ips_count'] = len(self.blocked_ips)
        stats['whitelist_size'] = len(self.whitelist_ips)
        stats['blacklist_size'] = len(self.blacklist_ips)
        stats['active_profiles'] = len(self.user_profiles)
        
        return stats
        
    def handle_threat(self, threat_info: dict):
        """Handle a threat detected by other layers."""
        # IDS/IPS can update its signatures or patterns based on threats
        threat_type = threat_info.get('type')
        source_ip = threat_info.get('source_ip')
        
        if source_ip and threat_info.get('severity', 0) > 8:
            self._auto_block_ip(source_ip, f"External threat: {threat_type}")
            
    def is_healthy(self) -> bool:
        """Check if the layer is healthy."""
        return len(self.signatures) > 0
        
    def reload_config(self):
        """Reload configuration."""
        self.whitelist_ips = set(self.config.get('whitelist_ips', []))
        self.blacklist_ips = set(self.config.get('blacklist_ips', []))
        self.auto_block = self.config.get('auto_block', True)
        self.anomaly_threshold = self.config.get('threat_threshold', 75)
        
        self.logger.info("Layer 3 configuration reloaded")
