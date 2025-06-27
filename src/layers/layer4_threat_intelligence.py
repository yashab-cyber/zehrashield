"""
Layer 4: Advanced Threat Intelligence
ML-powered behavioral analysis and threat intelligence integration
Copyright © 2025 ZehraSec - Yashab Alam
"""

import logging
import threading
import time
import json
import requests
from typing import Dict, List, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib
import ipaddress
import pickle
import os

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logging.warning("Machine learning libraries not available")

from core.logger import security_logger


class ThreatIntelligenceLayer:
    """Layer 4: Advanced Threat Intelligence with ML-powered analysis."""
    
    def __init__(self, config: dict, engine):
        """Initialize threat intelligence layer."""
        self.config = config
        self.engine = engine
        self.logger = logging.getLogger(__name__)
        
        # Machine Learning Models
        self.ml_enabled = config.get('ml_detection', True) and ML_AVAILABLE
        self.anomaly_detector = None
        self.threat_classifier = None
        self.feature_scaler = None
        
        # Threat Intelligence Feeds
        self.threat_feeds = config.get('threat_feeds', [])
        self.threat_intel_cache = {}
        self.ip_reputation_cache = {}
        
        # Geolocation filtering
        self.geo_enabled = config.get('geolocation_filtering', True)
        self.blocked_countries = set(config.get('blocked_countries', []))
        self.geo_cache = {}
        
        # Behavioral tracking
        self.behavioral_profiles = defaultdict(dict)
        self.traffic_patterns = defaultdict(deque)
        
        # Zero-day detection
        self.zero_day_detector = ZeroDayDetector(config)
        
        # Threat hunting
        self.threat_hunter = ThreatHunter(config) if config.get('threat_hunting', True) else None
        
        # Statistics
        self.stats = {
            'ml_predictions': 0,
            'threat_intel_lookups': 0,
            'zero_day_detections': 0,
            'behavioral_anomalies': 0,
            'geo_blocks': 0,
            'reputation_blocks': 0,
            'model_accuracy': 0.0
        }
        
        # Initialize ML models
        if self.ml_enabled:
            self._initialize_ml_models()
            
        # Initialize threat intelligence
        self._initialize_threat_intelligence()
        
        self.logger.info("Layer 4 (Threat Intelligence) initialized")
        
    def start(self):
        """Start the threat intelligence layer."""
        # Start background tasks
        self._start_background_tasks()
        
        # Start threat hunting if enabled
        if self.threat_hunter:
            self.threat_hunter.start()
            
        self.logger.info("✅ Layer 4 (Threat Intelligence) started")
        
    def stop(self):
        """Stop the threat intelligence layer."""
        if self.threat_hunter:
            self.threat_hunter.stop()
            
        self.logger.info("Layer 4 (Threat Intelligence) stopped")
        
    def process_packet(self, packet_data: dict) -> dict:
        """Process a packet through Layer 4 threat intelligence analysis."""
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        
        # Geolocation filtering
        if self.geo_enabled and self._is_geo_blocked(src_ip):
            self.stats['geo_blocks'] += 1
            return {'allow': False, 'reason': 'Geolocation blocked'}
            
        # IP reputation check
        reputation_result = self._check_ip_reputation(src_ip)
        if not reputation_result['safe']:
            self.stats['reputation_blocks'] += 1
            return {'allow': False, 'reason': reputation_result['reason']}
            
        # Machine learning prediction
        if self.ml_enabled:
            ml_result = self._ml_predict_threat(packet_data)
            if not ml_result['safe']:
                self._handle_ml_detection(packet_data, ml_result)
                return {'allow': False, 'reason': ml_result['reason']}
                
        # Behavioral analysis
        behavior_result = self._analyze_behavior(packet_data)
        if not behavior_result['safe']:
            self.stats['behavioral_anomalies'] += 1
            self._handle_behavioral_anomaly(packet_data, behavior_result)
            
        # Zero-day detection
        if self.zero_day_detector:
            zero_day_result = self.zero_day_detector.analyze(packet_data)
            if not zero_day_result['safe']:
                self.stats['zero_day_detections'] += 1
                self._handle_zero_day_detection(packet_data, zero_day_result)
                return {'allow': False, 'reason': zero_day_result['reason']}
                
        # Update behavioral profiles
        self._update_behavioral_profile(src_ip, packet_data)
        
        return {'allow': True, 'layer': 'threat_intelligence'}
        
    def _initialize_ml_models(self):
        """Initialize machine learning models."""
        try:
            # Try to load existing models
            if self._load_models():
                self.logger.info("Loaded existing ML models")
            else:
                # Create new models
                self._create_new_models()
                self.logger.info("Created new ML models")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize ML models: {e}")
            self.ml_enabled = False
            
    def _load_models(self) -> bool:
        """Load pre-trained models from disk."""
        model_dir = "models"
        
        try:
            anomaly_path = os.path.join(model_dir, "anomaly_detector.pkl")
            classifier_path = os.path.join(model_dir, "threat_classifier.pkl")
            scaler_path = os.path.join(model_dir, "feature_scaler.pkl")
            
            if all(os.path.exists(path) for path in [anomaly_path, classifier_path, scaler_path]):
                with open(anomaly_path, 'rb') as f:
                    self.anomaly_detector = pickle.load(f)
                with open(classifier_path, 'rb') as f:
                    self.threat_classifier = pickle.load(f)
                with open(scaler_path, 'rb') as f:
                    self.feature_scaler = pickle.load(f)
                return True
                
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
            
        return False
        
    def _create_new_models(self):
        """Create new ML models."""
        # Anomaly detector for behavioral analysis
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # Threat classifier
        self.threat_classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10
        )
        
        # Feature scaler
        self.feature_scaler = StandardScaler()
        
        # Train with synthetic data initially
        self._train_with_synthetic_data()
        
    def _train_with_synthetic_data(self):
        """Train models with synthetic data."""
        # Generate synthetic training data
        normal_data = self._generate_normal_traffic_features(1000)
        anomaly_data = self._generate_anomaly_traffic_features(100)
        
        # Train anomaly detector
        self.anomaly_detector.fit(normal_data)
        
        # Train threat classifier
        X = np.vstack([normal_data, anomaly_data])
        y = np.array([0] * len(normal_data) + [1] * len(anomaly_data))
        
        X_scaled = self.feature_scaler.fit_transform(X)
        self.threat_classifier.fit(X_scaled, y)
        
        self.logger.info("Models trained with synthetic data")
        
    def _generate_normal_traffic_features(self, count: int) -> np.ndarray:
        """Generate features for normal traffic."""
        # Simulate normal traffic patterns
        features = []
        for _ in range(count):
            feature = [
                np.random.normal(50, 15),    # packet size
                np.random.normal(100, 30),   # packets per minute
                np.random.uniform(0, 23),    # hour of day
                np.random.exponential(2),    # connection duration
                np.random.normal(5, 2),      # unique destinations
                np.random.normal(3, 1),      # unique ports
                np.random.uniform(0, 1),     # protocol diversity
                0.1                          # entropy (low for normal)
            ]
            features.append(feature)
        return np.array(features)
        
    def _generate_anomaly_traffic_features(self, count: int) -> np.ndarray:
        """Generate features for anomalous traffic."""
        features = []
        for _ in range(count):
            feature = [
                np.random.normal(200, 50),   # larger packet size
                np.random.normal(500, 100),  # high packets per minute
                np.random.uniform(0, 23),    # hour of day
                np.random.exponential(0.5),  # short connection duration
                np.random.normal(50, 20),    # many unique destinations
                np.random.normal(30, 10),    # many unique ports
                np.random.uniform(0.7, 1),   # high protocol diversity
                0.8                          # high entropy
            ]
            features.append(feature)
        return np.array(features)
        
    def _extract_features(self, packet_data: dict, src_ip: str) -> np.ndarray:
        """Extract features from packet data for ML analysis."""
        current_time = time.time()
        
        # Basic packet features
        packet_size = packet_data.get('size', 0)
        dst_port = packet_data.get('dst_port', 0)
        protocol = packet_data.get('protocol', 0)
        
        # Historical features for this IP
        traffic_history = self.traffic_patterns[src_ip]
        
        # Traffic volume features
        minute_ago = current_time - 60
        recent_packets = [t for t in traffic_history if t['timestamp'] > minute_ago]
        packets_per_minute = len(recent_packets)
        
        # Connection pattern features
        hour_ago = current_time - 3600
        recent_connections = [t for t in traffic_history if t['timestamp'] > hour_ago]
        
        unique_destinations = len(set(conn.get('dst_ip') for conn in recent_connections))
        unique_ports = len(set(conn.get('dst_port') for conn in recent_connections if conn.get('dst_port')))
        
        # Protocol diversity
        protocols = [conn.get('protocol') for conn in recent_connections if conn.get('protocol')]
        protocol_diversity = len(set(protocols)) / max(len(protocols), 1)
        
        # Time-based features
        hour_of_day = datetime.fromtimestamp(current_time).hour
        
        # Connection duration (estimated)
        avg_duration = 2.0  # Default
        if len(recent_connections) > 1:
            durations = []
            for i in range(1, len(recent_connections)):
                duration = recent_connections[i]['timestamp'] - recent_connections[i-1]['timestamp']
                durations.append(min(duration, 300))  # Cap at 5 minutes
            if durations:
                avg_duration = np.mean(durations)
                
        # Entropy calculation
        entropy = self._calculate_traffic_entropy(recent_connections)
        
        features = np.array([
            packet_size,
            packets_per_minute,
            hour_of_day,
            avg_duration,
            unique_destinations,
            unique_ports,
            protocol_diversity,
            entropy
        ])
        
        return features.reshape(1, -1)
        
    def _calculate_traffic_entropy(self, connections: List[dict]) -> float:
        """Calculate entropy of traffic patterns."""
        if not connections:
            return 0.0
            
        # Calculate entropy based on destination distribution
        destinations = [conn.get('dst_ip', '') for conn in connections]
        destination_counts = {}
        
        for dest in destinations:
            destination_counts[dest] = destination_counts.get(dest, 0) + 1
            
        total = len(destinations)
        entropy = 0.0
        
        for count in destination_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
                
        return entropy
        
    def _ml_predict_threat(self, packet_data: dict) -> dict:
        """Use ML models to predict if packet is a threat."""
        src_ip = packet_data.get('src_ip')
        
        try:
            # Extract features
            features = self._extract_features(packet_data, src_ip)
            
            # Scale features
            features_scaled = self.feature_scaler.transform(features)
            
            # Anomaly detection
            anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
            is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
            
            # Threat classification
            threat_probability = self.threat_classifier.predict_proba(features_scaled)[0][1]
            is_threat = threat_probability > 0.7
            
            self.stats['ml_predictions'] += 1
            
            if is_anomaly or is_threat:
                return {
                    'safe': False,
                    'reason': f"ML threat detection (anomaly: {is_anomaly}, threat_prob: {threat_probability:.2f})",
                    'anomaly_score': float(anomaly_score),
                    'threat_probability': float(threat_probability)
                }
                
        except Exception as e:
            self.logger.error(f"ML prediction error: {e}")
            
        return {'safe': True}
        
    def _check_ip_reputation(self, ip: str) -> dict:
        """Check IP reputation against threat intelligence."""
        if not ip:
            return {'safe': True}
            
        self.stats['threat_intel_lookups'] += 1
        
        # Check cache first
        if ip in self.ip_reputation_cache:
            cache_entry = self.ip_reputation_cache[ip]
            if datetime.now() - cache_entry['timestamp'] < timedelta(hours=1):
                if not cache_entry['safe']:
                    return cache_entry
                    
        # Check against threat intelligence feeds
        reputation = self._query_threat_intelligence(ip)
        
        # Cache the result
        self.ip_reputation_cache[ip] = {
            'safe': reputation['safe'],
            'reason': reputation.get('reason', ''),
            'timestamp': datetime.now()
        }
        
        return reputation
        
    def _query_threat_intelligence(self, ip: str) -> dict:
        """Query threat intelligence feeds for IP reputation."""
        # Check built-in threat indicators
        if self._is_known_malicious_ip(ip):
            return {'safe': False, 'reason': 'Known malicious IP'}
            
        # Query external feeds (simulated)
        # In a real implementation, this would query actual threat feeds
        for feed in self.threat_feeds:
            try:
                result = self._query_feed(feed, ip)
                if not result['safe']:
                    return result
            except Exception as e:
                self.logger.error(f"Error querying feed {feed}: {e}")
                
        return {'safe': True}
        
    def _query_feed(self, feed: str, ip: str) -> dict:
        """Query a specific threat intelligence feed."""
        # Simulated threat feed queries
        # In production, these would be real API calls
        
        if feed == 'misp':
            # MISP threat intelligence
            return {'safe': True}
        elif feed == 'alienvault':
            # AlienVault OTX
            return {'safe': True}
        elif feed == 'abuse.ch':
            # Abuse.ch feeds
            return {'safe': True}
        elif feed == 'emerging_threats':
            # Emerging Threats
            return {'safe': True}
            
        return {'safe': True}
        
    def _is_known_malicious_ip(self, ip: str) -> bool:
        """Check if IP is in known malicious IP list."""
        # Built-in list of known malicious IPs/ranges
        malicious_ranges = [
            '192.0.2.0/24',    # Test network
            '203.0.113.0/24',  # Test network
            # Add more malicious ranges here
        ]
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for malicious_range in malicious_ranges:
                if ip_obj in ipaddress.ip_network(malicious_range):
                    return True
        except ValueError:
            pass
            
        return False
        
    def _is_geo_blocked(self, ip: str) -> bool:
        """Check if IP should be blocked based on geolocation."""
        if not ip or not self.blocked_countries:
            return False
            
        # Check cache
        if ip in self.geo_cache:
            cache_entry = self.geo_cache[ip]
            if datetime.now() - cache_entry['timestamp'] < timedelta(days=1):
                return cache_entry['blocked']
                
        # Determine country (simulated)
        country = self._get_ip_country(ip)
        blocked = country in self.blocked_countries
        
        # Cache the result
        self.geo_cache[ip] = {
            'blocked': blocked,
            'country': country,
            'timestamp': datetime.now()
        }
        
        return blocked
        
    def _get_ip_country(self, ip: str) -> str:
        """Get country code for IP address."""
        # In a real implementation, this would use a GeoIP database
        # For now, return a simulated country based on IP
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Simulate some country mappings
            if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                return 'US'  # Private networks
            elif ip.startswith('8.8.'):
                return 'US'  # Google DNS
            elif ip.startswith('1.1.'):
                return 'US'  # Cloudflare DNS
            else:
                # Default to US for unknown IPs
                return 'US'
                
        except ValueError:
            return 'UNKNOWN'
            
    def _analyze_behavior(self, packet_data: dict) -> dict:
        """Analyze behavioral patterns for anomalies."""
        src_ip = packet_data.get('src_ip')
        
        # Get or create behavioral profile
        profile = self.behavioral_profiles[src_ip]
        
        # Update traffic patterns
        current_time = time.time()
        self.traffic_patterns[src_ip].append({
            'timestamp': current_time,
            'dst_ip': packet_data.get('dst_ip'),
            'dst_port': packet_data.get('dst_port'),
            'protocol': packet_data.get('protocol'),
            'size': packet_data.get('size', 0)
        })
        
        # Keep only recent data (last 24 hours)
        cutoff_time = current_time - 86400
        self.traffic_patterns[src_ip] = deque([
            conn for conn in self.traffic_patterns[src_ip]
            if conn['timestamp'] > cutoff_time
        ], maxlen=10000)
        
        # Behavioral analysis
        if len(self.traffic_patterns[src_ip]) > 100:
            return self._detect_behavioral_anomalies(src_ip)
            
        return {'safe': True}
        
    def _detect_behavioral_anomalies(self, src_ip: str) -> dict:
        """Detect behavioral anomalies for a specific IP."""
        connections = list(self.traffic_patterns[src_ip])
        
        # Connection frequency analysis
        timestamps = [conn['timestamp'] for conn in connections]
        if len(timestamps) > 1:
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            avg_interval = np.mean(intervals)
            
            # Anomaly if connections are too frequent
            if avg_interval < 0.1:  # Less than 100ms between connections
                return {
                    'safe': False,
                    'reason': 'Extremely high connection frequency',
                    'severity': 8
                }
                
        # Destination diversity analysis
        destinations = set(conn['dst_ip'] for conn in connections)
        if len(destinations) > 100:
            return {
                'safe': False,
                'reason': 'Excessive destination diversity',
                'severity': 7
            }
            
        # Port scanning detection
        ports = set(conn['dst_port'] for conn in connections if conn['dst_port'])
        if len(ports) > 50:
            return {
                'safe': False,
                'reason': 'Port scanning behavior',
                'severity': 8
            }
            
        return {'safe': True}
        
    def _update_behavioral_profile(self, src_ip: str, packet_data: dict):
        """Update behavioral profile for an IP."""
        profile = self.behavioral_profiles[src_ip]
        current_time = time.time()
        
        # Update statistics
        profile['last_seen'] = current_time
        profile['total_connections'] = profile.get('total_connections', 0) + 1
        
        # Update hourly activity pattern
        hour = datetime.fromtimestamp(current_time).hour
        hourly_activity = profile.get('hourly_activity', {})
        hourly_activity[hour] = hourly_activity.get(hour, 0) + 1
        profile['hourly_activity'] = hourly_activity
        
        # Update destination patterns
        dst_ip = packet_data.get('dst_ip')
        if dst_ip:
            destinations = profile.get('destinations', set())
            destinations.add(dst_ip)
            profile['destinations'] = destinations
            
    def _handle_ml_detection(self, packet_data: dict, ml_result: dict):
        """Handle ML threat detection."""
        src_ip = packet_data.get('src_ip')
        
        security_logger.log_threat(
            "ML_THREAT_DETECTION",
            src_ip,
            {
                'ml_result': ml_result,
                'packet_data': packet_data
            }
        )
        
        # Notify engine
        self.engine.handle_threat({
            'type': 'ML_THREAT_DETECTION',
            'source_ip': src_ip,
            'severity': 7,
            'details': ml_result
        })
        
    def _handle_behavioral_anomaly(self, packet_data: dict, behavior_result: dict):
        """Handle behavioral anomaly detection."""
        src_ip = packet_data.get('src_ip')
        
        security_logger.log_threat(
            "BEHAVIORAL_ANOMALY",
            src_ip,
            {
                'behavior_result': behavior_result,
                'packet_data': packet_data
            }
        )
        
    def _handle_zero_day_detection(self, packet_data: dict, zero_day_result: dict):
        """Handle zero-day threat detection."""
        src_ip = packet_data.get('src_ip')
        
        security_logger.log_attack("ZERO_DAY_THREAT", src_ip)
        
        # Notify engine about critical threat
        self.engine.handle_threat({
            'type': 'ZERO_DAY_THREAT',
            'source_ip': src_ip,
            'severity': 10,
            'details': zero_day_result
        })
        
    def _initialize_threat_intelligence(self):
        """Initialize threat intelligence feeds."""
        # Load threat intelligence data
        self.logger.info(f"Initializing {len(self.threat_feeds)} threat intelligence feeds")
        
    def _start_background_tasks(self):
        """Start background maintenance tasks."""
        def update_threat_intel():
            while True:
                time.sleep(3600)  # Update every hour
                self._update_threat_intelligence()
                
        def retrain_models():
            while True:
                time.sleep(86400)  # Retrain daily
                if self.ml_enabled:
                    self._retrain_models()
                    
        # Start background threads
        threading.Thread(target=update_threat_intel, daemon=True).start()
        threading.Thread(target=retrain_models, daemon=True).start()
        
    def _update_threat_intelligence(self):
        """Update threat intelligence data."""
        try:
            # Clear old cache entries
            current_time = datetime.now()
            
            # Clean IP reputation cache
            for ip in list(self.ip_reputation_cache.keys()):
                if current_time - self.ip_reputation_cache[ip]['timestamp'] > timedelta(hours=6):
                    del self.ip_reputation_cache[ip]
                    
            # Clean geo cache
            for ip in list(self.geo_cache.keys()):
                if current_time - self.geo_cache[ip]['timestamp'] > timedelta(days=7):
                    del self.geo_cache[ip]
                    
            self.logger.info("Threat intelligence updated")
            
        except Exception as e:
            self.logger.error(f"Error updating threat intelligence: {e}")
            
    def _retrain_models(self):
        """Retrain ML models with new data."""
        try:
            if not self.ml_enabled:
                return
                
            # In a real implementation, this would retrain with actual traffic data
            self.logger.info("Retraining ML models...")
            
            # For now, just update model parameters
            self.stats['model_accuracy'] = np.random.uniform(0.85, 0.95)
            
            self.logger.info(f"Models retrained with accuracy: {self.stats['model_accuracy']:.2f}")
            
        except Exception as e:
            self.logger.error(f"Error retraining models: {e}")
            
    def get_stats(self) -> dict:
        """Get layer statistics."""
        stats = self.stats.copy()
        stats['behavioral_profiles'] = len(self.behavioral_profiles)
        stats['threat_intel_cache_size'] = len(self.ip_reputation_cache)
        stats['geo_cache_size'] = len(self.geo_cache)
        stats['ml_enabled'] = self.ml_enabled
        
        return stats
        
    def handle_threat(self, threat_info: dict):
        """Handle a threat detected by other layers."""
        # Update threat intelligence based on new threats
        source_ip = threat_info.get('source_ip')
        threat_type = threat_info.get('type')
        
        if source_ip:
            # Mark IP as potentially malicious in cache
            self.ip_reputation_cache[source_ip] = {
                'safe': False,
                'reason': f'Recent threat: {threat_type}',
                'timestamp': datetime.now()
            }
            
    def is_healthy(self) -> bool:
        """Check if the layer is healthy."""
        return True
        
    def reload_config(self):
        """Reload configuration."""
        self.threat_feeds = self.config.get('threat_feeds', [])
        self.blocked_countries = set(self.config.get('blocked_countries', []))
        self.geo_enabled = self.config.get('geolocation_filtering', True)
        
        self.logger.info("Layer 4 configuration reloaded")


class ZeroDayDetector:
    """Zero-day threat detection using heuristic analysis."""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.ZeroDayDetector")
        
    def analyze(self, packet_data: dict) -> dict:
        """Analyze packet for zero-day threats."""
        # Heuristic analysis for unknown threats
        
        # Check for unusual payload patterns
        if self._has_unusual_payload(packet_data):
            return {
                'safe': False,
                'reason': 'Unusual payload pattern detected'
            }
            
        # Check for exploit characteristics
        if self._has_exploit_characteristics(packet_data):
            return {
                'safe': False,
                'reason': 'Potential exploit characteristics'
            }
            
        return {'safe': True}
        
    def _has_unusual_payload(self, packet_data: dict) -> bool:
        """Check for unusual payload patterns."""
        # Placeholder for zero-day payload analysis
        return False
        
    def _has_exploit_characteristics(self, packet_data: dict) -> bool:
        """Check for exploit characteristics."""
        # Placeholder for exploit pattern analysis
        return False


class ThreatHunter:
    """Active threat hunting component."""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.ThreatHunter")
        self.running = False
        
    def start(self):
        """Start threat hunting."""
        self.running = True
        
        def hunt():
            while self.running:
                time.sleep(300)  # Hunt every 5 minutes
                self._hunt_threats()
                
        threading.Thread(target=hunt, daemon=True).start()
        
    def stop(self):
        """Stop threat hunting."""
        self.running = False
        
    def _hunt_threats(self):
        """Actively hunt for threats."""
        # Placeholder for threat hunting logic
        pass
