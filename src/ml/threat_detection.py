"""
ZehraShield Machine Learning Engine
Copyright © 2025 ZehraSec - Yashab Alam

Advanced machine learning models for threat detection, anomaly detection,
behavioral analysis, and predictive security analytics.
"""

import logging
import numpy as np
import pandas as pd
import pickle
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import sqlite3
import json

# Machine Learning imports
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Deep Learning imports
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam

# Network analysis
import networkx as nx
from scipy import stats


class ThreatDetectionML:
    """Machine Learning engine for threat detection and analysis."""
    
    def __init__(self, config):
        """Initialize the ML engine."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Model configurations
        self.models_dir = Path("models")
        self.models_dir.mkdir(exist_ok=True)
        
        # Initialize models
        self.anomaly_model = None
        self.threat_classifier = None
        self.behavioral_model = None
        
        # Feature scalers
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        # Training data
        self.training_data = []
        self.training_labels = []
        
        # Model status
        self.models_loaded = False
        self.training_in_progress = False
        
        # Auto-training settings
        self.auto_retrain = config.get('training', {}).get('auto_retrain', True)
        self.retrain_interval_hours = config.get('training', {}).get('retrain_interval_hours', 24)
        self.min_samples = config.get('training', {}).get('min_samples', 1000)
        
        # Training thread
        self.training_thread = None
        
        # Load existing models
        self._load_models()
        
        # Initialize feature extractors
        self.feature_extractors = {
            'packet_features': self._extract_packet_features,
            'temporal_features': self._extract_temporal_features,
            'behavioral_features': self._extract_behavioral_features,
            'network_features': self._extract_network_features
        }
        
        # Statistics
        self.stats = {
            'predictions_made': 0,
            'anomalies_detected': 0,
            'threats_classified': 0,
            'model_accuracy': 0.0,
            'last_training': None,
            'training_samples': 0
        }
        
    def start(self):
        """Start the ML engine."""
        self.logger.info("Starting Machine Learning Engine...")
        
        # Start auto-training if enabled
        if self.auto_retrain:
            self.training_thread = threading.Thread(target=self._auto_training_loop, daemon=True)
            self.training_thread.start()
        
        self.logger.info("✅ Machine Learning Engine started")
        
    def stop(self):
        """Stop the ML engine."""
        self.logger.info("Stopping Machine Learning Engine...")
        
        # Save models before stopping
        self._save_models()
        
        self.logger.info("Machine Learning Engine stopped")
        
    def _load_models(self):
        """Load pre-trained models from disk."""
        try:
            # Load anomaly detection model
            anomaly_path = self.models_dir / "anomaly_model.pkl"
            if anomaly_path.exists():
                self.anomaly_model = joblib.load(anomaly_path)
                self.logger.info("Loaded anomaly detection model")
            
            # Load threat classifier
            classifier_path = self.models_dir / "threat_classifier.pkl"
            if classifier_path.exists():
                self.threat_classifier = joblib.load(classifier_path)
                self.logger.info("Loaded threat classification model")
            
            # Load behavioral model
            behavioral_path = self.models_dir / "behavioral_model.h5"
            if behavioral_path.exists():
                self.behavioral_model = load_model(behavioral_path)
                self.logger.info("Loaded behavioral analysis model")
            
            # Load scalers
            scaler_path = self.models_dir / "scaler.pkl"
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
            
            encoder_path = self.models_dir / "label_encoder.pkl"
            if encoder_path.exists():
                self.label_encoder = joblib.load(encoder_path)
            
            self.models_loaded = True
            
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
            self._initialize_default_models()
            
    def _save_models(self):
        """Save trained models to disk."""
        try:
            if self.anomaly_model:
                joblib.dump(self.anomaly_model, self.models_dir / "anomaly_model.pkl")
            
            if self.threat_classifier:
                joblib.dump(self.threat_classifier, self.models_dir / "threat_classifier.pkl")
            
            if self.behavioral_model:
                self.behavioral_model.save(self.models_dir / "behavioral_model.h5")
            
            # Save scalers
            joblib.dump(self.scaler, self.models_dir / "scaler.pkl")
            joblib.dump(self.label_encoder, self.models_dir / "label_encoder.pkl")
            
            self.logger.info("Models saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
            
    def _initialize_default_models(self):
        """Initialize default models when no pre-trained models exist."""
        try:
            # Initialize anomaly detection model
            self.anomaly_model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            
            # Initialize threat classifier
            self.threat_classifier = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                n_jobs=-1
            )
            
            # Initialize behavioral LSTM model
            self.behavioral_model = self._create_lstm_model()
            
            self.logger.info("Initialized default ML models")
            
        except Exception as e:
            self.logger.error(f"Error initializing default models: {e}")
            
    def _create_lstm_model(self, sequence_length=10, features=20):
        """Create LSTM model for behavioral analysis."""
        model = Sequential([
            LSTM(50, return_sequences=True, input_shape=(sequence_length, features)),
            Dropout(0.2),
            LSTM(50, return_sequences=False),
            Dropout(0.2),
            Dense(25, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
        
    def detect_anomaly(self, network_data: Dict[str, Any]) -> Tuple[bool, float]:
        """Detect network anomalies using machine learning."""
        try:
            if not self.anomaly_model:
                return False, 0.0
            
            # Extract features
            features = self._extract_features(network_data)
            
            if len(features) == 0:
                return False, 0.0
            
            # Scale features
            features_scaled = self.scaler.transform([features])
            
            # Predict anomaly
            anomaly_score = self.anomaly_model.decision_function(features_scaled)[0]
            is_anomaly = self.anomaly_model.predict(features_scaled)[0] == -1
            
            # Convert score to probability (0-1)
            anomaly_probability = max(0.0, min(1.0, (0.5 - anomaly_score) * 2))
            
            if is_anomaly:
                self.stats['anomalies_detected'] += 1
            
            self.stats['predictions_made'] += 1
            
            return is_anomaly, anomaly_probability
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            return False, 0.0
            
    def classify_threat(self, network_data: Dict[str, Any]) -> Tuple[str, float]:
        """Classify the type of threat using machine learning."""
        try:
            if not self.threat_classifier:
                return "unknown", 0.0
            
            # Extract features
            features = self._extract_features(network_data)
            
            if len(features) == 0:
                return "unknown", 0.0
            
            # Scale features
            features_scaled = self.scaler.transform([features])
            
            # Predict threat type
            prediction = self.threat_classifier.predict(features_scaled)[0]
            probability = max(self.threat_classifier.predict_proba(features_scaled)[0])
            
            # Decode label
            threat_type = self.label_encoder.inverse_transform([prediction])[0]
            
            self.stats['threats_classified'] += 1
            
            return threat_type, probability
            
        except Exception as e:
            self.logger.error(f"Error in threat classification: {e}")
            return "unknown", 0.0
            
    def analyze_behavior(self, sequence_data: List[Dict[str, Any]]) -> Tuple[bool, float]:
        """Analyze behavioral patterns using LSTM."""
        try:
            if not self.behavioral_model or len(sequence_data) < 10:
                return False, 0.0
            
            # Extract sequential features
            features_sequence = []
            for data_point in sequence_data[-10:]:  # Use last 10 data points
                features = self._extract_features(data_point)
                if len(features) > 0:
                    features_sequence.append(features)
            
            if len(features_sequence) < 10:
                return False, 0.0
            
            # Pad or truncate to exactly 10 sequences
            features_sequence = features_sequence[-10:]
            
            # Convert to numpy array and reshape
            X = np.array(features_sequence).reshape(1, 10, -1)
            
            # Predict
            prediction = self.behavioral_model.predict(X, verbose=0)[0][0]
            
            is_suspicious = prediction > 0.5
            confidence = float(prediction) if is_suspicious else float(1 - prediction)
            
            return is_suspicious, confidence
            
        except Exception as e:
            self.logger.error(f"Error in behavioral analysis: {e}")
            return False, 0.0
            
    def _extract_features(self, network_data: Dict[str, Any]) -> List[float]:
        """Extract comprehensive features from network data."""
        features = []
        
        try:
            # Basic packet features
            features.extend(self._extract_packet_features(network_data))
            
            # Temporal features
            features.extend(self._extract_temporal_features(network_data))
            
            # Behavioral features
            features.extend(self._extract_behavioral_features(network_data))
            
            # Network topology features
            features.extend(self._extract_network_features(network_data))
            
            # Pad or truncate to fixed size
            target_size = 50
            if len(features) > target_size:
                features = features[:target_size]
            elif len(features) < target_size:
                features.extend([0.0] * (target_size - len(features)))
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            return []
            
    def _extract_packet_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract packet-level features."""
        features = []
        
        try:
            # Packet size features
            packet_size = data.get('packet_size', 0)
            features.append(float(packet_size))
            features.append(float(np.log1p(packet_size)))  # Log-transformed size
            
            # Protocol features
            protocol = data.get('protocol', '').upper()
            features.append(1.0 if protocol == 'TCP' else 0.0)
            features.append(1.0 if protocol == 'UDP' else 0.0)
            features.append(1.0 if protocol == 'ICMP' else 0.0)
            
            # Port features
            src_port = data.get('source_port', 0)
            dst_port = data.get('destination_port', 0)
            
            features.append(float(src_port))
            features.append(float(dst_port))
            features.append(1.0 if src_port < 1024 else 0.0)  # Well-known port
            features.append(1.0 if dst_port < 1024 else 0.0)  # Well-known port
            
            # Flags and TCP features
            tcp_flags = data.get('tcp_flags', {})
            features.append(1.0 if tcp_flags.get('syn', False) else 0.0)
            features.append(1.0 if tcp_flags.get('ack', False) else 0.0)
            features.append(1.0 if tcp_flags.get('fin', False) else 0.0)
            features.append(1.0 if tcp_flags.get('rst', False) else 0.0)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting packet features: {e}")
            return [0.0] * 13
            
    def _extract_temporal_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract time-based features."""
        features = []
        
        try:
            # Time of day features
            timestamp = data.get('timestamp', datetime.now())
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            hour = timestamp.hour
            day_of_week = timestamp.weekday()
            
            features.append(float(hour) / 24.0)  # Normalized hour
            features.append(float(day_of_week) / 7.0)  # Normalized day of week
            
            # Cyclical encoding for time
            features.append(np.sin(2 * np.pi * hour / 24))
            features.append(np.cos(2 * np.pi * hour / 24))
            features.append(np.sin(2 * np.pi * day_of_week / 7))
            features.append(np.cos(2 * np.pi * day_of_week / 7))
            
            # Weekend indicator
            features.append(1.0 if day_of_week >= 5 else 0.0)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting temporal features: {e}")
            return [0.0] * 7
            
    def _extract_behavioral_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract behavioral features."""
        features = []
        
        try:
            # Connection patterns
            connection_count = data.get('connection_count', 0)
            unique_destinations = data.get('unique_destinations', 0)
            
            features.append(float(connection_count))
            features.append(float(unique_destinations))
            features.append(float(connection_count / max(1, unique_destinations)))  # Fan-out ratio
            
            # Traffic patterns
            bytes_sent = data.get('bytes_sent', 0)
            bytes_received = data.get('bytes_received', 0)
            
            features.append(float(bytes_sent))
            features.append(float(bytes_received))
            features.append(float(bytes_sent / max(1, bytes_received)))  # Upload/download ratio
            
            # Session features
            session_duration = data.get('session_duration', 0)
            features.append(float(session_duration))
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting behavioral features: {e}")
            return [0.0] * 7
            
    def _extract_network_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract network topology features."""
        features = []
        
        try:
            # IP address features
            src_ip = data.get('source_ip', '0.0.0.0')
            dst_ip = data.get('destination_ip', '0.0.0.0')
            
            # IP classification
            features.append(1.0 if self._is_private_ip(src_ip) else 0.0)
            features.append(1.0 if self._is_private_ip(dst_ip) else 0.0)
            features.append(1.0 if src_ip == dst_ip else 0.0)  # Loopback indicator
            
            # Geographic features (simplified)
            geo_data = data.get('geo_location', {})
            features.append(float(geo_data.get('latitude', 0.0)))
            features.append(float(geo_data.get('longitude', 0.0)))
            
            # Reputation scores
            threat_intel = data.get('threat_intelligence', {})
            features.append(float(threat_intel.get('reputation_score', 0.0)))
            features.append(1.0 if threat_intel.get('is_malicious', False) else 0.0)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting network features: {e}")
            return [0.0] * 7
            
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
            
    def train_models(self, training_data: List[Dict[str, Any]], labels: List[str]):
        """Train all ML models with new data."""
        try:
            if self.training_in_progress:
                self.logger.warning("Training already in progress")
                return False
            
            self.training_in_progress = True
            self.logger.info(f"Starting model training with {len(training_data)} samples")
            
            # Extract features
            X = []
            y = []
            
            for i, data in enumerate(training_data):
                features = self._extract_features(data)
                if len(features) > 0:
                    X.append(features)
                    y.append(labels[i])
            
            if len(X) < self.min_samples:
                self.logger.warning(f"Insufficient training data: {len(X)} < {self.min_samples}")
                return False
            
            X = np.array(X)
            y = np.array(y)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            self.scaler.fit(X_train)
            X_train_scaled = self.scaler.transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Encode labels
            self.label_encoder.fit(y)
            y_train_encoded = self.label_encoder.transform(y_train)
            y_test_encoded = self.label_encoder.transform(y_test)
            
            # Train anomaly detection model
            # Create binary labels for anomaly detection (malicious = -1, benign = 1)
            y_anomaly = np.where(np.isin(y_train, ['malware', 'intrusion', 'ddos']), -1, 1)
            self.anomaly_model.fit(X_train_scaled)
            
            # Train threat classifier
            self.threat_classifier.fit(X_train_scaled, y_train_encoded)
            
            # Evaluate models
            anomaly_pred = self.anomaly_model.predict(X_test_scaled)
            threat_pred = self.threat_classifier.predict(X_test_scaled)
            
            # Calculate accuracy
            threat_accuracy = np.mean(threat_pred == y_test_encoded)
            self.stats['model_accuracy'] = threat_accuracy
            
            # Save models
            self._save_models()
            
            self.stats['last_training'] = datetime.now().isoformat()
            self.stats['training_samples'] = len(X)
            
            self.logger.info(f"Model training completed. Accuracy: {threat_accuracy:.3f}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error training models: {e}")
            return False
            
        finally:
            self.training_in_progress = False
            
    def _auto_training_loop(self):
        """Automatic retraining loop."""
        while True:
            try:
                time.sleep(self.retrain_interval_hours * 3600)
                
                # Collect training data from database
                training_data, labels = self._collect_training_data()
                
                if len(training_data) >= self.min_samples:
                    self.train_models(training_data, labels)
                else:
                    self.logger.info(f"Insufficient data for retraining: {len(training_data)} samples")
                    
            except Exception as e:
                self.logger.error(f"Error in auto-training loop: {e}")
                time.sleep(3600)  # Wait 1 hour before retrying
                
    def _collect_training_data(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Collect training data from security events database."""
        training_data = []
        labels = []
        
        try:
            # This would collect data from the SIEM database
            # For now, return empty data
            # In a real implementation, this would query the events database
            # and extract features and labels from verified security events
            pass
            
        except Exception as e:
            self.logger.error(f"Error collecting training data: {e}")
            
        return training_data, labels
        
    def predict_threat_probability(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get comprehensive threat prediction."""
        try:
            # Anomaly detection
            is_anomaly, anomaly_score = self.detect_anomaly(network_data)
            
            # Threat classification
            threat_type, threat_confidence = self.classify_threat(network_data)
            
            # Calculate overall threat score
            threat_score = (anomaly_score + threat_confidence) / 2.0
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': anomaly_score,
                'threat_type': threat_type,
                'threat_confidence': threat_confidence,
                'overall_threat_score': threat_score,
                'recommendation': self._get_recommendation(threat_score, threat_type),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error in threat prediction: {e}")
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'threat_type': 'unknown',
                'threat_confidence': 0.0,
                'overall_threat_score': 0.0,
                'recommendation': 'allow',
                'timestamp': datetime.now().isoformat()
            }
            
    def _get_recommendation(self, threat_score: float, threat_type: str) -> str:
        """Get action recommendation based on threat analysis."""
        if threat_score > 0.8:
            return 'block_immediately'
        elif threat_score > 0.6:
            return 'quarantine'
        elif threat_score > 0.4:
            return 'monitor_closely'
        elif threat_score > 0.2:
            return 'log_and_allow'
        else:
            return 'allow'
            
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models."""
        return {
            'models_loaded': self.models_loaded,
            'anomaly_model_type': type(self.anomaly_model).__name__ if self.anomaly_model else None,
            'threat_classifier_type': type(self.threat_classifier).__name__ if self.threat_classifier else None,
            'behavioral_model_layers': len(self.behavioral_model.layers) if self.behavioral_model else 0,
            'training_in_progress': self.training_in_progress,
            'auto_retrain_enabled': self.auto_retrain,
            'stats': self.stats
        }
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get ML engine statistics."""
        return {
            **self.stats,
            'models_loaded': self.models_loaded,
            'training_in_progress': self.training_in_progress,
            'auto_retrain_enabled': self.auto_retrain
        }
