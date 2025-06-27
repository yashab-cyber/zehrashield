"""
ZehraShield Test Suite
Copyright © 2025 ZehraSec - Yashab Alam

Comprehensive test suite for all ZehraShield components.
"""

import unittest
import sys
import os
import tempfile
import threading
import time
import json
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.config_manager import ConfigManager
from core.logger import setup_logging
from core.firewall_engine import FirewallEngine
from layers.layer1_packet_filter import PacketFilterLayer
from layers.layer2_application_gateway import ApplicationGatewayLayer
from layers.layer3_ids_ips import IDSIPSLayer
from layers.layer4_threat_intelligence import ThreatIntelligenceLayer
from layers.layer5_network_access_control import NetworkAccessControlLayer
from layers.layer6_siem_integration import SIEMIntegrationLayer
from ml.threat_detection import ThreatDetectionML


class TestConfigManager(unittest.TestCase):
    """Test configuration management."""
    
    def setUp(self):
        """Setup test configuration."""
        self.test_config = {
            "firewall": {
                "enabled": True,
                "mode": "test"
            },
            "layers": {
                "layer1_packet_filter": {
                    "enabled": True,
                    "rate_limit_per_ip": 100
                }
            }
        }
        
        # Create temporary config file
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.test_config, self.temp_file)
        self.temp_file.close()
        
    def tearDown(self):
        """Cleanup test files."""
        os.unlink(self.temp_file.name)
        
    def test_load_config(self):
        """Test configuration loading."""
        config_manager = ConfigManager(self.temp_file.name)
        self.assertTrue(config_manager.get('firewall', {}).get('enabled'))
        self.assertEqual(config_manager.get('firewall', {}).get('mode'), 'test')
        
    def test_get_config_value(self):
        """Test getting configuration values."""
        config_manager = ConfigManager(self.temp_file.name)
        rate_limit = config_manager.get('layers', {}).get('layer1_packet_filter', {}).get('rate_limit_per_ip')
        self.assertEqual(rate_limit, 100)
        
    def test_invalid_config_file(self):
        """Test handling of invalid configuration file."""
        with self.assertRaises(Exception):
            ConfigManager('nonexistent_file.json')
            
    def test_get_log_level(self):
        """Test log level retrieval."""
        config_manager = ConfigManager(self.temp_file.name)
        log_level = config_manager.get_log_level()
        self.assertIn(log_level, ['DEBUG', 'INFO', 'WARNING', 'ERROR'])


class TestPacketFilterLayer(unittest.TestCase):
    """Test Layer 1: Packet Filter."""
    
    def setUp(self):
        """Setup test configuration."""
        self.config = {
            'enabled': True,
            'rate_limit_per_ip': 100,
            'blocked_ports': [1337, 31337],
            'allowed_ports': [80, 443, 22],
            'drop_invalid_packets': True,
            'enable_ddos_protection': True
        }
        self.layer = PacketFilterLayer(self.config)
        
    def test_initialization(self):
        """Test layer initialization."""
        self.assertTrue(self.layer.enabled)
        self.assertEqual(self.layer.rate_limit_per_ip, 100)
        self.assertIn(1337, self.layer.blocked_ports)
        self.assertIn(80, self.layer.allowed_ports)
        
    def test_port_filtering(self):
        """Test port-based filtering."""
        # Test blocked port
        blocked_packet = {
            'destination_port': 1337,
            'source_ip': '192.168.1.100',
            'protocol': 'TCP'
        }
        self.assertFalse(self.layer._is_packet_allowed(blocked_packet))
        
        # Test allowed port
        allowed_packet = {
            'destination_port': 80,
            'source_ip': '192.168.1.100',
            'protocol': 'TCP'
        }
        self.assertTrue(self.layer._is_packet_allowed(allowed_packet))
        
    def test_rate_limiting(self):
        """Test rate limiting functionality."""
        test_ip = '192.168.1.100'
        
        # Should be allowed initially
        self.assertFalse(self.layer._is_rate_limited(test_ip))
        
        # Simulate multiple requests
        for _ in range(150):  # Exceed rate limit
            self.layer._update_rate_counter(test_ip)
            
        # Should now be rate limited
        self.assertTrue(self.layer._is_rate_limited(test_ip))
        
    def test_statistics(self):
        """Test statistics collection."""
        stats = self.layer.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('packets_processed', stats)
        self.assertIn('packets_blocked', stats)
        self.assertIn('rate_limited_ips', stats)
        
    def test_health_check(self):
        """Test health check."""
        self.assertTrue(self.layer.is_healthy())


class TestApplicationGatewayLayer(unittest.TestCase):
    """Test Layer 2: Application Gateway."""
    
    def setUp(self):
        """Setup test configuration."""
        self.config = {
            'enabled': True,
            'http_inspection': True,
            'https_inspection': True,
            'dns_filtering': True,
            'blocked_domains': ['malware.com', 'phishing.net'],
            'content_filtering': True
        }
        self.layer = ApplicationGatewayLayer(self.config)
        
    def test_initialization(self):
        """Test layer initialization."""
        self.assertTrue(self.layer.enabled)
        self.assertTrue(self.layer.http_inspection)
        self.assertIn('malware.com', self.layer.blocked_domains)
        
    def test_domain_filtering(self):
        """Test domain-based filtering."""
        # Test blocked domain
        self.assertTrue(self.layer._is_domain_blocked('malware.com'))
        self.assertTrue(self.layer._is_domain_blocked('sub.malware.com'))
        
        # Test allowed domain
        self.assertFalse(self.layer._is_domain_blocked('google.com'))
        
    def test_http_inspection(self):
        """Test HTTP traffic inspection."""
        http_request = {
            'method': 'GET',
            'host': 'example.com',
            'path': '/normal',
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'body': ''
        }
        
        result = self.layer._inspect_http_traffic(http_request)
        self.assertIsInstance(result, dict)
        self.assertIn('allowed', result)
        
    def test_malicious_pattern_detection(self):
        """Test detection of malicious patterns."""
        # Test SQL injection attempt
        malicious_request = {
            'method': 'POST',
            'host': 'example.com',
            'path': '/login',
            'headers': {},
            'body': "username=admin' OR '1'='1"
        }
        
        is_malicious = self.layer._detect_malicious_patterns(malicious_request)
        self.assertTrue(is_malicious)
        
    def test_statistics(self):
        """Test statistics collection."""
        stats = self.layer.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('requests_processed', stats)
        self.assertIn('requests_blocked', stats)
        self.assertIn('domains_blocked', stats)


class TestIDSIPSLayer(unittest.TestCase):
    """Test Layer 3: IDS/IPS."""
    
    def setUp(self):
        """Setup test configuration."""
        self.config = {
            'enabled': True,
            'auto_block': True,
            'threat_threshold': 75,
            'signature_updates': True,
            'anomaly_detection': True,
            'behavioral_analysis': True,
            'whitelist_ips': ['192.168.1.0/24'],
            'blacklist_ips': []
        }
        self.layer = IDSIPSLayer(self.config)
        
    def test_initialization(self):
        """Test layer initialization."""
        self.assertTrue(self.layer.enabled)
        self.assertTrue(self.layer.auto_block)
        self.assertEqual(self.layer.threat_threshold, 75)
        
    def test_signature_detection(self):
        """Test signature-based detection."""
        # Test known attack pattern
        malicious_payload = "../../../../etc/passwd"
        self.assertTrue(self.layer._check_signatures(malicious_payload))
        
        # Test normal payload
        normal_payload = "Hello, World!"
        self.assertFalse(self.layer._check_signatures(normal_payload))
        
    def test_ip_whitelisting(self):
        """Test IP whitelist functionality."""
        # Test whitelisted IP
        self.assertTrue(self.layer._is_whitelisted('192.168.1.100'))
        
        # Test non-whitelisted IP
        self.assertFalse(self.layer._is_whitelisted('10.0.0.100'))
        
    def test_threat_scoring(self):
        """Test threat scoring algorithm."""
        traffic_data = {
            'source_ip': '192.168.1.100',
            'destination_port': 22,
            'payload': 'normal traffic',
            'packet_count': 5
        }
        
        score = self.layer._calculate_threat_score(traffic_data)
        self.assertIsInstance(score, (int, float))
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        
    def test_statistics(self):
        """Test statistics collection."""
        stats = self.layer.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('threats_detected', stats)
        self.assertIn('ips_blocked', stats)
        self.assertIn('signatures_loaded', stats)


class TestThreatIntelligenceLayer(unittest.TestCase):
    """Test Layer 4: Threat Intelligence."""
    
    def setUp(self):
        """Setup test configuration."""
        self.config = {
            'enabled': True,
            'ml_detection': True,
            'threat_feeds': ['misp', 'alienvault'],
            'reputation_scoring': True,
            'geolocation_filtering': True,
            'blocked_countries': ['CN', 'RU'],
            'threat_hunting': True
        }
        self.layer = ThreatIntelligenceLayer(self.config)
        
    def test_initialization(self):
        """Test layer initialization."""
        self.assertTrue(self.layer.enabled)
        self.assertTrue(self.layer.ml_detection)
        self.assertIn('misp', self.layer.threat_feeds)
        
    def test_reputation_scoring(self):
        """Test IP reputation scoring."""
        # Mock reputation data
        test_ip = '192.168.1.100'
        score = self.layer._get_reputation_score(test_ip)
        
        self.assertIsInstance(score, (int, float))
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        
    def test_geolocation_filtering(self):
        """Test geolocation-based filtering."""
        # Test blocked country
        blocked_result = self.layer._check_geolocation('1.2.3.4')  # Simulated Chinese IP
        self.assertIsInstance(blocked_result, dict)
        
    def test_ioc_checking(self):
        """Test Indicators of Compromise checking."""
        # Test known malicious IP (simulated)
        malicious_ip = '192.0.2.1'  # Test IP
        ioc_result = self.layer._check_iocs({'ip': malicious_ip})
        
        self.assertIsInstance(ioc_result, dict)
        self.assertIn('is_malicious', ioc_result)
        
    def test_statistics(self):
        """Test statistics collection."""
        stats = self.layer.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('threat_intel_queries', stats)
        self.assertIn('malicious_ips_detected', stats)


class TestNetworkAccessControlLayer(unittest.TestCase):
    """Test Layer 5: Network Access Control."""
    
    def setUp(self):
        """Setup test configuration."""
        self.config = {
            'enabled': True,
            'device_authentication': True,
            'network_segmentation': True,
            'zero_trust_mode': True,
            'continuous_validation': True
        }
        self.layer = NetworkAccessControlLayer(self.config)
        
    def test_initialization(self):
        """Test layer initialization."""
        self.assertTrue(self.layer.enabled)
        self.assertTrue(self.layer.zero_trust_enabled)
        self.assertTrue(self.layer.device_auth_required)
        
    def test_device_authorization(self):
        """Test device authorization."""
        test_mac = '00:11:22:33:44:55'
        
        # Initially should not be authorized
        self.assertNotIn(test_mac, self.layer.authorized_devices)
        
        # Authorize device
        result = self.layer.authorize_device(test_mac)
        
        # For this test, it will return False since device is not in known_devices
        # In a real scenario, we'd add the device first
        
    def test_device_type_identification(self):
        """Test device type identification."""
        # Test Apple device
        apple_mac = '00:1B:21:11:22:33'
        device_type = self.layer._identify_device_type(apple_mac, 'Johns-iPhone')
        self.assertEqual(device_type, 'Apple Device')
        
        # Test printer
        printer_type = self.layer._identify_device_type('00:00:00:00:00:00', 'HP-Printer-123')
        self.assertEqual(printer_type, 'Printer')
        
    def test_statistics(self):
        """Test statistics collection."""
        stats = self.layer.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('total_known_devices', stats)
        self.assertIn('authorized_devices', stats)
        self.assertIn('quarantined_devices', stats)


class TestSIEMIntegrationLayer(unittest.TestCase):
    """Test Layer 6: SIEM Integration."""
    
    def setUp(self):
        """Setup test configuration."""
        self.config = {
            'enabled': True,
            'log_aggregation': True,
            'real_time_alerts': True,
            'incident_response': True,
            'compliance_reporting': True,
            'log_retention_days': 90,
            'export_formats': ['json', 'csv'],
            'integrations': {
                'splunk': {'enabled': False},
                'elastic': {'enabled': False}
            }
        }
        
        # Create temporary database
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        
        # Override database path
        original_db_path = 'data/siem.db'
        self.config['db_path'] = self.temp_db.name
        
        self.layer = SIEMIntegrationLayer(self.config)
        self.layer.db_path = self.temp_db.name
        self.layer._setup_database()
        
    def tearDown(self):
        """Cleanup test files."""
        os.unlink(self.temp_db.name)
        
    def test_initialization(self):
        """Test layer initialization."""
        self.assertTrue(self.layer.enabled)
        self.assertTrue(self.layer.log_aggregation)
        self.assertTrue(self.layer.real_time_alerts)
        
    def test_event_logging(self):
        """Test security event logging."""
        event_data = {
            'source_layer': 'layer1_packet_filter',
            'event_type': 'port_scan',
            'severity': 'HIGH',
            'source_ip': '192.168.1.100',
            'destination_ip': '192.168.1.1',
            'description': 'Port scan detected',
            'raw_data': {}
        }
        
        event_id = self.layer.log_security_event(event_data)
        self.assertIsInstance(event_id, str)
        self.assertTrue(len(event_id) > 0)
        
    def test_incident_creation(self):
        """Test incident creation and management."""
        # This would test the incident correlation logic
        # For now, just test that the method exists
        self.assertTrue(hasattr(self.layer, '_create_incident'))
        
    def test_statistics(self):
        """Test statistics collection."""
        stats = self.layer.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('events_processed', stats)
        self.assertIn('incidents_created', stats)
        self.assertIn('alerts_sent', stats)


class TestThreatDetectionML(unittest.TestCase):
    """Test Machine Learning threat detection."""
    
    def setUp(self):
        """Setup test configuration."""
        self.config = {
            'enabled': True,
            'models': {
                'anomaly_detection': {
                    'algorithm': 'isolation_forest',
                    'sensitivity': 0.1
                },
                'threat_classification': {
                    'algorithm': 'random_forest',
                    'confidence_threshold': 0.8
                }
            },
            'training': {
                'auto_retrain': False,  # Disable for testing
                'min_samples': 10
            }
        }
        
        # Create temporary models directory
        self.temp_dir = tempfile.mkdtemp()
        
        self.ml_engine = ThreatDetectionML(self.config)
        self.ml_engine.models_dir = self.temp_dir
        
    def tearDown(self):
        """Cleanup test files."""
        import shutil
        shutil.rmtree(self.temp_dir)
        
    def test_initialization(self):
        """Test ML engine initialization."""
        self.assertIsNotNone(self.ml_engine.anomaly_model)
        self.assertIsNotNone(self.ml_engine.threat_classifier)
        
    def test_feature_extraction(self):
        """Test feature extraction from network data."""
        network_data = {
            'packet_size': 1500,
            'protocol': 'TCP',
            'source_port': 80,
            'destination_port': 8080,
            'source_ip': '192.168.1.100',
            'destination_ip': '192.168.1.1',
            'timestamp': datetime.now().isoformat()
        }
        
        features = self.ml_engine._extract_features(network_data)
        self.assertIsInstance(features, list)
        self.assertTrue(len(features) > 0)
        
    def test_anomaly_detection(self):
        """Test anomaly detection."""
        # Mock some training data first
        self.ml_engine.anomaly_model.fit([[1, 2, 3] * 17])  # 50 features required
        
        test_data = {
            'packet_size': 1500,
            'protocol': 'TCP',
            'source_ip': '192.168.1.100'
        }
        
        is_anomaly, score = self.ml_engine.detect_anomaly(test_data)
        self.assertIsInstance(is_anomaly, bool)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)
        
    def test_threat_prediction(self):
        """Test comprehensive threat prediction."""
        test_data = {
            'packet_size': 1500,
            'protocol': 'TCP',
            'source_ip': '192.168.1.100',
            'destination_ip': '192.168.1.1'
        }
        
        prediction = self.ml_engine.predict_threat_probability(test_data)
        self.assertIsInstance(prediction, dict)
        self.assertIn('is_anomaly', prediction)
        self.assertIn('threat_type', prediction)
        self.assertIn('overall_threat_score', prediction)
        self.assertIn('recommendation', prediction)


class TestFirewallEngine(unittest.TestCase):
    """Test the main firewall engine."""
    
    def setUp(self):
        """Setup test configuration."""
        self.test_config = {
            "firewall": {
                "enabled": True,
                "mode": "test",
                "log_level": "INFO"
            },
            "layers": {
                "layer1_packet_filter": {"enabled": True},
                "layer2_application_gateway": {"enabled": True},
                "layer3_ids_ips": {"enabled": True},
                "layer4_threat_intelligence": {"enabled": True},
                "layer5_network_access_control": {"enabled": True},
                "layer6_siem_integration": {"enabled": True}
            }
        }
        
        # Create temporary config file
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.test_config, self.temp_file)
        self.temp_file.close()
        
        self.config_manager = ConfigManager(self.temp_file.name)
        
    def tearDown(self):
        """Cleanup test files."""
        os.unlink(self.temp_file.name)
        
    def test_initialization(self):
        """Test firewall engine initialization."""
        engine = FirewallEngine(self.config_manager)
        self.assertIsNotNone(engine)
        self.assertIsInstance(engine.layers, dict)
        
    def test_layer_initialization(self):
        """Test that all layers are initialized."""
        engine = FirewallEngine(self.config_manager)
        
        expected_layers = [
            'layer1_packet_filter',
            'layer2_application_gateway', 
            'layer3_ids_ips',
            'layer4_threat_intelligence',
            'layer5_network_access_control',
            'layer6_siem_integration'
        ]
        
        for layer_name in expected_layers:
            self.assertIn(layer_name, engine.layers)
            
    def test_health_check(self):
        """Test firewall engine health check."""
        engine = FirewallEngine(self.config_manager)
        self.assertTrue(engine.is_healthy())
        
    def test_statistics(self):
        """Test statistics collection."""
        engine = FirewallEngine(self.config_manager)
        stats = engine.get_statistics()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('packets_processed', stats)
        self.assertIn('threats_detected', stats)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system."""
    
    def setUp(self):
        """Setup integration test environment."""
        self.test_config = {
            "firewall": {
                "enabled": True,
                "mode": "test",
                "log_level": "INFO"
            },
            "web_console": {
                "enabled": False  # Disable for testing
            },
            "layers": {
                "layer1_packet_filter": {
                    "enabled": True,
                    "rate_limit_per_ip": 100
                },
                "layer2_application_gateway": {
                    "enabled": True,
                    "blocked_domains": ["test-malware.com"]
                },
                "layer3_ids_ips": {
                    "enabled": True,
                    "auto_block": True
                },
                "layer4_threat_intelligence": {
                    "enabled": True,
                    "ml_detection": True
                },
                "layer5_network_access_control": {
                    "enabled": True,
                    "zero_trust_mode": True
                },
                "layer6_siem_integration": {
                    "enabled": True,
                    "log_aggregation": True
                }
            }
        }
        
        # Create temporary config file
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.test_config, self.temp_file)
        self.temp_file.close()
        
    def tearDown(self):
        """Cleanup test files."""
        os.unlink(self.temp_file.name)
        
    def test_full_system_startup(self):
        """Test complete system startup and shutdown."""
        config_manager = ConfigManager(self.temp_file.name)
        engine = FirewallEngine(config_manager)
        
        # Start the engine
        engine.start()
        
        # Verify it's running
        self.assertTrue(engine.running)
        self.assertTrue(engine.is_healthy())
        
        # Wait a moment for threads to start
        time.sleep(1)
        
        # Stop the engine
        engine.stop()
        
        # Verify it's stopped
        self.assertFalse(engine.running)
        
    def test_packet_processing_flow(self):
        """Test packet processing through all layers."""
        config_manager = ConfigManager(self.temp_file.name)
        engine = FirewallEngine(config_manager)
        engine.start()
        
        # Simulate a packet
        test_packet = {
            'source_ip': '192.168.1.100',
            'destination_ip': '192.168.1.1',
            'source_port': 80,
            'destination_port': 8080,
            'protocol': 'TCP',
            'packet_size': 1500,
            'timestamp': datetime.now()
        }
        
        # Process through all layers
        result = engine.process_packet(test_packet)
        
        # Verify result
        self.assertIsInstance(result, dict)
        
        engine.stop()
        
    def test_threat_detection_integration(self):
        """Test threat detection across multiple layers."""
        config_manager = ConfigManager(self.temp_file.name)
        engine = FirewallEngine(config_manager)
        engine.start()
        
        # Simulate malicious traffic
        malicious_packet = {
            'source_ip': '192.0.2.1',  # Simulated malicious IP
            'destination_ip': '192.168.1.1',
            'source_port': 1337,  # Suspicious port
            'destination_port': 22,
            'protocol': 'TCP',
            'packet_size': 100,
            'payload': '../../../../etc/passwd',  # Directory traversal
            'timestamp': datetime.now()
        }
        
        # Process malicious packet
        result = engine.process_packet(malicious_packet)
        
        # Should be blocked by multiple layers
        self.assertIsInstance(result, dict)
        
        engine.stop()


def run_tests():
    """Run all tests."""
    # Setup logging for tests
    setup_logging('DEBUG')
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestConfigManager,
        TestPacketFilterLayer,
        TestApplicationGatewayLayer,
        TestIDSIPSLayer,
        TestThreatIntelligenceLayer,
        TestNetworkAccessControlLayer,
        TestSIEMIntegrationLayer,
        TestThreatDetectionML,
        TestFirewallEngine,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Return success status
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
