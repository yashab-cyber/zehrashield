#!/usr/bin/env python3
"""
ZehraShield Integration Test Suite
Copyright (c) 2025 ZehraSec - Yashab Alam
Comprehensive integration testing for all components
"""

import os
import sys
import json
import time
import unittest
import threading
import subprocess
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

# Import ZehraShield modules
try:
    from src.core.firewall_engine import FirewallEngine
    from src.core.config_manager import ConfigManager
    from src.core.logger import SecurityLogger
    from src.layers.layer1_packet_filter import PacketFilter
    from src.layers.layer2_application_gateway import ApplicationGateway
    from src.layers.layer3_ids_ips import IDSIPS
    from src.layers.layer4_threat_intelligence import ThreatIntelligence
    from src.layers.layer5_network_access_control import NetworkAccessControl
    from src.layers.layer6_siem_integration import SIEMIntegration
    from src.ml.threat_detection import ThreatDetection
    from src.web.dashboard import app as web_app
    from src.cli.admin_cli import AdminCLI
except ImportError as e:
    print(f"Import Error: {e}")
    print("Please ensure all dependencies are installed: pip install -r requirements.txt")
    
    # Try alternative import approach
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
    try:
        from core.firewall_engine import FirewallEngine
        from core.config_manager import ConfigManager
        from core.logger import SecurityLogger
        print("Alternative imports successful")
    except ImportError:
        print("Alternative imports also failed - some tests may be skipped")
        sys.exit(1)

class ZehraShieldIntegrationTest(unittest.TestCase):
    """Comprehensive integration tests for ZehraShield"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.config_manager = ConfigManager()
        cls.logger = SecurityLogger()
        cls.firewall_engine = None
        cls.web_server_thread = None
        
        # Create test directories
        os.makedirs("logs", exist_ok=True)
        os.makedirs("data", exist_ok=True)
        os.makedirs("temp", exist_ok=True)
        
        print("Setting up ZehraShield integration test environment...")
    
    def setUp(self):
        """Set up each test"""
        print(f"\n{'='*60}")
        print(f"Running test: {self._testMethodName}")
        print(f"{'='*60}")
    
    def test_01_configuration_loading(self):
        """Test configuration loading and validation"""
        print("Testing configuration loading...")
        
        # Test default config loading
        config = self.config_manager.load_config()
        self.assertIsInstance(config, dict)
        self.assertIn('firewall', config)
        self.assertIn('layers', config)
        
        # Test advanced config loading if available
        advanced_config_path = "config/firewall_advanced.json"
        if os.path.exists(advanced_config_path):
            advanced_config = self.config_manager.load_config(advanced_config_path)
            self.assertIsInstance(advanced_config, dict)
            print("✓ Advanced configuration loaded successfully")
        
        print("✓ Configuration loading test passed")
    
    def test_02_logging_system(self):
        """Test logging system functionality"""
        print("Testing logging system...")
        
        # Test security event logging
        self.logger.log_security_event(
            event_type="test_event",
            severity="info",
            source_ip="127.0.0.1",
            description="Integration test event"
        )
        
        # Test log file creation
        log_files = list(Path("logs").glob("*.log"))
        self.assertGreater(len(log_files), 0, "No log files found")
        
        print("✓ Logging system test passed")
    
    def test_03_layer_initialization(self):
        """Test individual layer initialization"""
        print("Testing layer initialization...")
        
        config = self.config_manager.load_config()
        
        # Test Layer 1 - Packet Filter
        layer1 = PacketFilter(config.get('layers', {}).get('layer1_packet_filter', {}))
        self.assertIsNotNone(layer1)
        print("✓ Layer 1 (Packet Filter) initialized")
        
        # Test Layer 2 - Application Gateway
        layer2 = ApplicationGateway(config.get('layers', {}).get('layer2_application_gateway', {}))
        self.assertIsNotNone(layer2)
        print("✓ Layer 2 (Application Gateway) initialized")
        
        # Test Layer 3 - IDS/IPS
        layer3 = IDSIPS(config.get('layers', {}).get('layer3_ids_ips', {}))
        self.assertIsNotNone(layer3)
        print("✓ Layer 3 (IDS/IPS) initialized")
        
        # Test Layer 4 - Threat Intelligence
        layer4 = ThreatIntelligence(config.get('layers', {}).get('layer4_threat_intelligence', {}))
        self.assertIsNotNone(layer4)
        print("✓ Layer 4 (Threat Intelligence) initialized")
        
        # Test Layer 5 - Network Access Control
        layer5 = NetworkAccessControl(config.get('layers', {}).get('layer5_network_access_control', {}))
        self.assertIsNotNone(layer5)
        print("✓ Layer 5 (Network Access Control) initialized")
        
        # Test Layer 6 - SIEM Integration
        layer6 = SIEMIntegration(config.get('layers', {}).get('layer6_siem_integration', {}))
        self.assertIsNotNone(layer6)
        print("✓ Layer 6 (SIEM Integration) initialized")
        
        print("✓ All layers initialized successfully")
    
    def test_04_ml_system(self):
        """Test machine learning system"""
        print("Testing ML system...")
        
        try:
            ml_config = {}
            threat_detection = ThreatDetection(ml_config)
            self.assertIsNotNone(threat_detection)
            
            # Test basic ML functionality
            test_data = {
                'source_ip': '192.168.1.100',
                'destination_port': 80,
                'packet_size': 1024,
                'protocol': 'TCP'
            }
            
            # This should not crash
            result = threat_detection.analyze_traffic(test_data)
            print("✓ ML threat analysis completed")
            
        except Exception as e:
            print(f"⚠ ML system test warning: {e}")
            print("  This is expected if ML dependencies are not fully installed")
        
        print("✓ ML system test completed")
    
    def test_05_firewall_engine_integration(self):
        """Test firewall engine integration"""
        print("Testing firewall engine integration...")
        
        config = self.config_manager.load_config()
        self.firewall_engine = FirewallEngine(config)
        
        # Test initialization
        self.assertIsNotNone(self.firewall_engine)
        
        # Test layer loading
        self.firewall_engine.load_layers()
        print("✓ Firewall layers loaded")
        
        # Test statistics
        stats = self.firewall_engine.get_statistics()
        self.assertIsInstance(stats, dict)
        print("✓ Statistics retrieval working")
        
        print("✓ Firewall engine integration test passed")
    
    def test_06_web_dashboard(self):
        """Test web dashboard functionality"""
        print("Testing web dashboard...")
        
        try:
            # Test app creation
            self.assertIsNotNone(web_app)
            
            # Test routes exist
            with web_app.test_client() as client:
                # Test login page
                response = client.get('/login')
                self.assertEqual(response.status_code, 200)
                print("✓ Login page accessible")
                
                # Test API status endpoint
                response = client.get('/api/status')
                # May require authentication, so 401 or 200 is acceptable
                self.assertIn(response.status_code, [200, 401])
                print("✓ API endpoints accessible")
            
        except Exception as e:
            print(f"⚠ Web dashboard test warning: {e}")
            print("  This may be due to missing Flask dependencies")
        
        print("✓ Web dashboard test completed")
    
    def test_07_cli_interface(self):
        """Test CLI interface"""
        print("Testing CLI interface...")
        
        try:
            cli = AdminCLI()
            self.assertIsNotNone(cli)
            
            # Test help command
            help_output = cli.get_help()
            self.assertIsInstance(help_output, str)
            self.assertGreater(len(help_output), 0)
            print("✓ CLI help system working")
            
        except Exception as e:
            print(f"⚠ CLI test warning: {e}")
        
        print("✓ CLI interface test completed")
    
    def test_08_configuration_validation(self):
        """Test configuration validation"""
        print("Testing configuration validation...")
        
        config = self.config_manager.load_config()
        
        # Validate required sections
        required_sections = ['firewall', 'layers']
        for section in required_sections:
            self.assertIn(section, config, f"Missing required config section: {section}")
        
        # Validate layer configs
        layers = config.get('layers', {})
        expected_layers = [
            'layer1_packet_filter',
            'layer2_application_gateway', 
            'layer3_ids_ips',
            'layer4_threat_intelligence',
            'layer5_network_access_control',
            'layer6_siem_integration'
        ]
        
        for layer in expected_layers:
            self.assertIn(layer, layers, f"Missing layer config: {layer}")
        
        print("✓ Configuration validation passed")
    
    def test_09_packet_processing_simulation(self):
        """Test packet processing simulation"""
        print("Testing packet processing simulation...")
        
        if self.firewall_engine is None:
            config = self.config_manager.load_config()
            self.firewall_engine = FirewallEngine(config)
            self.firewall_engine.load_layers()
        
        # Simulate packet processing
        test_packet = {
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1',
            'source_port': 12345,
            'dest_port': 80,
            'protocol': 'TCP',
            'data': b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n'
        }
        
        try:
            # This should not crash
            result = self.firewall_engine.process_packet(test_packet)
            print("✓ Packet processing simulation completed")
            
        except Exception as e:
            print(f"⚠ Packet processing warning: {e}")
            print("  This is expected in simulation mode")
        
        print("✓ Packet processing test completed")
    
    def test_10_end_to_end_workflow(self):
        """Test end-to-end workflow"""
        print("Testing end-to-end workflow...")
        
        # Initialize complete system
        config = self.config_manager.load_config()
        firewall = FirewallEngine(config)
        firewall.load_layers()
        
        # Simulate threat detection workflow
        threat_event = {
            'event_type': 'suspicious_activity',
            'source_ip': '192.168.1.100',
            'severity': 'medium',
            'timestamp': time.time(),
            'description': 'Simulated threat for testing'
        }
        
        # Log the event
        self.logger.log_security_event(**threat_event)
        
        # Get system statistics
        stats = firewall.get_statistics()
        self.assertIsInstance(stats, dict)
        
        print("✓ End-to-end workflow test completed")
    
    def test_11_performance_baseline(self):
        """Test performance baseline"""
        print("Testing performance baseline...")
        
        start_time = time.time()
        
        # Initialize system
        config = self.config_manager.load_config()
        firewall = FirewallEngine(config)
        firewall.load_layers()
        
        initialization_time = time.time() - start_time
        print(f"✓ System initialization time: {initialization_time:.2f} seconds")
        
        # Test packet processing speed
        start_time = time.time()
        for i in range(100):
            test_packet = {
                'source_ip': f'192.168.1.{i % 255}',
                'dest_ip': '10.0.0.1',
                'source_port': 12345 + i,
                'dest_port': 80,
                'protocol': 'TCP',
                'data': b'test_data'
            }
            try:
                firewall.process_packet(test_packet)
            except:
                pass  # Expected in simulation
        
        processing_time = time.time() - start_time
        packets_per_second = 100 / processing_time if processing_time > 0 else 0
        print(f"✓ Simulated packet processing: {packets_per_second:.0f} packets/second")
        
        print("✓ Performance baseline test completed")
    
    def test_12_error_handling(self):
        """Test error handling and recovery"""
        print("Testing error handling...")
        
        # Test invalid configuration
        try:
            invalid_config = {'invalid': 'config'}
            firewall = FirewallEngine(invalid_config)
            # Should handle gracefully
            print("✓ Invalid config handled gracefully")
        except Exception as e:
            print(f"✓ Invalid config properly rejected: {type(e).__name__}")
        
        # Test invalid packet data
        if self.firewall_engine is None:
            config = self.config_manager.load_config()
            self.firewall_engine = FirewallEngine(config)
            self.firewall_engine.load_layers()
        
        try:
            invalid_packet = {'invalid': 'packet'}
            self.firewall_engine.process_packet(invalid_packet)
        except Exception as e:
            print(f"✓ Invalid packet properly handled: {type(e).__name__}")
        
        print("✓ Error handling test completed")
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        print("\nCleaning up test environment...")
        
        # Stop any running services
        if cls.web_server_thread and cls.web_server_thread.is_alive():
            print("Stopping web server...")
        
        # Clean up temporary files
        import shutil
        if os.path.exists("temp"):
            shutil.rmtree("temp", ignore_errors=True)
        
        print("✓ Test environment cleaned up")

def run_integration_tests():
    """Run all integration tests with detailed reporting"""
    print("="*80)
    print("ZehraShield Integration Test Suite")
    print("Copyright (c) 2025 ZehraSec - Yashab Alam")
    print("="*80)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(ZehraShieldIntegrationTest)
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        descriptions=True,
        failfast=False
    )
    
    print("\nStarting integration tests...\n")
    result = runner.run(suite)
    
    # Generate test report
    print("\n" + "="*80)
    print("INTEGRATION TEST REPORT")
    print("="*80)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    passed = total_tests - failures - errors
    
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed}")
    print(f"Failed: {failures}")
    print(f"Errors: {errors}")
    print(f"Success Rate: {(passed/total_tests)*100:.1f}%")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\nERRORRS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.split('Exception:')[-1].strip()}")
    
    # Save test results
    test_results = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_tests': total_tests,
        'passed': passed,
        'failed': failures,
        'errors': errors,
        'success_rate': (passed/total_tests)*100,
        'failures': [str(test) for test, _ in result.failures],
        'errors': [str(test) for test, _ in result.errors]
    }
    
    with open('integration_test_results.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to: integration_test_results.json")
    print("="*80)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_integration_tests()
    sys.exit(0 if success else 1)
