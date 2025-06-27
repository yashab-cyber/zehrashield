"""
ZehraShield Firewall Engine - Core orchestrator for all 6 layers
Copyright © 2025 ZehraSec - Yashab Alam
"""

import logging
import threading
import time
from typing import Dict, List, Any
import psutil
from datetime import datetime

from layers.layer1_packet_filter import PacketFilterLayer
from layers.layer2_application_gateway import ApplicationGatewayLayer
from layers.layer3_ids_ips import IDSIPSLayer
from layers.layer4_threat_intelligence import ThreatIntelligenceLayer
from layers.layer5_network_access_control import NetworkAccessControlLayer
from layers.layer6_siem_integration import SIEMIntegrationLayer
from core.logger import security_logger
from core.performance_monitor import PerformanceMonitor
from core.update_manager import UpdateManager


class FirewallEngine:
    """Main firewall engine that orchestrates all 6 security layers."""
    
    def __init__(self, config_manager):
        """Initialize the firewall engine."""
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # Initialize layers
        self.layers = {}
        self._initialize_layers()
        
        # Initialize performance monitor and update manager
        self.performance_monitor = PerformanceMonitor(
            self.config_manager.get_config(), 
            self.logger
        )
        self.update_manager = UpdateManager(
            self.config_manager.get_config(),
            self.logger
        )
        
        # Engine state
        self.running = False
        self.start_time = None
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'ips_blocked': 0,
            'last_threat': None
        }
        
        # Health monitoring
        self.health_check_thread = None
        self.last_health_check = datetime.now()
        
    def _initialize_layers(self):
        """Initialize all security layers."""
        layer_classes = {
            'layer1_packet_filter': PacketFilterLayer,
            'layer2_application_gateway': ApplicationGatewayLayer,
            'layer3_ids_ips': IDSIPSLayer,
            'layer4_threat_intelligence': ThreatIntelligenceLayer,
            'layer5_network_access_control': NetworkAccessControlLayer,
            'layer6_siem_integration': SIEMIntegrationLayer
        }
        
        for layer_name, layer_class in layer_classes.items():
            if self.config_manager.is_layer_enabled(layer_name):
                try:
                    self.layers[layer_name] = layer_class(
                        self.config_manager.get_layer_config(layer_name),
                        self
                    )
                    self.logger.info(f"✅ Initialized {layer_name}")
                except Exception as e:
                    self.logger.error(f"❌ Failed to initialize {layer_name}: {e}")
            else:
                self.logger.info(f"⏭️  Skipped {layer_name} (disabled)")
                
    def start(self):
        """Start the firewall engine and all enabled layers."""
        if self.running:
            self.logger.warning("Firewall engine is already running")
            return
            
        self.logger.info("🚀 Starting ZehraShield Firewall Engine")
        
        try:
            # Start each layer in sequence
            for layer_name, layer in self.layers.items():
                self.logger.info(f"Starting {layer_name}...")
                layer.start()
                
            # Start performance monitoring
            self.performance_monitor.start_monitoring()
            
            # Start update manager
            self.update_manager.start_update_service()
                
            self.running = True
            self.start_time = datetime.now()
            
            # Start health monitoring
            self._start_health_monitoring()
            
            # Log security event
            security_logger.log_security_event(
                "FIREWALL_STARTED",
                {
                    "layers_active": list(self.layers.keys()),
                    "start_time": self.start_time.isoformat(),
                    "version": "3.0.0"
                }
            )
            
            self.logger.info("🛡️  All layers started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start firewall engine: {e}")
            self.stop()
            raise
            
    def stop(self):
        """Stop the firewall engine and all layers."""
        if not self.running:
            return
            
        self.logger.info("Stopping ZehraShield Firewall Engine")
        self.running = False
        
        # Stop health monitoring
        if self.health_check_thread:
            self.health_check_thread = None
            
        # Stop performance monitoring and update manager
        self.performance_monitor.stop_monitoring_service()
        self.update_manager.stop_update_service()
            
        # Stop all layers
        for layer_name, layer in self.layers.items():
            try:
                self.logger.info(f"Stopping {layer_name}...")
                layer.stop()
            except Exception as e:
                self.logger.error(f"Error stopping {layer_name}: {e}")
                
        # Log security event
        security_logger.log_security_event(
            "FIREWALL_STOPPED",
            {
                "stop_time": datetime.now().isoformat(),
                "uptime_seconds": self.get_uptime(),
                "final_stats": self.stats
            }
        )
        
        self.logger.info("Firewall engine stopped")
        
    def process_packet(self, packet_data: dict) -> bool:
        """Process a packet through all layers."""
        self.stats['packets_processed'] += 1
        
        # Update performance monitor
        self.performance_monitor.increment_packet_counter()
        
        # Process packet through each layer
        for layer_name, layer in self.layers.items():
            try:
                result = layer.process_packet(packet_data)
                if not result.get('allow', True):
                    # Packet blocked by this layer
                    self.logger.debug(f"Packet blocked by {layer_name}: {result.get('reason', 'Unknown')}")
                    return False
                    
            except Exception as e:
                self.logger.error(f"Error processing packet in {layer_name}: {e}")
                
        return True
        
    def handle_threat(self, threat_info: dict):
        """Handle a detected threat."""
        self.stats['threats_detected'] += 1
        self.stats['last_threat'] = threat_info
        
        # Update performance monitor
        self.performance_monitor.increment_threat_counter()
        
        # Log the threat
        security_logger.log_threat(
            threat_info.get('type', 'Unknown'),
            threat_info.get('source_ip', 'Unknown'),
            threat_info
        )
        
        # Notify all layers about the threat
        for layer in self.layers.values():
            try:
                layer.handle_threat(threat_info)
            except Exception as e:
                self.logger.error(f"Error handling threat in layer: {e}")
                
    def block_ip(self, ip_address: str, reason: str, duration: int = None):
        """Block an IP address across all layers."""
        self.stats['ips_blocked'] += 1
        
        # Log the block action
        security_logger.log_block(ip_address, reason)
        
        # Implement block in applicable layers
        for layer in self.layers.values():
            try:
                if hasattr(layer, 'block_ip'):
                    layer.block_ip(ip_address, reason, duration)
            except Exception as e:
                self.logger.error(f"Error blocking IP in layer: {e}")
                
    def get_stats(self) -> dict:
        """Get firewall engine statistics."""
        stats = self.stats.copy()
        stats['uptime_seconds'] = self.get_uptime()
        stats['layers_active'] = len(self.layers)
        stats['memory_usage_mb'] = psutil.Process().memory_info().rss / 1024 / 1024
        stats['cpu_percent'] = psutil.Process().cpu_percent()
        
        return stats
        
    def get_uptime(self) -> int:
        """Get uptime in seconds."""
        if not self.start_time:
            return 0
        return int((datetime.now() - self.start_time).total_seconds())
        
    def is_healthy(self) -> bool:
        """Check if the firewall engine is healthy."""
        if not self.running:
            return False
            
        try:
            # Check system resources
            memory_usage = psutil.Process().memory_info().rss / 1024 / 1024
            cpu_percent = psutil.Process().cpu_percent()
            
            max_memory = self.config_manager.get('performance.max_memory_usage_mb', 1024)
            max_cpu = self.config_manager.get('performance.max_cpu_usage_percent', 80)
            
            if memory_usage > max_memory:
                self.logger.warning(f"High memory usage: {memory_usage:.1f}MB")
                return False
                
            if cpu_percent > max_cpu:
                self.logger.warning(f"High CPU usage: {cpu_percent:.1f}%")
                return False
                
            # Check layer health
            for layer_name, layer in self.layers.items():
                if hasattr(layer, 'is_healthy') and not layer.is_healthy():
                    self.logger.warning(f"Layer {layer_name} is unhealthy")
                    return False
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False
            
    def _start_health_monitoring(self):
        """Start health monitoring thread."""
        def health_monitor():
            while self.running:
                try:
                    time.sleep(30)  # Check every 30 seconds
                    self.last_health_check = datetime.now()
                    
                    if not self.is_healthy():
                        self.logger.warning("Health check failed")
                        
                except Exception as e:
                    self.logger.error(f"Health monitoring error: {e}")
                    
        self.health_check_thread = threading.Thread(target=health_monitor, daemon=True)
        self.health_check_thread.start()
        
    def get_layer_stats(self) -> dict:
        """Get statistics from all layers."""
        layer_stats = {}
        
        for layer_name, layer in self.layers.items():
            try:
                if hasattr(layer, 'get_stats'):
                    layer_stats[layer_name] = layer.get_stats()
                else:
                    layer_stats[layer_name] = {"status": "active"}
            except Exception as e:
                layer_stats[layer_name] = {"status": "error", "error": str(e)}
                
        return layer_stats
        
    def reload_config(self):
        """Reload configuration for all layers."""
        self.logger.info("Reloading configuration...")
        
        for layer in self.layers.values():
            try:
                if hasattr(layer, 'reload_config'):
                    layer.reload_config()
            except Exception as e:
                self.logger.error(f"Error reloading config for layer: {e}")
                
        self.logger.info("Configuration reloaded")
        
    def get_performance_metrics(self) -> dict:
        """Get current performance metrics."""
        return self.performance_monitor.get_current_metrics()
        
    def get_performance_report(self) -> dict:
        """Get comprehensive performance report."""
        return self.performance_monitor.get_performance_report()
        
    def get_update_status(self) -> dict:
        """Get update system status."""
        return self.update_manager.get_update_status()
        
    def check_for_updates(self, force=False) -> dict:
        """Check for available updates."""
        return self.update_manager.check_for_updates(force)
        
    def perform_update(self, version=None) -> bool:
        """Perform system update."""
        return self.update_manager.perform_update(version)
        
    def export_performance_metrics(self, filepath, format="json") -> bool:
        """Export performance metrics to file."""
        return self.performance_monitor.export_metrics(filepath, format)
