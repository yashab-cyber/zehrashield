"""
ZehraShield Core Configuration Manager
Copyright © 2025 ZehraSec - Yashab Alam
"""

import json
import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path


class ConfigManager:
    """Manages configuration for ZehraShield firewall system."""
    
    def __init__(self, config_path: str = "config/firewall.json"):
        """Initialize configuration manager."""
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.load_config()
        
    def load_config(self) -> None:
        """Load configuration from file."""
        try:
            if not self.config_path.exists():
                self.logger.warning(f"Config file not found: {self.config_path}")
                self._create_default_config()
                
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
                
            self.logger.info(f"Configuration loaded from {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            self._create_default_config()
            
    def save_config(self) -> None:
        """Save configuration to file."""
        try:
            # Ensure directory exists
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
                
            self.logger.info(f"Configuration saved to {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)."""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
            
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by key (supports dot notation)."""
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        # Set the value
        config[keys[-1]] = value
        
    def get_log_level(self) -> str:
        """Get logging level from configuration or environment."""
        # Check environment variable first
        env_level = os.environ.get('ZEHRASHIELD_LOG_LEVEL')
        if env_level:
            return env_level.upper()
            
        return self.get('firewall.log_level', 'INFO').upper()
        
    def is_test_mode(self) -> bool:
        """Check if running in test mode."""
        # Check environment variable first
        if os.environ.get('ZEHRASHIELD_TEST_MODE') == '1':
            return True
            
        return self.get('firewall.test_mode', False)
        
    def get_layer_config(self, layer_name: str) -> Dict[str, Any]:
        """Get configuration for a specific layer."""
        return self.get(f'layers.{layer_name}', {})
        
    def is_layer_enabled(self, layer_name: str) -> bool:
        """Check if a specific layer is enabled."""
        return self.get_layer_config(layer_name).get('enabled', False)
        
    def _create_default_config(self) -> None:
        """Create default configuration."""
        self.config = {
            "firewall": {
                "enabled": True,
                "mode": "production",
                "log_level": "INFO",
                "test_mode": False
            },
            "web_console": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 8443,
                "ssl": True,
                "username": "admin",
                "password": "zehrashield123"
            },
            "layers": {
                "layer1_packet_filter": {
                    "enabled": True,
                    "rate_limit_per_ip": 1000
                },
                "layer2_application_gateway": {
                    "enabled": True,
                    "http_inspection": True
                },
                "layer3_ids_ips": {
                    "enabled": True,
                    "auto_block": True,
                    "threat_threshold": 75
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
        
        self.save_config()
        self.logger.info("Default configuration created")
        
    def validate_config(self) -> bool:
        """Validate configuration settings."""
        required_sections = ['firewall', 'layers']
        
        for section in required_sections:
            if section not in self.config:
                self.logger.error(f"Missing required configuration section: {section}")
                return False
                
        return True
        
    def get_web_console_credentials(self) -> tuple:
        """Get web console credentials."""
        username = self.get('web_console.username', 'admin')
        password = self.get('web_console.password', 'zehrashield123')
        return username, password
        
    def update_config(self, updates: Dict[str, Any]) -> None:
        """Update configuration with new values."""
        def update_nested_dict(d: dict, u: dict):
            for k, v in u.items():
                if isinstance(v, dict):
                    d[k] = update_nested_dict(d.get(k, {}), v)
                else:
                    d[k] = v
            return d
            
        update_nested_dict(self.config, updates)
        self.save_config()
