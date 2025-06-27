"""
ZehraShield Logging Setup
Copyright © 2025 ZehraSec - Yashab Alam
"""

import logging
import logging.handlers
import os
from pathlib import Path
from datetime import datetime


def setup_logging(log_level: str = "INFO", log_file: str = None) -> None:
    """Setup logging configuration for ZehraShield."""
    
    # Create logs directory if it doesn't exist
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Default log file
    if log_file is None:
        timestamp = datetime.now().strftime("%Y%m%d")
        log_file = logs_dir / f"zehrashield_{timestamp}.log"
    
    # Configure logging format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    logger.addHandler(file_handler)
    
    # Security events handler (separate file)
    security_log = logs_dir / f"security_{timestamp}.log"
    security_handler = logging.handlers.RotatingFileHandler(
        security_log,
        maxBytes=50 * 1024 * 1024,  # 50MB
        backupCount=10
    )
    security_handler.setFormatter(formatter)
    security_handler.setLevel(logging.WARNING)
    
    # Create security logger
    security_logger = logging.getLogger('security')
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)
    
    # Suppress noisy third-party loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('scapy').setLevel(logging.WARNING)


class SecurityLogger:
    """Specialized logger for security events."""
    
    def __init__(self):
        self.logger = logging.getLogger('security')
        
    def log_threat(self, threat_type: str, source_ip: str, details: dict = None):
        """Log a detected threat."""
        message = f"THREAT DETECTED: {threat_type} from {source_ip}"
        if details:
            message += f" - Details: {details}"
        self.logger.warning(message)
        
    def log_block(self, ip: str, reason: str):
        """Log an IP block action."""
        self.logger.warning(f"IP BLOCKED: {ip} - Reason: {reason}")
        
    def log_attack(self, attack_type: str, source_ip: str, target: str = None):
        """Log an attack attempt."""
        message = f"ATTACK: {attack_type} from {source_ip}"
        if target:
            message += f" targeting {target}"
        self.logger.error(message)
        
    def log_security_event(self, event_type: str, details: dict):
        """Log a general security event."""
        self.logger.info(f"SECURITY EVENT: {event_type} - {details}")


# Global security logger instance
security_logger = SecurityLogger()
