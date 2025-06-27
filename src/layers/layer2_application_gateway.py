"""
Layer 2: Application Layer Gateway (ALG)
HTTP/HTTPS, DNS, FTP protocol analysis and content filtering
Copyright © 2025 ZehraSec - Yashab Alam
"""

import logging
import re
import json
import threading
from typing import Dict, List, Any, Set
from urllib.parse import urlparse, unquote
from datetime import datetime, timedelta
import base64

from core.logger import security_logger


class ApplicationGatewayLayer:
    """Layer 2: Application Layer Gateway with protocol analysis."""
    
    def __init__(self, config: dict, engine):
        """Initialize application gateway layer."""
        self.config = config
        self.engine = engine
        self.logger = logging.getLogger(__name__)
        
        # Protocol inspectors
        self.http_inspector = HTTPInspector(config)
        self.dns_inspector = DNSInspector(config)
        self.ftp_inspector = FTPInspector(config)
        self.smtp_inspector = SMTPInspector(config)
        
        # Content filtering
        self.blocked_domains = set(config.get('blocked_domains', []))
        self.suspicious_patterns = self._load_suspicious_patterns()
        
        # Statistics
        self.stats = {
            'http_requests': 0,
            'https_requests': 0,
            'dns_queries': 0,
            'ftp_connections': 0,
            'smtp_connections': 0,
            'blocked_requests': 0,
            'malicious_content': 0
        }
        
        # Threat cache
        self.threat_cache = {}
        self.cache_expiry = timedelta(hours=1)
        
        self.logger.info("Layer 2 (Application Gateway) initialized")
        
    def start(self):
        """Start the application gateway layer."""
        self.logger.info("✅ Layer 2 (Application Gateway) started")
        
    def stop(self):
        """Stop the application gateway layer."""
        self.logger.info("Layer 2 (Application Gateway) stopped")
        
    def process_packet(self, packet_data: dict) -> dict:
        """Process a packet through Layer 2 application analysis."""
        dst_port = packet_data.get('dst_port')
        protocol = packet_data.get('protocol')
        src_ip = packet_data.get('src_ip')
        
        # HTTP/HTTPS inspection
        if dst_port in [80, 8080] and self.config.get('http_inspection', True):
            return self._inspect_http(packet_data)
            
        elif dst_port == 443 and self.config.get('https_inspection', True):
            return self._inspect_https(packet_data)
            
        # DNS inspection
        elif dst_port == 53 and self.config.get('dns_filtering', True):
            return self._inspect_dns(packet_data)
            
        # FTP inspection
        elif dst_port in [21, 20] and self.config.get('ftp_inspection', True):
            return self._inspect_ftp(packet_data)
            
        # SMTP inspection
        elif dst_port in [25, 587, 465] and self.config.get('smtp_inspection', True):
            return self._inspect_smtp(packet_data)
            
        return {'allow': True, 'layer': 'application_gateway'}
        
    def _inspect_http(self, packet_data: dict) -> dict:
        """Inspect HTTP traffic."""
        self.stats['http_requests'] += 1
        
        # Simulate HTTP request extraction
        http_data = self._extract_http_data(packet_data)
        if not http_data:
            return {'allow': True}
            
        # Check for malicious patterns
        result = self.http_inspector.inspect(http_data, packet_data['src_ip'])
        
        if not result['safe']:
            self.stats['blocked_requests'] += 1
            security_logger.log_threat(
                "MALICIOUS_HTTP_REQUEST",
                packet_data['src_ip'],
                {
                    'url': http_data.get('url'),
                    'method': http_data.get('method'),
                    'reason': result['reason']
                }
            )
            return {'allow': False, 'reason': result['reason']}
            
        return {'allow': True, 'layer': 'application_gateway'}
        
    def _inspect_https(self, packet_data: dict) -> dict:
        """Inspect HTTPS traffic (limited due to encryption)."""
        self.stats['https_requests'] += 1
        
        # For HTTPS, we can only inspect SNI and certificate info
        # In a real implementation, this would require SSL/TLS inspection
        
        # Check destination IP reputation
        dst_ip = packet_data.get('dst_ip')
        if self._is_ip_suspicious(dst_ip):
            security_logger.log_threat(
                "SUSPICIOUS_HTTPS_DESTINATION",
                packet_data['src_ip'],
                {'dst_ip': dst_ip}
            )
            return {'allow': False, 'reason': 'Suspicious HTTPS destination'}
            
        return {'allow': True, 'layer': 'application_gateway'}
        
    def _inspect_dns(self, packet_data: dict) -> dict:
        """Inspect DNS queries."""
        self.stats['dns_queries'] += 1
        
        # Simulate DNS query extraction
        dns_data = self._extract_dns_data(packet_data)
        if not dns_data:
            return {'allow': True}
            
        # Check against blocked domains
        domain = dns_data.get('domain', '').lower()
        
        if self._is_domain_blocked(domain):
            self.stats['blocked_requests'] += 1
            security_logger.log_threat(
                "BLOCKED_DOMAIN_QUERY",
                packet_data['src_ip'],
                {'domain': domain}
            )
            return {'allow': False, 'reason': f'Domain {domain} is blocked'}
            
        # Check for DNS tunneling
        if self._detect_dns_tunneling(dns_data, packet_data['src_ip']):
            security_logger.log_attack("DNS_TUNNELING", packet_data['src_ip'])
            return {'allow': False, 'reason': 'DNS tunneling detected'}
            
        return {'allow': True, 'layer': 'application_gateway'}
        
    def _inspect_ftp(self, packet_data: dict) -> dict:
        """Inspect FTP traffic."""
        self.stats['ftp_connections'] += 1
        
        # FTP inspection logic
        ftp_data = self._extract_ftp_data(packet_data)
        if not ftp_data:
            return {'allow': True}
            
        result = self.ftp_inspector.inspect(ftp_data, packet_data['src_ip'])
        
        if not result['safe']:
            self.stats['blocked_requests'] += 1
            return {'allow': False, 'reason': result['reason']}
            
        return {'allow': True, 'layer': 'application_gateway'}
        
    def _inspect_smtp(self, packet_data: dict) -> dict:
        """Inspect SMTP traffic."""
        self.stats['smtp_connections'] += 1
        
        # SMTP inspection logic
        smtp_data = self._extract_smtp_data(packet_data)
        if not smtp_data:
            return {'allow': True}
            
        result = self.smtp_inspector.inspect(smtp_data, packet_data['src_ip'])
        
        if not result['safe']:
            self.stats['blocked_requests'] += 1
            return {'allow': False, 'reason': result['reason']}
            
        return {'allow': True, 'layer': 'application_gateway'}
        
    def _extract_http_data(self, packet_data: dict) -> dict:
        """Extract HTTP request data from packet."""
        # Simulated HTTP data extraction
        # In a real implementation, this would parse actual HTTP headers
        return {
            'method': 'GET',
            'url': f"http://{packet_data.get('dst_ip')}/",
            'headers': {},
            'user_agent': 'Mozilla/5.0',
            'payload': ''
        }
        
    def _extract_dns_data(self, packet_data: dict) -> dict:
        """Extract DNS query data from packet."""
        # Simulated DNS data extraction
        return {
            'domain': 'example.com',
            'query_type': 'A',
            'query_id': 12345
        }
        
    def _extract_ftp_data(self, packet_data: dict) -> dict:
        """Extract FTP data from packet."""
        # Simulated FTP data extraction
        return {
            'command': 'USER',
            'args': 'anonymous',
            'data_channel': False
        }
        
    def _extract_smtp_data(self, packet_data: dict) -> dict:
        """Extract SMTP data from packet."""
        # Simulated SMTP data extraction
        return {
            'command': 'MAIL FROM',
            'sender': 'user@example.com',
            'recipient': 'dest@example.com'
        }
        
    def _is_domain_blocked(self, domain: str) -> bool:
        """Check if a domain is in the blocked list."""
        if domain in self.blocked_domains:
            return True
            
        # Check for subdomain matches
        for blocked in self.blocked_domains:
            if domain.endswith(f'.{blocked}'):
                return True
                
        return False
        
    def _is_ip_suspicious(self, ip: str) -> bool:
        """Check if an IP is suspicious based on threat intelligence."""
        # Check cache first
        if ip in self.threat_cache:
            cache_entry = self.threat_cache[ip]
            if datetime.now() - cache_entry['timestamp'] < self.cache_expiry:
                return cache_entry['suspicious']
                
        # In a real implementation, this would query threat intelligence feeds
        suspicious = False
        
        # Cache the result
        self.threat_cache[ip] = {
            'suspicious': suspicious,
            'timestamp': datetime.now()
        }
        
        return suspicious
        
    def _detect_dns_tunneling(self, dns_data: dict, src_ip: str) -> bool:
        """Detect DNS tunneling attempts."""
        domain = dns_data.get('domain', '')
        
        # Check for unusually long domain names
        if len(domain) > 100:
            return True
            
        # Check for high entropy in subdomain
        subdomains = domain.split('.')
        for subdomain in subdomains:
            if len(subdomain) > 20 and self._calculate_entropy(subdomain) > 4.5:
                return True
                
        # Check for Base64-like patterns
        for subdomain in subdomains:
            if self._is_base64_like(subdomain):
                return True
                
        return False
        
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math
        
        if not s:
            return 0
            
        entropy = 0
        for c in set(s):
            p = s.count(c) / len(s)
            entropy -= p * math.log2(p)
            
        return entropy
        
    def _is_base64_like(self, s: str) -> bool:
        """Check if string looks like Base64 encoding."""
        if len(s) < 8:
            return False
            
        # Base64 character set
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        
        # Check if most characters are Base64
        base64_count = sum(1 for c in s if c in base64_chars)
        return (base64_count / len(s)) > 0.8
        
    def _load_suspicious_patterns(self) -> List[re.Pattern]:
        """Load suspicious content patterns."""
        patterns = [
            # SQL Injection patterns
            r'(\bunion\b.*\bselect\b)|(\bselect\b.*\bfrom\b)',
            r'(\bdrop\b.*\btable\b)|(\binsert\b.*\binto\b)',
            r'(\bdelete\b.*\bfrom\b)|(\bupdate\b.*\bset\b)',
            
            # XSS patterns
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            
            # Command injection patterns
            r'(\||&|;|\n|\r).*?(cat|ls|pwd|whoami|id|uname)',
            r'(\.\./){2,}',
            
            # File inclusion patterns
            r'(file://|ftp://|gopher://)',
            r'(etc/passwd|etc/shadow|windows/system32)',
        ]
        
        return [re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in patterns]
        
    def get_stats(self) -> dict:
        """Get layer statistics."""
        return self.stats.copy()
        
    def handle_threat(self, threat_info: dict):
        """Handle a threat detected by other layers."""
        # Application gateway can update its block lists based on threats
        threat_type = threat_info.get('type', '')
        source_ip = threat_info.get('source_ip')
        
        if 'domain' in threat_info:
            domain = threat_info['domain']
            self.blocked_domains.add(domain)
            self.logger.info(f"Added {domain} to blocked domains list")
            
    def is_healthy(self) -> bool:
        """Check if the layer is healthy."""
        return True
        
    def reload_config(self):
        """Reload configuration."""
        self.blocked_domains = set(self.config.get('blocked_domains', []))
        self.logger.info("Layer 2 configuration reloaded")


class HTTPInspector:
    """HTTP protocol inspector."""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.HTTPInspector")
        
    def inspect(self, http_data: dict, src_ip: str) -> dict:
        """Inspect HTTP request."""
        url = http_data.get('url', '')
        method = http_data.get('method', '')
        headers = http_data.get('headers', {})
        payload = http_data.get('payload', '')
        
        # Check for malicious URLs
        if self._is_malicious_url(url):
            return {'safe': False, 'reason': 'Malicious URL detected'}
            
        # Check for suspicious headers
        if self._has_suspicious_headers(headers):
            return {'safe': False, 'reason': 'Suspicious headers detected'}
            
        # Check payload for attacks
        if self._has_malicious_payload(payload):
            return {'safe': False, 'reason': 'Malicious payload detected'}
            
        return {'safe': True}
        
    def _is_malicious_url(self, url: str) -> bool:
        """Check if URL contains malicious patterns."""
        malicious_patterns = [
            r'\.\./',  # Directory traversal
            r'<script',  # XSS
            r'union.*select',  # SQL injection
            r'exec\(',  # Command execution
        ]
        
        for pattern in malicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
                
        return False
        
    def _has_suspicious_headers(self, headers: dict) -> bool:
        """Check for suspicious HTTP headers."""
        # Check User-Agent
        user_agent = headers.get('User-Agent', '').lower()
        suspicious_agents = ['sqlmap', 'nikto', 'burp', 'nmap']
        
        for agent in suspicious_agents:
            if agent in user_agent:
                return True
                
        return False
        
    def _has_malicious_payload(self, payload: str) -> bool:
        """Check payload for malicious content."""
        if not payload:
            return False
            
        # Check for common attack patterns
        attack_patterns = [
            r'<script[^>]*>',  # XSS
            r'union.*select',  # SQL injection
            r'exec\s*\(',  # Command execution
            r'eval\s*\(',  # Code evaluation
        ]
        
        for pattern in attack_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
                
        return False


class DNSInspector:
    """DNS protocol inspector."""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.DNSInspector")


class FTPInspector:
    """FTP protocol inspector."""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.FTPInspector")
        
    def inspect(self, ftp_data: dict, src_ip: str) -> dict:
        """Inspect FTP traffic."""
        # Basic FTP inspection
        return {'safe': True}


class SMTPInspector:
    """SMTP protocol inspector."""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.SMTPInspector")
        
    def inspect(self, smtp_data: dict, src_ip: str) -> dict:
        """Inspect SMTP traffic."""
        # Basic SMTP inspection
        return {'safe': True}
