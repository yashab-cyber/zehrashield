"""
Layer 1: Network Packet Filtering
Deep packet inspection with rate limiting and DDoS protection
Copyright © 2025 ZehraSec - Yashab Alam
"""

import logging
import threading
import time
import socket
import struct
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Any
import ipaddress

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available - packet inspection limited")

from core.logger import security_logger


class PacketFilterLayer:
    """Layer 1: Network Packet Filtering with deep packet inspection."""
    
    def __init__(self, config: dict, engine):
        """Initialize packet filter layer."""
        self.config = config
        self.engine = engine
        self.logger = logging.getLogger(__name__)
        
        # Rate limiting
        self.rate_limits = defaultdict(lambda: deque(maxlen=100))
        self.blocked_ips = set()
        self.temp_blocks = {}  # IP -> expiry time
        
        # Traffic analysis
        self.packet_stats = {
            'total_packets': 0,
            'blocked_packets': 0,
            'dropped_invalid': 0,
            'rate_limited': 0
        }
        
        # DDoS protection
        self.connection_tracker = defaultdict(int)
        self.syn_flood_tracker = defaultdict(list)
        
        # Packet capture
        self.capture_thread = None
        self.running = False
        
        # Port filtering
        self.blocked_ports = set(config.get('blocked_ports', []))
        self.allowed_ports = set(config.get('allowed_ports', []))
        
        self.logger.info("Layer 1 (Packet Filter) initialized")
        
    def start(self):
        """Start the packet filtering layer."""
        self.running = True
        
        # Start packet capture if available
        if SCAPY_AVAILABLE and not self.engine.config_manager.is_test_mode():
            self._start_packet_capture()
        else:
            self.logger.info("Running in test mode or Scapy unavailable - packet capture disabled")
            
        self.logger.info("✅ Layer 1 (Packet Filter) started")
        
    def stop(self):
        """Stop the packet filtering layer."""
        self.running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
            
        self.logger.info("Layer 1 (Packet Filter) stopped")
        
    def process_packet(self, packet_data: dict) -> dict:
        """Process a packet through Layer 1 filtering."""
        self.packet_stats['total_packets'] += 1
        
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        dst_port = packet_data.get('dst_port')
        protocol = packet_data.get('protocol', 'unknown')
        
        # Check if source IP is blocked
        if self._is_ip_blocked(src_ip):
            self.packet_stats['blocked_packets'] += 1
            return {'allow': False, 'reason': 'IP blocked'}
            
        # Check rate limiting
        if self._is_rate_limited(src_ip):
            self.packet_stats['rate_limited'] += 1
            return {'allow': False, 'reason': 'Rate limited'}
            
        # Check port filtering
        if dst_port and not self._is_port_allowed(dst_port):
            self.packet_stats['blocked_packets'] += 1
            security_logger.log_threat(
                "BLOCKED_PORT_ACCESS",
                src_ip,
                {'dst_port': dst_port, 'protocol': protocol}
            )
            return {'allow': False, 'reason': f'Port {dst_port} blocked'}
            
        # DDoS protection
        if self._detect_ddos(src_ip, packet_data):
            self._block_ip_temporary(src_ip, "DDoS detected", 300)  # 5 minutes
            return {'allow': False, 'reason': 'DDoS protection triggered'}
            
        # Packet validation
        if self.config.get('drop_invalid_packets', True):
            if not self._validate_packet(packet_data):
                self.packet_stats['dropped_invalid'] += 1
                return {'allow': False, 'reason': 'Invalid packet'}
                
        return {'allow': True, 'layer': 'packet_filter'}
        
    def _start_packet_capture(self):
        """Start packet capture thread."""
        def capture_packets():
            try:
                # Use raw socket for packet capture
                self.logger.info("Starting packet capture...")
                
                def packet_handler(packet):
                    if not self.running:
                        return
                        
                    try:
                        packet_data = self._parse_packet(packet)
                        if packet_data:
                            # Process through the engine
                            self.engine.process_packet(packet_data)
                    except Exception as e:
                        self.logger.debug(f"Error processing packet: {e}")
                
                # Start sniffing (requires root/admin privileges)
                sniff(prn=packet_handler, store=0, stop_filter=lambda x: not self.running)
                
            except Exception as e:
                self.logger.error(f"Packet capture error: {e}")
                
        self.capture_thread = threading.Thread(target=capture_packets, daemon=True)
        self.capture_thread.start()
        
    def _parse_packet(self, packet) -> dict:
        """Parse packet data into standardized format."""
        try:
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet)
            }
            
            if packet.haslayer(IP):
                packet_data.update({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'ttl': packet[IP].ttl,
                    'flags': packet[IP].flags if hasattr(packet[IP], 'flags') else 0
                })
                
            if packet.haslayer(TCP):
                packet_data.update({
                    'src_port': packet[TCP].sport,
                    'dst_port': packet[TCP].dport,
                    'tcp_flags': packet[TCP].flags,
                    'seq': packet[TCP].seq,
                    'ack': packet[TCP].ack
                })
                
            elif packet.haslayer(UDP):
                packet_data.update({
                    'src_port': packet[UDP].sport,
                    'dst_port': packet[UDP].dport
                })
                
            return packet_data
            
        except Exception as e:
            self.logger.debug(f"Error parsing packet: {e}")
            return None
            
    def _is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP address is blocked."""
        if not ip:
            return False
            
        # Check permanent blocks
        if ip in self.blocked_ips:
            return True
            
        # Check temporary blocks
        if ip in self.temp_blocks:
            if datetime.now() > self.temp_blocks[ip]:
                # Temporary block expired
                del self.temp_blocks[ip]
                return False
            return True
            
        return False
        
    def _is_rate_limited(self, ip: str) -> bool:
        """Check if an IP address should be rate limited."""
        if not ip:
            return False
            
        current_time = time.time()
        rate_limit = self.config.get('rate_limit_per_ip', 1000)
        
        # Add current request
        self.rate_limits[ip].append(current_time)
        
        # Count requests in the last minute
        minute_ago = current_time - 60
        recent_requests = [t for t in self.rate_limits[ip] if t > minute_ago]
        
        if len(recent_requests) > rate_limit:
            security_logger.log_threat(
                "RATE_LIMIT_EXCEEDED",
                ip,
                {'requests_per_minute': len(recent_requests), 'limit': rate_limit}
            )
            return True
            
        return False
        
    def _is_port_allowed(self, port: int) -> bool:
        """Check if a port is allowed."""
        if not port:
            return True
            
        # If there's an allowed ports list, check it first
        if self.allowed_ports:
            return port in self.allowed_ports
            
        # Otherwise, check if port is in blocked list
        return port not in self.blocked_ports
        
    def _detect_ddos(self, src_ip: str, packet_data: dict) -> bool:
        """Detect DDoS attacks."""
        if not self.config.get('enable_ddos_protection', True):
            return False
            
        current_time = time.time()
        
        # SYN flood detection
        if packet_data.get('tcp_flags') == 2:  # SYN flag
            self.syn_flood_tracker[src_ip].append(current_time)
            
            # Remove old entries (older than 10 seconds)
            self.syn_flood_tracker[src_ip] = [
                t for t in self.syn_flood_tracker[src_ip] 
                if current_time - t < 10
            ]
            
            # Check if too many SYN packets
            if len(self.syn_flood_tracker[src_ip]) > 50:
                security_logger.log_attack("SYN_FLOOD", src_ip)
                return True
                
        # Connection tracking
        self.connection_tracker[src_ip] += 1
        
        # Reset counter every minute
        if hasattr(self, '_last_reset') and current_time - self._last_reset > 60:
            self.connection_tracker.clear()
            self._last_reset = current_time
        elif not hasattr(self, '_last_reset'):
            self._last_reset = current_time
            
        # Check connection flood
        if self.connection_tracker[src_ip] > 1000:
            security_logger.log_attack("CONNECTION_FLOOD", src_ip)
            return True
            
        return False
        
    def _validate_packet(self, packet_data: dict) -> bool:
        """Validate packet structure and contents."""
        # Basic validation
        if not packet_data.get('src_ip') or not packet_data.get('dst_ip'):
            return False
            
        # IP address validation
        try:
            ipaddress.ip_address(packet_data['src_ip'])
            ipaddress.ip_address(packet_data['dst_ip'])
        except ValueError:
            return False
            
        # Port validation
        for port_key in ['src_port', 'dst_port']:
            port = packet_data.get(port_key)
            if port is not None and (port < 1 or port > 65535):
                return False
                
        return True
        
    def block_ip(self, ip: str, reason: str, duration: int = None):
        """Block an IP address."""
        if duration:
            # Temporary block
            expiry = datetime.now() + timedelta(seconds=duration)
            self.temp_blocks[ip] = expiry
            self.logger.info(f"Temporarily blocked {ip} for {duration}s: {reason}")
        else:
            # Permanent block
            self.blocked_ips.add(ip)
            self.logger.info(f"Permanently blocked {ip}: {reason}")
            
        security_logger.log_block(ip, reason)
        
    def _block_ip_temporary(self, ip: str, reason: str, duration: int):
        """Block an IP temporarily."""
        self.block_ip(ip, reason, duration)
        
    def unblock_ip(self, ip: str):
        """Unblock an IP address."""
        self.blocked_ips.discard(ip)
        self.temp_blocks.pop(ip, None)
        self.logger.info(f"Unblocked {ip}")
        
    def get_stats(self) -> dict:
        """Get layer statistics."""
        return {
            'packet_stats': self.packet_stats.copy(),
            'blocked_ips': len(self.blocked_ips),
            'temp_blocked_ips': len(self.temp_blocks),
            'active_connections': len(self.connection_tracker),
            'syn_flood_sources': len(self.syn_flood_tracker)
        }
        
    def handle_threat(self, threat_info: dict):
        """Handle a threat detected by other layers."""
        source_ip = threat_info.get('source_ip')
        if source_ip and threat_info.get('severity', 0) > 7:
            # High severity threats get IP blocked
            self.block_ip(source_ip, f"High severity threat: {threat_info.get('type')}", 3600)
            
    def is_healthy(self) -> bool:
        """Check if the layer is healthy."""
        return self.running
        
    def reload_config(self):
        """Reload configuration."""
        # Update port lists
        self.blocked_ports = set(self.config.get('blocked_ports', []))
        self.allowed_ports = set(self.config.get('allowed_ports', []))
        
        self.logger.info("Layer 1 configuration reloaded")
