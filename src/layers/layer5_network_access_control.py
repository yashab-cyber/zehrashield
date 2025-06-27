"""
ZehraShield Layer 5 - Network Access Control (NAC)
Copyright © 2025 ZehraSec - Yashab Alam

Implements Zero Trust architecture, device authentication, network segmentation,
and continuous validation of network access permissions.
"""

import logging
import threading
import time
import hashlib
import socket
import struct
import subprocess
import platform
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from scapy.all import ARP, Ether, srp, get_if_list, get_if_addr
import netifaces
import psutil
from core.logger import security_logger


@dataclass
class Device:
    """Represents a network device."""
    mac_address: str
    ip_address: str
    hostname: str
    first_seen: datetime
    last_seen: datetime
    trust_level: int  # 0-100
    device_type: str
    os_fingerprint: str
    authorized: bool
    risk_score: int  # 0-100


@dataclass
class NetworkSegment:
    """Represents a network segment with access policies."""
    segment_id: str
    network_cidr: str
    trust_level: int
    allowed_ports: List[int]
    allowed_protocols: List[str]
    isolation_level: str  # 'none', 'partial', 'full'


class NetworkAccessControlLayer:
    """Layer 5: Network Access Control with Zero Trust implementation."""
    
    def __init__(self, config):
        """Initialize the Network Access Control layer."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.running = False
        
        # Device management
        self.known_devices: Dict[str, Device] = {}
        self.authorized_devices: Set[str] = set()
        self.quarantined_devices: Set[str] = set()
        
        # Network segments
        self.network_segments: Dict[str, NetworkSegment] = {}
        self._initialize_segments()
        
        # Zero Trust settings
        self.zero_trust_enabled = config.get('zero_trust_mode', True)
        self.continuous_validation = config.get('continuous_validation', True)
        self.device_auth_required = config.get('device_authentication', True)
        
        # MAC filtering
        self.mac_filtering_enabled = config.get('mac_filtering', False)
        self.allowed_macs: Set[str] = set(config.get('allowed_macs', []))
        
        # 802.1X authentication
        self.dot1x_enabled = config.get('802_1x_authentication', False)
        
        # Monitoring and validation
        self.device_scan_thread = None
        self.validation_thread = None
        self.last_scan = datetime.now()
        
        # Statistics
        self.stats = {
            'devices_discovered': 0,
            'devices_authorized': 0,
            'devices_quarantined': 0,
            'access_violations': 0,
            'trust_score_updates': 0,
            'segment_violations': 0
        }
        
    def start(self):
        """Start the Network Access Control layer."""
        if self.running:
            return
            
        self.logger.info("Starting Network Access Control Layer...")
        self.running = True
        
        # Start device discovery
        self.device_scan_thread = threading.Thread(target=self._device_scanner, daemon=True)
        self.device_scan_thread.start()
        
        # Start continuous validation
        if self.continuous_validation:
            self.validation_thread = threading.Thread(target=self._continuous_validator, daemon=True)
            self.validation_thread.start()
        
        # Perform initial network scan
        self._discover_devices()
        
        self.logger.info("✅ Network Access Control Layer started")
        security_logger.info("NAC Layer activated with Zero Trust mode")
        
    def stop(self):
        """Stop the Network Access Control layer."""
        if not self.running:
            return
            
        self.logger.info("Stopping Network Access Control Layer...")
        self.running = False
        
        # Wait for threads to finish
        if self.device_scan_thread and self.device_scan_thread.is_alive():
            self.device_scan_thread.join(timeout=5)
            
        if self.validation_thread and self.validation_thread.is_alive():
            self.validation_thread.join(timeout=5)
        
        self.logger.info("Network Access Control Layer stopped")
        
    def _initialize_segments(self):
        """Initialize network segments based on configuration."""
        # Default segments
        segments_config = [
            {
                'segment_id': 'management',
                'network_cidr': '192.168.1.0/24',
                'trust_level': 90,
                'allowed_ports': [22, 443, 8443],
                'allowed_protocols': ['TCP', 'ICMP'],
                'isolation_level': 'partial'
            },
            {
                'segment_id': 'user_network',
                'network_cidr': '192.168.100.0/24',
                'trust_level': 50,
                'allowed_ports': [80, 443, 53],
                'allowed_protocols': ['TCP', 'UDP', 'ICMP'],
                'isolation_level': 'none'
            },
            {
                'segment_id': 'iot_devices',
                'network_cidr': '192.168.200.0/24',
                'trust_level': 30,
                'allowed_ports': [443],
                'allowed_protocols': ['TCP', 'UDP'],
                'isolation_level': 'full'
            },
            {
                'segment_id': 'quarantine',
                'network_cidr': '192.168.255.0/24',
                'trust_level': 0,
                'allowed_ports': [53, 80, 443],
                'allowed_protocols': ['TCP', 'UDP'],
                'isolation_level': 'full'
            }
        ]
        
        for segment_config in segments_config:
            segment = NetworkSegment(**segment_config)
            self.network_segments[segment.segment_id] = segment
            
        self.logger.info(f"Initialized {len(self.network_segments)} network segments")
        
    def _device_scanner(self):
        """Continuously scan for new devices on the network."""
        while self.running:
            try:
                if datetime.now() - self.last_scan > timedelta(minutes=5):
                    self._discover_devices()
                    self.last_scan = datetime.now()
                    
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in device scanner: {e}")
                time.sleep(60)
                
    def _discover_devices(self):
        """Discover devices on all network interfaces."""
        try:
            # Get all network interfaces
            interfaces = netifaces.interfaces()
            
            for interface in interfaces:
                if interface == 'lo':  # Skip loopback
                    continue
                    
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        ip_info = addrs[netifaces.AF_INET][0]
                        ip = ip_info.get('addr')
                        netmask = ip_info.get('netmask')
                        
                        if ip and netmask:
                            network = self._get_network_from_ip_mask(ip, netmask)
                            self._scan_network(network)
                            
                except Exception as e:
                    self.logger.warning(f"Error scanning interface {interface}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error in device discovery: {e}")
            
    def _get_network_from_ip_mask(self, ip: str, netmask: str) -> str:
        """Convert IP and netmask to network CIDR."""
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
            mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
            network_int = ip_int & mask_int
            
            # Calculate CIDR prefix
            cidr_prefix = bin(mask_int).count('1')
            
            network_ip = socket.inet_ntoa(struct.pack("!I", network_int))
            return f"{network_ip}/{cidr_prefix}"
            
        except Exception as e:
            self.logger.error(f"Error calculating network CIDR: {e}")
            return f"{ip}/24"  # Fallback
            
    def _scan_network(self, network: str):
        """Scan a network for devices using ARP."""
        try:
            # Create ARP request
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send request and receive response
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                
                # Get hostname
                hostname = self._get_hostname(ip)
                
                # Update or create device
                self._update_device(mac, ip, hostname)
                
        except Exception as e:
            self.logger.error(f"Error scanning network {network}: {e}")
            
    def _get_hostname(self, ip: str) -> str:
        """Get hostname for IP address."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
            
    def _update_device(self, mac: str, ip: str, hostname: str):
        """Update or create device information."""
        now = datetime.now()
        
        if mac in self.known_devices:
            device = self.known_devices[mac]
            device.ip_address = ip
            device.hostname = hostname
            device.last_seen = now
        else:
            # New device discovered
            device = Device(
                mac_address=mac,
                ip_address=ip,
                hostname=hostname,
                first_seen=now,
                last_seen=now,
                trust_level=0,  # Start with no trust
                device_type=self._identify_device_type(mac, hostname),
                os_fingerprint=self._fingerprint_os(ip),
                authorized=False,
                risk_score=50  # Default risk score
            )
            
            self.known_devices[mac] = device
            self.stats['devices_discovered'] += 1
            
            # Log new device discovery
            security_logger.warning(f"New device discovered: {mac} ({ip}) - {hostname}")
            
            # Apply zero trust policies
            if self.zero_trust_enabled:
                self._apply_zero_trust_policy(device)
                
    def _identify_device_type(self, mac: str, hostname: str) -> str:
        """Identify device type based on MAC address and hostname."""
        # OUI (Organizationally Unique Identifier) mapping
        oui = mac[:8].upper()
        
        oui_mapping = {
            '00:50:56': 'VMware Virtual',
            '08:00:27': 'VirtualBox Virtual',
            '00:0C:29': 'VMware Virtual',
            '00:1B:21': 'Apple Device',
            '00:25:9C': 'Apple Device',
            '28:CF:E9': 'Apple Device',
            'B8:27:EB': 'Raspberry Pi',
            'DC:A6:32': 'Raspberry Pi',
            '00:16:3E': 'Cisco Device',
            '00:1F:CA': 'Cisco Device',
        }
        
        if oui in oui_mapping:
            return oui_mapping[oui]
            
        # Check hostname patterns
        hostname_lower = hostname.lower()
        if any(pattern in hostname_lower for pattern in ['android', 'phone', 'mobile']):
            return 'Mobile Device'
        elif any(pattern in hostname_lower for pattern in ['printer', 'canon', 'hp', 'epson']):
            return 'Printer'
        elif any(pattern in hostname_lower for pattern in ['iot', 'camera', 'sensor']):
            return 'IoT Device'
        elif any(pattern in hostname_lower for pattern in ['server', 'srv']):
            return 'Server'
        elif any(pattern in hostname_lower for pattern in ['desktop', 'pc', 'workstation']):
            return 'Desktop'
        elif any(pattern in hostname_lower for pattern in ['laptop', 'notebook']):
            return 'Laptop'
        else:
            return 'Unknown'
            
    def _fingerprint_os(self, ip: str) -> str:
        """Perform OS fingerprinting using various techniques."""
        try:
            # Simple TTL-based fingerprinting
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', ip], 
                                      capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['ping', '-c', '1', ip], 
                                      capture_output=True, text=True, timeout=5)
                
            if result.returncode == 0:
                output = result.stdout
                
                # Parse TTL from ping output
                if 'ttl=' in output.lower():
                    ttl_line = [line for line in output.split('\n') if 'ttl=' in line.lower()][0]
                    ttl = int(ttl_line.split('ttl=')[1].split()[0])
                    
                    # Common TTL values for OS detection
                    if ttl >= 64 and ttl <= 64:
                        return 'Linux/Unix'
                    elif ttl >= 128 and ttl <= 128:
                        return 'Windows'
                    elif ttl >= 255 and ttl <= 255:
                        return 'Cisco/Network Device'
                    elif ttl >= 64 and ttl <= 127:
                        return 'Linux/Unix (modified)'
                    elif ttl >= 129 and ttl <= 254:
                        return 'Windows (modified)'
                        
        except Exception as e:
            self.logger.debug(f"OS fingerprinting failed for {ip}: {e}")
            
        return 'Unknown'
        
    def _apply_zero_trust_policy(self, device: Device):
        """Apply zero trust policies to a new device."""
        # New devices start with minimal trust
        device.trust_level = 10
        
        # Quarantine unknown devices by default
        if not device.authorized:
            self._quarantine_device(device.mac_address, "Unauthorized device - Zero Trust policy")
            
        # Apply device-specific policies
        if device.device_type == 'IoT Device':
            device.trust_level = max(0, device.trust_level - 20)
            device.risk_score += 30
        elif device.device_type in ['Server', 'Desktop']:
            device.trust_level += 10
            
        self.logger.info(f"Applied Zero Trust policy to {device.mac_address}: trust={device.trust_level}")
        
    def _quarantine_device(self, mac: str, reason: str):
        """Quarantine a device by moving it to isolation network."""
        if mac not in self.quarantined_devices:
            self.quarantined_devices.add(mac)
            self.stats['devices_quarantined'] += 1
            
            security_logger.warning(f"Device quarantined: {mac} - Reason: {reason}")
            
            # Here you would implement actual network isolation
            # This could involve VLAN changes, firewall rules, etc.
            self._implement_network_isolation(mac)
            
    def _implement_network_isolation(self, mac: str):
        """Implement actual network isolation for a device."""
        # This is where you'd implement the actual isolation mechanism
        # Examples:
        # 1. VLAN assignment
        # 2. Firewall rule creation
        # 3. Switch port configuration
        # 4. SDN controller integration
        
        self.logger.info(f"Implementing network isolation for device: {mac}")
        
        # For demonstration, we'll log the action
        # In a real implementation, this would use network management APIs
        
    def _continuous_validator(self):
        """Continuously validate device trust and access permissions."""
        while self.running:
            try:
                now = datetime.now()
                
                for mac, device in self.known_devices.items():
                    # Check if device has been inactive
                    if now - device.last_seen > timedelta(hours=24):
                        device.trust_level = max(0, device.trust_level - 10)
                        self.stats['trust_score_updates'] += 1
                        
                    # Validate device behavior
                    self._validate_device_behavior(device)
                    
                    # Check for policy violations
                    self._check_policy_violations(device)
                    
                time.sleep(300)  # Validate every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in continuous validation: {e}")
                time.sleep(300)
                
    def _validate_device_behavior(self, device: Device):
        """Validate device behavior patterns."""
        # This would implement behavioral analysis
        # Examples:
        # 1. Traffic pattern analysis
        # 2. Time-based access patterns
        # 3. Protocol usage validation
        # 4. Geolocation consistency
        
        # For now, implement basic trust decay
        if datetime.now() - device.last_seen > timedelta(hours=1):
            device.trust_level = max(0, device.trust_level - 1)
            
    def _check_policy_violations(self, device: Device):
        """Check for network access policy violations."""
        # Implement policy checking logic
        # Examples:
        # 1. Segment access violations
        # 2. Time-based access violations
        # 3. Protocol violations
        # 4. Geographic violations
        
        # Basic implementation
        if device.risk_score > 80 and device.mac_address not in self.quarantined_devices:
            self._quarantine_device(device.mac_address, f"High risk score: {device.risk_score}")
            
    def authorize_device(self, mac: str) -> bool:
        """Authorize a device for network access."""
        if mac in self.known_devices:
            device = self.known_devices[mac]
            device.authorized = True
            device.trust_level = min(100, device.trust_level + 50)
            
            if mac in self.quarantined_devices:
                self.quarantined_devices.remove(mac)
                
            self.authorized_devices.add(mac)
            self.stats['devices_authorized'] += 1
            
            security_logger.info(f"Device authorized: {mac}")
            return True
            
        return False
        
    def revoke_device_access(self, mac: str, reason: str = "Manual revocation"):
        """Revoke device access authorization."""
        if mac in self.authorized_devices:
            self.authorized_devices.remove(mac)
            
        if mac in self.known_devices:
            device = self.known_devices[mac]
            device.authorized = False
            device.trust_level = 0
            
        self._quarantine_device(mac, reason)
        security_logger.warning(f"Device access revoked: {mac} - Reason: {reason}")
        
    def get_device_info(self, mac: str) -> Optional[Dict]:
        """Get detailed information about a device."""
        if mac in self.known_devices:
            device = self.known_devices[mac]
            return {
                'mac_address': device.mac_address,
                'ip_address': device.ip_address,
                'hostname': device.hostname,
                'first_seen': device.first_seen.isoformat(),
                'last_seen': device.last_seen.isoformat(),
                'trust_level': device.trust_level,
                'device_type': device.device_type,
                'os_fingerprint': device.os_fingerprint,
                'authorized': device.authorized,
                'risk_score': device.risk_score,
                'quarantined': mac in self.quarantined_devices
            }
        return None
        
    def get_statistics(self) -> Dict:
        """Get Network Access Control statistics."""
        return {
            **self.stats,
            'total_known_devices': len(self.known_devices),
            'authorized_devices': len(self.authorized_devices),
            'quarantined_devices': len(self.quarantined_devices),
            'network_segments': len(self.network_segments),
            'zero_trust_enabled': self.zero_trust_enabled,
            'continuous_validation_enabled': self.continuous_validation
        }
        
    def is_healthy(self) -> bool:
        """Check if the NAC layer is healthy."""
        return (
            self.running and
            (self.device_scan_thread is None or self.device_scan_thread.is_alive()) and
            (self.validation_thread is None or self.validation_thread.is_alive())
        )
