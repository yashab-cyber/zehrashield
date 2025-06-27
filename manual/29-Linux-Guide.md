# 29. Linux Guide

![ZehraSec](https://img.shields.io/badge/🛡️-ZehraSec%20Linux-orange?style=for-the-badge&logo=linux)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## 🐧 **Overview**

This comprehensive guide covers the installation, configuration, and management of ZehraSec Advanced Firewall on Linux systems. It supports major distributions including Ubuntu, Debian, RHEL, CentOS, SUSE, Arch Linux, and more.

---

## 📋 **System Requirements**

### **Minimum Requirements**
- **OS**: Linux kernel 4.15+ (Ubuntu 18.04+, Debian 10+, RHEL 8+, CentOS 8+)
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 2 GB (4 GB recommended)
- **Storage**: 2 GB available space
- **Network**: Active network interface
- **Privileges**: Root or sudo access

### **Recommended Requirements**
- **OS**: Linux kernel 5.4+ (Ubuntu 20.04+, Debian 11+, RHEL 9+)
- **CPU**: 4+ cores, 2.5+ GHz
- **RAM**: 8 GB (16 GB for enterprise)
- **Storage**: 10 GB available space (SSD recommended)
- **Network**: Gigabit Ethernet
- **Additional**: iptables/netfilter, Python 3.8+

### **Supported Distributions**
- **Ubuntu**: 18.04 LTS, 20.04 LTS, 22.04 LTS, 24.04 LTS
- **Debian**: 10 (Buster), 11 (Bullseye), 12 (Bookworm)
- **RHEL/CentOS**: 8, 9, Stream
- **Fedora**: 35, 36, 37, 38, 39
- **SUSE**: openSUSE Leap 15.4+, SLES 15
- **Arch Linux**: Rolling release
- **Alpine Linux**: 3.15+

---

## 🚀 **Installation**

### **Method 1: Universal Installation Script (Recommended)**

```bash
# Download and run the universal installer
curl -fsSL https://raw.githubusercontent.com/yashab-cyber/ZehraSec-Advanced-Firewall/main/install.sh | sudo bash

# Or download first, then run
wget https://raw.githubusercontent.com/yashab-cyber/ZehraSec-Advanced-Firewall/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

### **Method 2: Distribution-Specific Installation**

#### **Ubuntu/Debian**
```bash
# Update package list
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv git curl wget \
    iptables-persistent netfilter-persistent build-essential \
    libssl-dev libffi-dev python3-dev

# Clone repository
git clone https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall.git
cd ZehraSec-Advanced-Firewall

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements_advanced.txt

# Install ZehraSec
sudo python3 setup.py install
```

#### **RHEL/CentOS/Fedora**
```bash
# Install EPEL repository (RHEL/CentOS)
sudo dnf install -y epel-release

# Update system
sudo dnf update -y

# Install dependencies
sudo dnf install -y python3 python3-pip python3-devel git curl wget \
    iptables iptables-services gcc openssl-devel libffi-devel

# Clone and install
git clone https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall.git
cd ZehraSec-Advanced-Firewall

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements_advanced.txt

# Install ZehraSec
sudo python3 setup.py install
```

#### **Arch Linux**
```bash
# Update system
sudo pacman -Syu

# Install dependencies
sudo pacman -S python python-pip git curl wget iptables \
    base-devel openssl libffi

# Install from AUR (if available)
yay -S zehrasec-advanced-firewall

# Or manual installation
git clone https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall.git
cd ZehraSec-Advanced-Firewall
makepkg -si
```

#### **SUSE/openSUSE**
```bash
# Update system
sudo zypper refresh && sudo zypper update

# Install dependencies
sudo zypper install -y python3 python3-pip python3-devel git curl wget \
    iptables gcc libopenssl-devel libffi-devel

# Clone and install
git clone https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall.git
cd ZehraSec-Advanced-Firewall

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements_advanced.txt
```

### **Method 3: Docker Installation**

```bash
# Pull ZehraSec Docker image
docker pull zehrasec/advanced-firewall:latest

# Run ZehraSec container
docker run -d \
    --name zehrasec-firewall \
    --privileged \
    --network host \
    -v /var/log/zehrasec:/logs \
    -v /etc/zehrasec:/config \
    -p 8443:8443 \
    -p 8080:8080 \
    zehrasec/advanced-firewall:latest

# Or using docker-compose
cat > docker-compose.yml << EOF
version: '3.8'
services:
  zehrasec:
    image: zehrasec/advanced-firewall:latest
    container_name: zehrasec-firewall
    privileged: true
    network_mode: host
    volumes:
      - /var/log/zehrasec:/logs
      - /etc/zehrasec:/config
      - /var/lib/zehrasec:/data
    ports:
      - "8443:8443"
      - "8080:8080"
      - "8081:8081"
    environment:
      - ZEHRASEC_CONFIG=/config/firewall_advanced.json
      - ZEHRASEC_LOG_LEVEL=INFO
    restart: unless-stopped
EOF

docker-compose up -d
```

---

## ⚙️ **Configuration**

### **System Configuration**

#### **Network Configuration**
```bash
# Configure network interfaces
sudo tee /etc/systemd/network/10-zehrasec.network << EOF
[Match]
Name=eth*

[Network]
DHCP=yes
IPForward=yes

[DHCPv4]
UseDNS=yes
UseRoutes=yes
EOF

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf

# Apply sysctl settings
sudo sysctl -p
```

#### **Firewall Integration**
```bash
# Configure iptables for ZehraSec
sudo tee /etc/iptables/rules.v4 << EOF
# ZehraSec Advanced Firewall Rules
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow loopback
-A INPUT -i lo -j ACCEPT

# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (modify port as needed)
-A INPUT -p tcp --dport 22 -j ACCEPT

# Allow ZehraSec web console
-A INPUT -p tcp --dport 8443 -j ACCEPT

# Allow ZehraSec API
-A INPUT -p tcp --dport 8080 -j ACCEPT

# Allow ZehraSec mobile API
-A INPUT -p tcp --dport 8081 -j ACCEPT

COMMIT
EOF

# Load iptables rules
sudo iptables-restore < /etc/iptables/rules.v4
sudo netfilter-persistent save
```

#### **SystemD Service Configuration**
```bash
# Create ZehraSec systemd service
sudo tee /etc/systemd/system/zehrasec.service << EOF
[Unit]
Description=ZehraSec Advanced Firewall
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/zehrasec
ExecStart=/opt/zehrasec/venv/bin/python /opt/zehrasec/main.py --config /etc/zehrasec/firewall_advanced.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zehrasec

# Security settings
NoNewPrivileges=false
PrivateDevices=false
ProtectSystem=false
ProtectHome=false

# Environment
Environment=PYTHONPATH=/opt/zehrasec
Environment=ZEHRASEC_CONFIG=/etc/zehrasec/firewall_advanced.json

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable zehrasec
sudo systemctl start zehrasec
```

### **Advanced Linux Configuration**

#### **Kernel Module Loading**
```bash
# Load required kernel modules
sudo tee /etc/modules-load.d/zehrasec.conf << EOF
# ZehraSec required modules
ip_tables
ip_conntrack
ip_conntrack_ftp
ip_conntrack_netbios_ns
ip_conntrack_irc
iptable_nat
ip_nat_ftp
EOF

# Load modules immediately
sudo modprobe ip_tables
sudo modprobe ip_conntrack
sudo modprobe iptable_nat
```

#### **Security Hardening**
```bash
# Configure kernel security parameters
sudo tee /etc/sysctl.d/99-zehrasec-security.conf << EOF
# Network security
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.icmp_echo_ignore_all=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0

# TCP security
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=15

# Memory protection
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=1

# File system security
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
EOF

# Apply security settings
sudo sysctl -p /etc/sysctl.d/99-zehrasec-security.conf
```

---

## 🔧 **Linux-Specific Features**

### **netfilter/iptables Integration**

```python
# linux_netfilter.py
import subprocess
import re
from typing import List, Dict, Optional

class NetfilterManager:
    def __init__(self):
        self.iptables_cmd = self._find_iptables()
        self.ip6tables_cmd = self._find_ip6tables()
    
    def _find_iptables(self):
        """Find iptables binary"""
        paths = ['/usr/sbin/iptables', '/sbin/iptables', '/usr/bin/iptables']
        for path in paths:
            try:
                subprocess.run([path, '--version'], check=True, capture_output=True)
                return path
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        raise RuntimeError("iptables not found")
    
    def _find_ip6tables(self):
        """Find ip6tables binary"""
        paths = ['/usr/sbin/ip6tables', '/sbin/ip6tables', '/usr/bin/ip6tables']
        for path in paths:
            try:
                subprocess.run([path, '--version'], check=True, capture_output=True)
                return path
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        return None
    
    def add_rule(self, chain: str, rule: str, ipv6: bool = False):
        """Add iptables rule"""
        try:
            cmd = self.ip6tables_cmd if ipv6 else self.iptables_cmd
            if not cmd:
                raise RuntimeError("Command not available")
            
            full_cmd = [cmd, '-A', chain] + rule.split()
            result = subprocess.run(full_cmd, check=True, capture_output=True, text=True)
            return {"success": True, "output": result.stdout}
            
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": e.stderr}
    
    def delete_rule(self, chain: str, rule: str, ipv6: bool = False):
        """Delete iptables rule"""
        try:
            cmd = self.ip6tables_cmd if ipv6 else self.iptables_cmd
            if not cmd:
                raise RuntimeError("Command not available")
            
            full_cmd = [cmd, '-D', chain] + rule.split()
            result = subprocess.run(full_cmd, check=True, capture_output=True, text=True)
            return {"success": True, "output": result.stdout}
            
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": e.stderr}
    
    def list_rules(self, chain: Optional[str] = None, ipv6: bool = False):
        """List iptables rules"""
        try:
            cmd = self.ip6tables_cmd if ipv6 else self.iptables_cmd
            if not cmd:
                raise RuntimeError("Command not available")
            
            full_cmd = [cmd, '-L']
            if chain:
                full_cmd.append(chain)
            full_cmd.extend(['-n', '-v', '--line-numbers'])
            
            result = subprocess.run(full_cmd, check=True, capture_output=True, text=True)
            return {"success": True, "rules": result.stdout}
            
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": e.stderr}
    
    def flush_chain(self, chain: str, ipv6: bool = False):
        """Flush iptables chain"""
        try:
            cmd = self.ip6tables_cmd if ipv6 else self.iptables_cmd
            if not cmd:
                raise RuntimeError("Command not available")
            
            full_cmd = [cmd, '-F', chain]
            result = subprocess.run(full_cmd, check=True, capture_output=True, text=True)
            return {"success": True, "output": result.stdout}
            
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": e.stderr}
    
    def create_custom_chain(self, chain_name: str, ipv6: bool = False):
        """Create custom iptables chain"""
        try:
            cmd = self.ip6tables_cmd if ipv6 else self.iptables_cmd
            if not cmd:
                raise RuntimeError("Command not available")
            
            full_cmd = [cmd, '-N', chain_name]
            result = subprocess.run(full_cmd, check=True, capture_output=True, text=True)
            return {"success": True, "output": result.stdout}
            
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": e.stderr}
    
    def save_rules(self):
        """Save current iptables rules"""
        try:
            # Try different save methods based on distribution
            save_commands = [
                ['iptables-save', '-f', '/etc/iptables/rules.v4'],
                ['service', 'iptables', 'save'],
                ['netfilter-persistent', 'save']
            ]
            
            for cmd in save_commands:
                try:
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    return {"success": True, "method": ' '.join(cmd), "output": result.stdout}
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
            
            return {"success": False, "error": "No save method available"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
```

### **Linux Network Monitoring**

```python
# linux_network_monitor.py
import psutil
import socket
import struct
from typing import Dict, List
import subprocess
import re

class LinuxNetworkMonitor:
    def __init__(self):
        self.interfaces = self.get_network_interfaces()
    
    def get_network_interfaces(self):
        """Get all network interfaces"""
        interfaces = {}
        
        try:
            # Get interface statistics
            net_io = psutil.net_io_counters(pernic=True)
            
            for interface, stats in net_io.items():
                # Get interface details
                addrs = psutil.net_if_addrs().get(interface, [])
                
                interfaces[interface] = {
                    'stats': {
                        'bytes_sent': stats.bytes_sent,
                        'bytes_recv': stats.bytes_recv,
                        'packets_sent': stats.packets_sent,
                        'packets_recv': stats.packets_recv,
                        'errin': stats.errin,
                        'errout': stats.errout,
                        'dropin': stats.dropin,
                        'dropout': stats.dropout
                    },
                    'addresses': []
                }
                
                # Add address information
                for addr in addrs:
                    addr_info = {
                        'family': addr.family.name,
                        'address': addr.address,
                        'netmask': getattr(addr, 'netmask', None),
                        'broadcast': getattr(addr, 'broadcast', None)
                    }
                    interfaces[interface]['addresses'].append(addr_info)
        
        except Exception as e:
            print(f"Error getting network interfaces: {e}")
        
        return interfaces
    
    def get_active_connections(self):
        """Get active network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                conn_info = {
                    'fd': conn.fd,
                    'family': conn.family.name if conn.family else 'unknown',
                    'type': conn.type.name if conn.type else 'unknown',
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'unknown',
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'unknown',
                    'status': conn.status,
                    'pid': conn.pid
                }
                
                # Get process information if available
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        conn_info['process'] = {
                            'name': process.name(),
                            'exe': process.exe(),
                            'cmdline': ' '.join(process.cmdline())
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        conn_info['process'] = {'name': 'unknown'}
                
                connections.append(conn_info)
        
        except Exception as e:
            print(f"Error getting connections: {e}")
        
        return connections
    
    def get_routing_table(self):
        """Get system routing table"""
        routes = []
        
        try:
            # Read /proc/net/route for IPv4 routes
            with open('/proc/net/route', 'r') as f:
                lines = f.readlines()[1:]  # Skip header
                
                for line in lines:
                    fields = line.strip().split('\t')
                    if len(fields) >= 8:
                        # Convert hex addresses to dotted decimal
                        dest = self._hex_to_ip(fields[1])
                        gateway = self._hex_to_ip(fields[2])
                        mask = self._hex_to_ip(fields[7])
                        
                        routes.append({
                            'interface': fields[0],
                            'destination': dest,
                            'gateway': gateway,
                            'flags': int(fields[3], 16),
                            'metric': int(fields[6]),
                            'mask': mask
                        })
        
        except Exception as e:
            print(f"Error reading routing table: {e}")
        
        return routes
    
    def _hex_to_ip(self, hex_ip):
        """Convert hex IP address to dotted decimal"""
        try:
            if hex_ip == '00000000':
                return '0.0.0.0'
            
            # Convert hex to integer and then to IP
            ip_int = int(hex_ip, 16)
            ip_bytes = struct.pack('<I', ip_int)
            return socket.inet_ntoa(ip_bytes)
        except:
            return hex_ip
    
    def get_arp_table(self):
        """Get ARP table"""
        arp_entries = []
        
        try:
            with open('/proc/net/arp', 'r') as f:
                lines = f.readlines()[1:]  # Skip header
                
                for line in lines:
                    fields = line.strip().split()
                    if len(fields) >= 6:
                        arp_entries.append({
                            'ip_address': fields[0],
                            'hw_type': fields[1],
                            'flags': fields[2],
                            'hw_address': fields[3],
                            'mask': fields[4],
                            'device': fields[5]
                        })
        
        except Exception as e:
            print(f"Error reading ARP table: {e}")
        
        return arp_entries
    
    def monitor_bandwidth(self, interval=1):
        """Monitor bandwidth usage"""
        try:
            # Get initial measurements
            initial_stats = psutil.net_io_counters(pernic=True)
            
            import time
            time.sleep(interval)
            
            # Get second measurements
            final_stats = psutil.net_io_counters(pernic=True)
            
            bandwidth_data = {}
            
            for interface in initial_stats:
                if interface in final_stats:
                    initial = initial_stats[interface]
                    final = final_stats[interface]
                    
                    bytes_sent_per_sec = (final.bytes_sent - initial.bytes_sent) / interval
                    bytes_recv_per_sec = (final.bytes_recv - initial.bytes_recv) / interval
                    
                    bandwidth_data[interface] = {
                        'upload_bps': bytes_sent_per_sec,
                        'download_bps': bytes_recv_per_sec,
                        'upload_mbps': bytes_sent_per_sec / (1024 * 1024),
                        'download_mbps': bytes_recv_per_sec / (1024 * 1024)
                    }
            
            return bandwidth_data
        
        except Exception as e:
            print(f"Error monitoring bandwidth: {e}")
            return {}
```

### **Linux Process Management**

```python
# linux_process_manager.py
import psutil
import signal
import os
from typing import List, Dict, Optional

class LinuxProcessManager:
    def __init__(self):
        self.processes = {}
    
    def get_process_list(self, filter_name: Optional[str] = None):
        """Get list of running processes"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_percent', 'cmdline']):
                try:
                    proc_info = proc.info
                    
                    # Filter by name if specified
                    if filter_name and filter_name.lower() not in proc_info['name'].lower():
                        continue
                    
                    # Get additional information
                    process_data = {
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'username': proc_info['username'],
                        'memory_mb': proc_info['memory_info'].rss / (1024 * 1024) if proc_info['memory_info'] else 0,
                        'cpu_percent': proc_info['cpu_percent'],
                        'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                        'status': proc.status(),
                        'create_time': proc.create_time(),
                        'num_threads': proc.num_threads()
                    }
                    
                    # Get network connections for process
                    try:
                        connections = proc.connections()
                        process_data['connections'] = len(connections)
                        process_data['listening_ports'] = [
                            conn.laddr.port for conn in connections 
                            if conn.status == 'LISTEN' and conn.laddr
                        ]
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        process_data['connections'] = 0
                        process_data['listening_ports'] = []
                    
                    processes.append(process_data)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            print(f"Error getting process list: {e}")
        
        return processes
    
    def kill_process(self, pid: int, force: bool = False):
        """Kill a process by PID"""
        try:
            process = psutil.Process(pid)
            
            if force:
                process.kill()  # SIGKILL
            else:
                process.terminate()  # SIGTERM
            
            # Wait for process to terminate
            process.wait(timeout=5)
            
            return {"success": True, "message": f"Process {pid} terminated"}
        
        except psutil.NoSuchProcess:
            return {"success": False, "error": f"Process {pid} not found"}
        except psutil.AccessDenied:
            return {"success": False, "error": f"Access denied to process {pid}"}
        except psutil.TimeoutExpired:
            return {"success": False, "error": f"Process {pid} did not terminate within timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_suspicious_processes(self):
        """Identify potentially suspicious processes"""
        suspicious = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
                try:
                    proc_info = proc.info
                    suspicion_score = 0
                    reasons = []
                    
                    # Check for suspicious characteristics
                    name = proc_info['name'].lower()
                    exe = proc_info['exe'] or ''
                    cmdline = ' '.join(proc_info['cmdline'] or []).lower()
                    
                    # Suspicious names
                    suspicious_names = [
                        'cryptominer', 'miner', 'xmrig', 'malware', 'backdoor',
                        'rootkit', 'keylogger', 'trojan', 'botnet'
                    ]
                    
                    for suspicious_name in suspicious_names:
                        if suspicious_name in name or suspicious_name in cmdline:
                            suspicion_score += 5
                            reasons.append(f"Suspicious name: {suspicious_name}")
                    
                    # Running from suspicious locations
                    suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/']
                    for path in suspicious_paths:
                        if path in exe:
                            suspicion_score += 3
                            reasons.append(f"Running from suspicious path: {path}")
                    
                    # High CPU usage
                    try:
                        cpu_percent = proc.cpu_percent(interval=1)
                        if cpu_percent > 80:
                            suspicion_score += 2
                            reasons.append(f"High CPU usage: {cpu_percent}%")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                    # Many network connections
                    try:
                        connections = proc.connections()
                        if len(connections) > 50:
                            suspicion_score += 2
                            reasons.append(f"Many network connections: {len(connections)}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                    # Running as root with suspicious characteristics
                    if proc_info['username'] == 'root' and suspicion_score > 0:
                        suspicion_score += 1
                        reasons.append("Running as root")
                    
                    # Add to suspicious list if score is high enough
                    if suspicion_score >= 3:
                        suspicious.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'exe': exe,
                            'cmdline': ' '.join(proc_info['cmdline'] or []),
                            'username': proc_info['username'],
                            'suspicion_score': suspicion_score,
                            'reasons': reasons
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            print(f"Error checking for suspicious processes: {e}")
        
        return suspicious
    
    def monitor_process_resources(self, pid: int, duration: int = 60):
        """Monitor process resource usage over time"""
        try:
            process = psutil.Process(pid)
            measurements = []
            
            import time
            start_time = time.time()
            
            while time.time() - start_time < duration:
                try:
                    measurement = {
                        'timestamp': time.time(),
                        'cpu_percent': process.cpu_percent(),
                        'memory_mb': process.memory_info().rss / (1024 * 1024),
                        'num_threads': process.num_threads(),
                        'connections': len(process.connections())
                    }
                    measurements.append(measurement)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
                
                time.sleep(5)  # Sample every 5 seconds
            
            # Calculate statistics
            if measurements:
                cpu_values = [m['cpu_percent'] for m in measurements]
                memory_values = [m['memory_mb'] for m in measurements]
                
                stats = {
                    'pid': pid,
                    'measurements': measurements,
                    'statistics': {
                        'avg_cpu': sum(cpu_values) / len(cpu_values),
                        'max_cpu': max(cpu_values),
                        'avg_memory': sum(memory_values) / len(memory_values),
                        'max_memory': max(memory_values),
                        'duration': duration,
                        'samples': len(measurements)
                    }
                }
                
                return stats
            else:
                return {"error": "No measurements collected"}
        
        except psutil.NoSuchProcess:
            return {"error": f"Process {pid} not found"}
        except Exception as e:
            return {"error": str(e)}
```

---

## 🔐 **Security Hardening**

### **SELinux/AppArmor Integration**

```bash
# SELinux configuration for ZehraSec
# Create SELinux policy module

cat > zehrasec.te << EOF
module zehrasec 1.0;

require {
    type unconfined_t;
    type admin_home_t;
    type http_port_t;
    type netlink_socket;
    class tcp_socket { bind listen accept };
    class netlink_socket { create bind read write };
    class capability { net_admin net_raw };
}

# Allow ZehraSec to bind to network ports
allow unconfined_t http_port_t:tcp_socket { bind listen accept };

# Allow network administration capabilities
allow unconfined_t self:capability { net_admin net_raw };

# Allow netlink socket operations
allow unconfined_t self:netlink_socket { create bind read write };
EOF

# Compile and install SELinux module
checkmodule -M -m -o zehrasec.mod zehrasec.te
semodule_package -o zehrasec.pp -m zehrasec.mod
sudo semodule -i zehrasec.pp

# AppArmor profile for ZehraSec
sudo tee /etc/apparmor.d/zehrasec << EOF
#include <tunables/global>

/opt/zehrasec/venv/bin/python {
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/nameservice>

  capability net_admin,
  capability net_raw,
  capability dac_override,

  network inet stream,
  network inet dgram,
  network netlink raw,

  /opt/zehrasec/** r,
  /opt/zehrasec/venv/bin/python ix,
  /etc/zehrasec/** r,
  /var/log/zehrasec/** rw,
  /var/lib/zehrasec/** rw,
  /proc/net/** r,
  /sys/class/net/** r,

  # Allow iptables execution
  /usr/sbin/iptables ix,
  /sbin/iptables ix,
}
EOF

# Load AppArmor profile
sudo apparmor_parser -r /etc/apparmor.d/zehrasec
```

### **Systemd Hardening**

```bash
# Enhanced systemd service with security features
sudo tee /etc/systemd/system/zehrasec-hardened.service << EOF
[Unit]
Description=ZehraSec Advanced Firewall (Hardened)
After=network.target
Wants=network.target

[Service]
Type=simple
User=zehrasec
Group=zehrasec
WorkingDirectory=/opt/zehrasec
ExecStart=/opt/zehrasec/venv/bin/python /opt/zehrasec/main.py --config /etc/zehrasec/firewall_advanced.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=false
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/log/zehrasec /var/lib/zehrasec /etc/zehrasec
ProtectKernelTunables=false
ProtectKernelModules=false
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Capabilities
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
```

---

## 🛠️ **Troubleshooting**

### **Common Linux Issues**

#### **Permission Issues**
```bash
# Fix file permissions
sudo chown -R zehrasec:zehrasec /opt/zehrasec
sudo chmod -R 755 /opt/zehrasec
sudo chmod -R 644 /etc/zehrasec/*
sudo chmod 600 /etc/zehrasec/ssl/*

# Fix log permissions
sudo mkdir -p /var/log/zehrasec
sudo chown zehrasec:zehrasec /var/log/zehrasec
sudo chmod 755 /var/log/zehrasec
```

#### **Network Interface Issues**
```bash
# Check network interfaces
ip addr show
ip link show

# Bring interface up
sudo ip link set eth0 up

# Check routing
ip route show
netstat -rn
```

#### **Service Issues**
```bash
# Check service status
sudo systemctl status zehrasec

# View service logs
sudo journalctl -u zehrasec -f

# Check for port conflicts
sudo netstat -tlnp | grep :8443
sudo ss -tlnp | grep :8443
```

### **Diagnostic Script**

```bash
#!/bin/bash
# ZehraSec Linux Diagnostic Script

echo "=== ZehraSec Linux Diagnostic ==="

# Check system information
echo "--- System Information ---"
echo "OS: $(lsb_release -d 2>/dev/null | cut -d: -f2- | sed 's/^\s*//' || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "Uptime: $(uptime -p)"

# Check ZehraSec installation
echo -e "\n--- ZehraSec Installation ---"
if [ -d "/opt/zehrasec" ]; then
    echo "✓ Installation directory found"
else
    echo "✗ Installation directory not found"
fi

# Check Python
echo -e "\n--- Python Environment ---"
if command -v python3 &> /dev/null; then
    echo "✓ Python3: $(python3 --version)"
else
    echo "✗ Python3 not found"
fi

# Check virtual environment
if [ -f "/opt/zehrasec/venv/bin/python" ]; then
    echo "✓ Virtual environment found"
    echo "  Python: $(/opt/zehrasec/venv/bin/python --version)"
else
    echo "✗ Virtual environment not found"
fi

# Check dependencies
echo -e "\n--- Dependencies ---"
dependencies=("iptables" "netstat" "ss" "curl" "wget")
for dep in "${dependencies[@]}"; do
    if command -v "$dep" &> /dev/null; then
        echo "✓ $dep found"
    else
        echo "✗ $dep not found"
    fi
done

# Check systemd service
echo -e "\n--- Service Status ---"
if systemctl is-active --quiet zehrasec; then
    echo "✓ ZehraSec service is running"
    echo "  Status: $(systemctl is-active zehrasec)"
    echo "  Enabled: $(systemctl is-enabled zehrasec)"
else
    echo "✗ ZehraSec service is not running"
    echo "  Status: $(systemctl is-active zehrasec)"
    echo "  Last failure: $(systemctl show zehrasec -p ExecMainStatus --value)"
fi

# Check network connectivity
echo -e "\n--- Network Connectivity ---"
if curl -k -s https://localhost:8443 > /dev/null; then
    echo "✓ Web console accessible"
else
    echo "✗ Web console not accessible"
fi

if curl -s http://localhost:8080/api/status > /dev/null; then
    echo "✓ API accessible"
else
    echo "✗ API not accessible"
fi

# Check firewall rules
echo -e "\n--- Firewall Rules ---"
if iptables -L | grep -q "8443\|8080\|8081"; then
    echo "✓ ZehraSec firewall rules found"
else
    echo "✗ ZehraSec firewall rules not found"
fi

# Check logs
echo -e "\n--- Log Files ---"
log_files=("/var/log/zehrasec/zehrasec.log" "/var/log/zehrasec/security.log")
for log_file in "${log_files[@]}"; do
    if [ -f "$log_file" ]; then
        echo "✓ Found: $log_file ($(wc -l < "$log_file") lines)"
    else
        echo "✗ Missing: $log_file"
    fi
done

# Check configuration
echo -e "\n--- Configuration ---"
config_files=("/etc/zehrasec/firewall_advanced.json" "/etc/zehrasec/firewall.json")
for config_file in "${config_files[@]}"; do
    if [ -f "$config_file" ]; then
        if python3 -m json.tool "$config_file" > /dev/null 2>&1; then
            echo "✓ Valid: $config_file"
        else
            echo "✗ Invalid JSON: $config_file"
        fi
    else
        echo "✗ Missing: $config_file"
    fi
done

echo -e "\n=== Diagnostic Complete ==="
```

---

## 📊 **Performance Optimization**

### **Linux Performance Tuning**

```bash
# Optimize Linux for ZehraSec performance
# Network performance tuning
echo 'net.core.rmem_default = 262144' | sudo tee -a /etc/sysctl.conf
echo 'net.core.rmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_default = 262144' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 30000' | sudo tee -a /etc/sysctl.conf
echo 'net.core.netdev_budget = 600' | sudo tee -a /etc/sysctl.conf

# TCP optimization
echo 'net.ipv4.tcp_rmem = 4096 65536 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_congestion_control = bbr' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_fastopen = 3' | sudo tee -a /etc/sysctl.conf

# Apply settings
sudo sysctl -p

# CPU governor optimization
echo 'performance' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# I/O scheduler optimization
echo 'deadline' | sudo tee /sys/block/*/queue/scheduler

# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups
sudo systemctl disable avahi-daemon
```

---

## 📋 **Best Practices**

### **Linux Security Best Practices**
1. **Keep System Updated**: Regular security updates
2. **Use Firewall**: Configure iptables/nftables properly
3. **Disable Unused Services**: Reduce attack surface
4. **Strong Authentication**: SSH keys, 2FA
5. **Log Monitoring**: Centralized logging and monitoring
6. **File Permissions**: Proper file and directory permissions
7. **SELinux/AppArmor**: Enable mandatory access controls

### **Performance Best Practices**
1. **Resource Monitoring**: Monitor CPU, memory, disk, network
2. **Kernel Parameters**: Optimize network and security parameters
3. **Process Management**: Manage ZehraSec process priorities
4. **Log Rotation**: Implement proper log rotation
5. **Disk I/O**: Use SSDs for better performance

---

## 📞 **Support**

### **Linux-Specific Support**
- **Email**: linux-support@zehrasec.com
- **Documentation**: https://docs.zehrasec.com/linux
- **Community**: https://community.zehrasec.com/linux
- **IRC**: #zehrasec on freenode

### **Distribution Support**
- **Ubuntu/Debian**: ubuntu-support@zehrasec.com
- **RHEL/CentOS**: rhel-support@zehrasec.com
- **SUSE**: suse-support@zehrasec.com
- **Arch**: arch-support@zehrasec.com

---

*ZehraSec Advanced Firewall - Linux Platform Guide*
