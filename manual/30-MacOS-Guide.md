# 30. MacOS Guide

![ZehraSec](https://img.shields.io/badge/🛡️-ZehraSec%20macOS-black?style=for-the-badge&logo=apple)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## 🍎 **Overview**

This comprehensive guide provides detailed instructions for installing, configuring, and managing ZehraSec Advanced Firewall on macOS systems. It covers macOS Monterey, Ventura, Sonoma, and the latest versions with platform-specific configurations and Apple security integration.

---

## 📋 **System Requirements**

### **Minimum Requirements**
- **OS**: macOS 12.0 (Monterey) or later
- **CPU**: Intel Core i5 or Apple M1 chip
- **RAM**: 8 GB (16 GB recommended)
- **Storage**: 5 GB available space
- **Network**: Active network connection
- **Privileges**: Administrator access

### **Recommended Requirements**
- **OS**: macOS 14.0 (Sonoma) or later
- **CPU**: Intel Core i7 or Apple M2 chip
- **RAM**: 16 GB (32 GB for enterprise)
- **Storage**: 20 GB available space (SSD)
- **Network**: Gigabit Ethernet or Wi-Fi 6
- **Additional**: Touch ID or Face ID for enhanced security

### **Supported macOS Versions**
- **macOS Monterey**: 12.0 - 12.7
- **macOS Ventura**: 13.0 - 13.6
- **macOS Sonoma**: 14.0 - 14.5
- **macOS Sequoia**: 15.0+

---

## 🚀 **Installation**

### **Method 1: Homebrew Installation (Recommended)**

1. **Install Homebrew** (if not already installed)
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Add ZehraSec Tap**
   ```bash
   brew tap zehrasec/advanced-firewall
   ```

3. **Install ZehraSec**
   ```bash
   brew install zehrasec-advanced-firewall
   ```

4. **Start ZehraSec Service**
   ```bash
   brew services start zehrasec-advanced-firewall
   ```

### **Method 2: macOS Installer Package**

1. **Download Installer**
   ```bash
   curl -L -o ZehraSec-Advanced-Firewall.pkg \
     "https://releases.zehrasec.com/macos/ZehraSec-Advanced-Firewall-latest.pkg"
   ```

2. **Install Package**
   ```bash
   sudo installer -pkg ZehraSec-Advanced-Firewall.pkg -target /
   ```

3. **Verify Installation**
   ```bash
   zehrasec --version
   ```

### **Method 3: Manual Installation**

1. **Install Prerequisites**
   ```bash
   # Install Xcode Command Line Tools
   xcode-select --install
   
   # Install Python 3.11 or later
   brew install python@3.11
   
   # Install required system libraries
   brew install openssl libffi
   ```

2. **Download and Extract ZehraSec**
   ```bash
   curl -L -o zehrasec-main.zip \
     "https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall/archive/refs/heads/main.zip"
   
   unzip zehrasec-main.zip
   cd ZehraSec-Advanced-Firewall-main
   ```

3. **Create Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

4. **Install Dependencies**
   ```bash
   pip install -r requirements_advanced.txt
   ```

5. **Configure Installation**
   ```bash
   sudo mkdir -p /usr/local/zehrasec
   sudo cp -r . /usr/local/zehrasec/
   sudo chown -R $(whoami):admin /usr/local/zehrasec
   ```

---

## ⚙️ **Configuration**

### **macOS Firewall Integration**

ZehraSec integrates with the built-in macOS firewall (pfctl) for comprehensive protection:

```bash
# Enable macOS firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

# Configure pfctl rules for ZehraSec
sudo tee /etc/pf.anchors/zehrasec << 'EOF'
# ZehraSec Advanced Firewall Rules
# Allow ZehraSec web console
pass in proto tcp from any to any port 8443

# Allow ZehraSec API
pass in proto tcp from any to any port 8080

# Allow ZehraSec mobile API
pass in proto tcp from any to any port 8081

# Block suspicious traffic
block in quick from <zehrasec_blocklist> to any
block out quick from any to <zehrasec_blocklist>

# Rate limiting
pass in proto tcp from any to any port 80 keep state (max-src-conn 100, max-src-conn-rate 50/10)
pass in proto tcp from any to any port 443 keep state (max-src-conn 100, max-src-conn-rate 50/10)
EOF

# Add anchor to main pf.conf
echo "anchor \"zehrasec\"" | sudo tee -a /etc/pf.conf
echo "load anchor \"zehrasec\" from \"/etc/pf.anchors/zehrasec\"" | sudo tee -a /etc/pf.conf

# Load pf rules
sudo pfctl -f /etc/pf.conf
```

### **LaunchDaemon Configuration**

Create a LaunchDaemon for automatic startup:

```bash
sudo tee /Library/LaunchDaemons/com.zehrasec.advanced-firewall.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.zehrasec.advanced-firewall</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/zehrasec/venv/bin/python</string>
        <string>/usr/local/zehrasec/main.py</string>
        <string>--config</string>
        <string>/usr/local/zehrasec/config/firewall_advanced.json</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/zehrasec/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/zehrasec/stderr.log</string>
    <key>WorkingDirectory</key>
    <string>/usr/local/zehrasec</string>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/zehrasec/venv/bin:/usr/local/bin:/bin:/usr/bin</string>
    </dict>
</dict>
</plist>
EOF

# Set permissions
sudo chown root:wheel /Library/LaunchDaemons/com.zehrasec.advanced-firewall.plist
sudo chmod 644 /Library/LaunchDaemons/com.zehrasec.advanced-firewall.plist

# Load and start the daemon
sudo launchctl load /Library/LaunchDaemons/com.zehrasec.advanced-firewall.plist
sudo launchctl start com.zehrasec.advanced-firewall
```

### **Keychain Integration**

Integrate with macOS Keychain for secure credential storage:

```python
# macos_keychain.py
import keyring
import subprocess
import json
from typing import Optional, Dict

class MacOSKeychain:
    def __init__(self, service_name="ZehraSec"):
        self.service_name = service_name
    
    def store_credential(self, account: str, password: str) -> bool:
        """Store credential in macOS Keychain"""
        try:
            keyring.set_password(self.service_name, account, password)
            return True
        except Exception as e:
            print(f"Failed to store credential: {e}")
            return False
    
    def get_credential(self, account: str) -> Optional[str]:
        """Retrieve credential from macOS Keychain"""
        try:
            return keyring.get_password(self.service_name, account)
        except Exception as e:
            print(f"Failed to retrieve credential: {e}")
            return None
    
    def delete_credential(self, account: str) -> bool:
        """Delete credential from macOS Keychain"""
        try:
            keyring.delete_password(self.service_name, account)
            return True
        except Exception as e:
            print(f"Failed to delete credential: {e}")
            return False
    
    def store_certificate(self, cert_path: str, keychain_name: str = "login") -> bool:
        """Store certificate in macOS Keychain"""
        try:
            cmd = [
                "security", "import", cert_path,
                "-k", f"{keychain_name}.keychain",
                "-T", "/usr/local/zehrasec/venv/bin/python"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Failed to store certificate: {e}")
            return False
    
    def get_certificates(self) -> list:
        """Get list of certificates from Keychain"""
        try:
            cmd = ["security", "find-certificate", "-a", "-p"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse certificate output
                certificates = []
                cert_lines = result.stdout.split('\n')
                current_cert = []
                
                for line in cert_lines:
                    if line.startswith('-----BEGIN CERTIFICATE-----'):
                        current_cert = [line]
                    elif line.startswith('-----END CERTIFICATE-----'):
                        current_cert.append(line)
                        certificates.append('\n'.join(current_cert))
                        current_cert = []
                    elif current_cert:
                        current_cert.append(line)
                
                return certificates
            else:
                return []
        except Exception as e:
            print(f"Failed to get certificates: {e}")
            return []

# Usage example
keychain = MacOSKeychain()
keychain.store_credential("zehrasec_admin", "secure_password")
password = keychain.get_credential("zehrasec_admin")
```

---

## 🔧 **macOS-Specific Features**

### **System Integration Framework**

```python
# macos_integration.py
import objc
from Foundation import NSBundle, NSUserNotification, NSUserNotificationCenter
from SystemConfiguration import SCDynamicStoreCreate, SCDynamicStoreCopyValue
import subprocess
import json

class MacOSIntegration:
    def __init__(self):
        self.notification_center = NSUserNotificationCenter.defaultUserNotificationCenter()
        self.dynamic_store = SCDynamicStoreCreate(None, "ZehraSec", None, None)
    
    def send_notification(self, title: str, message: str, sound: bool = True):
        """Send macOS notification"""
        try:
            notification = NSUserNotification.alloc().init()
            notification.setTitle_(title)
            notification.setInformativeText_(message)
            
            if sound:
                notification.setSoundName_("NSUserNotificationDefaultSoundName")
            
            self.notification_center.deliverNotification_(notification)
            return True
        except Exception as e:
            print(f"Failed to send notification: {e}")
            return False
    
    def get_network_interfaces(self) -> dict:
        """Get network interface information using SystemConfiguration"""
        try:
            interfaces = {}
            
            # Get network interface list
            interface_list = SCDynamicStoreCopyValue(
                self.dynamic_store,
                "State:/Network/Interface"
            )
            
            if interface_list:
                for interface in interface_list:
                    interface_key = f"State:/Network/Interface/{interface}/IPv4"
                    interface_info = SCDynamicStoreCopyValue(
                        self.dynamic_store,
                        interface_key
                    )
                    
                    if interface_info:
                        interfaces[interface] = {
                            'addresses': interface_info.get('Addresses', []),
                            'subnet_masks': interface_info.get('SubnetMasks', []),
                            'router': interface_info.get('Router', ''),
                            'interface_name': interface_info.get('InterfaceName', '')
                        }
            
            return interfaces
        except Exception as e:
            print(f"Failed to get network interfaces: {e}")
            return {}
    
    def get_system_info(self) -> dict:
        """Get macOS system information"""
        try:
            # Get system version
            cmd = ["sw_vers", "-productVersion"]
            version_result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Get hardware info
            cmd = ["system_profiler", "SPHardwareDataType", "-json"]
            hardware_result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Get network info
            cmd = ["system_profiler", "SPNetworkDataType", "-json"]
            network_result = subprocess.run(cmd, capture_output=True, text=True)
            
            system_info = {
                'os_version': version_result.stdout.strip() if version_result.returncode == 0 else 'Unknown',
                'hardware': {},
                'network': {}
            }
            
            # Parse hardware info
            if hardware_result.returncode == 0:
                try:
                    hardware_data = json.loads(hardware_result.stdout)
                    if 'SPHardwareDataType' in hardware_data:
                        hw_info = hardware_data['SPHardwareDataType'][0]
                        system_info['hardware'] = {
                            'model': hw_info.get('machine_model', 'Unknown'),
                            'processor': hw_info.get('cpu_type', 'Unknown'),
                            'memory': hw_info.get('physical_memory', 'Unknown'),
                            'serial': hw_info.get('serial_number', 'Unknown'),
                            'uuid': hw_info.get('platform_UUID', 'Unknown')
                        }
                except json.JSONDecodeError:
                    pass
            
            # Parse network info
            if network_result.returncode == 0:
                try:
                    network_data = json.loads(network_result.stdout)
                    if 'SPNetworkDataType' in network_data:
                        system_info['network'] = network_data['SPNetworkDataType']
                except json.JSONDecodeError:
                    pass
            
            return system_info
        except Exception as e:
            print(f"Failed to get system info: {e}")
            return {}
    
    def is_sip_enabled(self) -> bool:
        """Check if System Integrity Protection is enabled"""
        try:
            cmd = ["csrutil", "status"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return "enabled" in result.stdout.lower()
            else:
                return True  # Assume enabled if we can't check
        except Exception as e:
            print(f"Failed to check SIP status: {e}")
            return True
    
    def get_security_events(self) -> list:
        """Get security events from macOS logs"""
        try:
            # Use log command to get security-related events
            cmd = [
                "log", "show",
                "--predicate", "subsystem == 'com.apple.securityd' OR subsystem == 'com.apple.security'",
                "--style", "json",
                "--last", "1h"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                try:
                    events = []
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            try:
                                event = json.loads(line)
                                events.append(event)
                            except json.JSONDecodeError:
                                continue
                    return events
                except Exception:
                    return []
            else:
                return []
        except Exception as e:
            print(f"Failed to get security events: {e}")
            return []
```

### **pfctl Integration**

```python
# macos_pfctl.py
import subprocess
import re
from typing import List, Dict, Optional

class MacOSPfctl:
    def __init__(self):
        self.pfctl_path = "/usr/sbin/pfctl"
    
    def enable_pf(self) -> bool:
        """Enable packet filter (pf)"""
        try:
            cmd = [self.pfctl_path, "-e"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Failed to enable pf: {e}")
            return False
    
    def disable_pf(self) -> bool:
        """Disable packet filter (pf)"""
        try:
            cmd = [self.pfctl_path, "-d"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Failed to disable pf: {e}")
            return False
    
    def load_rules(self, rules_file: str) -> bool:
        """Load pf rules from file"""
        try:
            cmd = [self.pfctl_path, "-f", rules_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Failed to load rules: {e}")
            return False
    
    def show_rules(self) -> str:
        """Show current pf rules"""
        try:
            cmd = [self.pfctl_path, "-s", "rules"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return ""
        except Exception as e:
            print(f"Failed to show rules: {e}")
            return ""
    
    def show_states(self) -> str:
        """Show current pf states"""
        try:
            cmd = [self.pfctl_path, "-s", "states"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return ""
        except Exception as e:
            print(f"Failed to show states: {e}")
            return ""
    
    def show_info(self) -> dict:
        """Show pf information and statistics"""
        try:
            cmd = [self.pfctl_path, "-s", "info"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                info = {}
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        info[key.strip()] = value.strip()
                return info
            else:
                return {}
        except Exception as e:
            print(f"Failed to show info: {e}")
            return {}
    
    def flush_states(self) -> bool:
        """Flush all pf states"""
        try:
            cmd = [self.pfctl_path, "-F", "states"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Failed to flush states: {e}")
            return False
    
    def add_table_entry(self, table_name: str, address: str) -> bool:
        """Add entry to pf table"""
        try:
            cmd = [self.pfctl_path, "-t", table_name, "-T", "add", address]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Failed to add table entry: {e}")
            return False
    
    def delete_table_entry(self, table_name: str, address: str) -> bool:
        """Delete entry from pf table"""
        try:
            cmd = [self.pfctl_path, "-t", table_name, "-T", "delete", address]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Failed to delete table entry: {e}")
            return False
    
    def show_table(self, table_name: str) -> list:
        """Show contents of pf table"""
        try:
            cmd = [self.pfctl_path, "-t", table_name, "-T", "show"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return [line.strip() for line in result.stdout.split('\n') if line.strip()]
            else:
                return []
        except Exception as e:
            print(f"Failed to show table: {e}")
            return []
```

### **Apple Silicon Optimization**

```python
# apple_silicon_optimizer.py
import platform
import subprocess
import psutil
from typing import Dict, Optional

class AppleSiliconOptimizer:
    def __init__(self):
        self.is_apple_silicon = self._is_apple_silicon()
        self.cpu_info = self._get_cpu_info()
    
    def _is_apple_silicon(self) -> bool:
        """Check if running on Apple Silicon"""
        try:
            machine = platform.machine()
            return machine == 'arm64' or 'Apple' in platform.processor()
        except Exception:
            return False
    
    def _get_cpu_info(self) -> dict:
        """Get CPU information"""
        try:
            cmd = ["sysctl", "-n", "machdep.cpu.brand_string"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            cpu_info = {
                'brand': result.stdout.strip() if result.returncode == 0 else 'Unknown',
                'cores': psutil.cpu_count(logical=False),
                'logical_cores': psutil.cpu_count(logical=True),
                'architecture': platform.machine()
            }
            
            # Get additional CPU features for Apple Silicon
            if self.is_apple_silicon:
                features_cmd = ["sysctl", "-a", "hw.optional"]
                features_result = subprocess.run(features_cmd, capture_output=True, text=True)
                
                features = {}
                if features_result.returncode == 0:
                    for line in features_result.stdout.split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            features[key.strip()] = value.strip()
                
                cpu_info['features'] = features
            
            return cpu_info
        except Exception as e:
            print(f"Failed to get CPU info: {e}")
            return {}
    
    def optimize_for_apple_silicon(self) -> dict:
        """Apply Apple Silicon specific optimizations"""
        optimizations = []
        
        if not self.is_apple_silicon:
            return {"message": "Not running on Apple Silicon", "optimizations": []}
        
        try:
            # Enable performance cores preference
            cmd = ["sudo", "sysctl", "-w", "kern.sched_limit_per_cpu=1"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                optimizations.append("Enabled performance core preference")
            
            # Optimize memory allocation
            cmd = ["sudo", "sysctl", "-w", "vm.compressor_mode=4"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                optimizations.append("Optimized memory compression")
            
            # Enable hardware encryption acceleration
            cmd = ["sudo", "sysctl", "-w", "kern.hv_vmm_present=1"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                optimizations.append("Enabled hardware virtualization")
            
            return {
                "success": True,
                "optimizations": optimizations,
                "cpu_info": self.cpu_info
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "optimizations": optimizations
            }
    
    def get_thermal_state(self) -> dict:
        """Get thermal state information"""
        try:
            cmd = ["pmset", "-g", "thermlog"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            thermal_data = {}
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'CPU_Speed_Limit' in line:
                        thermal_data['cpu_speed_limit'] = line.split('=')[1].strip()
                    elif 'GPU_Speed_Limit' in line:
                        thermal_data['gpu_speed_limit'] = line.split('=')[1].strip()
            
            # Get temperature sensors if available
            temp_cmd = ["sudo", "powermetrics", "-n", "1", "-s", "cpu_power"]
            temp_result = subprocess.run(temp_cmd, capture_output=True, text=True)
            
            if temp_result.returncode == 0:
                # Parse temperature data from powermetrics output
                for line in temp_result.stdout.split('\n'):
                    if 'CPU Temperature' in line:
                        thermal_data['cpu_temperature'] = line.split(':')[1].strip()
            
            return thermal_data
        
        except Exception as e:
            print(f"Failed to get thermal state: {e}")
            return {}
    
    def monitor_performance(self, duration: int = 60) -> dict:
        """Monitor performance metrics"""
        try:
            cmd = [
                "sudo", "powermetrics",
                "-n", "1",
                "-s", "cpu_power,gpu_power,network",
                "--show-process-coalition",
                "--show-process-gpu"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration)
            
            metrics = {
                'cpu_power': 0,
                'gpu_power': 0,
                'network_activity': {},
                'process_info': []
            }
            
            if result.returncode == 0:
                # Parse powermetrics output
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'CPU Power' in line:
                        metrics['cpu_power'] = float(line.split(':')[1].strip().replace('mW', ''))
                    elif 'GPU Power' in line:
                        metrics['gpu_power'] = float(line.split(':')[1].strip().replace('mW', ''))
                    elif 'Bytes received' in line:
                        metrics['network_activity']['bytes_received'] = line.split(':')[1].strip()
                    elif 'Bytes sent' in line:
                        metrics['network_activity']['bytes_sent'] = line.split(':')[1].strip()
            
            return metrics
        
        except Exception as e:
            print(f"Failed to monitor performance: {e}")
            return {}
```

---

## 🔐 **Security Integration**

### **macOS Security Framework**

```bash
# Configure macOS security features for ZehraSec
# Enable Gatekeeper
sudo spctl --master-enable

# Configure code signing verification
sudo codesign --verify --deep --strict --verbose=2 /usr/local/zehrasec/

# Create custom code signing certificate for ZehraSec
security create-keypair \
    -a RSA \
    -s 2048 \
    -f "ZehraSec Code Signing Key" \
    -K /Library/Keychains/System.keychain

# Configure System Integrity Protection exceptions
# Note: This requires disabling SIP temporarily
# sudo csrutil disable  # Reboot to Recovery Mode first
# sudo spctl --add --label "ZehraSec" /usr/local/zehrasec/
# sudo csrutil enable    # Reboot to Recovery Mode again

# Configure privacy permissions
sudo tccutil reset All com.zehrasec.advanced-firewall
sudo tccutil enable NetworkAccess com.zehrasec.advanced-firewall
sudo tccutil enable FullDiskAccess com.zehrasec.advanced-firewall
```

### **FileVault Integration**

```python
# macos_filevault.py
import subprocess
import json
from typing import Dict, Optional, List

class FileVaultManager:
    def __init__(self):
        self.fdesetup_path = "/usr/bin/fdesetup"
    
    def is_enabled(self) -> bool:
        """Check if FileVault is enabled"""
        try:
            cmd = [self.fdesetup_path, "status"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return "FileVault is On" in result.stdout
            else:
                return False
        except Exception as e:
            print(f"Failed to check FileVault status: {e}")
            return False
    
    def get_status(self) -> dict:
        """Get detailed FileVault status"""
        try:
            cmd = [self.fdesetup_path, "status", "-extended"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            status = {
                'enabled': False,
                'status': 'Unknown',
                'details': {}
            }
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'FileVault is' in line:
                        status['enabled'] = 'On' in line
                        status['status'] = line.strip()
                    elif ':' in line:
                        key, value = line.split(':', 1)
                        status['details'][key.strip()] = value.strip()
            
            return status
        except Exception as e:
            print(f"Failed to get FileVault status: {e}")
            return {'enabled': False, 'error': str(e)}
    
    def list_users(self) -> list:
        """List FileVault enabled users"""
        try:
            cmd = [self.fdesetup_path, "list"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            users = []
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        users.append(line.strip())
            
            return users
        except Exception as e:
            print(f"Failed to list FileVault users: {e}")
            return []
    
    def check_key_escrow(self) -> dict:
        """Check if recovery key is escrowed"""
        try:
            cmd = ["profiles", "-P", "-o", "stdout-xml"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            escrow_info = {
                'escrowed': False,
                'service': None,
                'details': {}
            }
            
            if result.returncode == 0:
                # Parse profile XML to check for FileVault escrow settings
                # This is a simplified check - real implementation would parse XML
                if 'FileVault' in result.stdout and 'Escrow' in result.stdout:
                    escrow_info['escrowed'] = True
                    escrow_info['service'] = 'MDM'
            
            return escrow_info
        except Exception as e:
            print(f"Failed to check key escrow: {e}")
            return {'escrowed': False, 'error': str(e)}
```

---

## 🛠️ **Troubleshooting**

### **Common macOS Issues**

#### **Permission Issues**
```bash
# Fix file permissions
sudo chown -R $(whoami):staff /usr/local/zehrasec
chmod -R 755 /usr/local/zehrasec

# Grant Full Disk Access
sudo tccutil reset All com.zehrasec.advanced-firewall
sudo tccutil enable FullDiskAccess com.zehrasec.advanced-firewall

# Fix Keychain permissions
security unlock-keychain ~/Library/Keychains/login.keychain
```

#### **Network Issues**
```bash
# Check network configuration
networksetup -listallnetworkservices
networksetup -getinfo "Wi-Fi"

# Reset network settings
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# Check pfctl status
sudo pfctl -s info
sudo pfctl -s rules
```

#### **Code Signing Issues**
```bash
# Verify code signature
codesign -vvv --deep --strict /usr/local/zehrasec/venv/bin/python

# Check Gatekeeper status
spctl --status
spctl --assess --verbose /usr/local/zehrasec/

# Re-sign application if needed
sudo codesign --force --deep --sign - /usr/local/zehrasec/
```

### **Diagnostic Script**

```bash
#!/bin/bash
# ZehraSec macOS Diagnostic Script

echo "=== ZehraSec macOS Diagnostic ==="

# System Information
echo "--- System Information ---"
echo "macOS Version: $(sw_vers -productVersion)"
echo "Hardware: $(system_profiler SPHardwareDataType | grep 'Model Name' | cut -d: -f2 | xargs)"
echo "Processor: $(system_profiler SPHardwareDataType | grep 'Processor Name' | cut -d: -f2 | xargs)"
echo "Memory: $(system_profiler SPHardwareDataType | grep 'Memory:' | cut -d: -f2 | xargs)"

# ZehraSec Installation
echo -e "\n--- ZehraSec Installation ---"
if [ -d "/usr/local/zehrasec" ]; then
    echo "✓ Installation directory found"
    echo "  Path: /usr/local/zehrasec"
    echo "  Size: $(du -sh /usr/local/zehrasec 2>/dev/null | cut -f1)"
else
    echo "✗ Installation directory not found"
fi

# Python Environment
echo -e "\n--- Python Environment ---"
if [ -f "/usr/local/zehrasec/venv/bin/python" ]; then
    echo "✓ Virtual environment found"
    echo "  Python: $(/usr/local/zehrasec/venv/bin/python --version)"
else
    echo "✗ Virtual environment not found"
fi

# Check Homebrew installation
if command -v brew &> /dev/null; then
    echo "✓ Homebrew found: $(brew --version | head -n1)"
    
    if brew list | grep -q zehrasec; then
        echo "✓ ZehraSec installed via Homebrew"
    else
        echo "○ ZehraSec not installed via Homebrew"
    fi
else
    echo "○ Homebrew not found"
fi

# LaunchDaemon Status
echo -e "\n--- Service Status ---"
if [ -f "/Library/LaunchDaemons/com.zehrasec.advanced-firewall.plist" ]; then
    echo "✓ LaunchDaemon found"
    
    if launchctl list | grep -q com.zehrasec.advanced-firewall; then
        echo "✓ Service is loaded"
        
        # Check if service is running
        if launchctl list com.zehrasec.advanced-firewall | grep -q '"PID"'; then
            pid=$(launchctl list com.zehrasec.advanced-firewall | grep '"PID"' | cut -d= -f2 | tr -d ' ,')
            echo "✓ Service is running (PID: $pid)"
        else
            echo "✗ Service is not running"
        fi
    else
        echo "✗ Service is not loaded"
    fi
else
    echo "✗ LaunchDaemon not found"
fi

# Network Connectivity
echo -e "\n--- Network Connectivity ---"
if curl -k -s https://localhost:8443 > /dev/null 2>&1; then
    echo "✓ Web console accessible (HTTPS)"
else
    echo "✗ Web console not accessible"
fi

if curl -s http://localhost:8080/api/status > /dev/null 2>&1; then
    echo "✓ API accessible (HTTP)"
else
    echo "✗ API not accessible"
fi

# Firewall Status
echo -e "\n--- Firewall Status ---"
if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
    echo "✓ pfctl is enabled"
else
    echo "○ pfctl is disabled"
fi

# Check application firewall
if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -q "enabled"; then
    echo "✓ Application firewall is enabled"
else
    echo "○ Application firewall is disabled"
fi

# Security Features
echo -e "\n--- Security Features ---"
if csrutil status | grep -q "enabled"; then
    echo "✓ System Integrity Protection is enabled"
else
    echo "○ System Integrity Protection is disabled"
fi

if spctl --status | grep -q "enabled"; then
    echo "✓ Gatekeeper is enabled"
else
    echo "○ Gatekeeper is disabled"
fi

if fdesetup status | grep -q "FileVault is On"; then
    echo "✓ FileVault is enabled"
else
    echo "○ FileVault is disabled"
fi

# Log Files
echo -e "\n--- Log Files ---"
log_files=(
    "/var/log/zehrasec/zehrasec.log"
    "/var/log/zehrasec/security.log"
    "/var/log/zehrasec/stdout.log"
    "/var/log/zehrasec/stderr.log"
)

for log_file in "${log_files[@]}"; do
    if [ -f "$log_file" ]; then
        lines=$(wc -l < "$log_file" 2>/dev/null)
        size=$(ls -lh "$log_file" 2>/dev/null | awk '{print $5}')
        echo "✓ Found: $log_file ($lines lines, $size)"
    else
        echo "✗ Missing: $log_file"
    fi
done

# Configuration Files
echo -e "\n--- Configuration Files ---"
config_files=(
    "/usr/local/zehrasec/config/firewall_advanced.json"
    "/usr/local/zehrasec/config/firewall.json"
    "/etc/pf.anchors/zehrasec"
)

for config_file in "${config_files[@]}"; do
    if [ -f "$config_file" ]; then
        echo "✓ Found: $config_file"
        
        # Validate JSON files
        if [[ "$config_file" == *.json ]]; then
            if python3 -m json.tool "$config_file" > /dev/null 2>&1; then
                echo "  ✓ Valid JSON"
            else
                echo "  ✗ Invalid JSON"
            fi
        fi
    else
        echo "✗ Missing: $config_file"
    fi
done

echo -e "\n=== Diagnostic Complete ==="
```

---

## 📊 **Performance Optimization**

### **macOS-Specific Optimizations**

```bash
# macOS performance optimization for ZehraSec
# Increase file descriptor limits
echo 'kern.maxfiles=65536' | sudo tee -a /etc/sysctl.conf
echo 'kern.maxfilesperproc=32768' | sudo tee -a /etc/sysctl.conf

# Optimize network performance
echo 'net.inet.tcp.sendspace=262144' | sudo tee -a /etc/sysctl.conf
echo 'net.inet.tcp.recvspace=262144' | sudo tee -a /etc/sysctl.conf
echo 'net.inet.udp.maxdgram=65536' | sudo tee -a /etc/sysctl.conf

# Optimize memory management
echo 'vm.swapusage=0' | sudo tee -a /etc/sysctl.conf
echo 'kern.memorystatus_level_critical=5' | sudo tee -a /etc/sysctl.conf

# Apply sysctl settings
sudo sysctl -p

# Optimize energy settings for performance
sudo pmset -a sleep 0
sudo pmset -a disksleep 0
sudo pmset -a displaysleep 15
sudo pmset -a standby 0
sudo pmset -a autopoweroff 0
sudo pmset -a powernap 0

# Set process priority
sudo renice -n -10 $(pgrep -f "zehrasec")
```

---

## 📋 **Best Practices**

### **macOS Security Best Practices**
1. **Keep macOS Updated**: Install security updates promptly
2. **Enable FileVault**: Full disk encryption
3. **Use Strong Passwords**: Enable Touch ID/Face ID
4. **Enable Firewall**: Configure both pfctl and Application Firewall
5. **Code Signing**: Verify application signatures
6. **Privacy Settings**: Configure privacy permissions appropriately
7. **Backup Strategy**: Regular Time Machine backups

### **Performance Best Practices**
1. **Resource Monitoring**: Use Activity Monitor and htop
2. **Thermal Management**: Monitor temperature and throttling
3. **Memory Management**: Optimize for available RAM
4. **Network Optimization**: Configure optimal network settings
5. **Apple Silicon**: Leverage hardware acceleration features

---

## 📞 **Support**

### **macOS-Specific Support**
- **Email**: macos-support@zehrasec.com
- **Documentation**: https://docs.zehrasec.com/macos
- **Community**: https://community.zehrasec.com/macos
- **Apple Developer Forums**: https://developer.apple.com/forums/

### **Apple Resources**
- **macOS Security**: https://support.apple.com/guide/security/
- **Developer Documentation**: https://developer.apple.com/documentation/
- **System Administration**: https://support.apple.com/guide/deployment/

---

*ZehraSec Advanced Firewall - macOS Platform Guide*
