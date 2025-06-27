# ZehraSec Advanced Firewall - Platform-Specific Setup

![Platform Setup](https://img.shields.io/badge/🖥️-Platform%20Setup-blue?style=for-the-badge)

**Version 1.0** | **ZehraSec Advanced Firewall v2.0+**

---

## 🖼️ **Overview**

This guide provides detailed platform-specific configuration instructions for Windows, Linux, macOS, and Android environments. Each platform has unique requirements and optimization strategies.

---

## 🪟 **Windows Platform Setup**

### **Windows Server Configuration**

#### **1. Windows Firewall Integration**
```powershell
# Disable Windows Firewall (ZehraSec replaces it)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Or configure Windows Firewall to work alongside ZehraSec
New-NetFirewallRule -DisplayName "ZehraSec API" -Direction Inbound -Port 8080 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "ZehraSec Web Console" -Direction Inbound -Port 443 -Protocol TCP -Action Allow
```

#### **2. Service Configuration**
```powershell
# Install as Windows Service
python deploy.py --install-service --service-name "ZehraSecFirewall"

# Configure service startup
sc config ZehraSecFirewall start= auto
sc config ZehraSecFirewall depend= Tcpip/Afd

# Set service recovery options
sc failure ZehraSecFirewall reset= 30 actions= restart/5000/restart/5000/restart/5000
```

#### **3. Performance Optimization**
```powershell
# Set high priority for ZehraSec process
wmic process where name="python.exe" CALL setpriority "high priority"

# Configure network adapter settings
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global chimney=enabled
netsh int tcp set global rss=enabled
```

#### **4. Windows-Specific Features**
```json
{
  "windows_config": {
    "wfp_integration": true,
    "event_log_integration": true,
    "perfmon_counters": true,
    "com_interface": true,
    "service_dependencies": ["Tcpip", "Afd", "Netman"],
    "registry_monitoring": true
  }
}
```

### **Windows Client Configuration**

#### **1. User Account Control (UAC)**
```powershell
# Run with elevated privileges
Start-Process powershell -Verb RunAs -ArgumentList "-File install.ps1"

# Or create scheduled task for startup
schtasks /create /tn "ZehraSecFirewall" /tr "C:\Program Files\ZehraSec\main.py" /sc onstart /ru SYSTEM
```

#### **2. Network Profile Configuration**
```powershell
# Set network profiles
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

# Configure network discovery
netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
```

---

## 🐧 **Linux Platform Setup**

### **Ubuntu/Debian Configuration**

#### **1. System Service Setup**
```bash
# Create systemd service
sudo tee /etc/systemd/system/zehrasec-firewall.service > /dev/null <<EOF
[Unit]
Description=ZehraSec Advanced Firewall
After=network.target
Wants=network.target

[Service]
Type=simple
User=zehrasec
Group=zehrasec
WorkingDirectory=/opt/zehrasec
ExecStart=/opt/zehrasec/venv/bin/python main.py --daemon
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable zehrasec-firewall
sudo systemctl start zehrasec-firewall
```

#### **2. Network Configuration**
```bash
# Configure iptables integration
sudo iptables -I INPUT 1 -j ZEHRASEC-INPUT
sudo iptables -I FORWARD 1 -j ZEHRASEC-FORWARD
sudo iptables -I OUTPUT 1 -j ZEHRASEC-OUTPUT

# Save iptables rules
sudo iptables-save > /etc/iptables/rules.v4

# Configure netfilter hooks
echo 'net.netfilter.nf_conntrack_max = 1048576' >> /etc/sysctl.conf
echo 'net.netfilter.nf_conntrack_tcp_timeout_established = 7200' >> /etc/sysctl.conf
sudo sysctl -p
```

#### **3. User and Permissions**
```bash
# Create dedicated user
sudo useradd -r -s /bin/false -d /opt/zehrasec zehrasec

# Set up capabilities
sudo setcap cap_net_admin,cap_net_raw=+ep /opt/zehrasec/venv/bin/python

# Configure sudo access for management
echo 'zehrasec-admin ALL=(root) NOPASSWD: /bin/systemctl restart zehrasec-firewall' >> /etc/sudoers.d/zehrasec
```

### **CentOS/RHEL Configuration**

#### **1. SELinux Configuration**
```bash
# Configure SELinux policy
sudo setsebool -P nis_enabled 1
sudo setsebool -P httpd_can_network_connect 1

# Create custom SELinux policy
sudo semanage port -a -t http_port_t -p tcp 8080
sudo semanage port -a -t websm_port_t -p tcp 8443

# Check SELinux status
sudo getenforce
sudo sestatus
```

#### **2. Firewall Configuration**
```bash
# Configure firewalld
sudo firewall-cmd --permanent --new-service=zehrasec
sudo firewall-cmd --permanent --service=zehrasec --add-port=8080/tcp
sudo firewall-cmd --permanent --service=zehrasec --add-port=443/tcp
sudo firewall-cmd --permanent --add-service=zehrasec
sudo firewall-cmd --reload

# Or disable firewalld and use iptables
sudo systemctl stop firewalld
sudo systemctl disable firewalld
sudo yum install iptables-services
```

---

## 🍎 **macOS Platform Setup**

### **System Configuration**

#### **1. Launch Daemon Setup**
```bash
# Create launch daemon plist
sudo tee /Library/LaunchDaemons/com.zehrasec.firewall.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.zehrasec.firewall</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/python3</string>
        <string>/Applications/ZehraSec/main.py</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/zehrasec/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/zehrasec/stderr.log</string>
</dict>
</plist>
EOF

# Load launch daemon
sudo launchctl load /Library/LaunchDaemons/com.zehrasec.firewall.plist
```

#### **2. Packet Filter (PF) Integration**
```bash
# Backup original pf.conf
sudo cp /etc/pf.conf /etc/pf.conf.backup

# Add ZehraSec anchor
sudo tee -a /etc/pf.conf > /dev/null <<EOF

# ZehraSec Advanced Firewall
anchor "zehrasec/*"
load anchor "zehrasec" from "/etc/pf.anchors/zehrasec"
EOF

# Create ZehraSec anchor file
sudo mkdir -p /etc/pf.anchors
sudo tee /etc/pf.anchors/zehrasec > /dev/null <<EOF
# ZehraSec firewall rules will be inserted here
EOF

# Enable and reload PF
sudo pfctl -e
sudo pfctl -f /etc/pf.conf
```

#### **3. Network Extension (Optional)**
```bash
# For advanced packet inspection
# Requires Apple Developer Program membership
# See manual/31-Plugin-Development.md for details
```

### **Homebrew Integration**

#### **1. Create Homebrew Formula**
```bash
# Install via Homebrew
brew tap zehrasec/tap
brew install zehrasec-advanced-firewall

# Or install from source
brew install --build-from-source zehrasec-advanced-firewall
```

---

## 📱 **Android Platform Setup**

### **Prerequisites**
```bash
# Enable developer options
# Settings > About phone > Tap "Build number" 7 times

# Enable USB debugging
# Settings > Developer options > USB debugging

# Install ADB (Android Debug Bridge)
# Download from: https://developer.android.com/studio/command-line/adb
```

### **Installation Methods**

#### **1. Termux Installation**
```bash
# Install Termux from F-Droid
# https://f-droid.org/en/packages/com.termux/

# Update packages
pkg update && pkg upgrade

# Install dependencies
pkg install python git curl openssh

# Clone repository
git clone https://github.com/ZehraSec/Advanced-Firewall.git
cd Advanced-Firewall

# Install Python requirements
pip install -r requirements.txt

# Run Android setup
python src/platforms/android_platform.py --setup
```

#### **2. Root Installation (Advanced)**
```bash
# Requires rooted device
# Install as system app for deeper integration

# Mount system partition as writable
mount -o remount,rw /system

# Copy ZehraSec to system
cp -r /data/data/com.termux/files/home/Advanced-Firewall /system/app/ZehraSec/

# Set permissions
chmod 755 /system/app/ZehraSec/
chmod 644 /system/app/ZehraSec/*

# Reboot device
reboot
```

### **Configuration**

#### **1. VPN Service Configuration**
```json
{
  "android_config": {
    "vpn_service": {
      "enabled": true,
      "capture_mode": "tun",
      "dns_servers": ["8.8.8.8", "1.1.1.1"],
      "mtu": 1500,
      "routes": ["0.0.0.0/0"]
    },
    "background_processing": {
      "enabled": true,
      "battery_optimization": false,
      "doze_whitelist": true
    }
  }
}
```

#### **2. Permissions Setup**
```bash
# Grant necessary permissions via ADB
adb shell pm grant com.zehrasec.firewall android.permission.INTERNET
adb shell pm grant com.zehrasec.firewall android.permission.ACCESS_NETWORK_STATE
adb shell pm grant com.zehrasec.firewall android.permission.WRITE_EXTERNAL_STORAGE
adb shell pm grant com.zehrasec.firewall android.permission.RECEIVE_BOOT_COMPLETED
```

---

## 🔧 **Cross-Platform Features**

### **Configuration Synchronization**
```json
{
  "sync_config": {
    "enabled": true,
    "sync_server": "https://sync.zehrasec.com",
    "encryption": "AES-256-GCM",
    "platforms": ["windows", "linux", "macos", "android"],
    "sync_interval": 300
  }
}
```

### **Multi-Platform Deployment**
```bash
# Deploy to multiple platforms
python deploy.py --platforms windows,linux,macos --config unified-config.json

# Monitor all platforms
python main.py --monitor-cluster --platforms all
```

### **Platform-Specific Optimizations**

#### **Windows Optimizations**
- Windows Filtering Platform (WFP) integration
- Event Tracing for Windows (ETW) logging
- Performance counters integration
- COM interface for third-party tools

#### **Linux Optimizations**
- Netfilter/iptables deep integration
- eBPF packet processing
- Systemd journal logging
- NUMA-aware thread allocation

#### **macOS Optimizations**
- Packet Filter (PF) integration
- Network Extension framework
- System Configuration framework
- Unified logging system

#### **Android Optimizations**
- VPN service framework
- Battery optimization handling
- Doze mode compatibility
- Background service limitations

---

## 📊 **Performance Tuning by Platform**

### **Windows Performance**
```powershell
# CPU affinity settings
$process = Get-Process -Name "python"
$process.ProcessorAffinity = 0x0F  # Use first 4 cores

# Memory settings
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=4096,MaximumSize=8192
```

### **Linux Performance**
```bash
# CPU governor settings
echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Network buffer tuning
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 65536 134217728' >> /etc/sysctl.conf
```

### **macOS Performance**
```bash
# Increase system limits
sudo launchctl limit maxfiles 65536 200000
sudo launchctl limit maxproc 2048 4096

# Network tuning
sudo sysctl -w net.inet.tcp.delayed_ack=0
sudo sysctl -w net.inet.tcp.sendspace=65536
```

---

## 🚨 **Platform-Specific Troubleshooting**

### **Windows Issues**
```powershell
# Check Windows Firewall conflicts
Get-NetFirewallProfile | Select-Object Name, Enabled

# Verify service status
Get-Service -Name "ZehraSecFirewall"

# Check event logs
Get-EventLog -LogName Application -Source "ZehraSec" -Newest 10
```

### **Linux Issues**
```bash
# Check service status
systemctl status zehrasec-firewall

# Verify iptables rules
iptables -L -n -v

# Check capabilities
getcap /opt/zehrasec/venv/bin/python
```

### **macOS Issues**
```bash
# Check launch daemon status
sudo launchctl list | grep zehrasec

# Verify PF rules
sudo pfctl -s rules

# Check system logs
log show --predicate 'subsystem == "com.zehrasec.firewall"' --last 1h
```

### **Android Issues**
```bash
# Check VPN service
adb shell dumpsys connectivity | grep -A 10 "VPN"

# Verify permissions
adb shell dumpsys package com.zehrasec.firewall | grep permission

# Monitor logs
adb logcat | grep ZehraSec
```

---

## 📋 **Platform Migration**

### **Configuration Export/Import**
```bash
# Export configuration
python main.py --export-config --platform current --output config-backup.json

# Import to new platform
python main.py --import-config --input config-backup.json --platform target
```

### **Data Migration**
```bash
# Migrate logs and data
python tools/migrate.py --source-platform windows --target-platform linux --data-path /path/to/data
```

---

## 📞 **Platform-Specific Support**

For platform-specific issues:

- **Windows**: windows-support@zehrasec.com
- **Linux**: linux-support@zehrasec.com  
- **macOS**: macos-support@zehrasec.com
- **Android**: mobile-support@zehrasec.com

---

**© 2024 ZehraSec. All rights reserved.**

*Platform-specific features and optimizations may vary by version. Always consult the latest documentation for your platform.*
