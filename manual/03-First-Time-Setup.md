# 03-First-Time-Setup.md - ZehraSec Advanced Firewall

![First Time Setup](https://img.shields.io/badge/📋-First%20Time%20Setup-green?style=for-the-badge&logo=checkmark)

**Version 3.0.0** | **Updated: June 19, 2025** | **Copyright © 2025 ZehraSec - Yashab Alam**

---

## 📋 **Overview**

This guide walks you through the essential first-time setup steps for ZehraSec Advanced Firewall after installation. Complete these steps to ensure optimal security and performance.

---

## 🎯 **Pre-Setup Checklist**

### ✅ **Installation Verification**
- [ ] ZehraSec successfully installed
- [ ] All dependencies satisfied
- [ ] System requirements met
- [ ] Network connectivity available
- [ ] Administrative privileges confirmed

### 📋 **Required Information**
- [ ] Network configuration details
- [ ] Organization/company name
- [ ] Administrator email address
- [ ] License key (if applicable)
- [ ] DNS server addresses
- [ ] NTP server configuration

---

## 🚀 **Step 1: Initial Configuration Wizard**

### 🖥️ **Launch Configuration Wizard**

```bash
# Windows
cd "C:\Program Files\ZehraSec"
python main.py --setup

# Linux/macOS
cd /opt/zehrasec
sudo python3 main.py --setup
```

### 📝 **Wizard Steps**

#### **1.1 Welcome Screen**
```
=== ZehraSec Advanced Firewall Setup Wizard ===
Version 3.0.0

Welcome to ZehraSec! This wizard will guide you through
the initial configuration process.

Press [Enter] to continue...
```

#### **1.2 License Agreement**
- Review and accept the license terms
- Enter license key (if applicable)
- Register installation with ZehraSec servers

#### **1.3 Basic Information**
```yaml
Organization Name: [Your Company]
Administrator Email: admin@company.com
Time Zone: UTC-05:00 (Eastern)
Country/Region: United States
```

#### **1.4 Network Configuration**
```yaml
Primary Interface: eth0
IP Address: 192.168.1.100
Subnet Mask: 255.255.255.0
Gateway: 192.168.1.1
DNS Primary: 8.8.8.8
DNS Secondary: 8.8.4.4
```

---

## 🔐 **Step 2: Security Configuration**

### 🔑 **Administrator Account Setup**

#### **2.1 Create Admin User**
```bash
# Interactive setup
python main.py --create-admin

# Manual configuration
python main.py --create-admin --username admin --email admin@company.com
```

#### **2.2 Password Policy**
```json
{
  "password_policy": {
    "min_length": 12,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_numbers": true,
    "require_special": true,
    "expiry_days": 90,
    "history_count": 5
  }
}
```

### 🛡️ **SSL Certificate Configuration**

#### **2.3 Generate Self-Signed Certificate**
```bash
# Generate SSL certificate
python main.py --generate-ssl --domain zehrasec.local

# Custom SSL certificate
python main.py --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem
```

#### **2.4 Certificate Installation**
```bash
# Install certificate
sudo cp ssl/zehrasec.crt /etc/ssl/certs/
sudo cp ssl/zehrasec.key /etc/ssl/private/
sudo chmod 600 /etc/ssl/private/zehrasec.key
```

---

## 🌐 **Step 3: Network Interface Setup**

### 🔌 **Interface Configuration**

#### **3.1 Identify Network Interfaces**
```bash
# List available interfaces
python main.py --list-interfaces

# Output example:
# eth0: 192.168.1.100/24 (Connected)
# wlan0: 10.0.0.50/24 (Connected)
# lo: 127.0.0.1/8 (Loopback)
```

#### **3.2 Configure Monitoring Interfaces**
```json
{
  "network_interfaces": {
    "external": {
      "interface": "eth0",
      "ip": "192.168.1.100",
      "monitor_mode": true,
      "promiscuous": false
    },
    "internal": {
      "interface": "eth1",
      "ip": "10.0.0.1",
      "monitor_mode": true,
      "promiscuous": true
    }
  }
}
```

### 🌊 **Traffic Flow Configuration**

#### **3.3 Bridge Mode Setup**
```bash
# Configure bridge mode
sudo python main.py --bridge-setup --external eth0 --internal eth1

# Transparent proxy mode
sudo python main.py --transparent-proxy --interface eth0
```

#### **3.4 Routing Configuration**
```bash
# Add routing rules
sudo ip route add 192.168.0.0/16 via 192.168.1.1
sudo ip route add default via 192.168.1.1

# Enable IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

---

## 🔧 **Step 4: Core Features Setup**

### 🤖 **AI/ML Engine Initialization**

#### **4.1 Download ML Models**
```bash
# Download threat detection models
python main.py --download-models --type threat-detection

# Download behavior analysis models
python main.py --download-models --type behavior-analysis

# Download all models
python main.py --download-models --all
```

#### **4.2 Model Training Setup**
```json
{
  "ml_config": {
    "auto_training": true,
    "training_schedule": "daily",
    "training_data_retention": 30,
    "model_update_interval": 24,
    "baseline_learning_period": 7
  }
}
```

### 🛡️ **Zero Trust Configuration**

#### **4.3 Zero Trust Policies**
```bash
# Initialize zero trust
python main.py --zero-trust-init

# Configure default policies
python main.py --zero-trust-policy --default-deny
```

#### **4.4 Device Registration**
```json
{
  "zero_trust": {
    "device_registration": {
      "auto_register": false,
      "approval_required": true,
      "certificate_required": true,
      "max_devices_per_user": 5
    }
  }
}
```

---

## 📊 **Step 5: Monitoring and Logging**

### 📈 **Dashboard Configuration**

#### **5.1 Web Console Setup**
```bash
# Configure web console
python main.py --web-console-setup --port 8443 --ssl-enabled

# Set dashboard preferences
python main.py --dashboard-config --refresh-interval 30
```

#### **5.2 Access Web Console**
```
URL: https://localhost:8443
Username: admin
Password: [configured during setup]
```

### 📝 **Logging Configuration**

#### **5.3 Log Levels and Destinations**
```json
{
  "logging": {
    "level": "INFO",
    "destinations": [
      {
        "type": "file",
        "path": "/var/log/zehrasec/firewall.log",
        "rotation": "daily",
        "retention": 30
      },
      {
        "type": "syslog",
        "facility": "local0",
        "host": "192.168.1.200"
      }
    ]
  }
}
```

#### **5.4 SIEM Integration Setup**
```bash
# Configure Splunk integration
python main.py --siem-setup --type splunk --host splunk.company.com --port 514

# Configure ELK integration
python main.py --siem-setup --type elasticsearch --host elk.company.com --port 9200
```

---

## 🔄 **Step 6: Service Configuration**

### ⚙️ **System Service Setup**

#### **6.1 Windows Service**
```powershell
# Install Windows service
python main.py --install-service

# Start service
Start-Service "ZehraSec Firewall"

# Enable auto-start
Set-Service "ZehraSec Firewall" -StartupType Automatic
```

#### **6.2 Linux Systemd Service**
```bash
# Create systemd service
sudo python main.py --create-systemd-service

# Enable and start service
sudo systemctl enable zehrasec-firewall
sudo systemctl start zehrasec-firewall

# Check status
sudo systemctl status zehrasec-firewall
```

#### **6.3 macOS LaunchDaemon**
```bash
# Install launch daemon
sudo python main.py --install-launchd

# Load service
sudo launchctl load /Library/LaunchDaemons/com.zehrasec.firewall.plist
```

---

## 📋 **Step 7: Initial Testing**

### 🧪 **Connectivity Tests**

#### **7.1 Basic Connectivity**
```bash
# Test internal connectivity
python main.py --test-connectivity --internal

# Test external connectivity
python main.py --test-connectivity --external

# Test DNS resolution
python main.py --test-dns --servers 8.8.8.8,8.8.4.4
```

#### **7.2 Firewall Rules Testing**
```bash
# Test default rules
python main.py --test-rules --default

# Test custom rules
python main.py --test-rules --ruleset custom

# Generate test traffic
python main.py --generate-test-traffic --duration 60
```

### 🔍 **Security Validation**

#### **7.3 Security Posture Check**
```bash
# Run security assessment
python main.py --security-check --comprehensive

# Vulnerability scan
python main.py --vuln-scan --internal

# Compliance check
python main.py --compliance-check --standard pci-dss
```

#### **7.4 Performance Baseline**
```bash
# Establish performance baseline
python main.py --baseline-performance --duration 300

# Memory usage check
python main.py --check-memory --alert-threshold 80

# CPU usage monitoring
python main.py --monitor-cpu --duration 60
```

---

## 📧 **Step 8: Notification Setup**

### 📮 **Email Configuration**

#### **8.1 SMTP Settings**
```json
{
  "notifications": {
    "email": {
      "smtp_server": "smtp.company.com",
      "smtp_port": 587,
      "use_tls": true,
      "username": "zehrasec@company.com",
      "password": "encrypted_password",
      "from_address": "zehrasec@company.com"
    }
  }
}
```

#### **8.2 Alert Recipients**
```bash
# Add alert recipients
python main.py --add-recipient --email admin@company.com --level critical
python main.py --add-recipient --email security@company.com --level warning
python main.py --add-recipient --email ops@company.com --level info
```

### 📱 **Mobile Notifications**

#### **8.3 Push Notification Setup**
```bash
# Configure push notifications
python main.py --mobile-setup --fcm-key [firebase-key]

# Register mobile devices
python main.py --register-device --token [device-token] --user admin
```

---

## 🎯 **Step 9: Backup Configuration**

### 💾 **Initial Backup**

#### **9.1 Configuration Backup**
```bash
# Create initial backup
python main.py --backup-config --destination /backup/zehrasec/

# Automated backup schedule
python main.py --schedule-backup --frequency daily --time 02:00
```

#### **9.2 Database Backup**
```bash
# Backup threat intelligence database
python main.py --backup-database --type threat-intel

# Backup configuration database
python main.py --backup-database --type config

# Full system backup
python main.py --full-backup --destination /backup/zehrasec-full/
```

---

## ✅ **Step 10: Final Validation**

### 🔍 **System Health Check**

#### **10.1 Comprehensive Status**
```bash
# Complete system status
python main.py --status --comprehensive

# Service status check
python main.py --check-services

# Configuration validation
python main.py --validate-config --verbose
```

#### **10.2 Security Audit**
```bash
# Run security audit
python main.py --security-audit --detailed

# Generate setup report
python main.py --setup-report --output /tmp/zehrasec-setup.pdf
```

---

## 📋 **Post-Setup Checklist**

### ✅ **Verification Items**
- [ ] Web console accessible
- [ ] All services running
- [ ] Firewall rules active
- [ ] Logging functioning
- [ ] Notifications configured
- [ ] Backup scheduled
- [ ] SSL certificates valid
- [ ] Performance baseline established
- [ ] Security policies enforced
- [ ] Documentation updated

### 📝 **Next Steps**
1. **[Web Console Guide](05-Web-Console-Guide.md)** - Learn the interface
2. **[Configuration Guide](04-Configuration-Guide.md)** - Advanced settings
3. **[Monitoring Setup](20-Monitoring-Setup.md)** - Enhanced monitoring
4. **[Security Hardening](24-Security-Hardening.md)** - Additional security

---

## 🆘 **Troubleshooting First-Time Setup**

### ❌ **Common Issues**

#### **Setup Wizard Fails**
```bash
# Check prerequisites
python main.py --check-prereqs

# Run setup in debug mode
python main.py --setup --debug --verbose

# Reset setup state
python main.py --reset-setup --confirm
```

#### **Service Won't Start**
```bash
# Check service logs
tail -f /var/log/zehrasec/service.log

# Test configuration
python main.py --test-config

# Rebuild service
python main.py --rebuild-service
```

#### **Web Console Not Accessible**
```bash
# Check web service
python main.py --check-web-service

# Verify SSL certificates
python main.py --check-ssl

# Test port connectivity
netstat -tlnp | grep 8443
```

### 🔧 **Recovery Options**

#### **Reset to Defaults**
```bash
# Reset configuration
python main.py --reset-config --backup-first

# Factory reset (WARNING: Destructive)
python main.py --factory-reset --confirm
```

#### **Emergency Access**
```bash
# Enable emergency access
python main.py --emergency-access --enable

# Direct console access
python main.py --console --local-only
```

---

## 📞 **Support Resources**

### 🏢 **Official Support**
- **Setup Support**: setup@zehrasec.com
- **Technical Support**: support@zehrasec.com
- **Documentation**: https://docs.zehrasec.com/setup

### 👨‍💻 **Community Resources**
- **Setup Forum**: https://forum.zehrasec.com/setup
- **Video Tutorials**: https://youtube.com/zehrasec-setup
- **Knowledge Base**: https://kb.zehrasec.com

---

**Copyright © 2025 ZehraSec - Yashab Alam**  
**All Rights Reserved**

---
