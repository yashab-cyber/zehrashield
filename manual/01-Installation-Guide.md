# Installation Guide - ZehraSec Advanced Firewall

![Installation](https://img.shields.io/badge/📦-Installation%20Guide-green?style=for-the-badge)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## 📋 **Table of Contents**

1. [System Requirements](#-system-requirements)
2. [Pre-Installation Checklist](#-pre-installation-checklist)
3. [Windows Installation](#-windows-installation)
4. [Linux Installation](#-linux-installation)
5. [macOS Installation](#-macos-installation)
6. [Android Installation](#-android-installation)
7. [Docker Installation](#-docker-installation)
8. [Post-Installation Verification](#-post-installation-verification)
9. [Troubleshooting Installation](#-troubleshooting-installation)

---

## 💻 **System Requirements**

### 🖥️ **Minimum Requirements**
- **CPU**: 2-core processor (2.0 GHz or higher)
- **RAM**: 4GB (8GB recommended)
- **Storage**: 2GB free space
- **Network**: Ethernet or Wi-Fi with administrative privileges
- **OS**: Windows 10+, Ubuntu 18.04+, macOS 10.15+, Android 7.0+

### 🚀 **Recommended Requirements**
- **CPU**: 4-core processor (3.0 GHz or higher)
- **RAM**: 16GB (32GB for enterprise)
- **Storage**: 10GB free space (SSD recommended)
- **Network**: Gigabit Ethernet
- **OS**: Latest stable versions

### 🏢 **Enterprise Requirements**
- **CPU**: 8-core processor (3.5 GHz or higher)
- **RAM**: 32GB+
- **Storage**: 50GB+ SSD
- **Network**: 10Gb Ethernet
- **Redundancy**: High availability setup

---

## ✅ **Pre-Installation Checklist**

### 🔐 **Administrative Access**
- [ ] Administrator/root privileges on target system
- [ ] Ability to modify system firewall settings
- [ ] Network configuration permissions

### 📦 **Software Dependencies**
- [ ] Python 3.8 or higher
- [ ] pip package manager
- [ ] Git (for source installation)
- [ ] curl/wget for downloads

### 🌐 **Network Requirements**
- [ ] Ports 8443 (HTTPS), 5000 (API) available
- [ ] Internet connection for threat intelligence
- [ ] DNS resolution working

### 🔧 **System Preparation**
- [ ] Antivirus software configured to allow ZehraSec
- [ ] System firewall configured
- [ ] Backup of existing network configuration

---

## 🪟 **Windows Installation**

### 📥 **Method 1: Automated Installation (Recommended)**

#### **Step 1: Download ZehraSec**
```powershell
# Download from GitHub
git clone https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall.git
cd ZehraSec-Advanced-Firewall
```

#### **Step 2: Run Automated Installer**
```powershell
# Run as Administrator
.\install.ps1
```

#### **Step 3: Verify Installation**
```powershell
# Check service status
Get-Service ZehraSecFirewall
```

### 📦 **Method 2: Manual Installation**

#### **Step 1: Install Python Dependencies**
```powershell
# Install Python 3.8+
# Download from https://python.org/downloads/

# Install dependencies
pip install -r requirements_advanced.txt
```

#### **Step 2: Install ZehraSec**
```powershell
# Install ZehraSec
python setup.py install

# Configure service
python deploy.py --install-service
```

#### **Step 3: Start Service**
```powershell
# Start ZehraSec service
Start-Service ZehraSecFirewall

# Enable auto-start
Set-Service ZehraSecFirewall -StartupType Automatic
```

### 🔧 **Windows-Specific Configuration**

#### **Firewall Rules**
```powershell
# Allow ZehraSec through Windows Firewall
New-NetFirewallRule -DisplayName "ZehraSec-HTTPS" -Direction Inbound -Port 8443 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "ZehraSec-API" -Direction Inbound -Port 5000 -Protocol TCP -Action Allow
```

#### **Registry Settings**
```powershell
# Optional: Configure registry settings
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\ZehraSec" /v "InstallPath" /t REG_SZ /d "C:\Program Files\ZehraSec"
```

---

## 🐧 **Linux Installation**

### 📥 **Method 1: Package Manager (Ubuntu/Debian)**

#### **Step 1: Add Repository**
```bash
# Add ZehraSec repository
curl -fsSL https://packages.zehrasec.com/gpg | sudo apt-key add -
echo "deb https://packages.zehrasec.com/ubuntu $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/zehrasec.list
```

#### **Step 2: Install Package**
```bash
# Update package list
sudo apt update

# Install ZehraSec
sudo apt install zehrasec-advanced-firewall
```

### 📦 **Method 2: From Source**

#### **Step 1: Install Dependencies**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3.8 python3-pip git curl

# CentOS/RHEL
sudo yum install python38 python3-pip git curl

# Fedora
sudo dnf install python3.8 python3-pip git curl
```

#### **Step 2: Download and Install**
```bash
# Clone repository
git clone https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall.git
cd ZehraSec-Advanced-Firewall

# Install dependencies
pip3 install -r requirements_advanced.txt

# Install ZehraSec
sudo python3 setup.py install
```

#### **Step 3: Configure Service**
```bash
# Create systemd service
sudo cp configs/zehrasec.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zehrasec
sudo systemctl start zehrasec
```

### 🔧 **Linux-Specific Configuration**

#### **Firewall Rules (iptables)**
```bash
# Allow ZehraSec ports
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

#### **SELinux Configuration (if enabled)**
```bash
# Configure SELinux policies
sudo setsebool -P httpd_can_network_connect 1
sudo semanage port -a -t http_port_t -p tcp 8443
```

---

## 🍎 **macOS Installation**

### 📥 **Method 1: Homebrew (Recommended)**

#### **Step 1: Install Homebrew**
```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### **Step 2: Install ZehraSec**
```bash
# Add ZehraSec tap
brew tap zehrasec/tap

# Install ZehraSec
brew install zehrasec-advanced-firewall
```

### 📦 **Method 2: Manual Installation**

#### **Step 1: Install Dependencies**
```bash
# Install Python 3.8+
brew install python@3.8

# Install Git
brew install git
```

#### **Step 2: Download and Install**
```bash
# Clone repository
git clone https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall.git
cd ZehraSec-Advanced-Firewall

# Install dependencies
pip3 install -r requirements_advanced.txt

# Install ZehraSec
sudo python3 setup.py install
```

#### **Step 3: Configure Launch Daemon**
```bash
# Install launch daemon
sudo cp configs/com.zehrasec.firewall.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.zehrasec.firewall.plist
```

### 🔧 **macOS-Specific Configuration**

#### **Firewall Configuration**
```bash
# Configure macOS firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/bin/zehrasec
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/local/bin/zehrasec
```

---

## 📱 **Android Installation**

### 📥 **Method 1: APK Installation**

#### **Step 1: Download APK**
```bash
# Download from official source
https://releases.zehrasec.com/android/zehrasec-v3.0.0.apk
```

#### **Step 2: Install APK**
1. Enable "Unknown Sources" in Android settings
2. Install the downloaded APK
3. Grant necessary permissions

### 📦 **Method 2: Termux Installation**

#### **Step 1: Install Termux**
```bash
# Install Termux from F-Droid or Google Play
```

#### **Step 2: Install ZehraSec in Termux**
```bash
# Update packages
pkg update && pkg upgrade

# Install dependencies
pkg install python git

# Clone and install
git clone https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall.git
cd ZehraSec-Advanced-Firewall
pip install -r requirements_advanced.txt
```

---

## 🐳 **Docker Installation**

### 📦 **Method 1: Docker Hub**

#### **Step 1: Pull Image**
```bash
# Pull official image
docker pull zehrasec/advanced-firewall:latest
```

#### **Step 2: Run Container**
```bash
# Run with default configuration
docker run -d \
  --name zehrasec-firewall \
  -p 8443:8443 \
  -p 5000:5000 \
  -v /path/to/config:/app/config \
  zehrasec/advanced-firewall:latest
```

### 🔧 **Method 2: Docker Compose**

#### **Step 1: Create docker-compose.yml**
```yaml
version: '3.8'
services:
  zehrasec:
    image: zehrasec/advanced-firewall:latest
    container_name: zehrasec-firewall
    ports:
      - "8443:8443"
      - "5000:5000"
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
    environment:
      - ZEHRASEC_CONFIG_PATH=/app/config
      - ZEHRASEC_LOG_LEVEL=INFO
    restart: unless-stopped
```

#### **Step 2: Deploy**
```bash
# Start services
docker-compose up -d

# Check status
docker-compose ps
```

---

## ✅ **Post-Installation Verification**

### 🔍 **Basic Verification**

#### **Check Service Status**
```bash
# Windows
Get-Service ZehraSecFirewall

# Linux
sudo systemctl status zehrasec

# macOS
sudo launchctl list | grep zehrasec
```

#### **Test Web Console**
```bash
# Access web console
https://localhost:8443

# Default credentials
Username: admin
Password: zehrasec123
```

#### **Test API**
```bash
# Check API status
curl -k https://localhost:8443/api/status

# Expected response
{
  "status": "running",
  "version": "3.0.0",
  "layers": {
    "layer1": "active",
    "layer2": "active",
    "layer3": "active",
    "layer4": "active",
    "layer5": "active",
    "layer6": "active"
  }
}
```

### 🧪 **Advanced Verification**

#### **Run Integration Tests**
```bash
# Run test suite
python test_integration.py

# Check test results
cat integration_test_results.json
```

#### **Performance Test**
```bash
# Run performance test
python performance_test.py --duration 60

# Check metrics
curl -k https://localhost:8443/api/metrics
```

---

## 🛠️ **Troubleshooting Installation**

### ❌ **Common Issues**

#### **Port Already in Use**
```bash
# Find process using port
netstat -tulpn | grep :8443

# Kill process
sudo kill -9 <PID>
```

#### **Permission Denied**
```bash
# Fix permissions
sudo chown -R $(whoami):$(whoami) /opt/zehrasec
sudo chmod +x /opt/zehrasec/bin/zehrasec
```

#### **Python Dependencies Error**
```bash
# Update pip
pip install --upgrade pip

# Install with verbose output
pip install -r requirements_advanced.txt -v
```

#### **Service Start Failure**
```bash
# Check logs
sudo journalctl -u zehrasec -f

# Manual start for debugging
sudo /opt/zehrasec/bin/zehrasec --debug
```

### 🔧 **Platform-Specific Issues**

#### **Windows Issues**
- **Antivirus Blocking**: Add ZehraSec to antivirus exclusions
- **UAC Prompts**: Run installer as Administrator
- **PowerShell Execution Policy**: `Set-ExecutionPolicy RemoteSigned`

#### **Linux Issues**
- **SELinux Denial**: Configure SELinux policies
- **Firewall Blocking**: Configure iptables/firewalld
- **Package Dependencies**: Install development tools

#### **macOS Issues**
- **Gatekeeper**: Allow unsigned application in Security preferences
- **System Integrity Protection**: May need to disable for advanced features
- **Network Extensions**: Approve network extension in System Preferences

---

## 📞 **Installation Support**

### 🆘 **Getting Help**
- **Installation Issues**: install-support@zehrasec.com
- **Technical Support**: support@zehrasec.com
- **Documentation**: https://docs.zehrasec.com/installation

### 📋 **What to Include in Support Requests**
1. Operating system and version
2. Hardware specifications
3. Installation method used
4. Complete error messages
5. Installation logs
6. Network configuration

---

## 🔄 **Next Steps**

After successful installation:

1. **[Quick Start Guide](02-Quick-Start.md)** - Get up and running quickly
2. **[First-Time Setup](03-First-Time-Setup.md)** - Configure basic settings
3. **[Web Console Guide](05-Web-Console-Guide.md)** - Learn the interface
4. **[Configuration Guide](04-Configuration-Guide.md)** - Advanced configuration

---

**Copyright © 2025 ZehraSec - Yashab Alam**  
*Installation Guide v3.0.0*
