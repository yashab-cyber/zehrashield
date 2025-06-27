# Quick Start Guide - ZehraSec Advanced Firewall

![Quick Start](https://img.shields.io/badge/🚀-Quick%20Start-brightgreen?style=for-the-badge)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## ⚡ **Get Started in 5 Minutes**

This guide will get you up and running with ZehraSec Advanced Firewall in just 5 minutes!

---

## 📋 **Prerequisites**

Before starting, ensure you have:
- [ ] Administrative privileges on your system
- [ ] Python 3.8+ installed
- [ ] Internet connection
- [ ] 2GB free disk space

---

## 🚀 **Step 1: Download ZehraSec (1 minute)**

### **Option A: Git Clone (Recommended)**
```bash
git clone https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall.git
cd ZehraSec-Advanced-Firewall
```

### **Option B: Direct Download**
1. Go to: https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall/releases
2. Download the latest release
3. Extract to your desired location

---

## ⚙️ **Step 2: Automated Installation (2 minutes)**

### **Windows**
```powershell
# Run as Administrator
.\install.ps1
```

### **Linux/macOS**
```bash
# Make executable and run
chmod +x install.sh
sudo ./install.sh
```

### **Manual Installation (Alternative)**
```bash
# Install dependencies
pip install -r requirements_advanced.txt

# Run setup
python deploy.py
```

---

## 🔧 **Step 3: Start ZehraSec (30 seconds)**

### **Automated Start**
```bash
# Windows
Start-Service ZehraSecFirewall

# Linux/macOS
sudo systemctl start zehrasec
```

### **Manual Start**
```bash
# Start with default configuration
python main.py --config config/firewall_advanced.json
```

**✅ You should see:**
```
[INFO] ZehraSec Advanced Firewall v3.0.0 Starting...
[INFO] Loading 6-Layer Security Architecture...
[INFO] Layer 1: Packet Filter - ACTIVE
[INFO] Layer 2: Application Gateway - ACTIVE
[INFO] Layer 3: IDS/IPS - ACTIVE
[INFO] Layer 4: Threat Intelligence - ACTIVE
[INFO] Layer 5: Network Access Control - ACTIVE
[INFO] Layer 6: SIEM Integration - ACTIVE
[INFO] Web Console: https://localhost:8443
[INFO] API Server: http://localhost:5000
[INFO] ZehraSec is now protecting your network!
```

---

## 🌐 **Step 4: Access Web Console (30 seconds)**

### **Open Your Browser**
1. Navigate to: https://localhost:8443
2. Accept the self-signed certificate warning
3. Login with default credentials:
   - **Username**: `admin`
   - **Password**: `zehrasec123`

### **First Login**
You'll see the ZehraSec Dashboard with:
- 🛡️ **Real-time Protection Status**
- 📊 **Network Activity Charts**
- 🚨 **Recent Threats (if any)**
- ⚙️ **Quick Settings Panel**

---

## ✅ **Step 5: Verify Everything Works (1 minute)**

### **Quick Health Check**
```bash
# Test API endpoint
curl -k https://localhost:8443/api/status
```

**Expected Response:**
```json
{
  "status": "running",
  "version": "3.0.0",
  "uptime": "00:05:23",
  "layers_active": 6,
  "threats_blocked": 0,
  "packets_processed": 1247
}
```

### **Dashboard Check**
In the web console, verify:
- [ ] All 6 layers show "ACTIVE" status
- [ ] Network traffic is being monitored
- [ ] No critical alerts (red indicators)
- [ ] System resources are normal

---

## 🎉 **Congratulations! You're Protected!**

ZehraSec is now actively protecting your network with:
- **Real-time packet inspection**
- **AI-powered threat detection**
- **Automated blocking of malicious traffic**
- **Comprehensive logging and monitoring**

---

## 🔧 **Quick Configuration Tips**

### **Change Default Password**
1. Go to **Settings** → **User Management**
2. Click **Change Password**
3. Use a strong password (12+ characters)

### **Configure Basic Rules**
1. Navigate to **Security** → **Firewall Rules**
2. Review default rules
3. Add custom rules as needed

### **Enable Threat Intelligence**
1. Go to **Threat Intelligence** → **Feeds**
2. Enable recommended feeds
3. Click **Update Now**

---

## 📊 **Monitor Your Protection**

### **Real-Time Dashboard**
- **Network Activity**: Live traffic visualization
- **Threat Detection**: Recent blocks and alerts
- **Performance Metrics**: CPU, memory, throughput
- **Security Events**: Detailed event timeline

### **Quick API Checks**
```bash
# View recent threats
curl -k https://localhost:8443/api/threats/recent

# Check system performance
curl -k https://localhost:8443/api/metrics

# View blocked IPs
curl -k https://localhost:8443/api/blocked-ips
```

---

## 🛡️ **Test Your Protection**

### **Safe Security Test**
1. Visit: https://localhost:8443/security-test
2. Run the built-in security scanner
3. Review the protection report

### **Simulate Threat (Safe)**
```bash
# Trigger test alert (safe)
curl -k "https://localhost:8443/test-alert?type=sql_injection"
```

This will generate a test security event to verify alerting works.

---

## 🚨 **Troubleshooting Quick Fixes**

### **Can't Access Web Console?**
```bash
# Check if service is running
# Windows
Get-Service ZehraSecFirewall

# Linux/macOS  
sudo systemctl status zehrasec

# Check ports
netstat -tulpn | grep :8443
```

### **Permission Errors?**
```bash
# Fix permissions (Linux/macOS)
sudo chown -R $(whoami):$(whoami) ./ZehraSec-Advanced-Firewall
chmod +x install.sh

# Windows: Run PowerShell as Administrator
```

### **Port Already in Use?**
```bash
# Find process using port 8443
netstat -tulpn | grep :8443

# Kill process (replace PID)
kill -9 <PID>

# Restart ZehraSec
python main.py --config config/firewall_advanced.json --port 8444
```

---

## 📱 **Mobile App (Optional)**

### **Install Mobile App**
```bash
# Navigate to mobile directory
cd mobile/ZehraSecMobile

# Install dependencies
npm install

# Run on Android
npx react-native run-android

# Run on iOS  
npx react-native run-ios
```

### **Connect Mobile App**
1. Open ZehraSec mobile app
2. Enter server IP: `your-server-ip:5000`
3. Login with same credentials
4. Monitor your network on-the-go!

---

## 🎯 **Next Steps**

Now that ZehraSec is running, explore these guides:

### **Essential Configuration**
- **[First-Time Setup](03-First-Time-Setup.md)** - Complete initial configuration
- **[Configuration Guide](04-Configuration-Guide.md)** - Detailed settings
- **[Web Console Guide](05-Web-Console-Guide.md)** - Master the interface

### **Advanced Features**
- **[6-Layer Architecture](08-6-Layer-Architecture.md)** - Understand the security model
- **[Threat Detection](09-Threat-Detection.md)** - Advanced threat capabilities
- **[API Documentation](07-API-Documentation.md)** - Integrate with other tools

### **Security Hardening**
- **[Security Hardening](24-Security-Hardening.md)** - Secure your installation  
- **[Best Practices](32-Best-Practices.md)** - Industry recommendations
- **[Compliance Guide](23-Compliance-Guide.md)** - Regulatory requirements

---

## 📞 **Need Help?**

### **Quick Support**
- **Email**: quickstart@zehrasec.com
- **Chat**: Available in web console (bottom right)
- **Documentation**: https://docs.zehrasec.com

### **Common Resources**
- **FAQ**: [34-FAQ.md](34-FAQ.md)
- **Troubleshooting**: [16-Troubleshooting-Guide.md](16-Troubleshooting-Guide.md)
- **Community**: https://community.zehrasec.com

---

## ⏱️ **Quick Reference Commands**

### **Service Management**
```bash
# Start
sudo systemctl start zehrasec    # Linux
Start-Service ZehraSecFirewall   # Windows

# Stop  
sudo systemctl stop zehrasec     # Linux
Stop-Service ZehraSecFirewall    # Windows

# Status
sudo systemctl status zehrasec   # Linux
Get-Service ZehraSecFirewall     # Windows
```

### **API Quick Test**
```bash
# Status check
curl -k https://localhost:8443/api/status

# Block IP (example)
curl -X POST https://localhost:8443/api/block-ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "reason": "test"}'

# View logs
curl -k https://localhost:8443/api/logs?limit=10
```

---

**🎉 Welcome to ZehraSec! Your network is now protected by the world's most advanced 6-layer firewall system.**

---

**Copyright © 2025 ZehraSec - Yashab Alam**  
*Quick Start Guide v3.0.0*
