# Troubleshooting Guide - ZehraSec Advanced Firewall

![Troubleshooting](https://img.shields.io/badge/🔧-Troubleshooting%20Guide-orange?style=for-the-badge)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## 📋 **Table of Contents**

1. [Quick Diagnostics](#-quick-diagnostics)
2. [Installation Issues](#-installation-issues)
3. [Service/Startup Problems](#-servicestartup-problems)
4. [Web Console Issues](#-web-console-issues)
5. [Network Connectivity Problems](#-network-connectivity-problems)
6. [Performance Issues](#-performance-issues)
7. [Security Features Not Working](#-security-features-not-working)
8. [Database and Logging Issues](#-database-and-logging-issues)
9. [Platform-Specific Issues](#-platform-specific-issues)
10. [Emergency Recovery](#-emergency-recovery)

---

## 🩺 **Quick Diagnostics**

### **Health Check Script**
```bash
# Run comprehensive health check
python diagnostics.py --full-check

# Quick system check
python diagnostics.py --quick
```

### **System Status Overview**
```bash
# Check all services
curl -k https://localhost:8443/api/health

# View system metrics
curl -k https://localhost:8443/api/metrics

# Check logs for errors
tail -f logs/zehrasec.log | grep ERROR
```

### **Common Status Indicators**
- 🟢 **Green**: Service running normally
- 🟡 **Yellow**: Warning or degraded performance
- 🔴 **Red**: Critical error or service down
- ⚪ **Gray**: Service disabled or not configured

---

## 🛠️ **Installation Issues**

### **❌ Problem: Installation Fails with Permission Errors**

#### **Symptoms:**
```
Permission denied: '/usr/local/bin/zehrasec'
[Errno 13] Permission denied
```

#### **Solutions:**

**Linux/macOS:**
```bash
# Fix permissions
sudo chown -R $(whoami):$(whoami) /opt/zehrasec
sudo chmod +x /opt/zehrasec/bin/*

# Run installer with sudo
sudo ./install.sh
```

**Windows:**
```powershell
# Run PowerShell as Administrator
Start-Process PowerShell -Verb RunAs

# Then run installer
.\install.ps1
```

### **❌ Problem: Python Dependencies Installation Fails**

#### **Symptoms:**
```
ERROR: Could not install packages due to an EnvironmentError
Failed building wheel for cryptography
```

#### **Solutions:**

**Update pip and setuptools:**
```bash
# Update tools
pip install --upgrade pip setuptools wheel

# Install with verbose output
pip install -r requirements_advanced.txt -v
```

**Install system dependencies:**
```bash
# Ubuntu/Debian
sudo apt install python3-dev libffi-dev libssl-dev build-essential

# CentOS/RHEL
sudo yum install python3-devel libffi-devel openssl-devel gcc

# macOS
xcode-select --install
```

### **❌ Problem: Port Already in Use**

#### **Symptoms:**
```
[ERROR] Port 8443 is already in use
OSError: [Errno 98] Address already in use
```

#### **Solutions:**

**Find and kill process:**
```bash
# Find process using port
netstat -tulpn | grep :8443
lsof -i :8443

# Kill process (replace PID)
sudo kill -9 <PID>

# Or use different port
python main.py --port 8444
```

---

## 🔄 **Service/Startup Problems**

### **❌ Problem: Service Won't Start**

#### **Symptoms:**
```bash
# Linux
sudo systemctl status zehrasec
● zehrasec.service - ZehraSec Advanced Firewall
   Loaded: loaded
   Active: failed (Result: exit-code)

# Windows
Get-Service ZehraSecFirewall
Status: Stopped
```

#### **Solutions:**

**Check configuration:**
```bash
# Validate configuration
python main.py --config config/firewall_advanced.json --validate

# Check for syntax errors
python -m json.tool config/firewall_advanced.json
```

**Check logs:**
```bash
# Linux
sudo journalctl -u zehrasec -f

# Manual start for debugging
sudo /opt/zehrasec/bin/zehrasec --debug --verbose
```

**Fix common configuration issues:**
```bash
# Reset to default config
cp config/firewall_default.json config/firewall_advanced.json

# Fix file permissions
sudo chown zehrasec:zehrasec /etc/zehrasec/*
sudo chmod 644 /etc/zehrasec/firewall_advanced.json
```

### **❌ Problem: Service Crashes Repeatedly**

#### **Symptoms:**
```
Service starts but stops after few seconds
Memory usage spikes then crash
Segmentation fault errors
```

#### **Solutions:**

**Check system resources:**
```bash
# Monitor resources
top -p $(pgrep zehrasec)
htop

# Check memory usage
free -h
df -h
```

**Reduce resource usage:**
```json
// In config/firewall_advanced.json
{
  "performance": {
    "max_threads": 4,
    "memory_limit": "1GB",
    "packet_buffer_size": 1024
  }
}
```

**Run in safe mode:**
```bash
# Start with minimal features
python main.py --safe-mode --config config/firewall_minimal.json
```

---

## 🌐 **Web Console Issues**

### **❌ Problem: Can't Access Web Console**

#### **Symptoms:**
```
This site can't be reached
Connection refused on https://localhost:8443
```

#### **Solutions:**

**Check service status:**
```bash
# Verify service is running
curl -I https://localhost:8443

# Check process
ps aux | grep zehrasec
```

**Verify network configuration:**
```bash
# Check if port is listening
netstat -tulpn | grep :8443
ss -tulpn | grep :8443

# Test with different IP
curl -k https://127.0.0.1:8443
curl -k https://0.0.0.0:8443
```

**Check firewall rules:**
```bash
# Linux
sudo iptables -L | grep 8443
sudo ufw status

# macOS
sudo pfctl -sr | grep 8443

# Windows
netsh advfirewall firewall show rule name="ZehraSec-HTTPS"
```

### **❌ Problem: Web Console Loads But Login Fails**

#### **Symptoms:**
```
"Invalid credentials" error
Login page keeps reloading
Authentication timeout
```

#### **Solutions:**

**Reset admin password:**
```bash
# Reset to default
python tools/reset_password.py --user admin --password zehrasec123

# Create new admin user
python tools/create_user.py --user newadmin --password newpassword --role admin
```

**Check authentication configuration:**
```json
// In config/firewall_advanced.json
{
  "authentication": {
    "method": "local",
    "session_timeout": 3600,
    "max_failed_attempts": 5,
    "lockout_duration": 300
  }
}
```

**Clear browser cache:**
```bash
# Clear SSL certificate cache
# Chrome: Settings > Privacy > Clear browsing data
# Firefox: Settings > Privacy > Clear Data
```

### **❌ Problem: Web Console Slow or Unresponsive**

#### **Symptoms:**
```
Pages load very slowly
Dashboard charts don't update
Frequent timeouts
```

#### **Solutions:**

**Optimize performance:**
```json
// In config/firewall_advanced.json
{
  "web_console": {
    "cache_enabled": true,
    "compression_enabled": true,
    "update_interval": 5000,
    "max_log_entries": 1000
  }
}
```

**Check system resources:**
```bash
# Monitor web server process
top -p $(pgrep -f "web_console")

# Check disk I/O
iostat -x 1

# Check network latency
ping localhost
```

---

## 🌐 **Network Connectivity Problems**

### **❌ Problem: Network Traffic Not Being Monitored**

#### **Symptoms:**
```
Dashboard shows no network activity
Packet counters remain at zero
No security events logged
```

#### **Solutions:**

**Check network interface:**
```bash
# List available interfaces
ip link show
ifconfig -a

# Verify ZehraSec is monitoring correct interface
python tools/check_interfaces.py
```

**Update configuration:**
```json
// In config/firewall_advanced.json
{
  "network": {
    "interface": "auto",  // or specific interface like "eth0"
    "promiscuous_mode": true,
    "capture_all_traffic": true
  }
}
```

**Check permissions:**
```bash
# Linux: Ensure raw socket permissions
sudo setcap cap_net_raw+ep /opt/zehrasec/bin/zehrasec

# Or run as root (not recommended for production)
sudo python main.py --config config/firewall_advanced.json
```

### **❌ Problem: False Positives Blocking Legitimate Traffic**

#### **Symptoms:**
```
Legitimate websites blocked
Internal applications can't connect
High number of blocked connections
```

#### **Solutions:**

**Review and adjust rules:**
```bash
# View recent blocks
curl -k https://localhost:8443/api/blocked-ips

# Whitelist legitimate IPs
curl -X POST https://localhost:8443/api/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "reason": "internal server"}'
```

**Tune sensitivity:**
```json
// In config/firewall_advanced.json
{
  "layers": {
    "layer3_ids_ips": {
      "sensitivity": "medium",  // high, medium, low
      "auto_block": false,
      "alert_only": true
    }
  }
}
```

**Disable specific detection rules:**
```bash
# List active rules
curl -k https://localhost:8443/api/rules

# Disable problematic rule
curl -X PUT https://localhost:8443/api/rules/SQL_INJECTION_001 \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

---

## ⚡ **Performance Issues**

### **❌ Problem: High CPU Usage**

#### **Symptoms:**
```
CPU usage consistently > 80%
System becomes unresponsive
Other applications slow down
```

#### **Solutions:**

**Optimize processing:**
```json
// In config/firewall_advanced.json
{
  "performance": {
    "max_threads": 2,  // Reduce from default
    "packet_processing_limit": 1000,
    "analysis_depth": "basic"  // vs "deep"
  }
}
```

**Disable resource-intensive features:**
```json
{
  "layers": {
    "layer4_threat_intel": {
      "ml_analysis": false,
      "behavioral_analysis": false
    }
  }
}
```

**Monitor resource usage:**
```bash
# Continuous monitoring
python tools/monitor_performance.py --interval 5

# Generate performance report
python tools/performance_report.py --duration 3600
```

### **❌ Problem: High Memory Usage**

#### **Symptoms:**
```
Memory usage grows over time
Out of memory errors
System swap usage high
```

#### **Solutions:**

**Configure memory limits:**
```json
// In config/firewall_advanced.json
{
  "memory": {
    "max_heap_size": "1GB",
    "packet_buffer_limit": 10000,
    "log_buffer_limit": 50000,
    "threat_cache_size": 100000
  }
}
```

**Enable garbage collection:**
```python
# In main.py configuration
import gc
gc.enable()
gc.set_threshold(700, 10, 10)
```

**Clear caches periodically:**
```bash
# Manual cache clear
curl -X POST https://localhost:8443/api/cache/clear

# Setup automatic cache clearing
python tools/setup_cache_cleanup.py --interval 3600
```

---

## 🛡️ **Security Features Not Working**

### **❌ Problem: Threats Not Being Detected**

#### **Symptoms:**
```
Known malicious traffic passes through
No threat alerts generated
Security dashboard shows no activity
```

#### **Solutions:**

**Update threat intelligence:**
```bash
# Manual update
curl -X POST https://localhost:8443/api/threat-intel/update

# Check last update time
curl -k https://localhost:8443/api/threat-intel/status
```

**Verify rule sets:**
```bash
# Check loaded rules
curl -k https://localhost:8443/api/rules/loaded

# Reload rules
curl -X POST https://localhost:8443/api/rules/reload
```

**Test detection with safe samples:**
```bash
# Test SQL injection detection
curl -k "https://localhost:8443/test?id=1' OR '1'='1"

# Test XSS detection  
curl -k "https://localhost:8443/test?input=<script>alert('xss')</script>"
```

### **❌ Problem: Machine Learning Features Not Working**

#### **Symptoms:**
```
ML analysis shows as disabled
Behavioral detection not functioning
AI threat scoring unavailable
```

#### **Solutions:**

**Check ML dependencies:**
```bash
# Verify ML libraries
pip list | grep -E "(tensorflow|pytorch|scikit-learn)"

# Install missing dependencies
pip install tensorflow scikit-learn numpy pandas
```

**Verify model files:**
```bash
# Check model directory
ls -la models/
python tools/verify_models.py
```

**Enable ML features:**
```json
// In config/firewall_advanced.json
{
  "machine_learning": {
    "enabled": true,
    "model_path": "./models/",
    "analysis_mode": "real_time",
    "confidence_threshold": 0.7
  }
}
```

---

## 💾 **Database and Logging Issues**

### **❌ Problem: Logs Not Being Generated**

#### **Symptoms:**
```
Empty log files
No entries in web console logs
Log directory doesn't exist
```

#### **Solutions:**

**Check logging configuration:**
```json
// In config/firewall_advanced.json
{
  "logging": {
    "enabled": true,
    "level": "INFO",
    "file": "logs/zehrasec.log",
    "max_size": "100MB",
    "backup_count": 5
  }
}
```

**Verify log directory permissions:**
```bash
# Create log directory
mkdir -p logs
chmod 755 logs

# Fix ownership
sudo chown zehrasec:zehrasec logs/
```

**Test logging:**
```bash
# Generate test log entry
curl -X POST https://localhost:8443/api/test/log \
  -H "Content-Type: application/json" \
  -d '{"message": "test log entry"}'

# Check if entry appears
tail -f logs/zehrasec.log
```

### **❌ Problem: Database Connection Errors**

#### **Symptoms:**
```
Database connection failed
Could not connect to database
Database locked errors
```

#### **Solutions:**

**Check database configuration:**
```json
// In config/firewall_advanced.json
{
  "database": {
    "type": "sqlite",
    "path": "data/zehrasec.db",
    "connection_timeout": 30,
    "retry_attempts": 3
  }
}
```

**Reset database:**
```bash
# Backup existing database
cp data/zehrasec.db data/zehrasec.db.backup

# Initialize new database
python tools/init_database.py --force

# Restore from backup if needed
python tools/restore_database.py --backup data/zehrasec.db.backup
```

---

## 💻 **Platform-Specific Issues**

### **🪟 Windows Issues**

#### **PowerShell Execution Policy**
```powershell
# Check current policy
Get-ExecutionPolicy

# Set policy to allow scripts
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### **Windows Defender Interference**
```powershell
# Add ZehraSec to exclusions
Add-MpPreference -ExclusionPath "C:\Program Files\ZehraSec"
Add-MpPreference -ExclusionProcess "zehrasec.exe"
```

#### **Service Installation Issues**
```powershell
# Install service manually
New-Service -Name "ZehraSecFirewall" -BinaryPathName "C:\Program Files\ZehraSec\bin\zehrasec.exe"

# Start service
Start-Service ZehraSecFirewall
```

### **🐧 Linux Issues**

#### **SELinux Denials**
```bash
# Check SELinux status
sestatus

# View denials
ausearch -m AVC -ts recent

# Create custom policy
audit2allow -M zehrasec_policy < /var/log/audit/audit.log
semodule -i zehrasec_policy.pp
```

#### **Systemd Service Issues**
```bash
# Reload systemd
sudo systemctl daemon-reload

# Check service file
sudo systemctl cat zehrasec

# View detailed status
sudo systemctl status zehrasec -l --no-pager
```

### **🍎 macOS Issues**

#### **Gatekeeper Blocking**
```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine /Applications/ZehraSec.app

# Add to allowed applications
spctl --add /Applications/ZehraSec.app
```

#### **Network Extension Approval**
```bash
# Check network extensions
systemextensionsctl list

# Reset network extensions (if needed)
sudo systemextensionsctl reset
```

---

## 🆘 **Emergency Recovery**

### **🚨 Complete System Recovery**

#### **Safe Mode Boot**
```bash
# Start in safe mode
python main.py --safe-mode --config config/firewall_minimal.json

# Disable all security layers
python main.py --disable-all-layers
```

#### **Reset to Factory Defaults**
```bash
# Backup current configuration
cp config/firewall_advanced.json config/firewall_advanced.json.backup

# Reset to defaults
cp config/firewall_default.json config/firewall_advanced.json

# Clear all data
python tools/factory_reset.py --confirm
```

#### **Emergency Stop**
```bash
# Kill all ZehraSec processes
pkill -f zehrasec
sudo systemctl stop zehrasec

# Remove firewall rules (if ZehraSec added them)
python tools/remove_firewall_rules.py
```

### **🔧 Configuration Recovery**

#### **Backup Configuration**
```bash
# Create backup
python tools/backup_config.py --output backup_$(date +%Y%m%d_%H%M%S).tar.gz

# List backups
python tools/list_backups.py
```

#### **Restore Configuration**
```bash
# Restore from backup
python tools/restore_config.py --backup backup_20250619_143022.tar.gz

# Validate restored configuration
python tools/validate_config.py --config config/firewall_advanced.json
```

---

## 📞 **Getting Additional Help**

### **🆘 Support Channels**
- **Emergency Support**: emergency@zehrasec.com
- **Technical Support**: support@zehrasec.com
- **Community Forum**: https://community.zehrasec.com
- **GitHub Issues**: https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall/issues

### **📋 Information to Include in Support Requests**

1. **System Information**
   ```bash
   # Generate system report
   python tools/generate_support_report.py
   ```

2. **Configuration Files**
   - Current configuration file
   - Log files (last 1000 lines)
   - Error messages (exact text)

3. **Reproduction Steps**
   - Detailed steps to reproduce the issue
   - Expected vs actual behavior
   - Screenshots if applicable

### **🔧 Self-Help Tools**
```bash
# Comprehensive diagnostic
python diagnostics.py --full --output diagnostic_report.html

# Configuration validator
python tools/validate_all.py

# Performance profiler
python tools/profile_performance.py --duration 300
```

---

## 📚 **Additional Resources**

- **[Debugging Guide](17-Debugging-Guide.md)** - Advanced debugging techniques
- **[Performance Optimization](18-Performance-Optimization.md)** - Detailed performance tuning
- **[Maintenance Guide](19-Maintenance-Guide.md)** - Regular maintenance procedures
- **[FAQ](34-FAQ.md)** - Frequently asked questions

---

**Copyright © 2025 ZehraSec - Yashab Alam**  
*Troubleshooting Guide v3.0.0*
