# ZehraShield Troubleshooting Guide

Welcome to the ZehraShield troubleshooting guide. This document provides solutions to common issues and debugging techniques for the ZehraShield Advanced Enterprise Firewall System.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Service Problems](#service-problems)
3. [Configuration Issues](#configuration-issues)
4. [Performance Problems](#performance-problems)
5. [Network Connectivity Issues](#network-connectivity-issues)
6. [Web Console Problems](#web-console-problems)
7. [Log Analysis](#log-analysis)
8. [Database Issues](#database-issues)
9. [Machine Learning Issues](#machine-learning-issues)
10. [SIEM Integration Problems](#siem-integration-problems)
11. [Emergency Procedures](#emergency-procedures)
12. [Advanced Debugging](#advanced-debugging)

## Installation Issues

### Problem: Installation Script Fails
**Symptoms:** Installation script exits with errors, missing dependencies
**Solutions:**
```bash
# Check system requirements
cat /etc/os-release
python3 --version
pip3 --version

# Update system packages
sudo apt update && sudo apt upgrade -y

# Install missing dependencies manually
sudo apt install python3-pip python3-dev build-essential

# Re-run installation with verbose output
sudo bash scripts/install.sh --verbose
```

### Problem: Permission Denied Errors
**Symptoms:** Cannot write to directories, service fails to start
**Solutions:**
```bash
# Fix file permissions
sudo chown -R root:root /opt/zehrashield
sudo chmod +x /opt/zehrashield/scripts/*.sh

# Fix service permissions
sudo chmod 644 /etc/systemd/system/zehrashield.service
sudo systemctl daemon-reload
```

### Problem: Python Dependencies Fail to Install
**Symptoms:** pip install errors, module import failures
**Solutions:**
```bash
# Use virtual environment
python3 -m venv /opt/zehrashield/venv
source /opt/zehrashield/venv/bin/activate
pip install -r requirements.txt

# Install system packages for problematic dependencies
sudo apt install python3-scapy python3-psutil python3-sklearn

# Clear pip cache and retry
pip cache purge
pip install --no-cache-dir -r requirements.txt
```

## Service Problems

### Problem: ZehraShield Service Won't Start
**Symptoms:** systemctl start fails, service remains inactive
**Diagnostic Commands:**
```bash
# Check service status
sudo systemctl status zehrashield

# View service logs
sudo journalctl -u zehrashield -f

# Check configuration
zehrashield-cli config validate

# Test manual startup
sudo python3 /opt/zehrashield/main.py --config /etc/zehrashield/firewall.json
```

**Common Solutions:**
```bash
# Fix configuration file
sudo nano /etc/zehrashield/firewall.json

# Reset service
sudo systemctl daemon-reload
sudo systemctl reset-failed zehrashield

# Check for port conflicts
sudo netstat -tulpn | grep :8080
sudo ss -tulpn | grep :8080
```

### Problem: Service Starts But Crashes
**Symptoms:** Service starts then stops, repeated restart attempts
**Solutions:**
```bash
# Check for crash logs
tail -f /var/log/zehrashield/error.log

# Run in debug mode
sudo python3 /opt/zehrashield/main.py --debug --config /etc/zehrashield/firewall.json

# Check memory usage
free -h
df -h

# Disable problematic layers temporarily
# Edit config to disable layers one by one
```

## Configuration Issues

### Problem: Invalid Configuration File
**Symptoms:** Validation errors, service won't start
**Solutions:**
```bash
# Validate JSON syntax
python3 -m json.tool /etc/zehrashield/firewall.json

# Use configuration validator
zehrashield-cli config validate

# Restore default configuration
sudo cp /opt/zehrashield/config/firewall.json /etc/zehrashield/firewall.json

# Check for required fields
grep -E '"enabled":|"port":|"interface":' /etc/zehrashield/firewall.json
```

### Problem: Network Interface Not Found
**Symptoms:** Layer 1 fails to start, interface binding errors
**Solutions:**
```bash
# List available interfaces
ip link show
ifconfig -a

# Update configuration with correct interface
sudo nano /etc/zehrashield/firewall.json
# Change "interface" field to existing interface (e.g., "eth0", "ens33")

# Check interface status
ip addr show eth0
```

### Problem: Port Conflicts
**Symptoms:** Web console won't start, binding errors
**Solutions:**
```bash
# Find what's using the port
sudo lsof -i :8080
sudo fuser -n tcp 8080

# Change port in configuration
sudo nano /etc/zehrashield/firewall.json
# Update "web_console" -> "port" to different port (e.g., 8888)

# Update firewall rules
sudo ufw allow 8888/tcp
```

## Performance Problems

### Problem: High CPU Usage
**Symptoms:** System sluggish, high load averages
**Diagnostic Commands:**
```bash
# Monitor CPU usage
top -p $(pgrep -f zehrashield)
htop

# Check performance metrics
zehrashield-cli stats

# Monitor packet processing
watch -n 1 'cat /var/log/zehrashield/performance.log | tail -5'
```

**Solutions:**
```bash
# Reduce packet processing load
# Edit config: reduce "max_concurrent_packets"
# Disable unnecessary layers temporarily

# Tune system parameters
echo 'net.core.rmem_max = 67108864' | sudo tee -a /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 5000' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Add CPU affinity
sudo systemctl edit zehrashield
# Add: [Service]
#      CPUAffinity=0-3
```

### Problem: Memory Leaks
**Symptoms:** Gradually increasing memory usage, system slowdown
**Solutions:**
```bash
# Monitor memory usage over time
watch -n 10 'ps aux | grep zehrashield'

# Enable memory profiling
# Add to config: "debug": {"memory_profiling": true}

# Restart service periodically (temporary fix)
# Add to crontab: 0 2 * * * systemctl restart zehrashield

# Check for large log files
du -sh /var/log/zehrashield/*
```

## Network Connectivity Issues

### Problem: Packets Not Being Filtered
**Symptoms:** Traffic bypasses firewall, rules not applied
**Solutions:**
```bash
# Check iptables rules
sudo iptables -L -n -v

# Verify packet capture
sudo tcpdump -i any -c 10

# Check interface binding
zehrashield-cli status

# Restart networking
sudo systemctl restart networking
sudo systemctl restart zehrashield
```

### Problem: Legitimate Traffic Blocked
**Symptoms:** Applications can't connect, services unreachable
**Solutions:**
```bash
# Check recent blocks
zehrashield-cli threats --hours 1

# Review firewall rules
zehrashield-cli rules

# Add temporary allow rule
# Via web console: Rules -> Add Rule -> Allow

# Check whitelist configuration
grep -A 10 "whitelist" /etc/zehrashield/firewall.json
```

## Web Console Problems

### Problem: Cannot Access Web Console
**Symptoms:** Browser can't connect, connection refused
**Solutions:**
```bash
# Check if web console is running
curl http://localhost:8080/
netstat -tulpn | grep :8080

# Check firewall rules
sudo ufw status
sudo iptables -L | grep 8080

# Check web console logs
tail -f /var/log/zehrashield/web.log

# Test different browser/incognito mode
# Clear browser cache and cookies
```

### Problem: Web Console Login Issues
**Symptoms:** Invalid credentials, authentication fails
**Solutions:**
```bash
# Reset admin password
sudo python3 /opt/zehrashield/scripts/reset_password.py

# Check authentication logs
grep "authentication" /var/log/zehrashield/security.log

# Verify user database
ls -la /var/lib/zehrashield/users.db

# Reset user database
sudo rm /var/lib/zehrashield/users.db
sudo systemctl restart zehrashield
```

## Log Analysis

### Understanding Log Levels
- **DEBUG**: Detailed debugging information
- **INFO**: General information about operations
- **WARNING**: Potentially harmful situations
- **ERROR**: Error events that allow application to continue
- **CRITICAL**: Very serious error events

### Key Log Files
```bash
# Main application log
tail -f /var/log/zehrashield/zehrashield.log

# Security events
tail -f /var/log/zehrashield/security.log

# Performance metrics
tail -f /var/log/zehrashield/performance.log

# Web console access
tail -f /var/log/zehrashield/web.log

# System service logs
sudo journalctl -u zehrashield -f
```

### Log Analysis Commands
```bash
# Search for errors
grep -i error /var/log/zehrashield/*.log

# Count threat types
awk '/threat_detected/ {print $5}' /var/log/zehrashield/security.log | sort | uniq -c

# Monitor real-time threats
tail -f /var/log/zehrashield/security.log | grep threat_detected

# Analyze performance trends
grep "performance_summary" /var/log/zehrashield/performance.log | tail -20
```

## Database Issues

### Problem: Database Connection Errors
**Symptoms:** Cannot save configurations, user login fails
**Solutions:**
```bash
# Check database file permissions
ls -la /var/lib/zehrashield/

# Fix database permissions
sudo chown zehrashield:zehrashield /var/lib/zehrashield/*.db
sudo chmod 640 /var/lib/zehrashield/*.db

# Recreate database
sudo rm /var/lib/zehrashield/firewall.db
sudo systemctl restart zehrashield
```

### Problem: Database Corruption
**Symptoms:** SQLite errors, data inconsistencies
**Solutions:**
```bash
# Check database integrity
sqlite3 /var/lib/zehrashield/firewall.db "PRAGMA integrity_check;"

# Repair database
sqlite3 /var/lib/zehrashield/firewall.db ".recover" | sqlite3 /var/lib/zehrashield/firewall_new.db

# Restore from backup
sudo cp /var/backups/zehrashield/firewall_backup_*.db /var/lib/zehrashield/firewall.db
```

## Machine Learning Issues

### Problem: ML Models Not Loading
**Symptoms:** Threat detection disabled, ML errors in logs
**Solutions:**
```bash
# Check ML dependencies
python3 -c "import sklearn, numpy, pandas; print('ML dependencies OK')"

# Verify model files
ls -la /var/lib/zehrashield/models/

# Retrain models
sudo python3 /opt/zehrashield/src/ml/threat_detection.py --retrain

# Disable ML temporarily
# Edit config: "machine_learning" -> "enabled": false
```

### Problem: Poor Threat Detection Accuracy
**Symptoms:** False positives/negatives, low detection rates
**Solutions:**
```bash
# Check training data quality
python3 /opt/zehrashield/src/ml/analyze_training_data.py

# Retrain with more data
# Collect more labeled samples
# Adjust ML parameters in configuration

# Review threat intelligence feeds
# Update threat signatures
# Tune detection thresholds
```

## SIEM Integration Problems

### Problem: SIEM Events Not Sending
**Symptoms:** Missing events in SIEM, connection errors
**Solutions:**
```bash
# Test SIEM connectivity
curl -X POST https://your-siem-server/api/events \
  -H "Content-Type: application/json" \
  -d '{"test": "connection"}'

# Check SIEM configuration
grep -A 10 "siem_integration" /etc/zehrashield/firewall.json

# Verify certificates
openssl verify /etc/ssl/certs/siem-ca.crt

# Check SIEM logs
tail -f /var/log/zehrashield/siem.log
```

## Emergency Procedures

### Emergency Shutdown
```bash
# Stop firewall immediately
sudo systemctl stop zehrashield

# Disable all filtering (emergency only)
sudo iptables -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Bypass mode (let all traffic through)
echo "BYPASS_MODE=true" | sudo tee /etc/zehrashield/emergency.conf
```

### Emergency Recovery
```bash
# Restore from backup
sudo systemctl stop zehrashield
sudo rm -rf /opt/zehrashield
sudo tar -xzf /var/backups/zehrashield/latest_backup.tar.gz -C /opt/
sudo systemctl start zehrashield

# Factory reset
sudo /opt/zehrashield/scripts/factory_reset.sh

# Safe mode startup
sudo python3 /opt/zehrashield/main.py --safe-mode
```

## Advanced Debugging

### Enable Debug Mode
```bash
# Edit configuration
sudo nano /etc/zehrashield/firewall.json
# Set: "debug": {"enabled": true, "level": "DEBUG"}

# Restart with debug
sudo systemctl restart zehrashield

# Watch debug logs
tail -f /var/log/zehrashield/debug.log
```

### Packet Tracing
```bash
# Trace packets through layers
echo "TRACE_PACKETS=true" | sudo tee -a /etc/zehrashield/debug.conf

# Monitor with tcpdump
sudo tcpdump -i any -w /tmp/capture.pcap &
# Generate test traffic
# Stop tcpdump and analyze
wireshark /tmp/capture.pcap
```

### Performance Profiling
```bash
# Enable profiling
python3 -m cProfile -o /tmp/zehrashield.prof /opt/zehrashield/main.py

# Analyze profile
python3 -c "
import pstats
stats = pstats.Stats('/tmp/zehrashield.prof')
stats.sort_stats('cumulative').print_stats(20)
"
```

### Memory Debugging
```bash
# Install memory profiler
pip3 install memory-profiler

# Profile memory usage
python3 -m memory_profiler /opt/zehrashield/main.py

# Monitor memory leaks
valgrind --tool=memcheck --leak-check=full python3 /opt/zehrashield/main.py
```

## Getting Help

### Check System Status
```bash
# Quick health check
zehrashield-cli status

# Detailed diagnostics
zehrashield-cli --diagnostics

# Generate support bundle
sudo /opt/zehrashield/scripts/generate_support_bundle.sh
```

### Collect Debug Information
```bash
# System information
uname -a
cat /etc/os-release
python3 --version

# Service status
systemctl status zehrashield
journalctl -u zehrashield --since "1 hour ago"

# Network configuration
ip addr show
ip route show
iptables -L -n

# Performance metrics
zehrashield-cli stats
df -h
free -h
```

### Community Support
- **GitHub Issues**: https://github.com/yashab-cyber/zehrashield/issues
- **Documentation**: https://zehrashield.zehrasec.com/docs
- **Security Issues**: security@zehrasec.com

### Enterprise Support
- **Support Portal**: https://support.zehrasec.com
- **Emergency Hotline**: Available with enterprise subscription
- **Professional Services**: Custom deployment and integration support

---

**Note**: This troubleshooting guide covers common scenarios. For complex issues or enterprise deployments, consider professional support services from ZehraSec.

**Security Notice**: When sharing logs or debug information for support, ensure no sensitive data (passwords, keys, private network information) is included.
