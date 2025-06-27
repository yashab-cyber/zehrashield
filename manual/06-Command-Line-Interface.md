# ZehraSec Advanced Firewall - Command Line Interface

![CLI Guide](https://img.shields.io/badge/💻-CLI%20Guide-black?style=for-the-badge)

**Version 1.0** | **ZehraSec Advanced Firewall v2.0+**

---

## 🚀 **CLI Overview**

The ZehraSec Command Line Interface (CLI) provides powerful tools for system administrators and developers to manage, configure, and monitor the advanced firewall system directly from the terminal. The CLI offers full functionality equivalent to the web console with additional automation capabilities.

---

## 📋 **Basic Commands**

### **System Management**

#### **Start/Stop/Restart Services**
```bash
# Start ZehraSec Firewall
python main.py --start

# Start with specific configuration
python main.py --start --config /path/to/config.json

# Start in daemon mode
python main.py --daemon --config config/firewall_advanced.json

# Stop the firewall
python main.py --stop

# Restart the firewall
python main.py --restart

# Check service status
python main.py --status
```

#### **System Information**
```bash
# Display system information
python main.py --info

# Show version information
python main.py --version

# Display detailed system health
python main.py --health-check

# Show configuration summary
python main.py --show-config

# Display license information
python main.py --license-info
```

### **Configuration Management**

#### **Configuration Commands**
```bash
# Validate configuration file
python main.py --validate-config --config config/firewall_advanced.json

# Generate default configuration
python main.py --generate-config --output config/default.json

# Reload configuration without restart
python main.py --reload-config

# Backup current configuration
python main.py --backup-config --output backup/config-$(date +%Y%m%d).json

# Restore configuration from backup
python main.py --restore-config --input backup/config-20241201.json
```

#### **Advanced Configuration**
```bash
# Interactive configuration wizard
python main.py --configure

# Set specific configuration values
python main.py --set-config security.threat_detection.enabled=true
python main.py --set-config network.max_connections=100000

# Get configuration values
python main.py --get-config security.threat_detection.enabled
python main.py --get-config network.interfaces

# Reset configuration to defaults
python main.py --reset-config --confirm
```

---

## 🛡️ **Security Commands**

### **Rule Management**

#### **Firewall Rules**
```bash
# List all rules
python main.py --list-rules

# Add a new rule
python main.py --add-rule --source 192.168.1.0/24 --destination any --port 80 --action allow

# Remove a rule by ID
python main.py --remove-rule --id 12345

# Enable/disable a rule
python main.py --enable-rule --id 12345
python main.py --disable-rule --id 12345

# Import rules from file
python main.py --import-rules --file rules/web_server_rules.json

# Export rules to file
python main.py --export-rules --output rules/current_rules.json
```

#### **IP Management**
```bash
# Block an IP address
python main.py --block-ip 192.168.1.100 --reason "Suspicious activity"

# Unblock an IP address
python main.py --unblock-ip 192.168.1.100

# List blocked IPs
python main.py --list-blocked-ips

# Add IP to whitelist
python main.py --whitelist-ip 192.168.1.50

# Remove IP from whitelist
python main.py --remove-whitelist-ip 192.168.1.50

# Emergency block (immediate action)
python main.py --emergency-block 10.0.0.100
```

### **Threat Detection**

#### **Threat Management**
```bash
# Scan for active threats
python main.py --scan-threats

# View threat summary
python main.py --threat-summary

# Export threat data
python main.py --export-threats --format json --output threats-$(date +%Y%m%d).json

# Update threat intelligence
python main.py --update-threats

# View threat statistics
python main.py --threat-stats --timeframe 24h
```

#### **Machine Learning**
```bash
# Train ML models
python main.py --train-ml --dataset training_data.csv

# Evaluate model performance
python main.py --evaluate-ml --test-dataset test_data.csv

# Update ML models
python main.py --update-ml-models

# Show ML model status
python main.py --ml-status

# Export ML model
python main.py --export-ml-model --output models/threat_detection_model.pkl
```

---

## 📊 **Monitoring Commands**

### **Real-time Monitoring**

#### **Live Statistics**
```bash
# Display live traffic statistics
python main.py --live-stats

# Monitor specific interface
python main.py --monitor-interface eth0

# Show connection statistics
python main.py --connection-stats

# Monitor threat detection
python main.py --monitor-threats

# Display bandwidth usage
python main.py --bandwidth-stats --interface all
```

#### **Log Management**
```bash
# View recent logs
python main.py --view-logs --lines 100

# Tail logs in real-time
python main.py --tail-logs

# Filter logs by level
python main.py --view-logs --level error --lines 50

# Search logs for specific terms
python main.py --search-logs --query "failed login" --timeframe 1h

# Export logs
python main.py --export-logs --output logs/export-$(date +%Y%m%d).log --timeframe 24h
```

### **Performance Monitoring**

#### **Performance Statistics**
```bash
# Show performance metrics
python main.py --performance-stats

# Generate performance report
python main.py --performance-report --output reports/performance-$(date +%Y%m%d).html

# Monitor resource usage
python main.py --resource-monitor

# Benchmark system performance
python main.py --benchmark --duration 300

# Show top connections
python main.py --top-connections --count 10
```

---

## 🔧 **Maintenance Commands**

### **Database Management**

#### **Database Operations**
```bash
# Backup database
python main.py --backup-database --output backup/db-$(date +%Y%m%d).sql

# Restore database
python main.py --restore-database --input backup/db-20241201.sql

# Optimize database
python main.py --optimize-database

# Clean old logs from database
python main.py --cleanup-logs --older-than 30d

# Database integrity check
python main.py --check-database-integrity
```

### **System Maintenance**

#### **Maintenance Operations**
```bash
# Rotate log files
python main.py --rotate-logs

# Clean temporary files
python main.py --cleanup-temp

# Update threat intelligence feeds
python main.py --update-intel-feeds

# System cleanup
python main.py --system-cleanup

# Generate system report
python main.py --system-report --output reports/system-$(date +%Y%m%d).html
```

---

## 🔗 **Integration Commands**

### **API Integration**

#### **API Management**
```bash
# Generate API key
python main.py --generate-api-key --name "Integration Service" --permissions read,write

# List API keys
python main.py --list-api-keys

# Revoke API key
python main.py --revoke-api-key --key-id 12345

# Test API connectivity
python main.py --test-api --endpoint https://api.example.com

# API health check
python main.py --api-health-check
```

### **External Integrations**

#### **SIEM Integration**
```bash
# Configure SIEM integration
python main.py --configure-siem --type splunk --server siem.company.com --port 514

# Test SIEM connectivity
python main.py --test-siem-connection

# Send test event to SIEM
python main.py --send-test-event --siem-type elasticsearch

# Export events for SIEM
python main.py --export-siem-events --format cef --output siem_export.log
```

---

## 🚨 **Emergency Commands**

### **Emergency Response**

#### **Critical Operations**
```bash
# Emergency shutdown
python main.py --emergency-shutdown

# Block all traffic (lockdown mode)
python main.py --lockdown --duration 3600

# Emergency rule activation
python main.py --emergency-rules --profile high_security

# Incident response mode
python main.py --incident-response --level critical

# Generate emergency report
python main.py --emergency-report --output emergency-$(date +%Y%m%d%H%M).json
```

### **Recovery Operations**

#### **System Recovery**
```bash
# Restore from safe configuration
python main.py --safe-mode

# Reset to factory defaults
python main.py --factory-reset --confirm

# Rollback to previous configuration
python main.py --rollback --version previous

# Emergency configuration restore
python main.py --emergency-restore --config backup/last_known_good.json
```

---

## 📋 **Command Options & Flags**

### **Global Options**

| Option | Description | Example |
|--------|-------------|---------|
| `--config` | Specify configuration file | `--config /etc/zehrasec/config.json` |
| `--log-level` | Set logging level | `--log-level debug` |
| `--quiet` | Suppress output | `--quiet` |
| `--verbose` | Verbose output | `--verbose` |
| `--dry-run` | Simulate action without executing | `--dry-run` |
| `--force` | Force action without confirmation | `--force` |
| `--output` | Specify output file/directory | `--output /tmp/export.json` |
| `--format` | Output format (json, xml, csv, text) | `--format json` |
| `--timeout` | Command timeout in seconds | `--timeout 300` |

### **Common Flags**

| Flag | Short | Description |
|------|-------|-------------|
| `--help` | `-h` | Show help message |
| `--version` | `-v` | Show version information |
| `--config` | `-c` | Configuration file path |
| `--output` | `-o` | Output file path |
| `--input` | `-i` | Input file path |
| `--force` | `-f` | Force operation |
| `--quiet` | `-q` | Quiet mode |
| `--verbose` | `-V` | Verbose mode |
| `--debug` | `-d` | Debug mode |

---

## 🔄 **Automation & Scripting**

### **Batch Operations**

#### **Script Examples**
```bash
#!/bin/bash
# Daily maintenance script

# Update threat intelligence
python main.py --update-threats --quiet

# Rotate logs
python main.py --rotate-logs

# Generate daily report
python main.py --system-report --output reports/daily-$(date +%Y%m%d).html

# Backup configuration
python main.py --backup-config --output backup/config-$(date +%Y%m%d).json

# Clean old backups (keep 30 days)
find backup/ -name "*.json" -mtime +30 -delete

echo "Daily maintenance completed"
```

#### **PowerShell Script (Windows)**
```powershell
# Windows maintenance script
$date = Get-Date -Format "yyyyMMdd"

# Update threats
python main.py --update-threats --quiet

# Generate report
python main.py --system-report --output "reports\daily-$date.html"

# Backup configuration
python main.py --backup-config --output "backup\config-$date.json"

Write-Output "Maintenance completed successfully"
```

### **Configuration Scripts**

#### **Initial Setup Script**
```bash
#!/bin/bash
# Initial ZehraSec setup script

echo "Setting up ZehraSec Advanced Firewall..."

# Generate initial configuration
python main.py --generate-config --output config/initial.json

# Configure basic security settings
python main.py --set-config security.threat_detection.enabled=true
python main.py --set-config security.ml_detection.enabled=true
python main.py --set-config logging.level=info

# Create default rules
python main.py --import-rules --file templates/default_rules.json

# Start the firewall
python main.py --start --config config/initial.json

echo "ZehraSec setup completed!"
```

---

## 🔍 **Troubleshooting CLI Issues**

### **Common CLI Problems**

#### **Permission Issues**
```bash
# Check file permissions
ls -la main.py

# Fix permissions
chmod +x main.py

# Run with appropriate privileges
sudo python main.py --start
```

#### **Configuration Issues**
```bash
# Validate configuration
python main.py --validate-config --verbose

# Show configuration problems
python main.py --check-config --detailed

# Reset to safe configuration
python main.py --safe-mode
```

#### **Connection Issues**
```bash
# Test connectivity
python main.py --test-connection --host localhost --port 8080

# Check service status
python main.py --status --detailed

# View error logs
python main.py --view-logs --level error --lines 50
```

---

## 📚 **CLI Reference**

### **Exit Codes**

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Permission denied |
| 4 | Service not running |
| 5 | Network error |
| 6 | Database error |
| 7 | Invalid arguments |
| 8 | Timeout |
| 9 | Emergency shutdown |

### **Environment Variables**

| Variable | Description | Default |
|----------|-------------|---------|
| `ZEHRASEC_CONFIG` | Default configuration file | `config/firewall_advanced.json` |
| `ZEHRASEC_LOG_LEVEL` | Default log level | `info` |
| `ZEHRASEC_DATA_DIR` | Data directory | `data/` |
| `ZEHRASEC_LOG_DIR` | Log directory | `logs/` |
| `ZEHRASEC_BACKUP_DIR` | Backup directory | `backup/` |

---

## 📞 **CLI Support**

For CLI-specific support:

- **Documentation**: [Troubleshooting Guide](16-Troubleshooting-Guide.md)
- **CLI Help**: `python main.py --help`
- **Support**: cli-support@zehrasec.com
- **Community**: [CLI Forum](https://community.zehrasec.com/cli)

---

**© 2024 ZehraSec. All rights reserved.**

*Master the command line for maximum control and automation of your ZehraSec Advanced Firewall.*
