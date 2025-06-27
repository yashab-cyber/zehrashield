# 21. Logging Guide

![ZehraSec](https://img.shields.io/badge/🛡️-ZehraSec%20Logging-green?style=for-the-badge&logo=file-text)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## 📋 **Overview**

ZehraSec Advanced Firewall provides comprehensive logging capabilities for security events, system activities, network traffic, and performance metrics. This guide covers log configuration, management, analysis, and best practices.

---

## 🔧 **Log Configuration**

### **Default Log Locations**
```
/logs/zehrasec.log          # Main application log
/logs/security.log          # Security events
/logs/network.log           # Network traffic
/logs/system.log            # System activities
/logs/performance.log       # Performance metrics
/logs/audit.log             # Audit trail
/logs/error.log             # Error messages
/logs/debug.log             # Debug information
```

### **Configuration File**
```json
{
  "logging": {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "rotation": {
      "max_size": "100MB",
      "backup_count": 30,
      "when": "midnight"
    },
    "handlers": {
      "file": {
        "enabled": true,
        "path": "/logs/zehrasec.log"
      },
      "console": {
        "enabled": true,
        "level": "WARNING"
      },
      "syslog": {
        "enabled": false,
        "facility": "local0",
        "address": "localhost:514"
      },
      "elasticsearch": {
        "enabled": false,
        "host": "localhost:9200",
        "index": "zehrasec-logs"
      }
    }
  }
}
```

---

## 📊 **Log Categories**

### **1. Security Logs**
- **Threat Detection**: Malware, intrusions, anomalies
- **Access Control**: Authentication, authorization failures
- **Policy Violations**: Rule violations, blocked connections
- **Incident Response**: Security incidents, responses

```log
2025-06-19 10:15:32 - SECURITY - WARNING - Suspicious IP detected: 192.168.1.100
2025-06-19 10:15:35 - SECURITY - CRITICAL - Malware blocked: trojan.exe from 10.0.0.5
2025-06-19 10:15:40 - SECURITY - INFO - Zero-trust verification passed for user: john.doe
```

### **2. Network Logs**
- **Traffic Analysis**: Packet inspection, flow monitoring
- **Connection Tracking**: Session establishment, termination
- **Bandwidth Usage**: Data transfer statistics
- **Protocol Analysis**: Protocol-specific events

```log
2025-06-19 10:20:15 - NETWORK - INFO - Connection established: 192.168.1.10:443 -> 8.8.8.8:53
2025-06-19 10:20:18 - NETWORK - WARNING - High bandwidth usage detected: 95% utilization
2025-06-19 10:20:22 - NETWORK - DEBUG - DNS query: example.com from 192.168.1.15
```

### **3. System Logs**
- **Service Status**: Start, stop, restart events
- **Configuration Changes**: Policy updates, rule modifications
- **Resource Usage**: CPU, memory, disk utilization
- **Error Conditions**: System errors, exceptions

```log
2025-06-19 10:25:10 - SYSTEM - INFO - ZehraSec firewall started successfully
2025-06-19 10:25:15 - SYSTEM - WARNING - High memory usage: 85% utilized
2025-06-19 10:25:20 - SYSTEM - ERROR - Failed to load configuration: invalid JSON
```

### **4. Audit Logs**
- **Administrative Actions**: User management, configuration changes
- **Policy Updates**: Rule additions, modifications, deletions
- **Access Attempts**: Login attempts, privilege escalations
- **Data Access**: File access, database queries

```log
2025-06-19 10:30:05 - AUDIT - INFO - Admin login: user=admin, ip=192.168.1.5
2025-06-19 10:30:10 - AUDIT - WARNING - Failed login attempt: user=hacker, ip=external
2025-06-19 10:30:15 - AUDIT - INFO - Policy updated: firewall_rules.json by admin
```

---

## ⚙️ **Log Management**

### **Log Rotation**
```python
# Configure log rotation
import logging.handlers

# Size-based rotation
handler = logging.handlers.RotatingFileHandler(
    'zehrasec.log',
    maxBytes=100*1024*1024,  # 100MB
    backupCount=30
)

# Time-based rotation
handler = logging.handlers.TimedRotatingFileHandler(
    'zehrasec.log',
    when='midnight',
    interval=1,
    backupCount=30
)
```

### **Log Compression**
```bash
# Automatic compression for old logs
find /logs -name "*.log.*" -mtime +7 -exec gzip {} \;

# Archive logs older than 30 days
find /logs -name "*.log.*.gz" -mtime +30 -exec mv {} /logs/archive/ \;
```

### **Log Cleanup**
```bash
#!/bin/bash
# cleanup_logs.sh

LOG_DIR="/logs"
ARCHIVE_DIR="/logs/archive"
DAYS_TO_KEEP=90

# Create archive directory
mkdir -p $ARCHIVE_DIR

# Archive old logs
find $LOG_DIR -name "*.log.*.gz" -mtime +30 -exec mv {} $ARCHIVE_DIR/ \;

# Delete very old archives
find $ARCHIVE_DIR -name "*.log.*.gz" -mtime +$DAYS_TO_KEEP -delete

echo "Log cleanup completed"
```

---

## 🔍 **Log Analysis**

### **Command Line Tools**
```bash
# View recent security events
tail -f /logs/security.log

# Search for specific IP address
grep "192.168.1.100" /logs/*.log

# Count error messages
grep -c "ERROR" /logs/zehrasec.log

# View logs from specific time period
sed -n '/2025-06-19 10:00:00/,/2025-06-19 11:00:00/p' /logs/zehrasec.log

# Extract unique IP addresses
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" /logs/network.log | sort | uniq
```

### **Log Analysis Scripts**
```python
# analyze_logs.py
import re
import json
from collections import Counter
from datetime import datetime

def analyze_security_logs():
    """Analyze security log patterns"""
    threats = Counter()
    ips = Counter()
    
    with open('/logs/security.log', 'r') as f:
        for line in f:
            if 'CRITICAL' in line:
                # Extract threat type
                if 'malware' in line.lower():
                    threats['malware'] += 1
                elif 'intrusion' in line.lower():
                    threats['intrusion'] += 1
                
                # Extract IP addresses
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ips_found = re.findall(ip_pattern, line)
                for ip in ips_found:
                    ips[ip] += 1
    
    return {
        'top_threats': threats.most_common(10),
        'top_ips': ips.most_common(10)
    }

# Generate daily report
def generate_daily_report():
    """Generate daily security report"""
    analysis = analyze_security_logs()
    
    report = {
        'date': datetime.now().isoformat(),
        'summary': {
            'total_threats': sum(dict(analysis['top_threats']).values()),
            'unique_ips': len(analysis['top_ips']),
            'top_threats': analysis['top_threats'],
            'suspicious_ips': analysis['top_ips']
        }
    }
    
    with open('/logs/reports/daily_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    return report
```

---

## 🚨 **Real-time Monitoring**

### **Log Monitoring Setup**
```python
# log_monitor.py
import time
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogMonitor(FileSystemEventHandler):
    def __init__(self):
        self.critical_patterns = [
            r'CRITICAL.*malware',
            r'CRITICAL.*intrusion',
            r'ERROR.*system failure'
        ]
    
    def on_modified(self, event):
        if event.src_path.endswith('.log'):
            self.check_for_alerts(event.src_path)
    
    def check_for_alerts(self, log_file):
        """Check for critical events in log file"""
        try:
            with open(log_file, 'r') as f:
                # Read only new lines
                f.seek(0, 2)  # Go to end of file
                lines = f.readlines()
                
                for line in lines:
                    for pattern in self.critical_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            self.send_alert(line.strip())
        except Exception as e:
            print(f"Error monitoring {log_file}: {e}")
    
    def send_alert(self, message):
        """Send alert for critical events"""
        # Send email, SMS, or webhook notification
        print(f"ALERT: {message}")
        # Additional alerting logic here

# Start monitoring
monitor = LogMonitor()
observer = Observer()
observer.schedule(monitor, '/logs', recursive=True)
observer.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
observer.join()
```

---

## 📈 **Performance Monitoring**

### **Log Performance Metrics**
```python
# log_performance.py
import time
import psutil
from datetime import datetime

def log_performance_metrics():
    """Log system performance metrics"""
    metrics = {
        'timestamp': datetime.now().isoformat(),
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_io': psutil.net_io_counters()._asdict(),
        'process_count': len(psutil.pids())
    }
    
    with open('/logs/performance.log', 'a') as f:
        f.write(f"{metrics['timestamp']} - PERFORMANCE - INFO - {metrics}\n")
    
    return metrics

# Schedule performance logging
while True:
    log_performance_metrics()
    time.sleep(60)  # Log every minute
```

---

## 🔐 **Log Security**

### **Log Encryption**
```python
# log_encryption.py
from cryptography.fernet import Fernet
import base64

class LogEncryption:
    def __init__(self, key=None):
        if key:
            self.key = key
        else:
            self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def encrypt_log_entry(self, message):
        """Encrypt sensitive log entries"""
        encrypted = self.cipher.encrypt(message.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_log_entry(self, encrypted_message):
        """Decrypt log entries for analysis"""
        encrypted_bytes = base64.b64decode(encrypted_message.encode())
        decrypted = self.cipher.decrypt(encrypted_bytes)
        return decrypted.decode()

# Usage example
log_crypto = LogEncryption()
sensitive_data = "User john.doe accessed classified document"
encrypted_entry = log_crypto.encrypt_log_entry(sensitive_data)
```

### **Log Integrity Verification**
```python
# log_integrity.py
import hashlib
import hmac

class LogIntegrity:
    def __init__(self, secret_key):
        self.secret_key = secret_key.encode()
    
    def sign_log_entry(self, message):
        """Create HMAC signature for log entry"""
        signature = hmac.new(
            self.secret_key,
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{message}|{signature}"
    
    def verify_log_entry(self, signed_message):
        """Verify log entry integrity"""
        try:
            message, signature = signed_message.rsplit('|', 1)
            expected_signature = hmac.new(
                self.secret_key,
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(signature, expected_signature)
        except ValueError:
            return False
```

---

## 📊 **Log Aggregation**

### **Centralized Logging**
```python
# centralized_logging.py
import logging
import logging.handlers
import json
from datetime import datetime

class CentralizedLogger:
    def __init__(self, config):
        self.config = config
        self.setup_handlers()
    
    def setup_handlers(self):
        """Setup multiple log handlers"""
        self.logger = logging.getLogger('zehrasec')
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        if self.config.get('file_handler', {}).get('enabled'):
            file_handler = logging.handlers.RotatingFileHandler(
                self.config['file_handler']['path'],
                maxBytes=100*1024*1024,
                backupCount=30
            )
            file_handler.setLevel(logging.INFO)
            self.logger.addHandler(file_handler)
        
        # Syslog handler
        if self.config.get('syslog_handler', {}).get('enabled'):
            syslog_handler = logging.handlers.SysLogHandler(
                address=self.config['syslog_handler']['address']
            )
            syslog_handler.setLevel(logging.WARNING)
            self.logger.addHandler(syslog_handler)
        
        # Elasticsearch handler (custom)
        if self.config.get('elasticsearch_handler', {}).get('enabled'):
            es_handler = ElasticsearchHandler(
                self.config['elasticsearch_handler']
            )
            es_handler.setLevel(logging.INFO)
            self.logger.addHandler(es_handler)

class ElasticsearchHandler(logging.Handler):
    def __init__(self, config):
        super().__init__()
        self.config = config
        # Initialize Elasticsearch client
    
    def emit(self, record):
        """Send log record to Elasticsearch"""
        try:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': record.levelname,
                'message': record.getMessage(),
                'module': record.module,
                'funcName': record.funcName,
                'lineno': record.lineno
            }
            # Send to Elasticsearch
            # self.es_client.index(index='zehrasec-logs', body=log_entry)
        except Exception as e:
            print(f"Failed to send log to Elasticsearch: {e}")
```

---

## 🛠️ **Troubleshooting**

### **Common Log Issues**

**1. Log Files Not Created**
```bash
# Check permissions
ls -la /logs/
chmod 755 /logs/
chown zehrasec:zehrasec /logs/

# Check disk space
df -h /logs/
```

**2. Log Rotation Not Working**
```bash
# Check logrotate configuration
cat /etc/logrotate.d/zehrasec

# Test logrotate
logrotate -d /etc/logrotate.d/zehrasec
```

**3. High Log Volume**
```bash
# Monitor log growth
watch -n 1 'ls -lh /logs/*.log'

# Reduce log level
# Change from DEBUG to INFO or WARNING
```

**4. Missing Log Entries**
```bash
# Check if service is running
systemctl status zehrasec

# Verify log configuration
python -c "import json; print(json.load(open('config/firewall_advanced.json'))['logging'])"
```

---

## 📋 **Best Practices**

### **Log Management**
1. **Set appropriate log levels** for different environments
2. **Implement log rotation** to prevent disk space issues
3. **Monitor log file sizes** and growth rates
4. **Secure sensitive logs** with encryption
5. **Backup critical logs** regularly

### **Log Analysis**
1. **Use structured logging** formats (JSON, key-value pairs)
2. **Implement log correlation** for better analysis
3. **Create automated reports** for regular review
4. **Set up real-time alerts** for critical events
5. **Archive old logs** for compliance requirements

### **Performance**
1. **Use asynchronous logging** for high-volume systems
2. **Implement log buffering** to reduce I/O operations
3. **Monitor logging overhead** on system performance
4. **Use appropriate log levels** to control volume
5. **Implement log sampling** for very high-volume events

---

## 📞 **Support**

For logging-related issues:
- **Email**: logging-support@zehrasec.com
- **Documentation**: https://docs.zehrasec.com/logging
- **Community**: https://community.zehrasec.com/logging

---

*ZehraSec Advanced Firewall - Comprehensive Logging Solution*
