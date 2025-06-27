# Debugging Guide - ZehraSec Advanced Firewall

![Debugging](https://img.shields.io/badge/🐛-Debugging%20Guide-red?style=for-the-badge)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## 📋 **Table of Contents**

1. [Debug Mode Setup](#-debug-mode-setup)
2. [Logging and Monitoring](#-logging-and-monitoring)
3. [Network Traffic Analysis](#-network-traffic-analysis)
4. [Performance Profiling](#-performance-profiling)
5. [Memory Debugging](#-memory-debugging)
6. [Security Layer Debugging](#-security-layer-debugging)
7. [API Debugging](#-api-debugging)
8. [Database Debugging](#-database-debugging)
9. [Advanced Debugging Tools](#-advanced-debugging-tools)
10. [Remote Debugging](#-remote-debugging)

---

## 🐛 **Debug Mode Setup**

### **Enable Debug Mode**

#### **Command Line Method**
```bash
# Start with debug mode
python main.py --debug --verbose --config config/firewall_advanced.json

# Start with specific debug modules
python main.py --debug-modules="network,security,api" --config config/firewall_advanced.json
```

#### **Configuration File Method**
```json
// In config/firewall_advanced.json
{
  "debug": {
    "enabled": true,
    "level": "DEBUG",
    "modules": ["all"],  // or specific: ["network", "security", "api"]
    "output": "console",  // "console", "file", "both"
    "file_path": "logs/debug.log",
    "max_file_size": "50MB",
    "backup_count": 3
  }
}
```

#### **Environment Variables**
```bash
# Set debug environment
export ZEHRASEC_DEBUG=true
export ZEHRASEC_DEBUG_LEVEL=DEBUG
export ZEHRASEC_DEBUG_MODULES="network,security"

# Run with debug environment
python main.py --config config/firewall_advanced.json
```

### **Debug Output Configuration**

#### **Console Output**
```python
# In main.py or debug configuration
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/debug.log')
    ]
)
```

#### **Structured Debug Output**
```json
// Debug output format
{
  "timestamp": "2025-06-19T14:30:22.123Z",
  "level": "DEBUG",
  "module": "network",
  "component": "packet_filter",
  "message": "Processing packet from 192.168.1.100",
  "data": {
    "src_ip": "192.168.1.100",
    "dst_ip": "192.168.1.1",
    "protocol": "TCP",
    "port": 80
  }
}
```

---

## 📊 **Logging and Monitoring**

### **Comprehensive Logging Setup**

#### **Multi-Level Logging**
```json
// In config/firewall_advanced.json
{
  "logging": {
    "levels": {
      "root": "INFO",
      "network": "DEBUG",
      "security": "DEBUG",
      "api": "INFO",
      "database": "WARNING"
    },
    "handlers": {
      "console": {
        "enabled": true,
        "level": "INFO",
        "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
      },
      "file": {
        "enabled": true,
        "level": "DEBUG",
        "file": "logs/zehrasec_debug.log",
        "format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s"
      },
      "syslog": {
        "enabled": false,
        "facility": "local0",
        "level": "INFO"
      }
    }
  }
}
```

#### **Real-Time Log Monitoring**
```bash
# Monitor all logs
tail -f logs/zehrasec_debug.log

# Monitor specific module
tail -f logs/zehrasec_debug.log | grep "network"

# Monitor with color highlighting
tail -f logs/zehrasec_debug.log | grep --color=always -E "(ERROR|DEBUG|INFO)"

# Monitor with log level filtering
tail -f logs/zehrasec_debug.log | grep -E "(DEBUG|ERROR)"
```

#### **Log Analysis Tools**
```bash
# Count log entries by level
grep -c "ERROR" logs/zehrasec_debug.log
grep -c "DEBUG" logs/zehrasec_debug.log

# Find specific errors
grep -B5 -A5 "Exception" logs/zehrasec_debug.log

# Generate log summary
python tools/log_analyzer.py --file logs/zehrasec_debug.log --summary
```

### **Performance Monitoring**

#### **Real-Time Metrics**
```bash
# Monitor system metrics
python tools/monitor_metrics.py --realtime

# API endpoint for metrics
curl -k https://localhost:8443/api/debug/metrics
```

#### **Custom Metrics Collection**
```python
# In your debug code
import time
from tools.metrics import MetricsCollector

metrics = MetricsCollector()

# Time function execution
@metrics.time_function
def process_packet(packet):
    # Processing logic
    pass

# Count events
metrics.increment_counter('packets_processed')
metrics.increment_counter('threats_detected')

# Record values
metrics.record_value('response_time', response_time)
metrics.record_value('memory_usage', memory_usage)
```

---

## 🌐 **Network Traffic Analysis**

### **Packet Capture and Analysis**

#### **Enable Packet Capture**
```json
// In config/firewall_advanced.json
{
  "debug": {
    "packet_capture": {
      "enabled": true,
      "interface": "eth0",  // or "auto"
      "capture_file": "debug/packets.pcap",
      "max_file_size": "100MB",
      "filter": "tcp port 80 or tcp port 443"
    }
  }
}
```

#### **Analyze Captured Packets**
```bash
# View captured packets with tcpdump
tcpdump -r debug/packets.pcap

# Analyze with Wireshark
wireshark debug/packets.pcap

# Python-based packet analysis
python tools/analyze_packets.py --file debug/packets.pcap
```

#### **Live Packet Monitoring**
```bash
# Monitor live packets
python tools/packet_monitor.py --interface eth0 --verbose

# Monitor specific protocols
python tools/packet_monitor.py --interface eth0 --protocol tcp --port 80

# Monitor with filtering
python tools/packet_monitor.py --interface eth0 --filter "host 192.168.1.100"
```

### **Traffic Flow Analysis**

#### **Connection Tracking**
```python
# Debug connection tracking
python tools/debug_connections.py --show-active

# Monitor connection states
python tools/debug_connections.py --monitor --duration 300
```

#### **Bandwidth Analysis**
```bash
# Monitor bandwidth usage
python tools/bandwidth_monitor.py --interface eth0 --interval 5

# Generate bandwidth report
python tools/bandwidth_report.py --duration 3600 --output bandwidth_report.html
```

---

## ⚡ **Performance Profiling**

### **CPU Profiling**

#### **Built-in Profiler**
```bash
# Profile main application
python -m cProfile -o profile_output.prof main.py --config config/firewall_advanced.json

# Analyze profile results
python -m pstats profile_output.prof
```

#### **Line-by-Line Profiling**
```bash
# Install line_profiler
pip install line_profiler

# Profile specific functions
kernprof -l -v main.py
```

#### **Real-Time CPU Monitoring**
```python
# Add to your code for real-time profiling
import psutil
import threading
import time

def monitor_cpu_usage():
    while True:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        print(f"CPU: {cpu_percent}%, Memory: {memory_percent}%")
        time.sleep(5)

# Start monitoring thread
monitor_thread = threading.Thread(target=monitor_cpu_usage, daemon=True)
monitor_thread.start()
```

### **Memory Profiling**

#### **Memory Usage Tracking**
```bash
# Install memory profiler
pip install memory_profiler

# Profile memory usage
python -m memory_profiler main.py --config config/firewall_advanced.json
```

#### **Heap Analysis**
```python
# Add to your code
import tracemalloc

# Start tracing
tracemalloc.start()

# Your code here...

# Get current memory usage
current, peak = tracemalloc.get_traced_memory()
print(f"Current memory usage: {current / 1024 / 1024:.1f} MB")
print(f"Peak memory usage: {peak / 1024 / 1024:.1f} MB")

# Stop tracing
tracemalloc.stop()
```

#### **Memory Leak Detection**
```bash
# Run memory leak detector
python tools/memory_leak_detector.py --duration 3600

# Generate memory report
python tools/memory_report.py --output memory_analysis.html
```

---

## 🔍 **Security Layer Debugging**

### **Layer-by-Layer Debug**

#### **Layer 1: Packet Filter Debug**
```bash
# Debug packet filtering
python -c "
from src.core.firewall_engine import FirewallEngine
engine = FirewallEngine(debug=True)
engine.debug_layer1()
"

# Monitor packet filter decisions
tail -f logs/zehrasec_debug.log | grep "layer1"
```

#### **Layer 2: Application Gateway Debug**
```bash
# Debug application layer
python tools/debug_layer2.py --protocol http --verbose

# Monitor application layer decisions
curl -k https://localhost:8443/api/debug/layer2/status
```

#### **Layer 3: IDS/IPS Debug**
```bash
# Debug intrusion detection
python tools/debug_ids.py --test-rules --verbose

# Test specific signatures
python tools/test_signature.py --signature "SQL_INJECTION_001" --payload "' OR 1=1--"
```

#### **Layer 4: Threat Intelligence Debug**
```bash
# Debug threat intelligence
python tools/debug_threat_intel.py --check-feeds --verbose

# Test IP reputation
python tools/test_ip_reputation.py --ip 192.168.1.100
```

### **Rule Engine Debugging**

#### **Rule Execution Trace**
```json
// In config/firewall_advanced.json
{
  "debug": {
    "rule_engine": {
      "trace_execution": true,
      "log_rule_matches": true,
      "log_rule_misses": false,
      "performance_metrics": true
    }
  }
}
```

#### **Custom Rule Testing**
```bash
# Test custom rules
python tools/test_rules.py --rule custom_rule.json --payload test_payload.txt

# Validate rule syntax
python tools/validate_rules.py --rule-file rules/custom_rules.json
```

---

## 🔌 **API Debugging**

### **API Request/Response Logging**

#### **Enable API Debug Mode**
```json
// In config/firewall_advanced.json
{
  "api": {
    "debug": {
      "log_requests": true,
      "log_responses": true,
      "log_headers": true,
      "log_body": true,
      "max_body_size": 1024
    }
  }
}
```

#### **API Performance Monitoring**
```bash
# Monitor API performance
python tools/api_monitor.py --endpoint /api/status --interval 5

# Load test API
python tools/api_load_test.py --endpoint /api/threats --concurrent 10 --duration 60
```

### **API Debugging Tools**

#### **Manual API Testing**
```bash
# Test API endpoints
curl -k -X GET https://localhost:8443/api/status -v
curl -k -X GET https://localhost:8443/api/health -v

# Test with authentication
curl -k -X GET https://localhost:8443/api/threats \
  -H "Authorization: Bearer YOUR_TOKEN" -v

# Test POST requests
curl -k -X POST https://localhost:8443/api/block-ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}' -v
```

#### **API Response Validation**
```python
# Validate API responses
import requests
import json

def test_api_endpoint(endpoint, expected_status=200):
    try:
        response = requests.get(f"https://localhost:8443{endpoint}", 
                              verify=False, timeout=10)
        print(f"Endpoint: {endpoint}")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == expected_status:
            print("✅ Test passed")
        else:
            print("❌ Test failed")
            
    except Exception as e:
        print(f"❌ Error: {e}")

# Test multiple endpoints
test_api_endpoint("/api/status")
test_api_endpoint("/api/health")
test_api_endpoint("/api/metrics")
```

---

## 💾 **Database Debugging**

### **Database Query Logging**

#### **Enable SQL Logging**
```json
// In config/firewall_advanced.json
{
  "database": {
    "debug": {
      "log_queries": true,
      "log_slow_queries": true,
      "slow_query_threshold": 1000,  // milliseconds
      "log_query_parameters": true
    }
  }
}
```

#### **Database Performance Analysis**
```bash
# Analyze database performance
python tools/db_analyzer.py --analyze-queries --output db_analysis.html

# Check database integrity
python tools/db_integrity.py --check-all

# Optimize database
python tools/db_optimizer.py --analyze --optimize
```

### **Database Connection Debugging**

#### **Connection Pool Monitoring**
```python
# Monitor database connections
from tools.db_monitor import DatabaseMonitor

monitor = DatabaseMonitor()
monitor.start_monitoring()

# Check connection pool status
pool_status = monitor.get_pool_status()
print(f"Active connections: {pool_status['active']}")
print(f"Idle connections: {pool_status['idle']}")
print(f"Pool size: {pool_status['size']}")
```

#### **Transaction Debugging**
```bash
# Debug database transactions
python tools/debug_transactions.py --monitor --duration 300

# Analyze transaction logs
python tools/analyze_transactions.py --log-file logs/transactions.log
```

---

## 🔧 **Advanced Debugging Tools**

### **Interactive Debugging**

#### **Remote Debug Server**
```python
# Add to main.py for remote debugging
import pdb
import sys

def debug_handler(sig, frame):
    pdb.set_trace()

if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGUSR1, debug_handler)
    
    # Your main code here
    main()
```

#### **Web-based Debug Interface**
```bash
# Start debug web interface
python tools/debug_server.py --port 9000

# Access debug interface
http://localhost:9000/debug
```

### **Automated Debug Scripts**

#### **Comprehensive Debug Report**
```bash
# Generate complete debug report
python tools/debug_report.py --full --output debug_report_$(date +%Y%m%d_%H%M%S).html
```

#### **Debug Script Template**
```python
#!/usr/bin/env python3
"""
Debug script template for ZehraSec
"""

import logging
import sys
import os
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def debug_function():
    """Main debug function"""
    logger.debug("Starting debug session")
    
    # Add your debug code here
    try:
        # Debug logic
        pass
    except Exception as e:
        logger.error(f"Debug error: {e}")
        raise
    
    logger.debug("Debug session completed")

if __name__ == "__main__":
    debug_function()
```

---

## 🌐 **Remote Debugging**

### **Remote Debug Setup**

#### **SSH Debug Session**
```bash
# Connect to remote system
ssh -L 8443:localhost:8443 user@remote-server

# Start debug session
python main.py --debug --remote-debug --config config/firewall_advanced.json
```

#### **Debug Over Network**
```python
# Enable remote debugging
import debugpy

# Listen on all interfaces
debugpy.listen(('0.0.0.0', 5678))
print("Waiting for debugger attach...")
debugpy.wait_for_client()

# Your code here
```

### **Remote Monitoring**

#### **Remote Log Collection**
```bash
# Collect logs from remote system
rsync -avz user@remote-server:/opt/zehrasec/logs/ ./remote_logs/

# Real-time log streaming
ssh user@remote-server 'tail -f /opt/zehrasec/logs/zehrasec_debug.log'
```

#### **Remote Performance Monitoring**
```bash
# Monitor remote system performance
ssh user@remote-server 'python /opt/zehrasec/tools/monitor_metrics.py --duration 300'

# Collect remote metrics
python tools/collect_remote_metrics.py --host remote-server --duration 3600
```

---

## 🛠️ **Debug Utilities and Tools**

### **Built-in Debug Commands**

#### **System Information**
```bash
# System debug info
python tools/debug_info.py --system

# Network debug info
python tools/debug_info.py --network

# Security debug info
python tools/debug_info.py --security
```

#### **Configuration Debug**
```bash
# Validate configuration
python tools/debug_config.py --validate

# Show effective configuration
python tools/debug_config.py --show-effective

# Compare configurations
python tools/debug_config.py --compare config1.json config2.json
```

### **Custom Debug Tools**

#### **Packet Injection Tool**
```bash
# Inject test packets
python tools/packet_injector.py --protocol tcp --src 192.168.1.100 --dst 192.168.1.1 --port 80

# Test specific attack patterns
python tools/packet_injector.py --attack-type sql_injection --target 192.168.1.1
```

#### **Stress Testing Tool**
```bash
# Stress test the firewall
python tools/stress_test.py --connections 1000 --duration 300

# Memory stress test
python tools/stress_test.py --memory-stress --size 1GB --duration 60
```

---

## 📊 **Debug Output Analysis**

### **Log Analysis**

#### **Automated Log Analysis**
```bash
# Analyze debug logs
python tools/log_analyzer.py --file logs/zehrasec_debug.log --analysis-type full

# Generate timeline
python tools/log_timeline.py --file logs/zehrasec_debug.log --output timeline.html

# Extract error patterns
python tools/error_pattern_analyzer.py --file logs/zehrasec_debug.log
```

#### **Performance Analysis**
```bash
# Analyze performance metrics
python tools/performance_analyzer.py --metrics-file logs/metrics.log

# Generate performance report
python tools/performance_report.py --duration 3600 --output performance.html
```

### **Debug Report Generation**

#### **Comprehensive Debug Report**
```bash
# Generate HTML debug report
python tools/generate_debug_report.py --format html --output debug_report.html

# Generate JSON debug report
python tools/generate_debug_report.py --format json --output debug_report.json

# Generate PDF debug report
python tools/generate_debug_report.py --format pdf --output debug_report.pdf
```

---

## 📞 **Debug Support**

### **Getting Debug Help**
- **Debug Support**: debug@zehrasec.com
- **Technical Support**: support@zehrasec.com
- **Developer Forum**: https://dev.zehrasec.com
- **GitHub Issues**: https://github.com/yashab-cyber/ZehraSec-Advanced-Firewall/issues

### **Debug Information to Collect**
1. **System Information**
2. **Debug Logs** (last 24 hours)
3. **Configuration Files**
4. **Network Configuration**
5. **Performance Metrics**
6. **Error Messages** (exact text)

---

## 📚 **Related Documentation**

- **[Troubleshooting Guide](16-Troubleshooting-Guide.md)** - Common issues and solutions
- **[Performance Optimization](18-Performance-Optimization.md)** - Performance tuning
- **[Logging Guide](21-Logging-Guide.md)** - Comprehensive logging setup
- **[Maintenance Guide](19-Maintenance-Guide.md)** - Regular maintenance

---

**Copyright © 2025 ZehraSec - Yashab Alam**  
*Debugging Guide v3.0.0*
