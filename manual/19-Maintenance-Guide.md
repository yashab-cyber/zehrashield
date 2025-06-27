# Maintenance Guide

## Overview

This guide covers the ongoing maintenance requirements for ZehraSec Advanced Firewall, including routine tasks, system updates, performance optimization, and preventive maintenance procedures to ensure optimal security and performance.

## Table of Contents

1. [Maintenance Schedule](#maintenance-schedule)
2. [Routine Maintenance Tasks](#routine-maintenance-tasks)
3. [System Updates and Patches](#system-updates-and-patches)
4. [Database Maintenance](#database-maintenance)
5. [Log Management](#log-management)
6. [Performance Optimization](#performance-optimization)
7. [Security Maintenance](#security-maintenance)
8. [Hardware Maintenance](#hardware-maintenance)
9. [Backup and Recovery](#backup-and-recovery)
10. [Monitoring and Alerting](#monitoring-and-alerting)

## Maintenance Schedule

### Daily Tasks

| Task | Description | Automated | Manual |
|------|-------------|-----------|---------|
| System Health Check | Monitor system status and alerts | ✓ | - |
| Log Review | Review critical security events | - | ✓ |
| Backup Verification | Verify backup completion | ✓ | - |
| Threat Intelligence Update | Update threat signatures | ✓ | - |
| Performance Monitoring | Check system performance metrics | ✓ | - |

### Weekly Tasks

| Task | Description | Automated | Manual |
|------|-------------|-----------|---------|
| Log Rotation | Rotate and archive log files | ✓ | - |
| Database Optimization | Optimize database performance | ✓ | - |
| Security Rule Review | Review and update security rules | - | ✓ |
| Capacity Planning | Monitor resource utilization | ✓ | - |
| Configuration Backup | Backup system configuration | ✓ | - |

### Monthly Tasks

| Task | Description | Automated | Manual |
|------|-------------|-----------|---------|
| Security Patch Review | Review and apply security patches | - | ✓ |
| Performance Analysis | Detailed performance analysis | - | ✓ |
| User Access Review | Review user accounts and permissions | - | ✓ |
| Hardware Health Check | Check hardware status and alerts | ✓ | ✓ |
| Disaster Recovery Test | Test backup and recovery procedures | - | ✓ |

### Quarterly Tasks

| Task | Description | Automated | Manual |
|------|-------------|-----------|---------|
| Security Audit | Comprehensive security review | - | ✓ |
| Hardware Refresh Planning | Plan hardware upgrades | - | ✓ |
| Policy Review | Review security policies | - | ✓ |
| Training Updates | Update staff training | - | ✓ |
| Vendor Review | Review vendor relationships | - | ✓ |

## Routine Maintenance Tasks

### System Health Monitoring

#### Automated Health Checks

```bash
#!/bin/bash
# Daily health check script
# /usr/local/bin/zehrasec-health-check.sh

LOG_FILE="/var/log/zehrasec/health-check.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] Starting system health check" >> $LOG_FILE

# Check system services
systemctl is-active --quiet zehrasec-firewall
if [ $? -eq 0 ]; then
    echo "[$DATE] ✓ Firewall service is running" >> $LOG_FILE
else
    echo "[$DATE] ✗ Firewall service is not running" >> $LOG_FILE
    systemctl restart zehrasec-firewall
fi

# Check database connectivity
zehrasec-cli db status
if [ $? -eq 0 ]; then
    echo "[$DATE] ✓ Database is accessible" >> $LOG_FILE
else
    echo "[$DATE] ✗ Database connection failed" >> $LOG_FILE
fi

# Check disk space
DISK_USAGE=$(df -h /var/log/zehrasec | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "[$DATE] ⚠ Disk usage is high: ${DISK_USAGE}%" >> $LOG_FILE
fi

# Check memory usage
MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
if [ $MEMORY_USAGE -gt 85 ]; then
    echo "[$DATE] ⚠ Memory usage is high: ${MEMORY_USAGE}%" >> $LOG_FILE
fi

# Check CPU load
CPU_LOAD=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
CPU_CORES=$(nproc)
if (( $(echo "$CPU_LOAD > $CPU_CORES" | bc -l) )); then
    echo "[$DATE] ⚠ CPU load is high: $CPU_LOAD" >> $LOG_FILE
fi

echo "[$DATE] Health check completed" >> $LOG_FILE
```

#### System Status Dashboard

```python
#!/usr/bin/env python3
# System status dashboard
# /usr/local/bin/zehrasec-status.py

import psutil
import json
import datetime
import subprocess

def get_system_status():
    """Get comprehensive system status"""
    status = {
        'timestamp': datetime.datetime.now().isoformat(),
        'system': {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': {
                'root': psutil.disk_usage('/').percent,
                'logs': psutil.disk_usage('/var/log').percent
            },
            'load_average': psutil.getloadavg(),
            'uptime': datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())
        },
        'services': get_service_status(),
        'network': get_network_stats(),
        'security': get_security_status()
    }
    
    return status

def get_service_status():
    """Check status of critical services"""
    services = ['zehrasec-firewall', 'zehrasec-web', 'postgresql', 'nginx']
    status = {}
    
    for service in services:
        try:
            result = subprocess.run(['systemctl', 'is-active', service], 
                                  capture_output=True, text=True)
            status[service] = result.stdout.strip()
        except Exception as e:
            status[service] = f"error: {str(e)}"
    
    return status

def get_network_stats():
    """Get network interface statistics"""
    stats = {}
    for interface, addrs in psutil.net_if_addrs().items():
        if interface != 'lo':  # Skip loopback
            net_io = psutil.net_io_counters(pernic=True).get(interface)
            if net_io:
                stats[interface] = {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv,
                    'errors_in': net_io.errin,
                    'errors_out': net_io.errout
                }
    
    return stats

def get_security_status():
    """Get security-related status"""
    try:
        # This would integrate with ZehraSec API
        result = subprocess.run(['zehrasec-cli', 'status', '--json'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception:
        pass
    
    return {'error': 'Unable to fetch security status'}

if __name__ == '__main__':
    import sys
    
    status = get_system_status()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--json':
        print(json.dumps(status, indent=2, default=str))
    else:
        # Human-readable output
        print(f"ZehraSec System Status - {status['timestamp']}")
        print("=" * 50)
        print(f"CPU Usage: {status['system']['cpu_percent']:.1f}%")
        print(f"Memory Usage: {status['system']['memory_percent']:.1f}%")
        print(f"Disk Usage (Root): {status['system']['disk_usage']['root']:.1f}%")
        print(f"Load Average: {status['system']['load_average'][0]:.2f}")
        print(f"Uptime: {status['system']['uptime']}")
        
        print("\nServices:")
        for service, state in status['services'].items():
            symbol = "✓" if state == "active" else "✗"
            print(f"  {symbol} {service}: {state}")
```

### Configuration Management

#### Configuration Backup

```bash
#!/bin/bash
# Configuration backup script
# /usr/local/bin/backup-config.sh

BACKUP_DIR="/var/backups/zehrasec"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="zehrasec-config-${DATE}.tar.gz"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup configuration files
tar -czf "${BACKUP_DIR}/${BACKUP_FILE}" \
    /etc/zehrasec/ \
    /var/lib/zehrasec/config/ \
    /etc/systemd/system/zehrasec*.service

# Keep only last 30 backups
find $BACKUP_DIR -name "zehrasec-config-*.tar.gz" -mtime +30 -delete

# Log backup completion
echo "$(date): Configuration backup completed: $BACKUP_FILE" >> /var/log/zehrasec/backup.log
```

#### Configuration Validation

```bash
#!/bin/bash
# Configuration validation script
# /usr/local/bin/validate-config.sh

CONFIG_DIR="/etc/zehrasec"
LOG_FILE="/var/log/zehrasec/config-validation.log"

echo "$(date): Starting configuration validation" >> $LOG_FILE

# Validate main configuration
zehrasec-cli config validate --file $CONFIG_DIR/firewall.json
if [ $? -eq 0 ]; then
    echo "$(date): ✓ Main configuration is valid" >> $LOG_FILE
else
    echo "$(date): ✗ Main configuration has errors" >> $LOG_FILE
    exit 1
fi

# Validate rules
zehrasec-cli rules validate --file $CONFIG_DIR/rules.json
if [ $? -eq 0 ]; then
    echo "$(date): ✓ Rules configuration is valid" >> $LOG_FILE
else
    echo "$(date): ✗ Rules configuration has errors" >> $LOG_FILE
    exit 1
fi

# Check syntax of custom scripts
find $CONFIG_DIR/scripts -name "*.py" -exec python3 -m py_compile {} \;
if [ $? -eq 0 ]; then
    echo "$(date): ✓ Custom scripts syntax is valid" >> $LOG_FILE
else
    echo "$(date): ✗ Custom scripts have syntax errors" >> $LOG_FILE
    exit 1
fi

echo "$(date): Configuration validation completed successfully" >> $LOG_FILE
```

## System Updates and Patches

### Update Management Process

#### Pre-Update Checklist

```yaml
# Pre-update checklist
pre_update_checklist:
  - name: "Backup current configuration"
    command: "/usr/local/bin/backup-config.sh"
    required: true
    
  - name: "Create system snapshot"
    command: "lvm snapshot"
    required: false
    note: "If using LVM"
    
  - name: "Verify system stability"
    command: "/usr/local/bin/zehrasec-health-check.sh"
    required: true
    
  - name: "Schedule maintenance window"
    manual: true
    required: true
    
  - name: "Notify stakeholders"
    manual: true
    required: true
    
  - name: "Prepare rollback plan"
    manual: true
    required: true
```

#### Update Installation Script

```bash
#!/bin/bash
# ZehraSec update installation script
# /usr/local/bin/update-zehrasec.sh

UPDATE_LOG="/var/log/zehrasec/updates.log"
BACKUP_DIR="/var/backups/zehrasec/pre-update"
DATE=$(date +%Y%m%d_%H%M%S)

log_message() {
    echo "$(date): $1" | tee -a $UPDATE_LOG
}

# Pre-update backup
create_backup() {
    log_message "Creating pre-update backup"
    mkdir -p $BACKUP_DIR
    
    # Backup configuration
    tar -czf "${BACKUP_DIR}/config-${DATE}.tar.gz" /etc/zehrasec/
    
    # Backup database
    sudo -u postgres pg_dump zehrasec > "${BACKUP_DIR}/database-${DATE}.sql"
    
    # Backup custom files
    tar -czf "${BACKUP_DIR}/custom-${DATE}.tar.gz" /var/lib/zehrasec/custom/
}

# Update process
perform_update() {
    log_message "Starting ZehraSec update process"
    
    # Stop services
    systemctl stop zehrasec-firewall
    systemctl stop zehrasec-web
    
    # Update packages
    apt update
    apt upgrade zehrasec-advanced-firewall -y
    
    # Run database migrations
    zehrasec-cli db migrate
    
    # Update configurations
    zehrasec-cli config update
    
    # Restart services
    systemctl start zehrasec-firewall
    systemctl start zehrasec-web
    
    # Verify update
    sleep 10
    systemctl is-active zehrasec-firewall
    if [ $? -eq 0 ]; then
        log_message "Update completed successfully"
        return 0
    else
        log_message "Update failed - service not running"
        return 1
    fi
}

# Rollback function
rollback_update() {
    log_message "Rolling back update"
    
    # Stop services
    systemctl stop zehrasec-firewall
    systemctl stop zehrasec-web
    
    # Restore configuration
    tar -xzf "${BACKUP_DIR}/config-${DATE}.tar.gz" -C /
    
    # Restore database
    sudo -u postgres psql zehrasec < "${BACKUP_DIR}/database-${DATE}.sql"
    
    # Restore custom files
    tar -xzf "${BACKUP_DIR}/custom-${DATE}.tar.gz" -C /
    
    # Restart services
    systemctl start zehrasec-firewall
    systemctl start zehrasec-web
    
    log_message "Rollback completed"
}

# Main execution
main() {
    log_message "Starting update process"
    
    # Create backup
    create_backup
    if [ $? -ne 0 ]; then
        log_message "Backup failed - aborting update"
        exit 1
    fi
    
    # Perform update
    perform_update
    if [ $? -ne 0 ]; then
        log_message "Update failed - initiating rollback"
        rollback_update
        exit 1
    fi
    
    log_message "Update process completed successfully"
}

# Run with proper logging
main 2>&1 | tee -a $UPDATE_LOG
```

### Patch Management

#### Security Patch Priority Matrix

| Severity | CVSS Score | Response Time | Testing Required |
|----------|------------|---------------|------------------|
| Critical | 9.0-10.0 | 24 hours | Minimal |
| High | 7.0-8.9 | 72 hours | Standard |
| Medium | 4.0-6.9 | 1 week | Full |
| Low | 0.1-3.9 | 1 month | Full |

#### Patch Testing Procedure

```bash
#!/bin/bash
# Patch testing script
# /usr/local/bin/test-patch.sh

PATCH_FILE=$1
TEST_LOG="/var/log/zehrasec/patch-testing.log"

if [ -z "$PATCH_FILE" ]; then
    echo "Usage: $0 <patch_file>"
    exit 1
fi

log_test() {
    echo "$(date): $1" | tee -a $TEST_LOG
}

# Pre-patch testing
pre_patch_tests() {
    log_test "Running pre-patch tests"
    
    # System health check
    /usr/local/bin/zehrasec-health-check.sh
    
    # Performance baseline
    zehrasec-cli performance baseline > /tmp/pre-patch-baseline.txt
    
    # Functionality tests
    zehrasec-cli test --suite basic
}

# Apply patch in test environment
apply_test_patch() {
    log_test "Applying patch in test environment"
    
    # Create test snapshot
    lvm snapshot test-env
    
    # Apply patch
    patch -p1 < $PATCH_FILE
    
    # Compile and restart
    make install
    systemctl restart zehrasec-firewall
}

# Post-patch testing
post_patch_tests() {
    log_test "Running post-patch tests"
    
    # System health check
    /usr/local/bin/zehrasec-health-check.sh
    
    # Performance comparison
    zehrasec-cli performance baseline > /tmp/post-patch-baseline.txt
    diff /tmp/pre-patch-baseline.txt /tmp/post-patch-baseline.txt
    
    # Functionality tests
    zehrasec-cli test --suite comprehensive
    
    # Security tests
    zehrasec-cli test --suite security
}

# Main testing process
main() {
    log_test "Starting patch testing for: $PATCH_FILE"
    
    pre_patch_tests
    if [ $? -ne 0 ]; then
        log_test "Pre-patch tests failed"
        exit 1
    fi
    
    apply_test_patch
    if [ $? -ne 0 ]; then
        log_test "Patch application failed"
        exit 1
    fi
    
    post_patch_tests
    if [ $? -ne 0 ]; then
        log_test "Post-patch tests failed"
        exit 1
    fi
    
    log_test "Patch testing completed successfully"
}

main
```

## Database Maintenance

### Database Optimization

#### Routine Optimization Script

```sql
-- Database maintenance script
-- /usr/local/bin/db-maintenance.sql

-- Update table statistics
ANALYZE;

-- Rebuild indexes
REINDEX DATABASE zehrasec;

-- Clean up old data
DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '90 days';
DELETE FROM session_logs WHERE created_at < NOW() - INTERVAL '30 days';
DELETE FROM temp_data WHERE created_at < NOW() - INTERVAL '1 day';

-- Vacuum tables
VACUUM ANALYZE audit_logs;
VACUUM ANALYZE session_logs;
VACUUM ANALYZE threat_events;
VACUUM ANALYZE firewall_rules;

-- Check for table bloat
SELECT schemaname, tablename, 
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
       pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table_size,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) as index_size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Check index usage
SELECT schemaname, tablename, attname, n_distinct, correlation 
FROM pg_stats 
WHERE schemaname = 'public' 
ORDER BY n_distinct DESC;
```

#### Database Backup Script

```bash
#!/bin/bash
# Database backup script
# /usr/local/bin/backup-database.sh

DB_NAME="zehrasec"
BACKUP_DIR="/var/backups/zehrasec/database"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="zehrasec-db-${DATE}.sql.gz"

mkdir -p $BACKUP_DIR

# Create backup
sudo -u postgres pg_dump $DB_NAME | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"

# Verify backup
if [ $? -eq 0 ]; then
    echo "$(date): Database backup completed: $BACKUP_FILE" >> /var/log/zehrasec/backup.log
    
    # Keep only last 7 daily backups
    find $BACKUP_DIR -name "zehrasec-db-*.sql.gz" -mtime +7 -delete
else
    echo "$(date): Database backup failed" >> /var/log/zehrasec/backup.log
    exit 1
fi

# Test backup restoration (weekly)
if [ $(date +%u) -eq 1 ]; then
    # Create test database
    sudo -u postgres createdb zehrasec_test
    
    # Restore backup
    gunzip -c "${BACKUP_DIR}/${BACKUP_FILE}" | sudo -u postgres psql zehrasec_test
    
    if [ $? -eq 0 ]; then
        echo "$(date): Backup restoration test successful" >> /var/log/zehrasec/backup.log
    else
        echo "$(date): Backup restoration test failed" >> /var/log/zehrasec/backup.log
    fi
    
    # Clean up test database
    sudo -u postgres dropdb zehrasec_test
fi
```

## Log Management

### Log Rotation Configuration

```conf
# /etc/logrotate.d/zehrasec
/var/log/zehrasec/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 zehrasec zehrasec
    postrotate
        /usr/bin/systemctl reload zehrasec-firewall > /dev/null 2>&1 || true
    endscript
}

/var/log/zehrasec/audit/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0600 zehrasec zehrasec
    # Don't rotate audit logs immediately
}

/var/log/zehrasec/threats/*.log {
    hourly
    rotate 168
    compress
    delaycompress
    missingok
    notifempty
    create 0644 zehrasec zehrasec
}
```

### Log Cleanup Script

```bash
#!/bin/bash
# Log cleanup script
# /usr/local/bin/cleanup-logs.sh

LOG_DIR="/var/log/zehrasec"
ARCHIVE_DIR="/var/log/zehrasec/archive"
DAYS_TO_KEEP=30
DAYS_TO_ARCHIVE=7

# Create archive directory
mkdir -p $ARCHIVE_DIR

# Archive old logs
find $LOG_DIR -name "*.log" -mtime +$DAYS_TO_ARCHIVE -not -path "*/archive/*" -exec mv {} $ARCHIVE_DIR/ \;

# Compress archived logs
find $ARCHIVE_DIR -name "*.log" -not -name "*.gz" -exec gzip {} \;

# Remove very old archived logs
find $ARCHIVE_DIR -name "*.log.gz" -mtime +$DAYS_TO_KEEP -delete

# Remove empty directories
find $LOG_DIR -type d -empty -delete

echo "$(date): Log cleanup completed" >> /var/log/zehrasec/maintenance.log
```

## Performance Optimization

### System Tuning

#### Network Performance Tuning

```bash
#!/bin/bash
# Network performance tuning
# /usr/local/bin/tune-network.sh

# Increase network buffer sizes
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 134217728' >> /etc/sysctl.conf

# Increase connection tracking table size
echo 'net.netfilter.nf_conntrack_max = 1048576' >> /etc/sysctl.conf
echo 'net.netfilter.nf_conntrack_buckets = 262144' >> /etc/sysctl.conf

# Optimize TCP settings
echo 'net.ipv4.tcp_window_scaling = 1' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_timestamps = 0' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_sack = 1' >> /etc/sysctl.conf

# Apply settings
sysctl -p

echo "Network tuning applied"
```

#### Disk I/O Optimization

```bash
#!/bin/bash
# Disk I/O optimization
# /usr/local/bin/tune-disk.sh

# Set I/O scheduler
echo mq-deadline > /sys/block/sda/queue/scheduler

# Adjust read-ahead
blockdev --setra 4096 /dev/sda

# Mount options for log partition
mount -o remount,noatime,data=writeback /var/log

echo "Disk I/O tuning applied"
```

### Performance Monitoring

```python
#!/usr/bin/env python3
# Performance monitoring script
# /usr/local/bin/performance-monitor.py

import psutil
import time
import json
import sqlite3
from datetime import datetime

class PerformanceMonitor:
    def __init__(self, db_path='/var/lib/zehrasec/performance.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                timestamp DATETIME,
                cpu_percent REAL,
                memory_percent REAL,
                disk_io_read INTEGER,
                disk_io_write INTEGER,
                network_bytes_sent INTEGER,
                network_bytes_recv INTEGER,
                load_avg_1min REAL,
                active_connections INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def collect_metrics(self):
        # CPU and Memory
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        # Disk I/O
        disk_io = psutil.disk_io_counters()
        
        # Network
        network_io = psutil.net_io_counters()
        
        # Load average
        load_avg = psutil.getloadavg()[0]
        
        # ZehraSec specific metrics (placeholder)
        active_connections = self.get_active_connections()
        
        metrics = {
            'timestamp': datetime.now(),
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_io_read': disk_io.read_bytes if disk_io else 0,
            'disk_io_write': disk_io.write_bytes if disk_io else 0,
            'network_bytes_sent': network_io.bytes_sent,
            'network_bytes_recv': network_io.bytes_recv,
            'load_avg_1min': load_avg,
            'active_connections': active_connections
        }
        
        return metrics
    
    def get_active_connections(self):
        # This would integrate with ZehraSec API
        try:
            # Placeholder - replace with actual API call
            return len(psutil.net_connections())
        except:
            return 0
    
    def store_metrics(self, metrics):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO performance_metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            metrics['timestamp'],
            metrics['cpu_percent'],
            metrics['memory_percent'],
            metrics['disk_io_read'],
            metrics['disk_io_write'],
            metrics['network_bytes_sent'],
            metrics['network_bytes_recv'],
            metrics['load_avg_1min'],
            metrics['active_connections']
        ))
        
        conn.commit()
        conn.close()
    
    def cleanup_old_data(self, days=30):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM performance_metrics 
            WHERE timestamp < datetime('now', '-{} days')
        '''.format(days))
        
        conn.commit()
        conn.close()
    
    def run_monitoring(self, interval=300):  # 5 minutes
        while True:
            try:
                metrics = self.collect_metrics()
                self.store_metrics(metrics)
                
                # Check for performance issues
                self.check_performance_alerts(metrics)
                
                time.sleep(interval)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error in monitoring: {e}")
                time.sleep(interval)
    
    def check_performance_alerts(self, metrics):
        # CPU alert
        if metrics['cpu_percent'] > 90:
            self.send_alert('High CPU Usage', f"CPU usage: {metrics['cpu_percent']:.1f}%")
        
        # Memory alert
        if metrics['memory_percent'] > 90:
            self.send_alert('High Memory Usage', f"Memory usage: {metrics['memory_percent']:.1f}%")
        
        # Load average alert
        if metrics['load_avg_1min'] > psutil.cpu_count() * 2:
            self.send_alert('High Load Average', f"Load average: {metrics['load_avg_1min']:.2f}")
    
    def send_alert(self, subject, message):
        # Implement alert sending logic
        print(f"ALERT: {subject} - {message}")
        # Could integrate with email, Slack, etc.

if __name__ == '__main__':
    monitor = PerformanceMonitor()
    monitor.run_monitoring()
```

## Security Maintenance

### Security Hardening Checklist

```yaml
security_hardening_checklist:
  - category: "System Hardening"
    tasks:
      - name: "Update system packages"
        command: "apt update && apt upgrade -y"
        frequency: "weekly"
        
      - name: "Review system users"
        command: "awk -F: '$3 >= 1000 {print $1}' /etc/passwd"
        frequency: "monthly"
        
      - name: "Check for rootkits"
        command: "rkhunter --check"
        frequency: "weekly"
        
  - category: "Firewall Security"
    tasks:
      - name: "Review firewall rules"
        command: "zehrasec-cli rules review"
        frequency: "weekly"
        
      - name: "Update threat signatures"
        command: "zehrasec-cli signatures update"
        frequency: "daily"
        
      - name: "Security policy review"
        manual: true
        frequency: "monthly"
        
  - category: "Access Control"
    tasks:
      - name: "Review user accounts"
        command: "zehrasec-cli users list"
        frequency: "monthly"
        
      - name: "Check failed login attempts"
        command: "grep 'authentication failure' /var/log/auth.log"
        frequency: "daily"
        
      - name: "Review sudo access"
        command: "cat /etc/sudoers"
        frequency: "monthly"
```

### Vulnerability Assessment

```bash
#!/bin/bash
# Vulnerability assessment script
# /usr/local/bin/vulnerability-scan.sh

SCAN_LOG="/var/log/zehrasec/vulnerability-scan.log"
DATE=$(date +%Y%m%d_%H%M%S)

log_scan() {
    echo "$(date): $1" | tee -a $SCAN_LOG
}

# System vulnerability scan
system_scan() {
    log_scan "Starting system vulnerability scan"
    
    # Check for security updates
    apt list --upgradable | grep -i security > /tmp/security-updates.txt
    if [ -s /tmp/security-updates.txt ]; then
        log_scan "Security updates available:"
        cat /tmp/security-updates.txt >> $SCAN_LOG
    fi
    
    # Port scan
    nmap -sS -O localhost > /tmp/port-scan.txt
    log_scan "Port scan completed"
    
    # File permissions check
    find /etc/zehrasec -type f -perm /o+w > /tmp/world-writable.txt
    if [ -s /tmp/world-writable.txt ]; then
        log_scan "World-writable files found:"
        cat /tmp/world-writable.txt >> $SCAN_LOG
    fi
}

# Application vulnerability scan
application_scan() {
    log_scan "Starting application vulnerability scan"
    
    # Check ZehraSec version
    CURRENT_VERSION=$(zehrasec-cli version)
    log_scan "Current ZehraSec version: $CURRENT_VERSION"
    
    # Check for known vulnerabilities
    zehrasec-cli security check > /tmp/security-check.txt
    cat /tmp/security-check.txt >> $SCAN_LOG
}

# Network vulnerability scan
network_scan() {
    log_scan "Starting network vulnerability scan"
    
    # Check network configuration
    netstat -tuln > /tmp/network-status.txt
    
    # Check for suspicious connections
    netstat -tulnp | grep ESTABLISHED > /tmp/established-connections.txt
    
    log_scan "Network scan completed"
}

# Generate report
generate_report() {
    log_scan "Generating vulnerability report"
    
    REPORT_FILE="/var/log/zehrasec/vulnerability-report-${DATE}.html"
    
    cat << EOF > $REPORT_FILE
<!DOCTYPE html>
<html>
<head>
    <title>ZehraSec Vulnerability Report - $DATE</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; }
        .section { margin: 20px 0; }
        .critical { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        .info { color: blue; }
    </style>
</head>
<body>
    <div class="header">
        <h1>ZehraSec Vulnerability Assessment Report</h1>
        <p>Generated: $(date)</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report contains the results of the automated vulnerability assessment performed on the ZehraSec Advanced Firewall system.</p>
    </div>
    
    <div class="section">
        <h2>Security Updates</h2>
        <pre>$(cat /tmp/security-updates.txt 2>/dev/null || echo "No security updates pending")</pre>
    </div>
    
    <div class="section">
        <h2>System Configuration</h2>
        <pre>$(cat /tmp/security-check.txt 2>/dev/null || echo "Security check completed successfully")</pre>
    </div>
    
    <div class="section">
        <h2>Network Status</h2>
        <pre>$(head -20 /tmp/network-status.txt 2>/dev/null || echo "Network status check failed")</pre>
    </div>
</body>
</html>
EOF
    
    log_scan "Report generated: $REPORT_FILE"
}

# Main execution
main() {
    log_scan "Starting vulnerability assessment"
    
    system_scan
    application_scan
    network_scan
    generate_report
    
    log_scan "Vulnerability assessment completed"
}

main
```

## Support and Resources

### Maintenance Contacts

- **Technical Support**: support@zehrasec.com
- **Emergency Support**: +1-800-ZEHRASEC
- **Professional Services**: services@zehrasec.com
- **Training**: training@zehrasec.com

### Documentation Resources

- **Online Documentation**: https://docs.zehrasec.com
- **Knowledge Base**: https://kb.zehrasec.com
- **Community Forum**: https://community.zehrasec.com
- **Video Tutorials**: https://training.zehrasec.com

### Maintenance Tools

All maintenance scripts and tools are available in:
- `/usr/local/bin/` - System-wide maintenance scripts
- `/etc/zehrasec/scripts/` - ZehraSec-specific scripts
- `/var/lib/zehrasec/tools/` - Additional maintenance tools

---

*This maintenance guide provides comprehensive procedures for keeping ZehraSec Advanced Firewall running optimally. Regular adherence to these maintenance procedures will ensure system stability, security, and performance.*
