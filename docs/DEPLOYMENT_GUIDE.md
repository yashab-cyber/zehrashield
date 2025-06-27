# ZehraShield Deployment Guide

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Service Management](#service-management)
5. [Security Hardening](#security-hardening)
6. [Monitoring and Maintenance](#monitoring-and-maintenance)
7. [Backup and Recovery](#backup-and-recovery)
8. [Troubleshooting](#troubleshooting)
9. [Performance Tuning](#performance-tuning)
10. [High Availability](#high-availability)

## System Requirements

### Minimum Requirements
- **OS**: Ubuntu 20.04 LTS, CentOS 8, or RHEL 8+
- **CPU**: 2 cores (4 cores recommended)
- **RAM**: 4 GB (8 GB recommended)
- **Storage**: 20 GB available space (50 GB recommended)
- **Network**: 1 Gbps network interface

### Recommended Requirements
- **OS**: Ubuntu 22.04 LTS
- **CPU**: 8 cores or more
- **RAM**: 16 GB or more
- **Storage**: 100 GB SSD storage
- **Network**: 10 Gbps network interface

### Software Dependencies
- Python 3.8 or later
- pip package manager
- systemd (for service management)
- iptables/netfilter
- OpenSSL (for SSL/TLS)

## Installation

### Automated Installation

The easiest way to install ZehraShield is using the automated installation script:

```bash
# Download and run installation script
curl -sSL https://raw.githubusercontent.com/yashab-cyber/zehrashield/main/scripts/install.sh | sudo bash
```

### Manual Installation

1. **Download ZehraShield**:
   ```bash
   cd /opt
   sudo git clone https://github.com/yashab-cyber/zehrashield.git
   cd zehrashield
   ```

2. **Create System User**:
   ```bash
   sudo useradd --system --shell /bin/false --home-dir /opt/zehrashield zehrashield
   sudo chown -R zehrashield:zehrashield /opt/zehrashield
   ```

3. **Install Python Dependencies**:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-venv
   sudo -u zehrashield python3 -m venv /opt/zehrashield/venv
   sudo -u zehrashield /opt/zehrashield/venv/bin/pip install -r requirements.txt
   ```

4. **Install System Dependencies**:
   ```bash
   sudo apt install iptables-persistent netfilter-persistent
   ```

5. **Create Configuration**:
   ```bash
   sudo -u zehrashield cp config/firewall.json.example config/firewall.json
   ```

6. **Set Up Systemd Service**:
   ```bash
   sudo cp scripts/zehrashield.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable zehrashield
   ```

7. **Configure Firewall Rules**:
   ```bash
   sudo bash scripts/setup-iptables.sh
   ```

8. **Start Service**:
   ```bash
   sudo systemctl start zehrashield
   sudo systemctl status zehrashield
   ```

### Platform-Specific Installation

#### Ubuntu/Debian
```bash
# Update package list
sudo apt update

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv git iptables-persistent

# Follow manual installation steps above
```

#### CentOS/RHEL
```bash
# Update package list
sudo yum update

# Install dependencies
sudo yum install -y python3 python3-pip git iptables-services

# Enable iptables service
sudo systemctl enable iptables
sudo systemctl start iptables

# Follow manual installation steps above
```

#### Docker Installation
```bash
# Build Docker image
docker build -t zehrashield:latest .

# Run container
docker run -d \
  --name zehrashield \
  --network host \
  --privileged \
  -v /opt/zehrashield/config:/app/config \
  -v /opt/zehrashield/logs:/app/logs \
  zehrashield:latest
```

## Configuration

### Initial Configuration

1. **Web Interface Access**:
   - URL: `https://your-server-ip:8443`
   - Default username: `admin`
   - Default password: `admin123`

2. **Change Default Password**:
   ```bash
   # Login to web interface and navigate to Configuration
   # Or use CLI:
   sudo /opt/zehrashield/venv/bin/python main.py --change-password
   ```

3. **Configure Network Interfaces**:
   ```json
   {
     "network": {
       "interfaces": ["eth0", "eth1"],
       "bridge_mode": false,
       "promiscuous_mode": true
     }
   }
   ```

4. **Set Up SSL Certificate**:
   ```bash
   # Generate self-signed certificate
   sudo openssl req -x509 -newkey rsa:4096 -keyout /opt/zehrashield/ssl/server.key -out /opt/zehrashield/ssl/server.crt -days 365 -nodes
   
   # Or use Let's Encrypt
   sudo certbot certonly --standalone -d your-domain.com
   ```

### Security Layer Configuration

#### Layer 1: Packet Filtering
```json
{
  "layers": {
    "layer1": {
      "enabled": true,
      "mode": "block",
      "whitelist": [
        "192.168.1.0/24",
        "10.0.0.0/8"
      ],
      "blacklist": [
        "1.2.3.4/32"
      ]
    }
  }
}
```

#### Layer 2: Application Gateway
```json
{
  "layers": {
    "layer2": {
      "enabled": true,
      "sensitivity": "medium",
      "protocols": ["HTTP", "HTTPS", "FTP", "SSH"]
    }
  }
}
```

#### Layer 3: IDS/IPS
```json
{
  "layers": {
    "layer3": {
      "enabled": true,
      "enable_ips": true,
      "update_frequency": "daily",
      "custom_rules": []
    }
  }
}
```

### Performance Configuration

```json
{
  "performance": {
    "max_threads": 10,
    "memory_limit_mb": 2048,
    "cache_size_mb": 512,
    "processing_timeout": 30
  }
}
```

## Service Management

### Systemd Commands

```bash
# Start service
sudo systemctl start zehrashield

# Stop service
sudo systemctl stop zehrashield

# Restart service
sudo systemctl restart zehrashield

# Check status
sudo systemctl status zehrashield

# Enable auto-start
sudo systemctl enable zehrashield

# Disable auto-start
sudo systemctl disable zehrashield

# View logs
sudo journalctl -u zehrashield -f
```

### Configuration Reload

```bash
# Reload configuration without restart
sudo systemctl reload zehrashield

# Or send SIGHUP signal
sudo pkill -HUP -f zehrashield
```

### Log Management

```bash
# View real-time logs
sudo tail -f /opt/zehrashield/logs/firewall.log

# View security events
sudo tail -f /opt/zehrashield/logs/security.log

# Rotate logs manually
sudo logrotate -f /etc/logrotate.d/zehrashield
```

## Security Hardening

### File Permissions

```bash
# Set secure permissions
sudo chmod 750 /opt/zehrashield
sudo chmod 640 /opt/zehrashield/config/firewall.json
sudo chmod 600 /opt/zehrashield/ssl/server.key
sudo chmod 644 /opt/zehrashield/ssl/server.crt

# Set ownership
sudo chown -R zehrashield:zehrashield /opt/zehrashield
sudo chown root:root /etc/systemd/system/zehrashield.service
```

### Network Security

```bash
# Configure firewall rules
sudo ufw allow 8443/tcp
sudo ufw deny 22/tcp from any to any
sudo ufw enable

# Or using iptables
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j DROP
```

### SSL/TLS Configuration

```bash
# Use strong SSL configuration
sudo openssl dhparam -out /opt/zehrashield/ssl/dhparam.pem 4096
```

Update configuration:
```json
{
  "web": {
    "ssl": {
      "cert_file": "/opt/zehrashield/ssl/server.crt",
      "key_file": "/opt/zehrashield/ssl/server.key",
      "dhparam_file": "/opt/zehrashield/ssl/dhparam.pem",
      "protocols": ["TLSv1.2", "TLSv1.3"],
      "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    }
  }
}
```

### Authentication Security

```json
{
  "auth": {
    "password_policy": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true,
      "require_symbols": true
    },
    "session_timeout": 30,
    "max_login_attempts": 3,
    "lockout_duration": 300
  }
}
```

## Monitoring and Maintenance

### Health Checks

```bash
# Check service health
curl -k https://localhost:8443/api/health

# Check system resources
htop
iostat -x 1
sar -u 1 10
```

### Performance Monitoring

```bash
# Monitor ZehraShield processes
ps aux | grep zehrashield

# Monitor network connections
netstat -tunlp | grep 8443

# Monitor memory usage
free -h
cat /proc/meminfo
```

### Log Analysis

```bash
# Search for specific events
grep "BLOCK" /opt/zehrashield/logs/security.log

# Count events by type
grep "Layer 1" /opt/zehrashield/logs/security.log | wc -l

# Analyze top blocked IPs
grep "BLOCK" /opt/zehrashield/logs/security.log | awk '{print $5}' | sort | uniq -c | sort -nr | head -10
```

### Automated Monitoring

Create monitoring script (`/opt/zehrashield/scripts/monitor.sh`):

```bash
#!/bin/bash

# Check if service is running
if ! systemctl is-active --quiet zehrashield; then
    echo "ZehraShield service is not running"
    # Send alert or restart service
    systemctl restart zehrashield
fi

# Check disk space
DISK_USAGE=$(df /opt/zehrashield | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 90 ]; then
    echo "Disk usage is high: ${DISK_USAGE}%"
    # Clean old logs or send alert
fi

# Check memory usage
MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.2f", $3/$2 * 100.0}')
if (( $(echo "$MEMORY_USAGE > 90" | bc -l) )); then
    echo "Memory usage is high: ${MEMORY_USAGE}%"
fi
```

Add to crontab:
```bash
sudo crontab -e
# Add line:
*/5 * * * * /opt/zehrashield/scripts/monitor.sh
```

## Backup and Recovery

### Configuration Backup

```bash
# Create backup script
#!/bin/bash
BACKUP_DIR="/opt/zehrashield/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup configuration
tar -czf $BACKUP_DIR/config_$DATE.tar.gz -C /opt/zehrashield config/

# Backup database (if using)
# mysqldump zehrashield > $BACKUP_DIR/database_$DATE.sql

# Keep only last 30 days of backups
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
```

### Recovery Process

```bash
# Stop service
sudo systemctl stop zehrashield

# Restore configuration
sudo tar -xzf /opt/zehrashield/backups/config_YYYYMMDD_HHMMSS.tar.gz -C /opt/zehrashield/

# Restore database (if applicable)
# mysql zehrashield < /opt/zehrashield/backups/database_YYYYMMDD_HHMMSS.sql

# Start service
sudo systemctl start zehrashield
```

### Disaster Recovery

1. **Full System Backup**:
   ```bash
   rsync -av /opt/zehrashield/ backup-server:/backups/zehrashield/
   ```

2. **Recovery on New System**:
   ```bash
   # Install ZehraShield on new system
   curl -sSL https://raw.githubusercontent.com/yashab-cyber/zehrashield/main/scripts/install.sh | sudo bash
   
   # Restore from backup
   sudo systemctl stop zehrashield
   sudo rsync -av backup-server:/backups/zehrashield/ /opt/zehrashield/
   sudo systemctl start zehrashield
   ```

## Troubleshooting

### Common Issues

#### Service Won't Start

```bash
# Check service status
sudo systemctl status zehrashield

# Check logs
sudo journalctl -u zehrashield -n 50

# Check configuration syntax
python3 -c "import json; json.load(open('/opt/zehrashield/config/firewall.json'))"

# Check permissions
ls -la /opt/zehrashield/config/firewall.json
```

#### High CPU Usage

```bash
# Check top processes
top -u zehrashield

# Check number of threads
ps -eLf | grep zehrashield | wc -l

# Reduce thread count in configuration
# Edit config/firewall.json and reduce performance.max_threads
```

#### Memory Issues

```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head

# Check for memory leaks
valgrind --tool=memcheck --leak-check=full python3 main.py

# Restart service to free memory
sudo systemctl restart zehrashield
```

#### Network Issues

```bash
# Check network interfaces
ip addr show

# Check iptables rules
sudo iptables -L -n

# Check port binding
sudo netstat -tunlp | grep 8443

# Test connectivity
curl -k https://localhost:8443/api/health
```

### Debug Mode

Enable debug mode for troubleshooting:

```bash
# Stop service
sudo systemctl stop zehrashield

# Run in debug mode
sudo -u zehrashield /opt/zehrashield/venv/bin/python main.py --debug --config config/firewall.json

# Or enable debug in configuration
{
  "debug": true,
  "logging": {
    "level": "DEBUG"
  }
}
```

### Log Analysis

```bash
# Parse error messages
grep -i error /opt/zehrashield/logs/firewall.log | tail -20

# Check for permission errors
grep -i permission /var/log/syslog

# Monitor real-time issues
sudo tail -f /opt/zehrashield/logs/firewall.log | grep -i error
```

## Performance Tuning

### System Optimization

```bash
# Increase file descriptor limits
echo "zehrashield soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "zehrashield hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network settings
echo 'net.core.rmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 16777216' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Application Tuning

```json
{
  "performance": {
    "max_threads": 16,
    "memory_limit_mb": 4096,
    "cache_size_mb": 1024,
    "processing_timeout": 15,
    "enable_caching": true,
    "enable_optimization": true
  }
}
```

### Database Optimization (if applicable)

```bash
# MySQL optimization
sudo mysql -e "SET GLOBAL innodb_buffer_pool_size = 1073741824;"
sudo mysql -e "SET GLOBAL query_cache_size = 67108864;"
```

## High Availability

### Load Balancer Setup

```bash
# Install HAProxy
sudo apt install haproxy

# Configure HAProxy (/etc/haproxy/haproxy.cfg)
frontend zehrashield_frontend
    bind *:443
    mode tcp
    default_backend zehrashield_backend

backend zehrashield_backend
    mode tcp
    balance roundrobin
    server zehrashield1 192.168.1.10:8443 check
    server zehrashield2 192.168.1.11:8443 check
```

### Database Clustering

For production deployments with multiple nodes:

```bash
# Set up MySQL master-slave replication
# Or use MySQL Cluster (NDB)
# Or PostgreSQL with streaming replication
```

### Configuration Synchronization

```bash
# Use rsync to sync configurations
rsync -av /opt/zehrashield/config/ node2:/opt/zehrashield/config/

# Or use configuration management tools like Ansible
```

### Health Monitoring

```bash
# Install monitoring tools
sudo apt install nagios-nrpe-server

# Configure health checks
sudo systemctl enable nagios-nrpe-server
sudo systemctl start nagios-nrpe-server
```

## Support and Maintenance

### Regular Maintenance Tasks

1. **Weekly**:
   - Review security logs
   - Check system performance
   - Update threat intelligence feeds

2. **Monthly**:
   - Update software packages
   - Review and clean logs
   - Test backup and recovery procedures

3. **Quarterly**:
   - Security audit
   - Performance review
   - Update documentation

### Getting Support

- **Documentation**: Check user guide and API reference
- **Community**: GitHub issues and discussions
- **Commercial Support**: support@zehrasec.com
- **Emergency Support**: Available 24/7 for enterprise customers

### Reporting Issues

When reporting issues, include:
- ZehraShield version
- Operating system and version
- Configuration files (sanitized)
- Log files
- Steps to reproduce
- Expected vs. actual behavior

For additional support and advanced deployment scenarios, contact ZehraSec professional services.
