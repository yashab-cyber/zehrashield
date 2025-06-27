#!/bin/bash

# ZehraShield Deployment Script
# Copyright © 2025 ZehraSec - Yashab Alam
# Automated deployment for enterprise environments

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOYMENT_CONFIG="$SCRIPT_DIR/deployment.conf"

# Default configuration
DEFAULT_INSTALL_DIR="/opt/zehrashield"
DEFAULT_SERVICE_USER="zehrashield"
DEFAULT_WEB_PORT="8443"
DEFAULT_API_PORT="5000"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Load deployment configuration
load_config() {
    if [[ -f "$DEPLOYMENT_CONFIG" ]]; then
        source "$DEPLOYMENT_CONFIG"
        log_info "Loaded deployment configuration from $DEPLOYMENT_CONFIG"
    else
        log_warning "No deployment configuration found, using defaults"
        INSTALL_DIR="$DEFAULT_INSTALL_DIR"
        SERVICE_USER="$DEFAULT_SERVICE_USER"
        WEB_PORT="$DEFAULT_WEB_PORT"
        API_PORT="$DEFAULT_API_PORT"
    fi
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Pre-deployment checks
check_prerequisites() {
    log_info "Checking deployment prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "Deployment script must be run as root"
        exit 1
    fi
    
    # Check if Python 3.8+ is available
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if [[ $(echo "$python_version >= 3.8" | bc -l) -eq 0 ]]; then
        log_error "Python 3.8 or newer is required (found $python_version)"
        exit 1
    fi
    
    # Check available disk space (minimum 2GB)
    available_space=$(df / | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 2097152 ]]; then  # 2GB in KB
        log_error "Insufficient disk space. At least 2GB required"
        exit 1
    fi
    
    # Check available memory (minimum 1GB)
    available_memory=$(free -m | awk 'NR==2 {print $7}')
    if [[ $available_memory -lt 1024 ]]; then
        log_error "Insufficient memory. At least 1GB available required"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Environment-specific deployment
deploy_development() {
    log_info "Deploying ZehraShield for development environment..."
    
    # Development-specific configuration
    export ZEHRASHIELD_ENV="development"
    export ZEHRASHIELD_DEBUG="true"
    export ZEHRASHIELD_LOG_LEVEL="DEBUG"
    
    # Install in development mode
    bash "$SCRIPT_DIR/install.sh"
    
    # Additional development tools
    cd "$INSTALL_DIR"
    source venv/bin/activate
    pip install pytest pytest-cov black flake8 mypy
    
    log_success "Development environment deployed"
}

deploy_staging() {
    log_info "Deploying ZehraShield for staging environment..."
    
    # Staging-specific configuration
    export ZEHRASHIELD_ENV="staging"
    export ZEHRASHIELD_DEBUG="false"
    export ZEHRASHIELD_LOG_LEVEL="INFO"
    
    # Install with staging configuration
    bash "$SCRIPT_DIR/install.sh"
    
    # Configure monitoring
    setup_monitoring "staging"
    
    # Run comprehensive tests
    run_deployment_tests
    
    log_success "Staging environment deployed"
}

deploy_production() {
    log_info "Deploying ZehraShield for production environment..."
    
    # Production-specific configuration
    export ZEHRASHIELD_ENV="production"
    export ZEHRASHIELD_DEBUG="false"
    export ZEHRASHIELD_LOG_LEVEL="WARNING"
    
    # Security hardening before installation
    harden_system
    
    # Install with production configuration
    bash "$SCRIPT_DIR/install.sh"
    
    # Configure high availability
    setup_high_availability
    
    # Configure monitoring and alerting
    setup_monitoring "production"
    
    # Configure backup
    setup_backup
    
    # Final security audit
    run_security_audit
    
    log_success "Production environment deployed"
}

# High availability setup
setup_high_availability() {
    log_info "Configuring high availability..."
    
    # Configure systemd service for auto-restart
    cat >> /etc/systemd/system/zehrashield.service << EOF

# High Availability Settings
StartLimitIntervalSec=60
StartLimitBurst=3
RestartSec=5
EOF

    # Configure log monitoring for automatic failover
    cat > /etc/logrotate.d/zehrashield-ha << EOF
/var/log/zehrashield/*.log {
    hourly
    missingok
    rotate 168
    compress
    delaycompress
    notifempty
    create 644 zehrashield zehrashield
    postrotate
        /usr/local/bin/zehrashield-health-check
    endscript
}
EOF

    # Create health check script
    cat > /usr/local/bin/zehrashield-health-check << 'EOF'
#!/bin/bash
# ZehraShield Health Check Script

HEALTH_URL="https://localhost:8443/api/system/status"
LOG_FILE="/var/log/zehrashield/health-check.log"

# Check if service is running
if ! systemctl is-active --quiet zehrashield; then
    echo "$(date): Service not running, attempting restart" >> "$LOG_FILE"
    systemctl restart zehrashield
    exit 1
fi

# Check if web interface responds
if ! curl -k -s --connect-timeout 10 "$HEALTH_URL" > /dev/null; then
    echo "$(date): Web interface not responding, attempting restart" >> "$LOG_FILE"
    systemctl restart zehrashield
    exit 1
fi

echo "$(date): Health check passed" >> "$LOG_FILE"
EOF

    chmod +x /usr/local/bin/zehrashield-health-check
    
    # Setup cron job for health checks
    echo "*/5 * * * * root /usr/local/bin/zehrashield-health-check" >> /etc/crontab
    
    log_success "High availability configured"
}

# Monitoring setup
setup_monitoring() {
    local environment="$1"
    log_info "Setting up monitoring for $environment environment..."
    
    # Install monitoring dependencies
    case $(cat /etc/os-release | grep ^ID= | cut -d= -f2) in
        "ubuntu"|"debian")
            apt-get install -y prometheus-node-exporter
            ;;
        "centos"|"rhel"|"fedora")
            yum install -y node_exporter
            ;;
    esac
    
    # Configure Prometheus node exporter
    systemctl enable node_exporter
    systemctl start node_exporter
    
    # Create ZehraShield metrics endpoint
    cat > /usr/local/bin/zehrashield-metrics << 'EOF'
#!/bin/bash
# ZehraShield Metrics Collection

METRICS_FILE="/var/lib/prometheus/node-exporter/zehrashield.prom"

# Get ZehraShield statistics
stats=$(curl -k -s https://localhost:8443/api/stats 2>/dev/null || echo '{}')

# Extract metrics
threats_blocked=$(echo "$stats" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('engine', {}).get('threats_detected', 0))" 2>/dev/null || echo 0)
packets_processed=$(echo "$stats" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('engine', {}).get('packets_processed', 0))" 2>/dev/null || echo 0)

# Write Prometheus metrics
cat > "$METRICS_FILE" << EOL
# HELP zehrashield_threats_blocked_total Total number of threats blocked
# TYPE zehrashield_threats_blocked_total counter
zehrashield_threats_blocked_total $threats_blocked

# HELP zehrashield_packets_processed_total Total number of packets processed
# TYPE zehrashield_packets_processed_total counter
zehrashield_packets_processed_total $packets_processed

# HELP zehrashield_service_up Whether ZehraShield service is up
# TYPE zehrashield_service_up gauge
zehrashield_service_up $(systemctl is-active --quiet zehrashield && echo 1 || echo 0)
EOL
EOF

    chmod +x /usr/local/bin/zehrashield-metrics
    
    # Setup cron job for metrics collection
    echo "* * * * * root /usr/local/bin/zehrashield-metrics" >> /etc/crontab
    
    log_success "Monitoring configured"
}

# Backup setup
setup_backup() {
    log_info "Setting up automated backup..."
    
    # Create backup script
    cat > /usr/local/bin/zehrashield-backup << 'EOF'
#!/bin/bash
# ZehraShield Automated Backup Script

BACKUP_DIR="/var/backups/zehrashield"
RETENTION_DAYS=30
INSTALL_DIR="/opt/zehrashield"
CONFIG_DIR="/etc/zehrashield"
DATA_DIR="/var/lib/zehrashield"

mkdir -p "$BACKUP_DIR"

# Create timestamped backup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/zehrashield_backup_$TIMESTAMP.tar.gz"

echo "Creating backup: $BACKUP_FILE"

tar -czf "$BACKUP_FILE" \
    --exclude="$INSTALL_DIR/venv" \
    --exclude="$DATA_DIR/backups" \
    "$INSTALL_DIR" \
    "$CONFIG_DIR" \
    "$DATA_DIR" \
    /var/log/zehrashield

# Cleanup old backups
find "$BACKUP_DIR" -name "zehrashield_backup_*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_FILE"

# Upload to remote storage if configured
if [[ -n "$BACKUP_REMOTE_URL" ]]; then
    echo "Uploading backup to remote storage..."
    # Add your remote upload logic here (S3, FTP, etc.)
fi
EOF

    chmod +x /usr/local/bin/zehrashield-backup
    
    # Setup daily backup cron job
    echo "0 2 * * * root /usr/local/bin/zehrashield-backup" >> /etc/crontab
    
    log_success "Automated backup configured"
}

# System hardening
harden_system() {
    log_info "Applying security hardening..."
    
    # Disable unnecessary services
    systemctl disable --now bluetooth 2>/dev/null || true
    systemctl disable --now cups 2>/dev/null || true
    
    # Configure kernel parameters
    cat >> /etc/sysctl.conf << EOF

# ZehraShield Security Hardening
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
EOF

    sysctl -p
    
    # Configure file permissions
    chmod 600 /etc/zehrashield/firewall.json
    
    # Setup fail2ban if available
    if command -v fail2ban-client &> /dev/null; then
        cat > /etc/fail2ban/jail.d/zehrashield.conf << EOF
[zehrashield]
enabled = true
port = 8443
filter = zehrashield
logpath = /var/log/zehrashield/security.log
maxretry = 3
bantime = 3600
EOF

        systemctl restart fail2ban
    fi
    
    log_success "Security hardening applied"
}

# Deployment tests
run_deployment_tests() {
    log_info "Running deployment tests..."
    
    cd "$INSTALL_DIR"
    source venv/bin/activate
    
    # Run test suite
    python tests/test_all.py
    
    # Test service start/stop
    systemctl start zehrashield
    sleep 10
    
    if ! systemctl is-active --quiet zehrashield; then
        log_error "Service failed to start"
        journalctl -u zehrashield --no-pager -n 50
        exit 1
    fi
    
    # Test web interface
    if ! curl -k -s --connect-timeout 30 https://localhost:8443 > /dev/null; then
        log_error "Web interface not accessible"
        exit 1
    fi
    
    systemctl stop zehrashield
    
    log_success "Deployment tests passed"
}

# Security audit
run_security_audit() {
    log_info "Running security audit..."
    
    # Check file permissions
    audit_log="/tmp/zehrashield_security_audit.log"
    
    echo "=== ZehraShield Security Audit ===" > "$audit_log"
    echo "Date: $(date)" >> "$audit_log"
    echo "" >> "$audit_log"
    
    # Check service user
    echo "Service User Check:" >> "$audit_log"
    id zehrashield >> "$audit_log" 2>&1
    echo "" >> "$audit_log"
    
    # Check file permissions
    echo "File Permissions Check:" >> "$audit_log"
    ls -la /etc/zehrashield/ >> "$audit_log"
    ls -la /opt/zehrashield/ | head -20 >> "$audit_log"
    echo "" >> "$audit_log"
    
    # Check running processes
    echo "Process Check:" >> "$audit_log"
    ps aux | grep zehrashield >> "$audit_log"
    echo "" >> "$audit_log"
    
    # Check network listeners
    echo "Network Listeners:" >> "$audit_log"
    netstat -tlnp | grep -E ':(8443|5000)' >> "$audit_log"
    echo "" >> "$audit_log"
    
    # Check firewall rules
    echo "Firewall Rules:" >> "$audit_log"
    iptables -L -n >> "$audit_log"
    echo "" >> "$audit_log"
    
    log_info "Security audit completed. Report saved to $audit_log"
}

# Rollback function
rollback_deployment() {
    log_warning "Rolling back deployment..."
    
    # Stop service
    systemctl stop zehrashield 2>/dev/null || true
    systemctl disable zehrashield 2>/dev/null || true
    
    # Remove service file
    rm -f /etc/systemd/system/zehrashield.service
    systemctl daemon-reload
    
    # Remove installation directory
    rm -rf "$INSTALL_DIR"
    
    # Remove configuration
    rm -rf /etc/zehrashield
    
    # Remove logs
    rm -rf /var/log/zehrashield
    
    # Remove data
    rm -rf /var/lib/zehrashield
    
    # Remove user
    userdel -r zehrashield 2>/dev/null || true
    
    # Remove admin script
    rm -f /usr/local/bin/zehrashield
    
    log_success "Rollback completed"
}

# Main deployment function
main() {
    echo "=============================================="
    echo "ZehraShield Enterprise Firewall Deployment"
    echo "Copyright © 2025 ZehraSec - Yashab Alam"
    echo "=============================================="
    echo ""
    
    load_config
    
    case "${1:-production}" in
        "development"|"dev")
            check_prerequisites
            deploy_development
            ;;
        "staging"|"stage")
            check_prerequisites
            deploy_staging
            ;;
        "production"|"prod")
            check_prerequisites
            deploy_production
            ;;
        "rollback")
            rollback_deployment
            ;;
        "test")
            run_deployment_tests
            ;;
        "audit")
            run_security_audit
            ;;
        *)
            echo "Usage: $0 {development|staging|production|rollback|test|audit}"
            echo ""
            echo "Environments:"
            echo "  development  - Deploy for development (debug enabled)"
            echo "  staging      - Deploy for staging (testing environment)"
            echo "  production   - Deploy for production (full security)"
            echo ""
            echo "Operations:"
            echo "  rollback     - Remove ZehraShield installation"
            echo "  test         - Run deployment tests"
            echo "  audit        - Run security audit"
            exit 1
            ;;
    esac
}

# Trap to handle cleanup on exit
trap 'echo "Deployment interrupted"; exit 1' INT TERM

# Run deployment
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
