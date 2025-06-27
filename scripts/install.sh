#!/bin/bash

# ZehraShield Installation Script
# Copyright © 2025 ZehraSec - Yashab Alam
# Enterprise Firewall Installation and Setup

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/zehrashield"
SERVICE_USER="zehrashield"
LOG_DIR="/var/log/zehrashield"
DATA_DIR="/var/lib/zehrashield"
CONFIG_DIR="/etc/zehrashield"

# Functions
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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect operating system"
        exit 1
    fi
    
    log_info "Detected OS: $OS $VERSION"
}

install_dependencies() {
    log_info "Installing system dependencies..."
    
    case $OS in
        "ubuntu"|"debian")
            apt-get update
            apt-get install -y python3 python3-pip python3-venv git curl wget \
                iptables netfilter-persistent ipset tcpdump nmap sqlite3 \
                build-essential libffi-dev libssl-dev libnfnetlink-dev \
                libnetfilter-queue-dev libpcap-dev
            ;;
        "centos"|"rhel"|"fedora")
            if command -v dnf &> /dev/null; then
                dnf install -y python3 python3-pip git curl wget iptables-services \
                    ipset tcpdump nmap sqlite gcc gcc-c++ libffi-devel \
                    openssl-devel libnfnetlink-devel libnetfilter_queue-devel libpcap-devel
            else
                yum install -y python3 python3-pip git curl wget iptables-services \
                    ipset tcpdump nmap sqlite gcc gcc-c++ libffi-devel \
                    openssl-devel libnfnetlink-devel libnetfilter_queue-devel libpcap-devel
            fi
            ;;
        "arch")
            pacman -Sy --noconfirm python python-pip git curl wget iptables \
                ipset tcpdump nmap sqlite gcc libffi openssl libnfnetlink \
                libnetfilter_queue libpcap
            ;;
        *)
            log_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    log_success "System dependencies installed"
}

create_user() {
    log_info "Creating service user..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d /nonexistent -c "ZehraShield Service" $SERVICE_USER
        log_success "Created user: $SERVICE_USER"
    else
        log_info "User $SERVICE_USER already exists"
    fi
}

create_directories() {
    log_info "Creating directories..."
    
    mkdir -p $INSTALL_DIR
    mkdir -p $LOG_DIR
    mkdir -p $DATA_DIR
    mkdir -p $CONFIG_DIR
    mkdir -p $DATA_DIR/{models,reports,backups}
    
    # Set ownership
    chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
    chown -R $SERVICE_USER:$SERVICE_USER $LOG_DIR
    chown -R $SERVICE_USER:$SERVICE_USER $DATA_DIR
    chown -R root:$SERVICE_USER $CONFIG_DIR
    
    # Set permissions
    chmod 755 $INSTALL_DIR
    chmod 755 $LOG_DIR
    chmod 755 $DATA_DIR
    chmod 750 $CONFIG_DIR
    
    log_success "Directories created and configured"
}

install_python_deps() {
    log_info "Installing Python dependencies..."
    
    # Create virtual environment
    python3 -m venv $INSTALL_DIR/venv
    source $INSTALL_DIR/venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install ZehraShield dependencies
    if [[ -f requirements.txt ]]; then
        pip install -r requirements.txt
    else
        # Install essential packages
        pip install flask flask-socketio scapy psutil requests netaddr \
            netifaces numpy pandas scikit-learn tensorflow \
            elasticsearch sqlite3 cryptography python-whois \
            geoip2 maxminddb-reader-python
    fi
    
    log_success "Python dependencies installed"
}

copy_files() {
    log_info "Copying application files..."
    
    # Copy source files
    cp -r src/ $INSTALL_DIR/
    cp -r config/ $INSTALL_DIR/
    cp -r scripts/ $INSTALL_DIR/
    cp main.py $INSTALL_DIR/
    cp requirements.txt $INSTALL_DIR/
    cp VERSION $INSTALL_DIR/
    
    # Copy configuration to system location
    cp config/firewall.json $CONFIG_DIR/firewall.json
    
    # Create CLI symlink
    log_info "Creating CLI command symlink..."
    ln -sf $INSTALL_DIR/scripts/zehrashield-cli /usr/local/bin/zehrashield-cli
    chmod +x $INSTALL_DIR/scripts/zehrashield-cli
    chmod +x $INSTALL_DIR/src/cli/admin_cli.py
    
    # Set ownership
    chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
    chown -R root:$SERVICE_USER $CONFIG_DIR
    
    # Set permissions
    chmod -R 755 $INSTALL_DIR
    chmod 640 $CONFIG_DIR/firewall.json
    
    log_success "Application files copied"
}

create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > /etc/systemd/system/zehrashield.service << EOF
[Unit]
Description=ZehraShield Enterprise Firewall
Documentation=https://github.com/yashab-cyber/zehrashield
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONPATH=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/main.py --config $CONFIG_DIR/firewall.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
TimeoutStartSec=300
TimeoutStopSec=60

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $DATA_DIR
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zehrashield

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable zehrashield.service
    
    log_success "Systemd service created and enabled"
}

configure_firewall() {
    log_info "Configuring system firewall rules..."
    
    # Create backup of existing rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /tmp/iptables-backup-$(date +%Y%m%d-%H%M%S).rules
    fi
    
    # Basic firewall setup for ZehraShield management
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # SSH
    iptables -A INPUT -p tcp --dport 8443 -j ACCEPT  # ZehraShield Web Console
    
    # Save rules
    case $OS in
        "ubuntu"|"debian")
            iptables-save > /etc/iptables/rules.v4
            systemctl enable netfilter-persistent
            ;;
        "centos"|"rhel"|"fedora")
            service iptables save
            systemctl enable iptables
            ;;
    esac
    
    log_success "Basic firewall rules configured"
}

setup_logging() {
    log_info "Setting up logging configuration..."
    
    # Create rsyslog configuration for ZehraShield
    cat > /etc/rsyslog.d/50-zehrashield.conf << EOF
# ZehraShield logging configuration
if \$programname == 'zehrashield' then $LOG_DIR/zehrashield.log
& stop
EOF

    # Create logrotate configuration
    cat > /etc/logrotate.d/zehrashield << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 $SERVICE_USER $SERVICE_USER
    postrotate
        systemctl reload-or-restart rsyslog
    endscript
}
EOF

    # Restart rsyslog
    systemctl restart rsyslog
    
    log_success "Logging configuration completed"
}

create_admin_script() {
    log_info "Creating administration script..."
    
    cat > /usr/local/bin/zehrashield << 'EOF'
#!/bin/bash

# ZehraShield Administration Script
INSTALL_DIR="/opt/zehrashield"
CONFIG_DIR="/etc/zehrashield"
LOG_DIR="/var/log/zehrashield"
DATA_DIR="/var/lib/zehrashield"

case "$1" in
    start)
        echo "Starting ZehraShield..."
        systemctl start zehrashield
        ;;
    stop)
        echo "Stopping ZehraShield..."
        systemctl stop zehrashield
        ;;
    restart)
        echo "Restarting ZehraShield..."
        systemctl restart zehrashield
        ;;
    status)
        systemctl status zehrashield
        ;;
    logs)
        if [[ "$2" == "-f" ]]; then
            journalctl -u zehrashield -f
        else
            journalctl -u zehrashield --no-pager
        fi
        ;;
    config)
        case "$2" in
            edit)
                ${EDITOR:-nano} $CONFIG_DIR/firewall.json
                ;;
            validate)
                python3 -c "import json; json.load(open('$CONFIG_DIR/firewall.json'))" && echo "Configuration is valid" || echo "Configuration has errors"
                ;;
            backup)
                cp $CONFIG_DIR/firewall.json $DATA_DIR/backups/firewall-$(date +%Y%m%d-%H%M%S).json
                echo "Configuration backed up"
                ;;
            *)
                echo "Usage: zehrashield config {edit|validate|backup}"
                ;;
        esac
        ;;
    update)
        echo "Updating ZehraShield..."
        systemctl stop zehrashield
        cd $INSTALL_DIR
        git pull origin main
        source venv/bin/activate
        pip install -r requirements.txt
        systemctl start zehrashield
        echo "Update completed"
        ;;
    test)
        echo "Running ZehraShield tests..."
        cd $INSTALL_DIR
        source venv/bin/activate
        python tests/test_all.py
        ;;
    backup)
        BACKUP_FILE="$DATA_DIR/backups/zehrashield-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        echo "Creating backup: $BACKUP_FILE"
        tar -czf "$BACKUP_FILE" -C / \
            opt/zehrashield \
            etc/zehrashield \
            var/lib/zehrashield \
            --exclude=opt/zehrashield/venv \
            --exclude=var/lib/zehrashield/backups
        echo "Backup created: $BACKUP_FILE"
        ;;
    *)
        echo "ZehraShield Enterprise Firewall Administration"
        echo "Usage: $0 {start|stop|restart|status|logs [-f]|config {edit|validate|backup}|update|test|backup}"
        echo ""
        echo "Commands:"
        echo "  start       Start the ZehraShield service"
        echo "  stop        Stop the ZehraShield service"
        echo "  restart     Restart the ZehraShield service"
        echo "  status      Show service status"
        echo "  logs [-f]   Show logs (use -f to follow)"
        echo "  config      Configuration management"
        echo "  update      Update ZehraShield from repository"
        echo "  test        Run test suite"
        echo "  backup      Create system backup"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/zehrashield
    
    log_success "Administration script created"
}

run_tests() {
    log_info "Running installation tests..."
    
    cd $INSTALL_DIR
    source venv/bin/activate
    
    # Test Python imports
    python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from src.core.config_manager import ConfigManager
    from src.core.firewall_engine import FirewallEngine
    print('✓ Core modules imported successfully')
except ImportError as e:
    print(f'✗ Import error: {e}')
    sys.exit(1)
"

    # Test configuration
    python3 -c "
import json
try:
    with open('/etc/zehrashield/firewall.json') as f:
        config = json.load(f)
    print('✓ Configuration file is valid JSON')
except Exception as e:
    print(f'✗ Configuration error: {e}')
    sys.exit(1)
"
    
    log_success "Installation tests passed"
}

show_completion_message() {
    echo ""
    log_success "ZehraShield installation completed successfully!"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Review configuration: zehrashield config edit"
    echo "2. Start the service: zehrashield start"
    echo "3. Check status: zehrashield status"
    echo "4. View logs: zehrashield logs -f"
    echo "5. Access web console: https://localhost:8443"
    echo ""
    echo -e "${BLUE}Default credentials:${NC}"
    echo "Username: admin"
    echo "Password: zehrashield123"
    echo ""
    echo -e "${YELLOW}Important:${NC} Change default credentials before production use!"
    echo ""
    echo -e "${BLUE}Documentation:${NC} https://github.com/yashab-cyber/zehrashield"
    echo -e "${BLUE}Support:${NC} yashabalam707@gmail.com"
    echo ""
}

# Main installation process
main() {
    echo "==============================================="
    echo "ZehraShield Enterprise Firewall Installation"
    echo "Copyright © 2025 ZehraSec - Yashab Alam"
    echo "==============================================="
    echo ""
    
    check_root
    detect_os
    install_dependencies
    create_user
    create_directories
    install_python_deps
    copy_files
    create_systemd_service
    configure_firewall
    setup_logging
    create_admin_script
    run_tests
    show_completion_message
}

# Run installation if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
