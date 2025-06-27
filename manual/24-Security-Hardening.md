# Security Hardening Guide

## Overview

This comprehensive guide covers security hardening procedures for ZehraSec Advanced Firewall, including system-level hardening, application security, network security, and compliance requirements. Follow these procedures to maximize the security posture of your firewall deployment.

## Table of Contents

1. [System-Level Hardening](#system-level-hardening)
2. [Application Security Hardening](#application-security-hardening)
3. [Network Security Hardening](#network-security-hardening)
4. [Access Control Hardening](#access-control-hardening)
5. [Cryptographic Hardening](#cryptographic-hardening)
6. [Logging and Monitoring Hardening](#logging-and-monitoring-hardening)
7. [Compliance Hardening](#compliance-hardening)
8. [Security Assessment Tools](#security-assessment-tools)
9. [Hardening Checklists](#hardening-checklists)
10. [Continuous Security Monitoring](#continuous-security-monitoring)

## System-Level Hardening

### Operating System Hardening

#### Kernel Hardening

```bash
#!/bin/bash
# Kernel hardening script
# /usr/local/bin/harden-kernel.sh

# Disable unused kernel modules
cat << 'EOF' > /etc/modprobe.d/blacklist-rare-network.conf
# Disable rare network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

# Kernel parameter hardening
cat << 'EOF' > /etc/sysctl.d/99-security-hardening.conf
# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# IPv6 security
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel security
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Memory protection
kernel.randomize_va_space = 2
vm.mmap_min_addr = 65536

# Process restrictions
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
EOF

# Apply kernel parameters
sysctl -p /etc/sysctl.d/99-security-hardening.conf

echo "Kernel hardening completed"
```

#### File System Hardening

```bash
#!/bin/bash
# File system hardening script
# /usr/local/bin/harden-filesystem.sh

# Secure mount options
cat << 'EOF' > /etc/fstab.hardened
# Hardened mount options
tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0
tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0
tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev,size=100M 0 0
/var/log ext4 defaults,noexec,nosuid,nodev 0 2
EOF

# Set secure permissions
chmod 700 /root
chmod 700 /boot
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/shadow
chmod 600 /etc/gshadow

# Remove world-writable files
find / -xdev -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null

# Set sticky bit on world-writable directories
find / -xdev -type d -perm -002 -exec chmod +t {} \; 2>/dev/null

# Secure log files
chmod 640 /var/log/messages
chmod 640 /var/log/secure
chmod 640 /var/log/maillog
chmod 640 /var/log/cron
chmod 640 /var/log/boot.log

echo "File system hardening completed"
```

#### Service Hardening

```bash
#!/bin/bash
# Service hardening script
# /usr/local/bin/harden-services.sh

# Disable unnecessary services
SERVICES_TO_DISABLE=(
    "avahi-daemon"
    "cups"
    "rpcbind"
    "nfs-server"
    "bluetooth"
    "wpa_supplicant"
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-enabled "$service" &>/dev/null; then
        systemctl disable "$service"
        systemctl stop "$service"
        echo "Disabled service: $service"
    fi
done

# Remove unnecessary packages
PACKAGES_TO_REMOVE=(
    "telnet"
    "rsh-server"
    "rsh"
    "ypbind"
    "ypserv"
    "tftp"
    "tftp-server"
    "talk"
    "talk-server"
)

for package in "${PACKAGES_TO_REMOVE[@]}"; do
    if dpkg -l | grep -q "^ii  $package "; then
        apt-get remove --purge -y "$package"
        echo "Removed package: $package"
    fi
done

echo "Service hardening completed" 
```

### User Account Hardening

#### Password Policy Configuration

```bash
#!/bin/bash
# Password policy hardening
# /usr/local/bin/harden-passwords.sh

# Install password quality checking
apt-get install -y libpam-pwquality

# Configure password quality
cat << 'EOF' > /etc/security/pwquality.conf
# Password quality requirements
minlen = 14
minclass = 4
maxrepeat = 2
maxclasrepeat = 2
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 8
enforce_for_root
EOF

# Configure password aging
cat << 'EOF' > /etc/login.defs
# Password aging controls
PASS_MAX_DAYS 90
PASS_MIN_DAYS 1
PASS_MIN_LEN 14
PASS_WARN_AGE 7
EOF

# Configure account lockout
cat << 'EOF' > /etc/pam.d/common-auth
# Account lockout configuration
auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
auth required pam_unix.so
auth required pam_pwquality.so retry=3
EOF

echo "Password policy hardening completed"
```

#### User Account Audit

```bash
#!/bin/bash
# User account audit script
# /usr/local/bin/audit-users.sh

AUDIT_LOG="/var/log/zehrasec/user-audit.log"

log_audit() {
    echo "$(date): $1" | tee -a "$AUDIT_LOG"
}

# Check for users with UID 0
log_audit "Checking for users with UID 0:"
awk -F: '($3 == 0) {print $1}' /etc/passwd | tee -a "$AUDIT_LOG"

# Check for users with empty passwords
log_audit "Checking for users with empty passwords:"
awk -F: '($2 == "") {print $1}' /etc/shadow | tee -a "$AUDIT_LOG"

# Check for inactive users
log_audit "Checking for inactive users (no login in 90 days):"
lastlog -b 90 | grep -v "Never logged in" | tee -a "$AUDIT_LOG"

# Check for users with shell access
log_audit "Users with shell access:"
grep -v "/bin/false\|/sbin/nologin" /etc/passwd | tee -a "$AUDIT_LOG"

# Check sudo access
log_audit "Users with sudo access:"
grep -Po '^sudo.+:\K.*$' /etc/group | tr ',' '\n' | tee -a "$AUDIT_LOG"

# Check for duplicate UIDs
log_audit "Checking for duplicate UIDs:"
awk -F: '{print $3}' /etc/passwd | sort | uniq -d | tee -a "$AUDIT_LOG"

# Check for duplicate usernames
log_audit "Checking for duplicate usernames:"
awk -F: '{print $1}' /etc/passwd | sort | uniq -d | tee -a "$AUDIT_LOG"

echo "User account audit completed"
```

## Application Security Hardening

### ZehraSec Application Hardening

#### Secure Configuration

```json
{
  "security_hardening": {
    "authentication": {
      "enforce_strong_passwords": true,
      "password_complexity": {
        "min_length": 14,
        "require_uppercase": true,
        "require_lowercase": true,
        "require_numbers": true,
        "require_symbols": true,
        "max_age_days": 90,
        "history_count": 12
      },
      "multi_factor_authentication": {
        "enabled": true,
        "methods": ["totp", "hardware_token"],
        "backup_codes": true
      },
      "session_management": {
        "timeout_minutes": 30,
        "concurrent_sessions": 1,
        "secure_cookies": true,
        "httponly_cookies": true
      }
    },
    "access_control": {
      "role_based_access": true,
      "principle_of_least_privilege": true,
      "default_deny": true,
      "admin_approval_required": true,
      "access_review_frequency": "monthly"
    },
    "api_security": {
      "rate_limiting": {
        "enabled": true,
        "requests_per_minute": 100,
        "burst_limit": 200
      },
      "api_key_rotation": {
        "enabled": true,
        "rotation_days": 30
      },
      "input_validation": {
        "strict_mode": true,
        "sanitization": true,
        "parameter_validation": true
      }
    },
    "data_protection": {
      "encryption_at_rest": {
        "enabled": true,
        "algorithm": "AES-256-GCM",
        "key_rotation": "quarterly"
      },
      "encryption_in_transit": {
        "tls_version": "1.3",
        "cipher_suites": [
          "TLS_AES_256_GCM_SHA384",
          "TLS_CHACHA20_POLY1305_SHA256"
        ],
        "perfect_forward_secrecy": true
      }
    }
  }
}
```

#### Application Hardening Script

```bash
#!/bin/bash
# ZehraSec application hardening script
# /usr/local/bin/harden-zehrasec.sh

ZEHRASEC_CONFIG="/etc/zehrasec"
BACKUP_DIR="/var/backups/zehrasec/hardening"

# Create backup
mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/pre-hardening-$(date +%Y%m%d).tar.gz" "$ZEHRASEC_CONFIG"

# Set secure file permissions
chmod 750 "$ZEHRASEC_CONFIG"
chmod 640 "$ZEHRASEC_CONFIG"/*.json
chmod 600 "$ZEHRASEC_CONFIG"/ssl/*.key
chmod 644 "$ZEHRASEC_CONFIG"/ssl/*.crt

# Set ownership
chown -R zehrasec:zehrasec "$ZEHRASEC_CONFIG"
chown root:zehrasec "$ZEHRASEC_CONFIG"/ssl/*.key

# Secure log directory
chmod 750 /var/log/zehrasec
chown zehrasec:zehrasec /var/log/zehrasec

# Secure temporary directories
chmod 1777 /tmp
chmod 1777 /var/tmp

# Configure secure umask
echo "umask 027" >> /etc/profile
echo "umask 027" >> /home/zehrasec/.bashrc

# Disable core dumps for security
echo "* hard core 0" >> /etc/security/limits.conf
echo "* soft core 0" >> /etc/security/limits.conf

# Configure process limits
cat << 'EOF' >> /etc/security/limits.conf
# ZehraSec process limits
zehrasec soft nproc 4096
zehrasec hard nproc 8192
zehrasec soft nofile 65536
zehrasec hard nofile 65536
EOF

echo "ZehraSec application hardening completed"
```

## Network Security Hardening

### Firewall Configuration

#### Host-Based Firewall

```bash
#!/bin/bash
# Host-based firewall configuration
# /usr/local/bin/configure-host-firewall.sh

# Install and configure UFW
apt-get install -y ufw

# Default policies
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# Allow SSH (change port as needed)
ufw allow 22/tcp

# Allow ZehraSec management interface
ufw allow 8443/tcp

# Allow ZehraSec API
ufw allow 8080/tcp

# Allow monitoring (if using external monitoring)
ufw allow from 192.168.1.0/24 to any port 9100

# Enable logging
ufw logging on

# Enable firewall
ufw --force enable

echo "Host-based firewall configured"
```

#### Network Segmentation

```bash
#!/bin/bash
# Network segmentation script
# /usr/local/bin/configure-network-segmentation.sh

# Create management VLAN interface
ip link add link eth0 name eth0.100 type vlan id 100
ip addr add 192.168.100.10/24 dev eth0.100
ip link set dev eth0.100 up

# Create DMZ VLAN interface  
ip link add link eth0 name eth0.200 type vlan id 200
ip addr add 192.168.200.10/24 dev eth0.200
ip link set dev eth0.200 up

# Configure routing rules
ip route add 192.168.100.0/24 dev eth0.100
ip route add 192.168.200.0/24 dev eth0.200

# Configure iptables rules for segmentation
iptables -A FORWARD -i eth0.100 -o eth0.200 -j DROP
iptables -A FORWARD -i eth0.200 -o eth0.100 -j DROP

echo "Network segmentation configured"
```

### SSL/TLS Hardening

#### Certificate Management

```bash
#!/bin/bash
# SSL/TLS certificate hardening
# /usr/local/bin/harden-ssl.sh

SSL_DIR="/etc/zehrasec/ssl"
CERT_FILE="$SSL_DIR/zehrasec.crt"
KEY_FILE="$SSL_DIR/zehrasec.key"
CSR_FILE="$SSL_DIR/zehrasec.csr"

# Generate strong private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$KEY_FILE"

# Set secure permissions
chmod 600 "$KEY_FILE"
chown root:zehrasec "$KEY_FILE"

# Generate CSR with secure configuration
openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -config <(
cat << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Organization
OU = IT Department
CN = zehrasec.company.com

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = zehrasec.company.com
DNS.2 = firewall.company.com
IP.1 = 192.168.1.100
EOF
)

# Configure strong cipher suites
cat << 'EOF' > /etc/zehrasec/ssl/ciphers.conf
# Strong cipher suites only
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA

# Protocol settings
ssl_protocols TLSv1.2 TLSv1.3
ssl_prefer_server_ciphers on
ssl_session_cache shared:SSL:10m
ssl_session_timeout 10m
ssl_session_tickets off

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always
EOF

echo "SSL/TLS hardening completed"
```

## Access Control Hardening

### Multi-Factor Authentication

#### TOTP Configuration

```bash
#!/bin/bash
# Configure TOTP for ZehraSec
# /usr/local/bin/configure-totp.sh

# Install Google Authenticator PAM module
apt-get install -y libpam-google-authenticator

# Configure PAM
cat << 'EOF' > /etc/pam.d/zehrasec-login
# ZehraSec MFA configuration
auth required pam_google_authenticator.so
auth required pam_unix.so
EOF

# Create TOTP setup script for users
cat << 'EOF' > /usr/local/bin/setup-totp.sh
#!/bin/bash
# TOTP setup for individual users

if [ "$EUID" -eq 0 ]; then
    echo "Do not run this script as root"
    exit 1
fi

echo "Setting up TOTP for user: $(whoami)"
google-authenticator -t -d -f -r 3 -R 30 -W

echo "TOTP setup completed. Please save your backup codes."
EOF

chmod +x /usr/local/bin/setup-totp.sh

echo "TOTP configuration completed"
```

### Role-Based Access Control

#### RBAC Configuration

```json
{
  "rbac_configuration": {
    "roles": {
      "super_admin": {
        "description": "Full system access",
        "permissions": ["*"],
        "max_concurrent_sessions": 2,
        "session_timeout": 30,
        "ip_restrictions": ["192.168.1.0/24"],
        "time_restrictions": {
          "allowed_hours": "06:00-20:00",
          "allowed_days": ["monday", "tuesday", "wednesday", "thursday", "friday"]
        }
      },
      "security_admin": {
        "description": "Security policy management",
        "permissions": [
          "firewall.rules.read",
          "firewall.rules.write",
          "threats.view",
          "logs.security.read",
          "users.view",
          "reports.security.read"
        ],
        "max_concurrent_sessions": 3,
        "session_timeout": 60
      },
      "network_admin": {
        "description": "Network configuration management",
        "permissions": [
          "network.config.read",
          "network.config.write",
          "interfaces.manage",
          "routing.manage",
          "logs.network.read"
        ],
        "max_concurrent_sessions": 2,
        "session_timeout": 45
      },
      "security_analyst": {
        "description": "Security monitoring and analysis",
        "permissions": [
          "threats.view",
          "logs.security.read",
          "reports.security.read",
          "dashboards.security.view",
          "incidents.read",
          "incidents.write"
        ],
        "max_concurrent_sessions": 5,
        "session_timeout": 120
      },
      "operator": {
        "description": "Basic operational tasks",
        "permissions": [
          "dashboards.view",
          "system.status.read",
          "logs.system.read",
          "reports.operational.read"
        ],
        "max_concurrent_sessions": 10,
        "session_timeout": 240
      },
      "auditor": {
        "description": "Audit and compliance access",
        "permissions": [
          "logs.audit.read",
          "reports.compliance.read",
          "users.audit.read",
          "system.audit.read"
        ],
        "max_concurrent_sessions": 2,
        "session_timeout": 60,
        "read_only": true
      }
    },
    "permission_groups": {
      "firewall_management": [
        "firewall.rules.read",
        "firewall.rules.write",
        "firewall.rules.deploy",
        "firewall.policies.manage"
      ],
      "user_management": [
        "users.create",
        "users.read",
        "users.update",
        "users.delete",
        "roles.assign"
      ],
      "system_administration": [
        "system.config.read",
        "system.config.write",
        "system.restart",
        "system.update",
        "backups.manage"
      ]
    }
  }
}
```

## Cryptographic Hardening

### Encryption Configuration

#### Full Disk Encryption

```bash
#!/bin/bash
# Configure full disk encryption
# /usr/local/bin/configure-disk-encryption.sh

# Check if LUKS is already configured
if ! cryptsetup isLuks /dev/sda2; then
    echo "Configuring LUKS encryption..."
    
    # Create LUKS header
    cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha512 /dev/sda2
    
    # Open encrypted device
    cryptsetup luksOpen /dev/sda2 root_crypt
    
    # Create filesystem
    mkfs.ext4 /dev/mapper/root_crypt
    
    echo "Disk encryption configured"
else
    echo "Disk encryption already configured"
fi
```

#### Database Encryption

```sql
-- Database encryption configuration
-- /usr/local/bin/configure-db-encryption.sql

-- Enable transparent data encryption
ALTER SYSTEM SET data_encryption = on;

-- Configure encryption key management
CREATE TABLE encryption_keys (
    key_id SERIAL PRIMARY KEY,
    key_name VARCHAR(255) NOT NULL,
    key_value BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active'
);

-- Encrypt sensitive columns
ALTER TABLE user_accounts ALTER COLUMN password_hash SET STORAGE ENCRYPTED;
ALTER TABLE api_keys ALTER COLUMN key_value SET STORAGE ENCRYPTED;
ALTER TABLE certificates ALTER COLUMN private_key SET STORAGE ENCRYPTED;

-- Configure key rotation policy
CREATE OR REPLACE FUNCTION rotate_encryption_keys()
RETURNS void AS $$
BEGIN
    -- Key rotation logic
    UPDATE encryption_keys 
    SET status = 'expired' 
    WHERE expires_at < CURRENT_TIMESTAMP;
    
    -- Generate new keys
    INSERT INTO encryption_keys (key_name, key_value, expires_at)
    SELECT 
        key_name || '_' || extract(epoch from now()),
        gen_random_bytes(32),
        CURRENT_TIMESTAMP + INTERVAL '90 days'
    FROM encryption_keys 
    WHERE status = 'expired';
END;
$$ LANGUAGE plpgsql;

-- Schedule key rotation
SELECT cron.schedule('key-rotation', '0 0 1 * *', 'SELECT rotate_encryption_keys();');
```

### Key Management

#### HSM Integration

```python
#!/usr/bin/env python3
# HSM integration for key management
# /usr/local/bin/hsm-integration.py

import pkcs11
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class HSMKeyManager:
    def __init__(self, hsm_library_path, token_label, pin):
        self.lib = pkcs11.lib(hsm_library_path)
        self.token = self.lib.get_token(token_label=token_label)
        self.session = self.token.open(user_pin=pin)
        self.logger = logging.getLogger(__name__)
    
    def generate_rsa_key_pair(self, key_size=4096, label="zehrasec-key"):
        """Generate RSA key pair in HSM"""
        try:
            # Generate key pair
            public_key, private_key = self.session.generate_keypair(
                pkcs11.KeyType.RSA,
                key_size,
                public_template={
                    pkcs11.Attribute.TOKEN: True,
                    pkcs11.Attribute.VERIFY: True,
                    pkcs11.Attribute.ENCRYPT: True,
                    pkcs11.Attribute.WRAP: True,
                    pkcs11.Attribute.LABEL: f"{label}-public",
                },
                private_template={
                    pkcs11.Attribute.TOKEN: True,
                    pkcs11.Attribute.PRIVATE: True,
                    pkcs11.Attribute.SENSITIVE: True,
                    pkcs11.Attribute.EXTRACTABLE: False,
                    pkcs11.Attribute.SIGN: True,
                    pkcs11.Attribute.DECRYPT: True,
                    pkcs11.Attribute.UNWRAP: True,
                    pkcs11.Attribute.LABEL: f"{label}-private",
                }
            )
            
            self.logger.info(f"Generated RSA key pair: {label}")
            return public_key, private_key
            
        except Exception as e:
            self.logger.error(f"Failed to generate key pair: {e}")
            raise
    
    def sign_data(self, private_key, data):
        """Sign data using HSM private key"""
        try:
            signature = private_key.sign(
                data,
                mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS
            )
            return signature
        except Exception as e:
            self.logger.error(f"Failed to sign data: {e}")
            raise
    
    def encrypt_data(self, public_key, data):
        """Encrypt data using HSM public key"""
        try:
            encrypted_data = public_key.encrypt(
                data,
                mechanism=pkcs11.Mechanism.RSA_PKCS_OAEP,
                mechanism_param=pkcs11.MGF.MGF1_SHA256
            )
            return encrypted_data
        except Exception as e:
            self.logger.error(f"Failed to encrypt data: {e}")
            raise
    
    def generate_aes_key(self, key_size=256, label="zehrasec-aes"):
        """Generate AES key in HSM"""
        try:
            aes_key = self.session.generate_key(
                pkcs11.KeyType.AES,
                key_size // 8,
                template={
                    pkcs11.Attribute.TOKEN: True,
                    pkcs11.Attribute.PRIVATE: True,
                    pkcs11.Attribute.SENSITIVE: True,
                    pkcs11.Attribute.EXTRACTABLE: False,
                    pkcs11.Attribute.ENCRYPT: True,
                    pkcs11.Attribute.DECRYPT: True,
                    pkcs11.Attribute.LABEL: label,
                }
            )
            
            self.logger.info(f"Generated AES key: {label}")
            return aes_key
            
        except Exception as e:
            self.logger.error(f"Failed to generate AES key: {e}")
            raise
    
    def close(self):
        """Close HSM session"""
        if hasattr(self, 'session'):
            self.session.close()

# Usage example
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize HSM
    hsm = HSMKeyManager(
        hsm_library_path="/usr/lib/softhsm/libsofthsm2.so",
        token_label="ZehraSec-Token",
        pin="1234"
    )
    
    try:
        # Generate key pair
        pub_key, priv_key = hsm.generate_rsa_key_pair(label="zehrasec-master")
        
        # Generate AES key
        aes_key = hsm.generate_aes_key(label="zehrasec-data")
        
        print("Key generation completed successfully")
        
    finally:
        hsm.close()
```

## Hardening Checklists

### Pre-Deployment Checklist

```yaml
pre_deployment_security_checklist:
  - category: "System Security"
    items:
      - task: "Operating system fully patched"
        status: "required"
        verification: "apt list --upgradable"
        
      - task: "Unnecessary services disabled"
        status: "required"
        verification: "systemctl list-unit-files --state=enabled"
        
      - task: "Host firewall configured"
        status: "required"
        verification: "ufw status"
        
      - task: "Kernel hardening applied"
        status: "required"
        verification: "sysctl -a | grep -E 'net.ipv4|kernel'"
        
  - category: "Application Security"
    items:
      - task: "Strong authentication configured"
        status: "required"
        verification: "grep -r 'password' /etc/zehrasec/"
        
      - task: "TLS 1.3 enabled"
        status: "required"
        verification: "openssl s_client -connect localhost:8443 -tls1_3"
        
      - task: "Default passwords changed"
        status: "critical"
        verification: "manual_verification"
        
      - task: "File permissions secured"
        status: "required"
        verification: "find /etc/zehrasec -ls"
        
  - category: "Network Security"
    items:
      - task: "Network segmentation implemented"
        status: "recommended"
        verification: "ip route show"
        
      - task: "Unnecessary ports closed"
        status: "required"
        verification: "nmap -sS localhost"
        
      - task: "SSL certificates valid"
        status: "required"
        verification: "openssl x509 -in /etc/zehrasec/ssl/cert.crt -text"
        
  - category: "Data Protection"
    items:
      - task: "Encryption at rest enabled"
        status: "required"
        verification: "cryptsetup status"
        
      - task: "Database encryption configured"
        status: "required"
        verification: "psql -c 'SHOW data_encryption;'"
        
      - task: "Backup encryption enabled"
        status: "required"
        verification: "gpg --list-keys"
```

### Post-Deployment Checklist

```yaml
post_deployment_security_checklist:
  - category: "Monitoring"
    items:
      - task: "Security logging enabled"
        status: "required"
        verification: "tail -f /var/log/zehrasec/security.log"
        
      - task: "Intrusion detection active"
        status: "required"
        verification: "systemctl status fail2ban"
        
      - task: "Performance monitoring configured"
        status: "recommended"
        verification: "curl http://localhost:9100/metrics"
        
  - category: "Access Control"
    items:
      - task: "User accounts reviewed"
        status: "required"
        verification: "zehrasec-cli users list"
        
      - task: "Administrative access limited"
        status: "required"
        verification: "grep sudo /etc/group"
        
      - task: "Session timeouts configured"
        status: "required"
        verification: "grep timeout /etc/zehrasec/config.json"
        
  - category: "Incident Response"
    items:
      - task: "Incident response plan documented"
        status: "required"
        verification: "manual_verification"
        
      - task: "Contact information updated"
        status: "required"
        verification: "manual_verification"
        
      - task: "Backup and recovery tested"
        status: "required"
        verification: "manual_verification"
```

## Continuous Security Monitoring

### Security Monitoring Script

```bash
#!/bin/bash
# Continuous security monitoring
# /usr/local/bin/security-monitor.sh

MONITOR_LOG="/var/log/zehrasec/security-monitor.log"
ALERT_EMAIL="security@company.com"

log_security() {
    echo "$(date): $1" | tee -a "$MONITOR_LOG"
}

send_alert() {
    local subject="$1"
    local message="$2"
    
    echo "$message" | mail -s "$subject" "$ALERT_EMAIL"
    log_security "ALERT: $subject"
}

# Monitor failed login attempts
check_failed_logins() {
    local failed_count=$(grep "authentication failure" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
    
    if [ "$failed_count" -gt 10 ]; then
        send_alert "High Failed Login Attempts" "Detected $failed_count failed login attempts today"
    fi
}

# Monitor for rootkit activity
check_rootkits() {
    if command -v rkhunter &> /dev/null; then
        rkhunter --check --skip-keypress --quiet
        if [ $? -ne 0 ]; then
            send_alert "Rootkit Detection Alert" "rkhunter detected potential security issues"
        fi
    fi
}

# Monitor file integrity
check_file_integrity() {
    if command -v aide &> /dev/null; then
        aide --check
        if [ $? -ne 0 ]; then
            send_alert "File Integrity Alert" "AIDE detected file system changes"
        fi
    fi
}

# Monitor network connections
check_network_connections() {
    local suspicious_connections=$(netstat -tuln | grep -E ":(6667|6668|6669|1234|31337)" | wc -l)
    
    if [ "$suspicious_connections" -gt 0 ]; then
        send_alert "Suspicious Network Activity" "Detected connections on suspicious ports"
    fi
}

# Monitor system resources
check_system_resources() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    local memory_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    
    if (( $(echo "$cpu_usage > 90" | bc -l) )); then
        send_alert "High CPU Usage" "CPU usage is at $cpu_usage%"
    fi
    
    if [ "$memory_usage" -gt 90 ]; then
        send_alert "High Memory Usage" "Memory usage is at $memory_usage%"
    fi
}

# Main monitoring loop
main() {
    log_security "Starting security monitoring cycle"
    
    check_failed_logins
    check_rootkits
    check_file_integrity
    check_network_connections
    check_system_resources
    
    log_security "Security monitoring cycle completed"
}

# Run monitoring
main
```

## Support and Resources

### Security Contacts

- **Security Team**: security@zehrasec.com
- **Incident Response**: incident-response@zehrasec.com
- **Vulnerability Reports**: security-reports@zehrasec.com
- **Emergency Hotline**: +1-800-SECURITY

### Documentation and Tools

- **Security Documentation**: https://docs.zehrasec.com/security
- **Hardening Scripts**: https://github.com/zehrasec/hardening-scripts
- **Security Benchmarks**: https://benchmarks.zehrasec.com
- **Vulnerability Database**: https://vulndb.zehrasec.com

---

*This security hardening guide provides comprehensive procedures for securing ZehraSec Advanced Firewall deployments. Regular application of these hardening measures is essential for maintaining strong security posture.*
