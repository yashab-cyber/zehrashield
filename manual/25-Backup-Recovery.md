# Backup and Recovery Guide

![Backup Badge](https://img.shields.io/badge/Backup-Recovery-orange?style=for-the-badge&logo=database)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## 📖 **Overview**

This comprehensive guide covers backup strategies, disaster recovery procedures, and data protection mechanisms for ZehraSec Advanced Firewall to ensure business continuity and data integrity.

---

## 🎯 **Backup Strategy**

### **Backup Components**

#### **Critical System Components**
- Configuration files (`/config/`)
- Rule databases (`/rules/`)
- Log files (`/logs/`)
- SSL certificates (`/certs/`)
- Machine learning models (`/models/`)
- User databases (`/data/users/`)
- Threat intelligence feeds (`/data/threat_intel/`)

#### **Backup Types**
- **Full Backup**: Complete system backup
- **Incremental Backup**: Changes since last backup
- **Differential Backup**: Changes since last full backup
- **Configuration Backup**: Settings and rules only
- **Live Backup**: Real-time continuous backup

---

## 🔧 **Backup Configuration**

### **Automated Backup Setup**

#### **Backup Configuration File**
```json
{
  "backup": {
    "schedule": {
      "full_backup": "0 2 * * 0",
      "incremental_backup": "0 2 * * 1-6",
      "configuration_backup": "0 */6 * * *"
    },
    "retention": {
      "full_backups": 12,
      "incremental_backups": 30,
      "configuration_backups": 168
    },
    "destinations": [
      {
        "type": "local",
        "path": "/backup/zehrasec",
        "encryption": true
      },
      {
        "type": "s3",
        "bucket": "zehrasec-backups",
        "region": "us-east-1",
        "encryption": "AES256"
      },
      {
        "type": "azure",
        "container": "zehrasec-backup",
        "account": "backupstorage"
      }
    ]
  }
}
```

#### **Backup Script Installation**
```bash
# Install backup automation
python -m zehrasec.tools.backup_installer

# Configure backup schedule
crontab -e
# Add backup entries
0 2 * * 0 /usr/local/bin/zehrasec-backup --type full
0 2 * * 1-6 /usr/local/bin/zehrasec-backup --type incremental
0 */6 * * * /usr/local/bin/zehrasec-backup --type config
```

---

## 💾 **Backup Procedures**

### **Full System Backup**
```bash
# Create full system backup
python -m zehrasec.tools.backup create \
  --type full \
  --destination /backup/zehrasec/full_$(date +%Y%m%d_%H%M%S) \
  --encrypt \
  --compress

# Verify backup integrity
python -m zehrasec.tools.backup verify \
  --backup-path /backup/zehrasec/full_20250619_020000
```

### **Configuration Backup**
```bash
# Quick configuration backup
python -m zehrasec.tools.config_backup \
  --output /backup/config_$(date +%Y%m%d_%H%M%S).tar.gz

# Backup specific configuration
python -m zehrasec.tools.config_backup \
  --components "firewall_rules,user_accounts,certificates" \
  --output /backup/selective_config.tar.gz
```

### **Database Backup**
```bash
# Backup threat intelligence database
pg_dump zehrasec_threat_intel > /backup/threat_intel_$(date +%Y%m%d).sql

# Backup user database
python -m zehrasec.tools.user_backup \
  --output /backup/users_$(date +%Y%m%d).json \
  --encrypt
```

---

## 🔄 **Recovery Procedures**

### **System Recovery Planning**

#### **Recovery Time Objectives (RTO)**
- **Critical Systems**: 15 minutes
- **Standard Systems**: 1 hour
- **Non-critical Systems**: 4 hours

#### **Recovery Point Objectives (RPO)**
- **Configuration**: 6 hours
- **Logs**: 1 hour
- **Threat Intelligence**: 24 hours

### **Full System Recovery**
```bash
# Stop ZehraSec services
systemctl stop zehrasec

# Restore from full backup
python -m zehrasec.tools.backup restore \
  --backup-path /backup/zehrasec/full_20250619_020000 \
  --target-path /opt/zehrasec \
  --decrypt \
  --verify

# Restore configuration
python -m zehrasec.tools.config_restore \
  --backup-path /backup/config_20250619_020000.tar.gz \
  --verify-config

# Start services
systemctl start zehrasec
```

### **Configuration Recovery**
```bash
# Restore configuration only
python -m zehrasec.tools.config_restore \
  --config-backup /backup/config_20250619_080000.tar.gz \
  --selective-restore \
  --components "firewall_rules,certificates"

# Validate configuration
python -m zehrasec.tools.config_validator \
  --config-path /config/firewall_advanced.json
```

### **Database Recovery**
```bash
# Restore threat intelligence database
psql zehrasec_threat_intel < /backup/threat_intel_20250619.sql

# Restore user database
python -m zehrasec.tools.user_restore \
  --backup-file /backup/users_20250619.json \
  --decrypt \
  --merge-strategy overwrite
```

---

## 🗂️ **Backup Storage Management**

### **Local Storage Configuration**
```json
{
  "local_storage": {
    "path": "/backup/zehrasec",
    "max_size": "100GB",
    "compression": "gzip",
    "encryption": {
      "algorithm": "AES-256-GCM",
      "key_rotation": "monthly"
    },
    "retention_policy": {
      "daily": 30,
      "weekly": 12,
      "monthly": 12,
      "yearly": 7
    }
  }
}
```

### **Cloud Storage Integration**

#### **AWS S3 Configuration**
```json
{
  "aws_s3": {
    "bucket": "zehrasec-backups",
    "region": "us-east-1",
    "storage_class": "STANDARD_IA",
    "lifecycle_policy": {
      "transition_to_glacier": 90,
      "transition_to_deep_archive": 365,
      "delete_after": 2555
    },
    "versioning": true,
    "encryption": "AES256"
  }
}
```

#### **Azure Blob Storage Configuration**
```json
{
  "azure_blob": {
    "account_name": "zehrasecbackups",
    "container": "firewall-backups",
    "access_tier": "Cool",
    "lifecycle_management": {
      "cool_after_days": 30,
      "archive_after_days": 90,
      "delete_after_days": 2555
    }
  }
}
```

---

## 🔐 **Backup Security**

### **Encryption Configuration**
```json
{
  "encryption": {
    "algorithm": "AES-256-GCM",
    "key_derivation": "PBKDF2",
    "salt_length": 32,
    "iterations": 100000,
    "key_management": {
      "type": "external",
      "service": "AWS KMS",
      "key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    }
  }
}
```

### **Access Control**
```json
{
  "backup_access": {
    "backup_operators": [
      "admin@company.com",
      "backup-service@company.com"
    ],
    "restore_operators": [
      "admin@company.com",
      "sysadmin@company.com"
    ],
    "audit_access": [
      "security@company.com",
      "compliance@company.com"
    ]
  }
}
```

---

## 🚨 **Disaster Recovery**

### **Disaster Recovery Plan**

#### **Recovery Scenarios**
1. **Hardware Failure**: Single server failure
2. **Site Disaster**: Complete data center failure
3. **Data Corruption**: Database or file system corruption
4. **Cyber Attack**: Ransomware or data breach
5. **Human Error**: Accidental deletion or misconfiguration

#### **Recovery Procedures by Scenario**

**Hardware Failure Recovery:**
```bash
# 1. Deploy new hardware
# 2. Install base OS and ZehraSec
# 3. Restore from latest backup
python -m zehrasec.tools.disaster_recovery \
  --scenario hardware_failure \
  --backup-source s3://zehrasec-backups/latest \
  --target-host new-firewall.company.com

# 4. Update DNS and routing
# 5. Verify functionality
```

**Site Disaster Recovery:**
```bash
# 1. Activate DR site
# 2. Deploy ZehraSec infrastructure
# 3. Restore from off-site backups
python -m zehrasec.tools.disaster_recovery \
  --scenario site_disaster \
  --dr-site us-west-2 \
  --restore-from-archive

# 4. Update network configuration
# 5. Notify stakeholders
```

### **Recovery Testing**
```bash
# Schedule monthly DR tests
python -m zehrasec.tools.dr_test \
  --scenario full_recovery \
  --test-environment staging \
  --report-to disaster-recovery@company.com
```

---

## 📊 **Monitoring and Alerts**

### **Backup Monitoring**
```json
{
  "backup_monitoring": {
    "check_intervals": {
      "backup_completion": "hourly",
      "backup_integrity": "daily",
      "storage_capacity": "hourly"
    },
    "alerts": {
      "backup_failure": {
        "severity": "critical",
        "notification": ["email", "sms", "slack"]
      },
      "storage_threshold": {
        "warning": 80,
        "critical": 95,
        "notification": ["email"]
      },
      "integrity_check_failure": {
        "severity": "high",
        "notification": ["email", "ticket"]
      }
    }
  }
}
```

### **Recovery Metrics**
- **Backup Success Rate**: >99.9%
- **Recovery Time**: <RTO targets
- **Data Loss**: <RPO targets
- **Integrity Check Pass Rate**: 100%

---

## 🔧 **Backup Tools and Scripts**

### **Backup Management Scripts**
```bash
#!/bin/bash
# zehrasec-backup.sh

BACKUP_TYPE=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/zehrasec"

case $BACKUP_TYPE in
  "full")
    python -m zehrasec.tools.backup create \
      --type full \
      --destination "$BACKUP_DIR/full_$TIMESTAMP" \
      --encrypt --compress
    ;;
  "config")
    python -m zehrasec.tools.config_backup \
      --output "$BACKUP_DIR/config_$TIMESTAMP.tar.gz"
    ;;
  "incremental")
    python -m zehrasec.tools.backup create \
      --type incremental \
      --destination "$BACKUP_DIR/inc_$TIMESTAMP" \
      --encrypt
    ;;
esac
```

### **Recovery Validation Script**
```python
#!/usr/bin/env python3
# recovery_validator.py

import subprocess
import json
import sys

def validate_recovery(backup_path):
    """Validate backup integrity and recoverability"""
    try:
        # Check backup integrity
        result = subprocess.run([
            'python', '-m', 'zehrasec.tools.backup',
            'verify', '--backup-path', backup_path
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            return False, f"Integrity check failed: {result.stderr}"
        
        # Test configuration validation
        result = subprocess.run([
            'python', '-m', 'zehrasec.tools.config_validator',
            '--backup-config', backup_path
        ], capture_output=True, text=True)
        
        return result.returncode == 0, result.stdout
        
    except Exception as e:
        return False, str(e)
```

---

## 📋 **Backup Checklist**

### **Daily Backup Verification**
- [ ] Backup completion status
- [ ] Backup file integrity
- [ ] Storage space availability
- [ ] Encryption verification
- [ ] Off-site replication status

### **Weekly Backup Tasks**
- [ ] Recovery testing
- [ ] Backup rotation cleanup
- [ ] Performance metrics review
- [ ] Storage capacity planning
- [ ] Documentation updates

### **Monthly Backup Tasks**
- [ ] Full disaster recovery test
- [ ] Backup strategy review
- [ ] Storage cost optimization
- [ ] Key rotation
- [ ] Compliance audit

---

## 🔍 **Troubleshooting Backup Issues**

### **Common Backup Problems**

#### **Backup Fails to Start**
```bash
# Check backup service status
systemctl status zehrasec-backup

# Check disk space
df -h /backup

# Check permissions
ls -la /backup/zehrasec

# Review logs
tail -f /var/log/zehrasec/backup.log
```

#### **Backup Corruption**
```bash
# Verify backup integrity
python -m zehrasec.tools.backup verify \
  --backup-path /backup/suspicious_backup

# Attempt repair
python -m zehrasec.tools.backup repair \
  --backup-path /backup/suspicious_backup \
  --repair-mode aggressive
```

#### **Slow Backup Performance**
```bash
# Enable backup compression
python -m zehrasec.tools.backup configure \
  --compression-level 6 \
  --parallel-streams 4

# Optimize backup scheduling
python -m zehrasec.tools.backup schedule \
  --optimize-for-performance
```

---

## 📚 **Best Practices**

### **Backup Best Practices**
1. **3-2-1 Rule**: 3 copies, 2 different media, 1 off-site
2. **Regular Testing**: Test restores monthly
3. **Automated Monitoring**: Monitor all backup operations
4. **Documentation**: Keep recovery procedures updated
5. **Security**: Encrypt all backups
6. **Retention**: Follow legal and business requirements

### **Recovery Best Practices**
1. **Plan Documentation**: Maintain detailed recovery procedures
2. **Regular Drills**: Practice recovery scenarios
3. **Communication**: Keep stakeholders informed
4. **Validation**: Always verify recovered systems
5. **Lessons Learned**: Document and improve processes

---

## 📞 **Support and Resources**

- **Backup Support**: backup@zehrasec.com
- **Emergency Recovery**: +1-800-ZEHRASEC
- **Documentation**: https://docs.zehrasec.com/backup
- **Training**: https://training.zehrasec.com/disaster-recovery

---

**Next:** [Update Management](26-Update-Management.md) | **Previous:** [Security Hardening](24-Security-Hardening.md)
