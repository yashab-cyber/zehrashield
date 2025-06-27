# Configuration Guide - ZehraSec Advanced Firewall

![Configuration](https://img.shields.io/badge/⚙️-Configuration%20Guide-blue?style=for-the-badge)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## 📋 **Table of Contents**

1. [Configuration Overview](#-configuration-overview)
2. [Configuration Files](#-configuration-files)
3. [Basic Configuration](#-basic-configuration)
4. [Layer Configuration](#-layer-configuration)
5. [Network Settings](#-network-settings)
6. [Security Policies](#-security-policies)
7. [Performance Tuning](#-performance-tuning)
8. [Logging Configuration](#-logging-configuration)
9. [Integration Settings](#-integration-settings)
10. [Advanced Configuration](#-advanced-configuration)

---

## 🔍 **Configuration Overview**

ZehraSec Advanced Firewall uses JSON-based configuration files that control all aspects of the system. The configuration is modular, allowing you to customize each security layer independently.

### **Configuration Hierarchy**
```
config/
├── firewall_advanced.json      # Main configuration file
├── firewall_default.json       # Default settings template
├── threat_intelligence.json    # Threat intel sources
├── ml_models.json              # Machine learning models
├── zero_trust_policies.json    # Zero trust policies
├── soar_playbooks.json         # SOAR automation
├── user_rules.json             # Custom user rules
└── certificates/               # SSL certificates
    ├── server.crt
    └── server.key
```

### **Configuration Validation**
```bash
# Validate configuration before applying
python tools/validate_config.py --config config/firewall_advanced.json

# Check for syntax errors
python -m json.tool config/firewall_advanced.json

# Test configuration
python main.py --config config/firewall_advanced.json --test-config
```

---

## 📄 **Configuration Files**

### **Main Configuration File**
The primary configuration file `config/firewall_advanced.json` contains all system settings:

```json
{
  "version": "3.0.0",
  "firewall": {
    "enabled": true,
    "mode": "production",
    "log_level": "INFO",
    "max_connections": 10000,
    "timeout": 30
  },
  "network": {
    "interfaces": ["auto"],
    "promiscuous_mode": false,
    "capture_all_traffic": true,
    "buffer_size": 65536
  },
  "layers": {
    "layer1_packet_filter": { "enabled": true },
    "layer2_application_gateway": { "enabled": true },
    "layer3_ids_ips": { "enabled": true },
    "layer4_threat_intelligence": { "enabled": true },
    "layer5_network_access_control": { "enabled": true },
    "layer6_siem_integration": { "enabled": true }
  },
  "web_console": {
    "enabled": true,
    "port": 8443,
    "ssl_enabled": true,
    "ssl_cert": "certificates/server.crt",
    "ssl_key": "certificates/server.key"
  },
  "api": {
    "enabled": true,
    "port": 5000,
    "rate_limit": 1000,
    "auth_required": true
  }
}
```

### **Configuration Includes**
For complex deployments, you can split configuration into multiple files:

```json
{
  "version": "3.0.0",
  "includes": [
    "config/network_settings.json",
    "config/security_policies.json",
    "config/threat_intelligence.json"
  ],
  "firewall": {
    "enabled": true,
    "mode": "production"
  }
}
```

---

## 🔧 **Basic Configuration**

### **System Settings**
```json
{
  "firewall": {
    "enabled": true,                    // Enable/disable firewall
    "mode": "production",               // production, development, testing
    "log_level": "INFO",               // DEBUG, INFO, WARNING, ERROR, CRITICAL
    "max_connections": 10000,          // Maximum concurrent connections
    "timeout": 30,                     // Connection timeout in seconds
    "startup_delay": 5,                // Delay before starting (seconds)
    "shutdown_timeout": 30             // Graceful shutdown timeout
  }
}
```

### **Debug Configuration**
```json
{
  "debug": {
    "enabled": false,                  // Enable debug mode
    "level": "INFO",                   // Debug level
    "modules": ["network", "security"], // Debug specific modules
    "output": "both",                  // console, file, both
    "file_path": "logs/debug.log",     // Debug log file
    "max_file_size": "50MB",           // Max debug log size
    "backup_count": 3                  // Number of backup files
  }
}
```

### **Performance Settings**
```json
{
  "performance": {
    "max_threads": 8,                  // Maximum worker threads
    "thread_pool_size": 4,             // Thread pool size
    "memory_limit": "2GB",             // Memory usage limit
    "packet_buffer_size": 65536,       // Packet buffer size
    "processing_timeout": 10,          // Packet processing timeout
    "optimization_level": "high"       // low, medium, high
  }
}
```

---

## 🛡️ **Layer Configuration**

### **Layer 1: Packet Filter**
```json
{
  "layers": {
    "layer1_packet_filter": {
      "enabled": true,
      "mode": "strict",                // permissive, balanced, strict
      "default_action": "drop",        // allow, drop, log
      "rate_limiting": {
        "enabled": true,
        "packets_per_second": 1000,
        "burst_size": 5000,
        "per_ip_limit": 100
      },
      "protocol_filtering": {
        "allowed_protocols": ["TCP", "UDP", "ICMP"],
        "blocked_protocols": ["GRE"],
        "custom_protocols": []
      },
      "port_filtering": {
        "blocked_ports": [1337, 31337, 6667],
        "allowed_ports": [80, 443, 22, 25, 53],
        "port_ranges": [
          {"start": 1024, "end": 65535, "action": "allow"}
        ]
      }
    }
  }
}
```

### **Layer 2: Application Gateway**
```json
{
  "layers": {
    "layer2_application_gateway": {
      "enabled": true,
      "protocols": {
        "http": {
          "enabled": true,
          "port": 80,
          "max_request_size": "10MB",
          "timeout": 30,
          "header_inspection": true,
          "content_filtering": true
        },
        "https": {
          "enabled": true,
          "port": 443,
          "ssl_inspection": false,
          "certificate_validation": true,
          "tls_versions": ["TLSv1.2", "TLSv1.3"]
        },
        "dns": {
          "enabled": true,
          "port": 53,
          "query_logging": true,
          "malicious_domain_blocking": true,
          "dns_over_https": false
        },
        "ftp": {
          "enabled": false,
          "port": 21,
          "passive_mode": true,
          "command_filtering": true
        }
      }
    }
  }
}
```

### **Layer 3: IDS/IPS**
```json
{
  "layers": {
    "layer3_ids_ips": {
      "enabled": true,
      "mode": "prevention",             // detection, prevention
      "sensitivity": "medium",          // low, medium, high
      "auto_block": true,
      "block_duration": 3600,          // seconds
      "whitelist_mode": false,
      "signature_detection": {
        "enabled": true,
        "rule_sets": [
          "emerging_threats",
          "snort_community",
          "custom_rules"
        ],
        "update_frequency": 14400       // seconds (4 hours)
      },
      "anomaly_detection": {
        "enabled": true,
        "baseline_learning": true,
        "learning_period": 604800,      // seconds (1 week)
        "deviation_threshold": 2.5,
        "statistical_analysis": true
      },
      "behavioral_analysis": {
        "enabled": true,
        "user_profiling": true,
        "network_profiling": true,
        "application_profiling": true,
        "time_based_analysis": true
      }
    }
  }
}
```

### **Layer 4: Threat Intelligence**
```json
{
  "layers": {
    "layer4_threat_intelligence": {
      "enabled": true,
      "feeds": {
        "commercial_feeds": {
          "enabled": true,
          "providers": ["alienvault", "threatfox", "malwaredomainlist"],
          "update_frequency": 3600,     // seconds
          "cache_duration": 86400       // seconds
        },
        "open_source_feeds": {
          "enabled": true,
          "providers": ["abuse.ch", "spamhaus", "malwaredomains"],
          "update_frequency": 7200      // seconds
        },
        "custom_feeds": {
          "enabled": true,
          "urls": [
            "https://your-custom-feed.com/indicators.json"
          ],
          "format": "json",             // json, xml, csv
          "authentication": {
            "type": "api_key",
            "key": "your_api_key"
          }
        }
      },
      "reputation_scoring": {
        "enabled": true,
        "scoring_algorithm": "weighted", // simple, weighted, ml
        "confidence_threshold": 0.7,
        "decay_factor": 0.1,
        "max_age": 2592000              // seconds (30 days)
      },
      "machine_learning": {
        "enabled": true,
        "model_path": "./models/",
        "inference_engine": "tensorflow", // tensorflow, pytorch, scikit
        "batch_processing": true,
        "real_time_analysis": true,
        "model_update_frequency": 86400   // seconds
      }
    }
  }
}
```

### **Layer 5: Network Access Control**
```json
{
  "layers": {
    "layer5_network_access_control": {
      "enabled": true,
      "authentication": {
        "methods": ["certificate", "radius", "ldap"],
        "certificate_validation": true,
        "radius_server": "192.168.1.10",
        "ldap_server": "ldap://192.168.1.11"
      },
      "device_identification": {
        "enabled": true,
        "mac_address_tracking": true,
        "device_fingerprinting": true,
        "dhcp_fingerprinting": true,
        "os_detection": true
      },
      "access_policies": {
        "default_policy": "deny",
        "guest_network": {
          "enabled": true,
          "subnet": "192.168.100.0/24",
          "bandwidth_limit": "10Mbps",
          "internet_only": true
        },
        "device_classes": {
          "corporate_devices": {
            "access_level": "full",
            "monitoring_level": "standard"
          },
          "byod_devices": {
            "access_level": "limited",
            "monitoring_level": "enhanced"
          },
          "iot_devices": {
            "access_level": "restricted",
            "monitoring_level": "minimal"
          }
        }
      }
    }
  }
}
```

### **Layer 6: SIEM Integration**
```json
{
  "layers": {
    "layer6_siem_integration": {
      "enabled": true,
      "syslog": {
        "enabled": true,
        "server": "192.168.1.20",
        "port": 514,
        "protocol": "udp",              // udp, tcp, tls
        "facility": "local0",
        "format": "rfc5424"             // rfc3164, rfc5424, cef
      },
      "splunk": {
        "enabled": false,
        "server": "splunk.company.com",
        "port": 8088,
        "token": "your_hec_token",
        "index": "zehrasec",
        "ssl_verify": true
      },
      "elasticsearch": {
        "enabled": false,
        "hosts": ["elasticsearch.company.com:9200"],
        "index": "zehrasec-logs",
        "username": "elastic",
        "password": "password"
      },
      "custom_webhook": {
        "enabled": false,
        "url": "https://your-webhook.com/events",
        "authentication": {
          "type": "bearer",
          "token": "your_token"
        },
        "retry_attempts": 3,
        "timeout": 10
      }
    }
  }
}
```

---

## 🌐 **Network Settings**

### **Interface Configuration**
```json
{
  "network": {
    "interfaces": {
      "monitor_all": true,
      "specific_interfaces": ["eth0", "wlan0"],
      "excluded_interfaces": ["lo", "docker0"],
      "promiscuous_mode": false,
      "capture_direction": "both"        // in, out, both
    },
    "packet_capture": {
      "enabled": true,
      "buffer_size": 65536,
      "snap_length": 1514,
      "timeout": 1000,                   // milliseconds
      "immediate_mode": true
    },
    "traffic_analysis": {
      "deep_packet_inspection": true,
      "protocol_analysis": true,
      "flow_tracking": true,
      "session_reconstruction": false
    }
  }
}
```

### **Routing and Filtering**
```json
{
  "network": {
    "routing": {
      "default_gateway": "192.168.1.1",
      "static_routes": [
        {
          "destination": "10.0.0.0/8",
          "gateway": "192.168.1.1",
          "interface": "eth0"
        }
      ],
      "route_monitoring": true
    },
    "nat": {
      "enabled": false,
      "masquerading": false,
      "port_forwarding": [
        {
          "external_port": 8080,
          "internal_ip": "192.168.1.100",
          "internal_port": 80,
          "protocol": "tcp"
        }
      ]
    }
  }
}
```

---

## 🔒 **Security Policies**

### **Firewall Rules**
```json
{
  "security": {
    "firewall_rules": {
      "default_input_policy": "DROP",
      "default_output_policy": "ACCEPT",
      "default_forward_policy": "DROP",
      "custom_rules": [
        {
          "id": "rule_001",
          "name": "Allow SSH",
          "action": "ACCEPT",
          "protocol": "tcp",
          "destination_port": 22,
          "source": "192.168.1.0/24",
          "enabled": true
        },
        {
          "id": "rule_002",
          "name": "Block Known Bad IPs",
          "action": "DROP",
          "source": "threat_intelligence",
          "log": true,
          "enabled": true
        }
      ]
    }
  }
}
```

### **Access Control Lists**
```json
{
  "security": {
    "access_control": {
      "ip_whitelist": [
        "192.168.1.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12"
      ],
      "ip_blacklist": [
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16"
      ],
      "domain_whitelist": [
        "*.company.com",
        "*.trusted-partner.com"
      ],
      "domain_blacklist": [
        "*.malicious.com",
        "*.phishing-site.com"
      ]
    }
  }
}
```

---

## ⚡ **Performance Tuning**

### **Resource Limits**
```json
{
  "performance": {
    "cpu": {
      "max_usage": 80,                 // percentage
      "thread_affinity": true,
      "priority": "normal",            // low, normal, high
      "scaling": "auto"                // auto, manual
    },
    "memory": {
      "max_usage": "2GB",
      "swap_usage": false,
      "buffer_limits": {
        "packet_buffer": "512MB",
        "log_buffer": "128MB",
        "threat_cache": "256MB"
      }
    },
    "disk": {
      "max_iops": 10000,
      "write_caching": true,
      "compression": true,
      "async_writes": true
    },
    "network": {
      "max_bandwidth": "1Gbps",
      "packet_processing_limit": 100000,
      "connection_limit": 10000,
      "timeout_settings": {
        "tcp_timeout": 300,
        "udp_timeout": 60,
        "icmp_timeout": 30
      }
    }
  }
}
```

### **Optimization Settings**
```json
{
  "optimization": {
    "caching": {
      "enabled": true,
      "cache_size": "1GB",
      "ttl": 3600,                     // seconds
      "cleanup_interval": 300          // seconds
    },
    "load_balancing": {
      "enabled": true,
      "algorithm": "round_robin",      // round_robin, least_connections, weighted
      "health_checks": true,
      "failover": true
    },
    "compression": {
      "logs": true,
      "configs": true,
      "data_streams": false
    }
  }
}
```

---

## 📊 **Logging Configuration**

### **Log Levels and Formats**
```json
{
  "logging": {
    "global": {
      "enabled": true,
      "level": "INFO",
      "format": "json",                // json, plain, syslog
      "timestamp_format": "iso8601",
      "timezone": "UTC"
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
        "file": "logs/zehrasec.log",
        "max_size": "100MB",
        "backup_count": 10,
        "rotation": "daily"
      },
      "syslog": {
        "enabled": false,
        "level": "WARNING",
        "facility": "local0",
        "address": "192.168.1.20:514"
      }
    },
    "loggers": {
      "network": {
        "level": "DEBUG",
        "handlers": ["file", "syslog"]
      },
      "security": {
        "level": "INFO",
        "handlers": ["file", "console"]
      },
      "api": {
        "level": "WARNING",
        "handlers": ["file"]
      }
    }
  }
}
```

### **Audit Logging**
```json
{
  "audit": {
    "enabled": true,
    "log_file": "logs/audit.log",
    "events": {
      "user_login": true,
      "config_changes": true,
      "rule_modifications": true,
      "threat_detections": true,
      "system_events": true
    },
    "retention": {
      "days": 365,
      "compression": true,
      "archive_location": "archive/"
    }
  }
}
```

---

## 🔗 **Integration Settings**

### **API Configuration**
```json
{
  "api": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 5000,
    "ssl": {
      "enabled": true,
      "cert_file": "certificates/api.crt",
      "key_file": "certificates/api.key"
    },
    "authentication": {
      "method": "jwt",                 // jwt, api_key, basic
      "jwt_secret": "your_jwt_secret",
      "token_expiry": 3600,            // seconds
      "refresh_token_expiry": 86400    // seconds
    },
    "rate_limiting": {
      "enabled": true,
      "requests_per_minute": 60,
      "burst_size": 100,
      "per_ip_limit": 1000
    },
    "cors": {
      "enabled": true,
      "allowed_origins": ["https://dashboard.company.com"],
      "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
      "allowed_headers": ["Authorization", "Content-Type"]
    }
  }
}
```

### **Web Console Configuration**
```json
{
  "web_console": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8443,
    "ssl": {
      "enabled": true,
      "cert_file": "certificates/server.crt",
      "key_file": "certificates/server.key",
      "protocols": ["TLSv1.2", "TLSv1.3"]
    },
    "session": {
      "timeout": 3600,                 // seconds
      "cookie_secure": true,
      "cookie_httponly": true,
      "csrf_protection": true
    },
    "ui": {
      "theme": "dark",                 // light, dark, auto
      "refresh_interval": 5000,        // milliseconds
      "max_log_entries": 1000,
      "charts_enabled": true,
      "real_time_updates": true
    }
  }
}
```

---

## 🔬 **Advanced Configuration**

### **Zero Trust Configuration**
```json
{
  "zero_trust": {
    "enabled": true,
    "policies": {
      "default_deny": true,
      "continuous_verification": true,
      "risk_based_access": true,
      "micro_segmentation": true
    },
    "device_trust": {
      "certificate_required": true,
      "device_registration": true,
      "compliance_checking": true,
      "risk_scoring": true
    },
    "user_trust": {
      "multi_factor_auth": true,
      "behavioral_analysis": true,
      "privilege_escalation_detection": true,
      "session_monitoring": true
    }
  }
}
```

### **SOAR Integration**
```json
{
  "soar": {
    "enabled": true,
    "engine": "internal",              // internal, phantom, demisto
    "playbooks": {
      "incident_response": {
        "enabled": true,
        "auto_execute": true,
        "escalation_rules": [
          {
            "condition": "severity >= high",
            "action": "auto_block",
            "notify": ["security_team"]
          }
        ]
      },
      "threat_hunting": {
        "enabled": true,
        "scheduled_runs": true,
        "schedule": "0 2 * * *"         // daily at 2 AM
      }
    },
    "integrations": {
      "ticketing_system": {
        "enabled": false,
        "type": "jira",
        "url": "https://company.atlassian.net",
        "credentials": {
          "username": "automation",
          "api_token": "your_token"
        }
      },
      "notification_system": {
        "enabled": true,
        "channels": ["email", "slack", "teams"],
        "email": {
          "smtp_server": "smtp.company.com",
          "port": 587,
          "username": "alerts@company.com",
          "password": "smtp_password"
        }
      }
    }
  }
}
```

---

## 🔧 **Configuration Management**

### **Version Control**
```bash
# Initialize configuration versioning
git init config/
git add config/
git commit -m "Initial ZehraSec configuration"

# Track configuration changes
git add config/firewall_advanced.json
git commit -m "Updated threat intelligence settings"
```

### **Configuration Backup**
```bash
# Automated backup script
#!/bin/bash
BACKUP_DIR="/backup/zehrasec/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r config/ "$BACKUP_DIR/"
tar -czf "${BACKUP_DIR}.tar.gz" "$BACKUP_DIR"
rm -rf "$BACKUP_DIR"
```

### **Configuration Deployment**
```bash
# Deploy configuration to multiple servers
ansible-playbook -i inventory deploy-config.yml

# Or using script
#!/bin/bash
SERVERS=("server1" "server2" "server3")
for server in "${SERVERS[@]}"; do
    scp config/firewall_advanced.json "$server:/opt/zehrasec/config/"
    ssh "$server" "sudo systemctl reload zehrasec"
done
```

---

## 📞 **Configuration Support**

### **Validation Tools**
```bash
# Built-in validation
python tools/validate_config.py --config config/firewall_advanced.json

# JSON schema validation
python tools/schema_validator.py --schema config/schema.json --config config/firewall_advanced.json

# Configuration test
python main.py --test-config --config config/firewall_advanced.json
```

### **Getting Help**
- **Configuration Support**: config@zehrasec.com
- **Professional Services**: consulting@zehrasec.com
- **Documentation**: https://docs.zehrasec.com/configuration
- **Community Forum**: https://community.zehrasec.com

---

## 📚 **Related Documentation**

- **[Installation Guide](01-Installation-Guide.md)** - System installation
- **[Performance Optimization](18-Performance-Optimization.md)** - Performance tuning
- **[Security Hardening](24-Security-Hardening.md)** - Security best practices
- **[API Documentation](07-API-Documentation.md)** - API configuration

---

**Copyright © 2025 ZehraSec - Yashab Alam**  
*Configuration Guide v3.0.0*
