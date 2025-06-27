# Advanced Configuration Guide

## Overview

ZehraSec Advanced Firewall provides extensive configuration options for enterprise environments, high-security deployments, and specialized use cases. This guide covers advanced configuration techniques, optimization strategies, and expert-level settings.

## Table of Contents

1. [Advanced Configuration Files](#advanced-configuration-files)
2. [Performance Optimization](#performance-optimization)
3. [Security Hardening](#security-hardening)
4. [Multi-Interface Configuration](#multi-interface-configuration)
5. [Load Balancing](#load-balancing)
6. [High Availability Setup](#high-availability-setup)
7. [Custom Rule Development](#custom-rule-development)
8. [Advanced Logging](#advanced-logging)
9. [Integration Configurations](#integration-configurations)
10. [Troubleshooting](#troubleshooting)

## Advanced Configuration Files

### Primary Configuration Structure

```json
{
  "firewall": {
    "advanced_mode": true,
    "performance_profile": "enterprise",
    "security_level": "maximum",
    "logging_level": "detailed",
    "interfaces": {
      "management": {
        "interface": "eth0",
        "ip": "192.168.1.100",
        "port": 8443,
        "ssl": true
      },
      "data": [
        {
          "interface": "eth1",
          "mode": "bridge",
          "vlan_support": true
        },
        {
          "interface": "eth2",
          "mode": "router",
          "nat_enabled": true
        }
      ]
    }
  }
}
```

### Layer-Specific Advanced Settings

#### Layer 1: Packet Filtering
```json
{
  "packet_filtering": {
    "inspection_depth": "deep",
    "fragmentation_handling": "reassemble",
    "connection_tracking": {
      "enabled": true,
      "timeout": 3600,
      "max_connections": 1000000
    },
    "advanced_protocols": {
      "ipv6": true,
      "icmpv6": true,
      "sctp": true,
      "dccp": true
    }
  }
}
```

#### Layer 2: Deep Packet Inspection
```json
{
  "dpi": {
    "ssl_inspection": {
      "enabled": true,
      "certificate_validation": "strict",
      "cipher_restrictions": ["TLS_1_3", "TLS_1_2"],
      "key_exchange": ["ECDHE", "DHE"]
    },
    "application_detection": {
      "signatures_update": "automatic",
      "custom_signatures": "/etc/zehrasec/custom-sigs/",
      "performance_mode": "optimized"
    }
  }
}
```

#### Layer 3: Machine Learning
```json
{
  "ml_engine": {
    "models": {
      "anomaly_detection": {
        "algorithm": "isolation_forest",
        "sensitivity": 0.8,
        "training_window": "7d",
        "update_frequency": "hourly"
      },
      "behavioral_analysis": {
        "user_profiling": true,
        "device_fingerprinting": true,
        "baseline_period": "30d"
      }
    },
    "gpu_acceleration": {
      "enabled": true,
      "device": "cuda:0",
      "memory_limit": "4GB"
    }
  }
}
```

## Performance Optimization

### Memory Management

```json
{
  "performance": {
    "memory": {
      "heap_size": "8GB",
      "packet_buffer": "1GB",
      "connection_cache": "512MB",
      "rule_cache": "256MB"
    },
    "cpu": {
      "worker_threads": "auto",
      "affinity": [0, 1, 2, 3],
      "scheduler": "deadline"
    }
  }
}
```

### Network Optimization

```json
{
  "network": {
    "receive_buffer": "16MB",
    "send_buffer": "16MB",
    "tcp_window_scaling": true,
    "tcp_timestamps": false,
    "zero_copy": true,
    "interrupt_coalescing": {
      "rx_usecs": 50,
      "tx_usecs": 50
    }
  }
}
```

## Security Hardening

### Cryptographic Settings

```json
{
  "crypto": {
    "tls": {
      "min_version": "1.2",
      "preferred_version": "1.3",
      "cipher_suites": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256"
      ],
      "ec_curves": ["secp384r1", "secp256r1"],
      "signature_algorithms": ["rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256"]
    },
    "hashing": {
      "algorithm": "SHA-256",
      "salt_length": 32,
      "iterations": 100000
    }
  }
}
```

### Access Control

```json
{
  "access_control": {
    "authentication": {
      "methods": ["certificate", "ldap", "radius"],
      "multi_factor": true,
      "session_timeout": 3600,
      "max_failed_attempts": 3,
      "lockout_duration": 900
    },
    "authorization": {
      "rbac": true,
      "attribute_based": true,
      "policy_engine": "opa"
    }
  }
}
```

## Multi-Interface Configuration

### Bridge Mode Setup

```json
{
  "bridge_configuration": {
    "interfaces": ["eth1", "eth2"],
    "stp": {
      "enabled": true,
      "priority": 32768,
      "forward_delay": 15,
      "hello_time": 2,
      "max_age": 20
    },
    "vlan": {
      "enabled": true,
      "native_vlan": 1,
      "allowed_vlans": [10, 20, 30, 100]
    }
  }
}
```

### Router Mode Setup

```json
{
  "router_configuration": {
    "interfaces": {
      "wan": {
        "interface": "eth0",
        "dhcp_client": false,
        "static_ip": "203.0.113.10/24",
        "gateway": "203.0.113.1"
      },
      "lan": {
        "interface": "eth1",
        "ip": "192.168.1.1/24",
        "dhcp_server": {
          "enabled": true,
          "range": "192.168.1.100-192.168.1.200",
          "lease_time": 86400
        }
      }
    },
    "routing": {
      "static_routes": [
        {
          "destination": "10.0.0.0/8",
          "gateway": "192.168.1.254",
          "interface": "eth2"
        }
      ],
      "dynamic_routing": {
        "ospf": {
          "enabled": true,
          "area": "0.0.0.0",
          "router_id": "192.168.1.1"
        }
      }
    }
  }
}
```

## Load Balancing

### Server Load Balancing

```json
{
  "load_balancing": {
    "virtual_servers": [
      {
        "name": "web_cluster",
        "vip": "203.0.113.100",
        "port": 443,
        "protocol": "https",
        "algorithm": "least_connections",
        "health_check": {
          "method": "GET",
          "uri": "/health",
          "interval": 30,
          "timeout": 5,
          "retries": 3
        },
        "real_servers": [
          {
            "ip": "192.168.10.10",
            "port": 443,
            "weight": 100,
            "backup": false
          },
          {
            "ip": "192.168.10.11",
            "port": 443,
            "weight": 100,
            "backup": false
          }
        ]
      }
    ]
  }
}
```

## High Availability Setup

### Active-Passive Configuration

```json
{
  "high_availability": {
    "mode": "active_passive",
    "cluster_id": "zehrasec_cluster_01",
    "nodes": [
      {
        "id": "node1",
        "ip": "192.168.100.10",
        "role": "primary",
        "priority": 100
      },
      {
        "id": "node2",
        "ip": "192.168.100.11",
        "role": "secondary",
        "priority": 90
      }
    ],
    "heartbeat": {
      "interface": "eth3",
      "interval": 1,
      "timeout": 5,
      "encryption": true
    },
    "failover": {
      "automatic": true,
      "preemption": true,
      "delay": 30
    }
  }
}
```

## Custom Rule Development

### Rule Syntax

```json
{
  "custom_rules": [
    {
      "id": "CUSTOM_001",
      "name": "Advanced Threat Detection",
      "description": "Detect advanced persistent threats",
      "conditions": {
        "and": [
          {
            "field": "payload_entropy",
            "operator": ">",
            "value": 7.5
          },
          {
            "field": "connection_frequency",
            "operator": ">",
            "value": 100
          },
          {
            "field": "unusual_port",
            "operator": "==",
            "value": true
          }
        ]
      },
      "actions": [
        {
          "type": "block",
          "duration": 3600
        },
        {
          "type": "alert",
          "severity": "high"
        },
        {
          "type": "log",
          "level": "warning"
        }
      ]
    }
  ]
}
```

### Rule Testing Framework

```bash
# Test custom rule
zehrasec-cli rule test --rule-id CUSTOM_001 --test-data /path/to/test.pcap

# Validate rule syntax
zehrasec-cli rule validate --config /path/to/custom_rules.json

# Deploy rule
zehrasec-cli rule deploy --rule-id CUSTOM_001 --environment production
```

## Advanced Logging

### Structured Logging Configuration

```json
{
  "logging": {
    "format": "json",
    "level": "info",
    "outputs": [
      {
        "type": "file",
        "path": "/var/log/zehrasec/firewall.log",
        "rotation": {
          "size": "100MB",
          "count": 10,
          "compress": true
        }
      },
      {
        "type": "syslog",
        "facility": "local0",
        "severity": "info"
      },
      {
        "type": "elasticsearch",
        "hosts": ["es-node1:9200", "es-node2:9200"],
        "index": "zehrasec-logs",
        "authentication": {
          "username": "elastic",
          "password": "changeme"
        }
      }
    ],
    "filters": [
      {
        "field": "event_type",
        "values": ["connection", "threat", "error"],
        "action": "include"
      }
    ]
  }
}
```

## Integration Configurations

### SIEM Integration

```json
{
  "siem_integration": {
    "splunk": {
      "enabled": true,
      "hec_url": "https://splunk.example.com:8088/services/collector",
      "token": "your-hec-token",
      "index": "zehrasec",
      "source_type": "zehrasec:firewall"
    },
    "qradar": {
      "enabled": true,
      "host": "qradar.example.com",
      "port": 514,
      "protocol": "tcp",
      "format": "leef"
    }
  }
}
```

### Threat Intelligence Integration

```json
{
  "threat_intelligence": {
    "feeds": [
      {
        "name": "commercial_feed",
        "type": "stix",
        "url": "https://threat-intel.example.com/feed",
        "authentication": {
          "type": "api_key",
          "key": "your-api-key"
        },
        "update_interval": 300,
        "priority": "high"
      }
    ],
    "enrichment": {
      "ip_reputation": true,
      "domain_reputation": true,
      "file_hash_lookup": true,
      "geo_location": true
    }
  }
}
```

## Environment-Specific Configurations

### Development Environment

```json
{
  "environment": "development",
  "debug": {
    "enabled": true,
    "level": "verbose",
    "packet_capture": true,
    "performance_metrics": true
  },
  "testing": {
    "mock_threats": true,
    "traffic_replay": true,
    "rule_simulation": true
  }
}
```

### Production Environment

```json
{
  "environment": "production",
  "optimization": {
    "performance_mode": "maximum",
    "memory_optimization": true,
    "cpu_optimization": true
  },
  "monitoring": {
    "health_checks": true,
    "performance_monitoring": true,
    "capacity_planning": true
  }
}
```

## Configuration Validation

### Syntax Validation

```bash
# Validate configuration syntax
zehrasec-cli config validate --file /etc/zehrasec/firewall_advanced.json

# Check configuration consistency
zehrasec-cli config check --environment production

# Test configuration changes
zehrasec-cli config test --config /path/to/new_config.json
```

### Best Practices

1. **Version Control**: Keep all configurations in version control
2. **Testing**: Test configurations in staging before production
3. **Backup**: Always backup working configurations
4. **Documentation**: Document all custom configurations
5. **Monitoring**: Monitor configuration changes and their impact

## Troubleshooting Advanced Configurations

### Common Issues

1. **Performance Degradation**
   - Check memory and CPU usage
   - Review rule complexity
   - Optimize database queries

2. **Connectivity Issues**
   - Verify interface configurations
   - Check routing tables
   - Test firewall rules

3. **Authentication Failures**
   - Verify certificate validity
   - Check LDAP/RADIUS connectivity
   - Review access control policies

### Debug Commands

```bash
# Show current configuration
zehrasec-cli config show --format json

# Display active connections
zehrasec-cli connections list --detailed

# Show performance statistics
zehrasec-cli stats show --module all

# Debug specific rules
zehrasec-cli debug rule --rule-id CUSTOM_001 --trace
```

## Support and Resources

- **Documentation**: `/usr/share/doc/zehrasec/`
- **Configuration Examples**: `/etc/zehrasec/examples/`
- **Support Forum**: https://support.zehrasec.com
- **Professional Services**: support@zehrasec.com

---

*This guide covers advanced configuration options for ZehraSec Advanced Firewall. For basic configuration, see the [Configuration Guide](04-Configuration-Guide.md).*
