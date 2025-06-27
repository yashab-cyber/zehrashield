# API Documentation - ZehraSec Advanced Firewall

![API Docs](https://img.shields.io/badge/🔌-API%20Documentation-blue?style=for-the-badge)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## 📋 **Table of Contents**

1. [API Overview](#-api-overview)
2. [Authentication](#-authentication)
3. [System Endpoints](#-system-endpoints)
4. [Security Endpoints](#-security-endpoints)
5. [Threat Intelligence](#-threat-intelligence)
6. [Network Management](#-network-management)
7. [Configuration Management](#-configuration-management)
8. [Monitoring & Metrics](#-monitoring--metrics)
9. [User Management](#-user-management)
10. [WebSocket API](#-websocket-api)

---

## 🌐 **API Overview**

### **Base Information**
- **Base URL**: `https://localhost:8443/api/v1`
- **Protocol**: HTTPS (TLS 1.3)
- **Format**: JSON
- **Authentication**: Bearer Token / API Key
- **Rate Limiting**: 1000 requests/hour per API key

### **API Versioning**
```
https://localhost:8443/api/v1/   # Current stable version
https://localhost:8443/api/v2/   # Beta version (if available)
```

### **Common Response Format**
```json
{
  "success": true,
  "data": {},
  "message": "Operation completed successfully",
  "timestamp": "2025-06-19T14:30:22.123Z",
  "version": "3.0.0"
}
```

### **Error Response Format**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid request parameters",
    "details": "Field 'ip' is required"
  },
  "timestamp": "2025-06-19T14:30:22.123Z"
}
```

---

## 🔐 **Authentication**

### **API Key Authentication**

#### **Generate API Key**
```bash
# Generate new API key
curl -X POST https://localhost:8443/api/v1/auth/api-key \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "zehrasec123",
    "key_name": "my-integration",
    "permissions": ["read", "write"]
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "api_key": "zs_1234567890abcdef",
    "key_id": "key_001",
    "permissions": ["read", "write"],
    "expires_at": "2026-06-19T14:30:22.123Z"
  }
}
```

#### **Use API Key**
```bash
# Using API key in header
curl -H "Authorization: Bearer zs_1234567890abcdef" \
  https://localhost:8443/api/v1/status
```

### **JWT Token Authentication**

#### **Login and Get Token**
```bash
# Login to get JWT token
curl -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "zehrasec123"
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600,
    "refresh_token": "refresh_token_here"
  }
}
```

#### **Refresh Token**
```bash
# Refresh expired token
curl -X POST https://localhost:8443/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "refresh_token_here"}'
```

---

## 🖥️ **System Endpoints**

### **GET /api/v1/status**
Get system status and health information.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://localhost:8443/api/v1/status
```

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "running",
    "version": "3.0.0",
    "uptime": "72:14:35",
    "layers": {
      "layer1_packet_filter": "active",
      "layer2_application_gateway": "active",
      "layer3_ids_ips": "active",
      "layer4_threat_intelligence": "active",
      "layer5_network_access_control": "active",
      "layer6_siem_integration": "active"
    },
    "performance": {
      "cpu_usage": 15.3,
      "memory_usage": 45.7,
      "disk_usage": 23.1,
      "network_throughput": "1.2 Gbps"
    }
  }
}
```

### **GET /api/v1/health**
Detailed health check endpoint.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://localhost:8443/api/v1/health
```

**Response:**
```json
{
  "success": true,
  "data": {
    "overall_health": "healthy",
    "components": {
      "database": {
        "status": "healthy",
        "response_time": "2ms",
        "last_check": "2025-06-19T14:30:22.123Z"
      },
      "threat_intelligence": {
        "status": "healthy",
        "feeds_active": 15,
        "last_update": "2025-06-19T14:25:00.000Z"
      },
      "ml_engine": {
        "status": "healthy",
        "models_loaded": 8,
        "inference_time": "0.5ms"
      }
    }
  }
}
```

### **GET /api/v1/version**
Get detailed version information.

```bash
curl https://localhost:8443/api/v1/version
```

**Response:**
```json
{
  "success": true,
  "data": {
    "version": "3.0.0",
    "build": "20250619-143022",
    "commit": "a1b2c3d4",
    "release_date": "2025-06-19",
    "python_version": "3.9.7",
    "platform": "Linux-5.4.0-x86_64"
  }
}
```

---

## 🛡️ **Security Endpoints**

### **GET /api/v1/threats**
Get recent threats and security events.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://localhost:8443/api/v1/threats?limit=10&severity=high"
```

**Parameters:**
- `limit` (int): Number of results (default: 50, max: 1000)
- `offset` (int): Pagination offset (default: 0)
- `severity` (string): Filter by severity (low, medium, high, critical)
- `start_time` (string): ISO 8601 start time
- `end_time` (string): ISO 8601 end time

**Response:**
```json
{
  "success": true,
  "data": {
    "threats": [
      {
        "id": "threat_001",
        "timestamp": "2025-06-19T14:30:22.123Z",
        "type": "sql_injection",
        "severity": "high",
        "source_ip": "192.168.1.100",
        "target_ip": "10.0.0.1",
        "target_port": 80,
        "blocked": true,
        "signature": "SQL_INJECTION_001",
        "details": {
          "payload": "' OR 1=1--",
          "user_agent": "Mozilla/5.0...",
          "method": "POST"
        }
      }
    ],
    "total": 1,
    "pagination": {
      "limit": 10,
      "offset": 0,
      "has_more": false
    }
  }
}
```

### **POST /api/v1/block-ip**
Block an IP address.

```bash
curl -X POST https://localhost:8443/api/v1/block-ip \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "reason": "Malicious activity detected",
    "duration": 3600,
    "notify": true
  }'
```

**Request Body:**
```json
{
  "ip": "192.168.1.100",          // Required: IP address to block
  "reason": "Attack detected",     // Optional: Reason for blocking
  "duration": 3600,               // Optional: Duration in seconds (0 = permanent)
  "notify": true,                 // Optional: Send notification
  "rule_name": "custom_block"     // Optional: Custom rule name
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "rule_id": "rule_12345",
    "ip": "192.168.1.100",
    "status": "blocked",
    "expires_at": "2025-06-19T15:30:22.123Z"
  }
}
```

### **DELETE /api/v1/block-ip/{ip}**
Unblock an IP address.

```bash
curl -X DELETE https://localhost:8443/api/v1/block-ip/192.168.1.100 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "ip": "192.168.1.100",
    "status": "unblocked",
    "message": "IP address has been unblocked"
  }
}
```

### **GET /api/v1/blocked-ips**
List all blocked IP addresses.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://localhost:8443/api/v1/blocked-ips?active_only=true"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "blocked_ips": [
      {
        "ip": "192.168.1.100",
        "blocked_at": "2025-06-19T14:30:22.123Z",
        "expires_at": "2025-06-19T15:30:22.123Z",
        "reason": "SQL injection attempt",
        "rule_id": "rule_12345",
        "permanent": false
      }
    ],
    "total": 1
  }
}
```

---

## 🧠 **Threat Intelligence**

### **GET /api/v1/threat-intel/feeds**
Get threat intelligence feed status.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://localhost:8443/api/v1/threat-intel/feeds
```

**Response:**
```json
{
  "success": true,
  "data": {
    "feeds": [
      {
        "name": "malware_ips",
        "status": "active",
        "last_update": "2025-06-19T14:00:00.000Z",
        "next_update": "2025-06-19T15:00:00.000Z",
        "entries": 15742,
        "source": "commercial"
      },
      {
        "name": "botnet_c2",
        "status": "active",
        "last_update": "2025-06-19T14:15:00.000Z",
        "next_update": "2025-06-19T15:15:00.000Z",
        "entries": 8534,
        "source": "open_source"
      }
    ]
  }
}
```

### **POST /api/v1/threat-intel/update**
Manually update threat intelligence feeds.

```bash
curl -X POST https://localhost:8443/api/v1/threat-intel/update \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"feeds": ["malware_ips", "botnet_c2"]}'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "update_id": "update_12345",
    "status": "started",
    "feeds_updating": ["malware_ips", "botnet_c2"],
    "estimated_completion": "2025-06-19T14:35:00.000Z"
  }
}
```

### **GET /api/v1/threat-intel/ip/{ip}**
Check IP reputation.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://localhost:8443/api/v1/threat-intel/ip/192.168.1.100
```

**Response:**
```json
{
  "success": true,
  "data": {
    "ip": "192.168.1.100",
    "reputation": {
      "score": 85,        // 0-100 (higher = more suspicious)
      "classification": "malicious",
      "confidence": 0.92,
      "first_seen": "2025-06-15T10:20:30.000Z",
      "last_seen": "2025-06-19T14:25:15.000Z"
    },
    "sources": [
      {
        "feed": "malware_ips",
        "category": "malware",
        "added": "2025-06-15T10:20:30.000Z"
      }
    ]
  }
}
```

---

## 🌐 **Network Management**

### **GET /api/v1/network/interfaces**
List network interfaces.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://localhost:8443/api/v1/network/interfaces
```

**Response:**
```json
{
  "success": true,
  "data": {
    "interfaces": [
      {
        "name": "eth0",
        "status": "up",
        "ip_address": "192.168.1.10",
        "mac_address": "00:11:22:33:44:55",
        "speed": "1000Mbps",
        "monitored": true,
        "stats": {
          "bytes_received": 1024768,
          "bytes_sent": 512384,
          "packets_received": 8765,
          "packets_sent": 4321
        }
      }
    ]
  }
}
```

### **GET /api/v1/network/connections**
Get active network connections.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://localhost:8443/api/v1/network/connections?state=established"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "connections": [
      {
        "id": "conn_001",
        "source_ip": "192.168.1.100",
        "source_port": 45678,
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "protocol": "TCP",
        "state": "ESTABLISHED",
        "started": "2025-06-19T14:25:00.000Z",
        "bytes_sent": 2048,
        "bytes_received": 4096
      }
    ],
    "total": 1
  }
}
```

### **POST /api/v1/network/scan**
Initiate network scan.

```bash
curl -X POST https://localhost:8443/api/v1/network/scan \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.0/24",
    "scan_type": "quick",
    "ports": [80, 443, 22, 25]
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": "scan_12345",
    "status": "started",
    "target": "192.168.1.0/24",
    "estimated_completion": "2025-06-19T14:45:00.000Z"
  }
}
```

---

## ⚙️ **Configuration Management**

### **GET /api/v1/config**
Get current configuration.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://localhost:8443/api/v1/config
```

**Response:**
```json
{
  "success": true,
  "data": {
    "firewall": {
      "enabled": true,
      "mode": "production",
      "log_level": "INFO"
    },
    "layers": {
      "layer1_packet_filter": {
        "enabled": true,
        "rate_limit_per_ip": 100
      }
    }
  }
}
```

### **PUT /api/v1/config**
Update configuration.

```bash
curl -X PUT https://localhost:8443/api/v1/config \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "firewall": {
      "log_level": "DEBUG"
    }
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Configuration updated successfully",
    "restart_required": false,
    "changes": ["firewall.log_level"]
  }
}
```

### **POST /api/v1/config/backup**
Create configuration backup.

```bash
curl -X POST https://localhost:8443/api/v1/config/backup \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "backup_id": "backup_20250619_143022",
    "filename": "config_backup_20250619_143022.json",
    "size": 15680,
    "created_at": "2025-06-19T14:30:22.123Z"
  }
}
```

---

## 📊 **Monitoring & Metrics**

### **GET /api/v1/metrics**
Get system metrics.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://localhost:8443/api/v1/metrics?timeframe=1h"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "timeframe": "1h",
    "metrics": {
      "system": {
        "cpu_usage": {
          "current": 15.3,
          "average": 12.7,
          "peak": 34.2
        },
        "memory_usage": {
          "current": 45.7,
          "average": 43.1,
          "peak": 52.8
        }
      },
      "network": {
        "packets_per_second": {
          "current": 1247,
          "average": 1156,
          "peak": 2340
        },
        "threats_blocked": {
          "total": 23,
          "by_type": {
            "sql_injection": 8,
            "xss": 5,
            "port_scan": 10
          }
        }
      }
    }
  }
}
```

### **GET /api/v1/logs**
Get system logs.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "https://localhost:8443/api/v1/logs?level=ERROR&limit=50"
```

**Parameters:**
- `level` (string): Log level filter (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `limit` (int): Number of log entries (default: 100, max: 1000)
- `start_time` (string): ISO 8601 start time
- `component` (string): Filter by component (network, security, api, etc.)

**Response:**
```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "timestamp": "2025-06-19T14:30:22.123Z",
        "level": "ERROR",
        "component": "network",
        "message": "Failed to process packet from 192.168.1.100",
        "details": {
          "error_code": "PACKET_MALFORMED",
          "source_ip": "192.168.1.100"
        }
      }
    ],
    "total": 1
  }
}
```

### **GET /api/v1/stats**
Get dashboard statistics.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://localhost:8443/api/v1/stats
```

**Response:**
```json
{
  "success": true,
  "data": {
    "uptime": "72:14:35",
    "total_packets": 15672843,
    "threats_detected": 1247,
    "threats_blocked": 1200,
    "active_connections": 45,
    "blocked_ips": 23,
    "rules_loaded": 1500,
    "last_threat": "2025-06-19T14:25:15.000Z"
  }
}
```

---

## 👥 **User Management**

### **GET /api/v1/users**
List users.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://localhost:8443/api/v1/users
```

**Response:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "user_001",
        "username": "admin",
        "email": "admin@company.com",
        "role": "administrator",
        "status": "active",
        "last_login": "2025-06-19T14:00:00.000Z",
        "created_at": "2025-06-01T10:00:00.000Z"
      }
    ]
  }
}
```

### **POST /api/v1/users**
Create new user.

```bash
curl -X POST https://localhost:8443/api/v1/users \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@company.com",
    "password": "secure_password",
    "role": "operator"
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user_id": "user_002",
    "username": "newuser",
    "message": "User created successfully"
  }
}
```

### **PUT /api/v1/users/{user_id}**
Update user.

```bash
curl -X PUT https://localhost:8443/api/v1/users/user_002 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "updated@company.com",
    "role": "administrator"
  }'
```

---

## 🔌 **WebSocket API**

### **WebSocket Connection**
Connect to real-time events.

```javascript
// JavaScript WebSocket client
const ws = new WebSocket('wss://localhost:8443/api/v1/ws');

ws.onopen = function(event) {
    console.log('Connected to ZehraSec WebSocket');
    
    // Subscribe to events
    ws.send(JSON.stringify({
        type: 'subscribe',
        events: ['threats', 'system_status', 'network_activity']
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};
```

### **WebSocket Event Types**

#### **Threat Events**
```json
{
  "type": "threat_detected",
  "timestamp": "2025-06-19T14:30:22.123Z",
  "data": {
    "threat_id": "threat_001",
    "type": "sql_injection",
    "severity": "high",
    "source_ip": "192.168.1.100",
    "blocked": true
  }
}
```

#### **System Status Events**
```json
{
  "type": "system_status",
  "timestamp": "2025-06-19T14:30:22.123Z",
  "data": {
    "component": "threat_intelligence",
    "status": "updating",
    "message": "Updating threat feeds"
  }
}
```

#### **Network Activity Events**
```json
{
  "type": "network_activity",
  "timestamp": "2025-06-19T14:30:22.123Z",
  "data": {
    "interface": "eth0",
    "packets_per_second": 1247,
    "bytes_per_second": 15672843
  }
}
```

---

## 📝 **SDK Examples**

### **Python SDK**
```python
import requests
from zehrasec_sdk import ZehraSecClient

# Initialize client
client = ZehraSecClient(
    base_url='https://localhost:8443',
    api_key='your_api_key',
    verify_ssl=False  # Only for development
)

# Get system status
status = client.get_status()
print(f"System status: {status['status']}")

# Block IP address
result = client.block_ip('192.168.1.100', reason='Suspicious activity')
print(f"IP blocked: {result['success']}")

# Get recent threats
threats = client.get_threats(limit=10, severity='high')
for threat in threats['threats']:
    print(f"Threat: {threat['type']} from {threat['source_ip']}")
```

### **JavaScript SDK**
```javascript
const ZehraSecAPI = require('zehrasec-js-sdk');

const client = new ZehraSecAPI({
    baseURL: 'https://localhost:8443',
    apiKey: 'your_api_key',
    timeout: 5000
});

// Get system metrics
client.getMetrics({ timeframe: '1h' })
    .then(metrics => {
        console.log('CPU Usage:', metrics.system.cpu_usage.current);
        console.log('Threats Blocked:', metrics.network.threats_blocked.total);
    })
    .catch(error => {
        console.error('API Error:', error.message);
    });
```

---

## 🔧 **Rate Limiting**

### **Rate Limit Headers**
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1624099200
X-RateLimit-Window: 3600
```

### **Rate Limit Response**
```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 60 seconds.",
    "retry_after": 60
  }
}
```

---

## 📞 **API Support**

### **Getting Help**
- **API Support**: api@zehrasec.com
- **Documentation**: https://api.zehrasec.com
- **SDK Issues**: https://github.com/zehrasec/sdks
- **Developer Forum**: https://dev.zehrasec.com

### **Additional Resources**
- **[Configuration Guide](04-Configuration-Guide.md)** - Configuration management
- **[Integration Guide](14-Integration-Guide.md)** - Third-party integrations
- **[Troubleshooting](16-Troubleshooting-Guide.md)** - API troubleshooting

---

**Copyright © 2025 ZehraSec - Yashab Alam**  
*API Documentation v3.0.0*
