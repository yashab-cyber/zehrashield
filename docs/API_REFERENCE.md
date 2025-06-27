# ZehraShield API Reference

## Overview

ZehraShield provides a comprehensive REST API for monitoring, configuration, and management of the enterprise firewall system.

**Base URL:** `https://localhost:8443/api`

**Authentication:** Basic authentication or session-based (web console)

## Core Endpoints

### System Status

#### Get System Status
```http
GET /api/system/status
```

**Response:**
```json
{
  "firewall_running": true,
  "uptime": 86400,
  "layers": {
    "layer1_packet_filter": true,
    "layer2_application_gateway": true,
    "layer3_ids_ips": true,
    "layer4_threat_intelligence": true,
    "layer5_network_access_control": true,
    "layer6_siem_integration": true
  },
  "system": {
    "cpu_percent": 15.2,
    "memory_percent": 45.8,
    "disk_usage": 23.1
  }
}
```

#### Get Statistics
```http
GET /api/stats
```

**Response:**
```json
{
  "engine": {
    "packets_processed": 1234567,
    "threats_detected": 42,
    "ips_blocked": 15,
    "last_threat": "2025-06-27T10:30:00Z"
  },
  "layer1_packet_filter": {
    "packets_processed": 1234567,
    "packets_blocked": 1234,
    "rate_limited_ips": 5
  },
  "layer2_application_gateway": {
    "requests_processed": 98765,
    "requests_blocked": 234,
    "domains_blocked": 12
  }
}
```

### Security Events

#### Get Recent Events
```http
GET /api/events?limit=50&severity=HIGH
```

**Parameters:**
- `limit` (int): Number of events to return (default: 50)
- `severity` (string): Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)

**Response:**
```json
{
  "events": [
    {
      "event_id": "uuid-string",
      "timestamp": "2025-06-27T10:30:00Z",
      "source_layer": "layer3_ids_ips",
      "event_type": "intrusion_attempt",
      "severity": "HIGH",
      "source_ip": "192.168.1.100",
      "destination_ip": "192.168.1.1",
      "description": "SQL injection attempt detected",
      "raw_data": {},
      "threat_intelligence": {}
    }
  ],
  "timestamp": "2025-06-27T10:35:00Z"
}
```

### Security Incidents

#### Get Active Incidents
```http
GET /api/incidents
```

**Response:**
```json
{
  "incidents": [
    {
      "incident_id": "uuid-string",
      "created_at": "2025-06-27T10:00:00Z",
      "title": "Multiple Failed Logins - 192.168.1.100",
      "severity": "HIGH",
      "status": "OPEN",
      "events": ["event-id-1", "event-id-2"],
      "response_actions": []
    }
  ]
}
```

### Network Devices

#### Get Network Devices
```http
GET /api/devices
```

**Response:**
```json
{
  "devices": [
    {
      "mac_address": "00:11:22:33:44:55",
      "ip_address": "192.168.1.100",
      "hostname": "desktop-001",
      "device_type": "Desktop",
      "authorized": true,
      "trust_level": 75,
      "risk_score": 15,
      "quarantined": false
    }
  ]
}
```

#### Authorize Device
```http
POST /api/device/{mac_address}/authorize
```

**Response:**
```json
{
  "success": true,
  "message": "Device authorized successfully"
}
```

#### Revoke Device Access
```http
POST /api/device/{mac_address}/revoke
```

**Request Body:**
```json
{
  "reason": "Security policy violation"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Device access revoked successfully"
}
```

### Configuration Management

#### Get Configuration
```http
GET /api/config
```

**Response:**
```json
{
  "firewall": {
    "enabled": true,
    "mode": "production"
  },
  "layers": {
    "layer1_packet_filter": {
      "enabled": true,
      "rate_limit_per_ip": 1000
    }
  }
}
```

#### Update Configuration
```http
POST /api/config
```

**Request Body:**
```json
{
  "firewall": {
    "log_level": "INFO"
  },
  "layers": {
    "layer1_packet_filter": {
      "rate_limit_per_ip": 2000
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration updated successfully"
}
```

### Log Management

#### Get Log Entries
```http
GET /api/logs?lines=100&file=zehrashield.log
```

**Parameters:**
- `lines` (int): Number of log lines to return (default: 100)
- `file` (string): Log file name (default: zehrashield.log)

**Response:**
```json
{
  "logs": [
    "2025-06-27 10:30:00 INFO Starting ZehraShield...",
    "2025-06-27 10:30:01 INFO Layer 1 initialized"
  ],
  "timestamp": "2025-06-27T10:35:00Z"
}
```

### System Control

#### Restart Firewall
```http
POST /api/restart
```

**Response:**
```json
{
  "success": true,
  "message": "Restart initiated"
}
```

## Machine Learning API

### Threat Prediction

#### Analyze Network Data
```http
POST /api/ml/analyze
```

**Request Body:**
```json
{
  "packet_size": 1500,
  "protocol": "TCP",
  "source_ip": "192.168.1.100",
  "destination_ip": "192.168.1.1",
  "source_port": 80,
  "destination_port": 8080
}
```

**Response:**
```json
{
  "is_anomaly": false,
  "anomaly_score": 0.12,
  "threat_type": "benign",
  "threat_confidence": 0.95,
  "overall_threat_score": 0.08,
  "recommendation": "allow"
}
```

### Model Information

#### Get Model Status
```http
GET /api/ml/models
```

**Response:**
```json
{
  "models_loaded": true,
  "anomaly_model_type": "IsolationForest",
  "threat_classifier_type": "RandomForestClassifier",
  "training_in_progress": false,
  "stats": {
    "predictions_made": 12345,
    "anomalies_detected": 42,
    "model_accuracy": 0.95
  }
}
```

## WebSocket Events

ZehraShield supports real-time updates via WebSocket connections.

### Connection
```javascript
const socket = io('https://localhost:8443');
```

### Events

#### Subscribe to Statistics Updates
```javascript
socket.emit('subscribe_stats');

socket.on('stats_update', function(data) {
    // Handle real-time statistics update
    console.log('Stats update:', data);
});
```

#### Real-time Security Events
```javascript
socket.on('security_event', function(event) {
    // Handle new security event
    console.log('New security event:', event);
});
```

#### Incident Notifications
```javascript
socket.on('incident_created', function(incident) {
    // Handle new security incident
    console.log('New incident:', incident);
});
```

## Error Handling

All API endpoints return standard HTTP status codes and error responses:

### Error Response Format
```json
{
  "error": "Error description",
  "code": "ERROR_CODE",
  "timestamp": "2025-06-27T10:35:00Z"
}
```

### Common Status Codes
- `200 OK` - Request successful
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

## Rate Limiting

API endpoints are rate-limited to prevent abuse:

- **Authentication endpoints:** 5 requests per minute
- **Configuration endpoints:** 10 requests per minute  
- **Statistics endpoints:** 60 requests per minute
- **Other endpoints:** 30 requests per minute

Rate limit headers are included in responses:
```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1640995200
```

## SDK Examples

### Python SDK Example
```python
import requests

class ZehraShieldAPI:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = False  # For self-signed certificates
    
    def get_stats(self):
        response = self.session.get(f"{self.base_url}/api/stats")
        return response.json()
    
    def get_events(self, limit=50, severity=None):
        params = {'limit': limit}
        if severity:
            params['severity'] = severity
        
        response = self.session.get(f"{self.base_url}/api/events", params=params)
        return response.json()
    
    def authorize_device(self, mac_address):
        response = self.session.post(f"{self.base_url}/api/device/{mac_address}/authorize")
        return response.json()

# Usage
api = ZehraShieldAPI('https://localhost:8443', 'admin', 'zehrashield123')
stats = api.get_stats()
print(f"Threats detected: {stats['engine']['threats_detected']}")
```

### JavaScript SDK Example
```javascript
class ZehraShieldAPI {
    constructor(baseUrl, username, password) {
        this.baseUrl = baseUrl;
        this.auth = btoa(`${username}:${password}`);
    }
    
    async request(endpoint, options = {}) {
        const response = await fetch(`${this.baseUrl}/api${endpoint}`, {
            ...options,
            headers: {
                'Authorization': `Basic ${this.auth}`,
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        return response.json();
    }
    
    async getStats() {
        return this.request('/stats');
    }
    
    async getEvents(limit = 50, severity = null) {
        const params = new URLSearchParams({ limit });
        if (severity) params.append('severity', severity);
        
        return this.request(`/events?${params}`);
    }
    
    async authorizeDevice(macAddress) {
        return this.request(`/device/${macAddress}/authorize`, {
            method: 'POST'
        });
    }
}

// Usage
const api = new ZehraShieldAPI('https://localhost:8443', 'admin', 'zehrashield123');
api.getStats().then(stats => {
    console.log(`Threats detected: ${stats.engine.threats_detected}`);
});
```

## Webhook Integration

ZehraShield can send security events to external systems via webhooks.

### Configuration
```json
{
  "notifications": {
    "webhook": {
      "enabled": true,
      "url": "https://your-system.com/webhooks/zehrashield",
      "secret": "your-webhook-secret"
    }
  }
}
```

### Webhook Payload
```json
{
  "type": "security_incident",
  "incident": {
    "incident_id": "uuid-string",
    "title": "Security Incident Title",
    "severity": "HIGH",
    "created_at": "2025-06-27T10:00:00Z"
  },
  "timestamp": "2025-06-27T10:00:00Z",
  "source": "zehrashield"
}
```

## Compliance and Reporting

### Generate Compliance Report
```http
POST /api/reports/compliance
```

**Request Body:**
```json
{
  "report_type": "daily",
  "start_date": "2025-06-26",
  "end_date": "2025-06-27",
  "format": "json"
}
```

**Response:**
```json
{
  "report_id": "uuid-string",
  "download_url": "/api/reports/download/uuid-string",
  "expires_at": "2025-06-28T10:00:00Z"
}
```

This API reference provides comprehensive documentation for integrating with ZehraShield's enterprise firewall system.
