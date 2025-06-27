# 20-Monitoring-Setup.md - ZehraSec Advanced Firewall

![Monitoring Setup](https://img.shields.io/badge/📊-Monitoring%20Setup-purple?style=for-the-badge&logo=chart-line)

**Version 3.0.0** | **Updated: June 19, 2025** | **Copyright © 2025 ZehraSec - Yashab Alam**

---

## 📊 **Overview**

This comprehensive guide covers the setup and configuration of monitoring systems for ZehraSec Advanced Firewall. Learn how to implement real-time monitoring, alerting, performance tracking, and integration with popular monitoring platforms.

---

## 🎯 **Monitoring Architecture**

### 🏗️ **System Components**

#### **Core Monitoring Stack**
```
┌─────────────────────────────────────────────────────────┐
│                    ZehraSec Firewall                    │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │
│ │   Metrics   │ │    Logs     │ │       Events        │ │
│ │ Collection  │ │ Aggregation │ │    Processing       │ │
│ └─────────────┘ └─────────────┘ └─────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │
│ │ Prometheus  │ │ Grafana     │ │    AlertManager     │ │
│ │   (Metrics) │ │(Dashboards)│ │   (Notifications)   │ │
│ └─────────────┘ └─────────────┘ └─────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │
│ │    ELK      │ │   Splunk    │ │        SIEM         │ │
│ │   Stack     │ │  Enterprise │ │    Integration      │ │
│ └─────────────┘ └─────────────┘ └─────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

#### **Data Flow Architecture**
```yaml
data_flow:
  sources:
    - firewall_engine
    - threat_detection
    - ml_analytics
    - network_traffic
    - system_resources
  
  collectors:
    - prometheus_exporter
    - log_forwarder
    - snmp_agent
    - custom_api
  
  processors:
    - data_enrichment
    - correlation_engine
    - anomaly_detection
    - threshold_checking
  
  destinations:
    - time_series_db
    - log_management
    - alerting_system
    - external_siem
```

---

## 🚀 **Initial Setup**

### 📋 **Prerequisites**

#### **System Requirements**
```yaml
monitoring_requirements:
  minimum:
    cpu: "2 cores"
    memory: "4 GB"
    storage: "50 GB"
    network: "1 Gbps"
  
  recommended:
    cpu: "4 cores"
    memory: "8 GB"
    storage: "200 GB SSD"
    network: "10 Gbps"
  
  enterprise:
    cpu: "8+ cores"
    memory: "16+ GB"
    storage: "500+ GB NVMe"
    network: "10+ Gbps"
```

#### **Software Dependencies**
```bash
# Install monitoring prerequisites
# Ubuntu/Debian
sudo apt update
sudo apt install -y curl wget gnupg software-properties-common

# CentOS/RHEL
sudo yum update
sudo yum install -y curl wget gnupg

# Install Docker (for containerized monitoring)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

### ⚙️ **Enable Monitoring in ZehraSec**

#### **Configuration File Setup**
```json
{
  "monitoring": {
    "enabled": true,
    "metrics": {
      "enabled": true,
      "port": 9090,
      "endpoint": "/metrics",
      "interval": 15,
      "retention": "30d"
    },
    "logging": {
      "enabled": true,
      "level": "INFO",
      "format": "json",
      "destinations": [
        {
          "type": "file",
          "path": "/var/log/zehrasec/monitoring.log",
          "rotation": "daily",
          "retention": 30
        },
        {
          "type": "syslog",
          "facility": "local0",
          "host": "syslog.company.com",
          "port": 514
        }
      ]
    },
    "alerting": {
      "enabled": true,
      "webhook_url": "http://alertmanager:9093/api/v1/alerts",
      "notification_channels": [
        {
          "type": "email",
          "recipients": ["admin@company.com", "security@company.com"]
        },
        {
          "type": "slack",
          "webhook": "https://hooks.slack.com/services/xxx/yyy/zzz"
        }
      ]
    }
  }
}
```

#### **Enable Monitoring via CLI**
```bash
# Enable monitoring
python main.py --enable-monitoring --config-file config/monitoring.json

# Verify monitoring status
python main.py --monitoring-status

# Test metrics endpoint
curl http://localhost:9090/metrics
```

---

## 📊 **Prometheus Setup**

### 🔧 **Prometheus Installation**

#### **Docker Deployment**
```yaml
# docker-compose.yml
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
    restart: unless-stopped

volumes:
  prometheus_data:
```

#### **Prometheus Configuration**
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "zehrasec_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'zehrasec-firewall'
    static_configs:
      - targets: ['localhost:9091']
    scrape_interval: 15s
    metrics_path: /metrics
    params:
      format: ['prometheus']
    
  - job_name: 'zehrasec-system'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 30s
    
  - job_name: 'zehrasec-network'
    static_configs:
      - targets: ['localhost:9116']
    scrape_interval: 10s
```

### 📈 **Metrics Collection**

#### **ZehraSec Metrics Exporter**
```python
# metrics_exporter.py
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time
import json

class ZehraSecMetrics:
    def __init__(self):
        # Traffic metrics
        self.packets_total = Counter('zehrasec_packets_total', 
                                   'Total packets processed', 
                                   ['direction', 'protocol'])
        
        self.bytes_total = Counter('zehrasec_bytes_total',
                                 'Total bytes processed',
                                 ['direction', 'protocol'])
        
        # Threat metrics
        self.threats_detected = Counter('zehrasec_threats_detected_total',
                                      'Total threats detected',
                                      ['threat_type', 'severity'])
        
        self.threats_blocked = Counter('zehrasec_threats_blocked_total',
                                     'Total threats blocked',
                                     ['threat_type', 'action'])
        
        # Performance metrics
        self.cpu_usage = Gauge('zehrasec_cpu_usage_percent',
                              'CPU usage percentage')
        
        self.memory_usage = Gauge('zehrasec_memory_usage_bytes',
                                'Memory usage in bytes')
        
        self.processing_time = Histogram('zehrasec_processing_time_seconds',
                                       'Packet processing time',
                                       ['layer', 'operation'])
        
        # System metrics
        self.active_connections = Gauge('zehrasec_active_connections',
                                      'Number of active connections')
        
        self.rule_matches = Counter('zehrasec_rule_matches_total',
                                  'Total rule matches',
                                  ['rule_name', 'action'])
    
    def update_traffic_metrics(self, direction, protocol, packets, bytes_count):
        self.packets_total.labels(direction=direction, protocol=protocol).inc(packets)
        self.bytes_total.labels(direction=direction, protocol=protocol).inc(bytes_count)
    
    def record_threat(self, threat_type, severity, action):
        self.threats_detected.labels(threat_type=threat_type, severity=severity).inc()
        if action == 'blocked':
            self.threats_blocked.labels(threat_type=threat_type, action=action).inc()
    
    def update_system_metrics(self, cpu_percent, memory_bytes):
        self.cpu_usage.set(cpu_percent)
        self.memory_usage.set(memory_bytes)

# Start metrics server
if __name__ == '__main__':
    metrics = ZehraSecMetrics()
    start_http_server(9091)
    
    while True:
        # Update metrics from ZehraSec firewall
        # This would typically read from ZehraSec's internal metrics
        time.sleep(15)
```

#### **Custom Metrics Configuration**
```yaml
# custom_metrics.yml
custom_metrics:
  - name: "zehrasec_threat_intelligence_feeds"
    type: "gauge"
    description: "Number of active threat intelligence feeds"
    labels: ["feed_name", "status"]
  
  - name: "zehrasec_ml_model_accuracy"
    type: "gauge"
    description: "ML model accuracy percentage"
    labels: ["model_name", "version"]
  
  - name: "zehrasec_zero_trust_violations"
    type: "counter"
    description: "Zero trust policy violations"
    labels: ["policy", "user", "device"]
  
  - name: "zehrasec_soar_playbook_executions"
    type: "counter"
    description: "SOAR playbook executions"
    labels: ["playbook", "status", "trigger"]
```

---

## 📊 **Grafana Dashboard Setup**

### 🎨 **Grafana Installation**

#### **Docker Setup**
```yaml
# Add to docker-compose.yml
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    restart: unless-stopped

volumes:
  grafana_data:
```

#### **Data Source Configuration**
```yaml
# grafana/provisioning/datasources/prometheus.yml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    
  - name: InfluxDB
    type: influxdb
    access: proxy
    url: http://influxdb:8086
    database: zehrasec
```

### 📈 **Dashboard Configuration**

#### **Main Security Dashboard**
```json
{
  "dashboard": {
    "title": "ZehraSec Security Overview",
    "tags": ["zehrasec", "security", "firewall"],
    "timezone": "browser",
    "refresh": "30s",
    "panels": [
      {
        "title": "Threats Detected",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(rate(zehrasec_threats_detected_total[5m]))",
            "legendFormat": "Threats/sec"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "color": {
              "mode": "thresholds"
            },
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 10},
                {"color": "red", "value": 50}
              ]
            }
          }
        }
      },
      {
        "title": "Traffic Volume",
        "type": "graph",
        "targets": [
          {
            "expr": "sum(rate(zehrasec_bytes_total[5m])) by (direction)",
            "legendFormat": "{{direction}}"
          }
        ],
        "yAxes": [
          {
            "label": "Bytes/sec",
            "unit": "binBps"
          }
        ]
      },
      {
        "title": "System Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "zehrasec_cpu_usage_percent",
            "legendFormat": "CPU %"
          },
          {
            "expr": "zehrasec_memory_usage_bytes / 1024 / 1024 / 1024",
            "legendFormat": "Memory GB"
          }
        ]
      }
    ]
  }
}
```

#### **Network Traffic Dashboard**
```json
{
  "dashboard": {
    "title": "ZehraSec Network Traffic",
    "panels": [
      {
        "title": "Protocol Distribution",
        "type": "piechart",
        "targets": [
          {
            "expr": "sum(rate(zehrasec_packets_total[5m])) by (protocol)",
            "legendFormat": "{{protocol}}"
          }
        ]
      },
      {
        "title": "Top Talkers",
        "type": "table",
        "targets": [
          {
            "expr": "topk(10, sum(rate(zehrasec_bytes_total[5m])) by (src_ip))",
            "format": "table"
          }
        ]
      },
      {
        "title": "Connection Patterns",
        "type": "heatmap",
        "targets": [
          {
            "expr": "sum(rate(zehrasec_active_connections[5m])) by (le)",
            "legendFormat": "{{le}}"
          }
        ]
      }
    ]
  }
}
```

---

## 🚨 **AlertManager Configuration**

### ⚙️ **AlertManager Setup**

#### **Docker Configuration**
```yaml
# Add to docker-compose.yml
  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager_data:/alertmanager
    restart: unless-stopped

volumes:
  alertmanager_data:
```

#### **AlertManager Configuration**
```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'smtp.company.com:587'
  smtp_from: 'zehrasec-alerts@company.com'
  smtp_auth_username: 'zehrasec-alerts@company.com'
  smtp_auth_password: 'password'

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default'
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
    - match:
        severity: warning
      receiver: 'warning-alerts'

receivers:
  - name: 'default'
    email_configs:
      - to: 'admin@company.com'
        subject: 'ZehraSec Alert: {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}

  - name: 'critical-alerts'
    email_configs:
      - to: 'security-team@company.com'
        subject: 'CRITICAL: ZehraSec Alert'
        body: |
          CRITICAL SECURITY ALERT
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          Severity: {{ .Labels.severity }}
          Time: {{ .StartsAt }}
          {{ end }}
    
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/xxx/yyy/zzz'
        channel: '#security-alerts'
        title: 'ZehraSec Critical Alert'
        text: |
          {{ range .Alerts }}
          🚨 *{{ .Annotations.summary }}*
          {{ .Annotations.description }}
          {{ end }}

  - name: 'warning-alerts'
    email_configs:
      - to: 'ops-team@company.com'
        subject: 'WARNING: ZehraSec Alert'
```

### 🔔 **Alert Rules**

#### **ZehraSec Alert Rules**
```yaml
# zehrasec_rules.yml
groups:
  - name: zehrasec.rules
    rules:
      - alert: HighThreatDetectionRate
        expr: rate(zehrasec_threats_detected_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High threat detection rate"
          description: "ZehraSec is detecting {{ $value }} threats per second"

      - alert: CriticalThreatDetected
        expr: increase(zehrasec_threats_detected_total{severity="critical"}[1m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Critical threat detected"
          description: "A critical threat has been detected by ZehraSec"

      - alert: SystemHighCPU
        expr: zehrasec_cpu_usage_percent > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage"
          description: "ZehraSec CPU usage is {{ $value }}%"

      - alert: SystemHighMemory
        expr: zehrasec_memory_usage_bytes / 1024 / 1024 / 1024 > 6
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "ZehraSec memory usage is {{ $value }}GB"

      - alert: FirewallDown
        expr: up{job="zehrasec-firewall"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "ZehraSec firewall is down"
          description: "ZehraSec firewall has been down for more than 1 minute"

      - alert: ThreatIntelligenceFeedDown
        expr: zehrasec_threat_intelligence_feeds{status="down"} > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Threat intelligence feed unavailable"
          description: "One or more threat intelligence feeds are down"

      - alert: MLModelAccuracyLow
        expr: zehrasec_ml_model_accuracy < 85
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "ML model accuracy low"
          description: "ML model {{ $labels.model_name }} accuracy is {{ $value }}%"

      - alert: ZeroTrustViolations
        expr: rate(zehrasec_zero_trust_violations_total[5m]) > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High zero trust violations"
          description: "{{ $value }} zero trust violations per second"
```

---

## 📝 **Log Management**

### 📊 **ELK Stack Integration**

#### **Elasticsearch Configuration**
```yaml
# elasticsearch.yml
cluster.name: zehrasec-logs
node.name: es-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
```

#### **Logstash Configuration**
```ruby
# logstash.conf
input {
  beats {
    port => 5044
  }
  
  syslog {
    port => 514
  }
  
  http {
    port => 8080
    codec => json
  }
}

filter {
  if [fields][log_type] == "zehrasec" {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} \[%{LOGLEVEL:level}\] %{GREEDYDATA:message}" }
    }
    
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    if [level] == "ERROR" or [level] == "CRITICAL" {
      mutate {
        add_tag => [ "alert" ]
      }
    }
    
    # Parse JSON logs
    if [message] =~ /^{.*}$/ {
      json {
        source => "message"
      }
    }
    
    # GeoIP lookup for external IPs
    if [src_ip] and [src_ip] !~ /^10\./ and [src_ip] !~ /^192\.168\./ {
      geoip {
        source => "src_ip"
        target => "geoip"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "zehrasec-logs-%{+YYYY.MM.dd}"
  }
  
  if "alert" in [tags] {
    http {
      url => "http://alertmanager:9093/api/v1/alerts"
      http_method => "post"
      format => "json"
      mapping => {
        "labels" => {
          "alertname" => "ZehraSecLogAlert"
          "severity" => "%{level}"
          "instance" => "%{host}"
        }
        "annotations" => {
          "summary" => "ZehraSec log alert"
          "description" => "%{message}"
        }
      }
    }
  }
}
```

#### **Filebeat Configuration**
```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/zehrasec/*.log
    fields:
      log_type: zehrasec
    fields_under_root: true
    multiline.pattern: '^\d{4}-\d{2}-\d{2}'
    multiline.negate: true
    multiline.match: after

output.logstash:
  hosts: ["logstash:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
```

### 🔍 **Kibana Dashboards**

#### **Security Events Dashboard**
```json
{
  "version": "7.15.0",
  "objects": [
    {
      "id": "zehrasec-security-dashboard",
      "type": "dashboard",
      "attributes": {
        "title": "ZehraSec Security Events",
        "hits": 0,
        "description": "Security events and threat analysis",
        "panelsJSON": "[{\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":15},\"panelIndex\":\"1\",\"embeddableConfig\":{},\"panelRefName\":\"panel_1\"}]",
        "optionsJSON": "{\"hidePanelTitles\":false,\"useMargins\":true}",
        "version": 1,
        "timeRestore": false,
        "kibanaSavedObjectMeta": {
          "searchSourceJSON": "{\"query\":{\"match_all\":{}},\"filter\":[]}"
        }
      }
    }
  ]
}
```

---

## 📡 **SNMP Monitoring**

### 🔧 **SNMP Configuration**

#### **SNMP Agent Setup**
```yaml
# snmp_config.yml
snmp:
  enabled: true
  agent_address: "0.0.0.0:161"
  community: "zehrasec_readonly"
  version: "2c"
  
  mibs:
    - name: "ZEHRASEC-FIREWALL-MIB"
      oid: "1.3.6.1.4.1.12345.1"
      objects:
        - name: "firewallStatus"
          oid: "1.3.6.1.4.1.12345.1.1.1"
          type: "integer"
          access: "read-only"
        - name: "threatsDetected"
          oid: "1.3.6.1.4.1.12345.1.1.2"
          type: "counter"
          access: "read-only"
        - name: "packetsProcessed"
          oid: "1.3.6.1.4.1.12345.1.1.3"
          type: "counter"
          access: "read-only"
```

#### **SNMP MIB Definition**
```
ZEHRASEC-FIREWALL-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Counter32, Gauge32, enterprises
        FROM SNMPv2-SMI;

zehraSecFirewall MODULE-IDENTITY
    LAST-UPDATED "202506190000Z"
    ORGANIZATION "ZehraSec"
    CONTACT-INFO "support@zehrasec.com"
    DESCRIPTION "ZehraSec Advanced Firewall MIB"
    ::= { enterprises 12345 1 }

-- Firewall Status Objects
firewallStatus OBJECT-TYPE
    SYNTAX INTEGER { running(1), stopped(2), error(3) }
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Current status of the firewall"
    ::= { zehraSecFirewall 1 }

threatsDetected OBJECT-TYPE
    SYNTAX Counter32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Total number of threats detected"
    ::= { zehraSecFirewall 2 }

packetsProcessed OBJECT-TYPE
    SYNTAX Counter32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Total number of packets processed"
    ::= { zehraSecFirewall 3 }

END
```

---

## 🔄 **Integration with External Systems**

### 🔗 **SIEM Integration**

#### **Splunk Integration**
```python
# splunk_forwarder.py
import splunklib.client as client
import json
import time

class SplunkForwarder:
    def __init__(self, host, port, username, password):
        self.service = client.connect(
            host=host,
            port=port,
            username=username,
            password=password
        )
        self.index = self.service.indexes["zehrasec"]
    
    def send_event(self, event_data):
        event = {
            "timestamp": time.time(),
            "source": "zehrasec-firewall",
            "sourcetype": "zehrasec:security",
            "event": event_data
        }
        
        self.index.submit(json.dumps(event))
    
    def send_threat_event(self, threat_data):
        event = {
            "timestamp": threat_data.get("timestamp"),
            "threat_type": threat_data.get("type"),
            "severity": threat_data.get("severity"),
            "source_ip": threat_data.get("src_ip"),
            "destination_ip": threat_data.get("dst_ip"),
            "action_taken": threat_data.get("action"),
            "description": threat_data.get("description")
        }
        
        self.send_event(event)

# Usage
forwarder = SplunkForwarder("splunk.company.com", 8089, "admin", "password")
forwarder.send_threat_event({
    "timestamp": "2025-06-19T14:32:15Z",
    "type": "malware",
    "severity": "high",
    "src_ip": "192.168.1.100",
    "dst_ip": "malicious-site.com",
    "action": "blocked",
    "description": "Malware communication attempt blocked"
})
```

#### **IBM QRadar Integration**
```python
# qradar_integration.py
import requests
import json
import base64

class QRadarIntegration:
    def __init__(self, console_ip, sec_token):
        self.console_ip = console_ip
        self.sec_token = sec_token
        self.headers = {
            'SEC': self.sec_token,
            'Content-Type': 'application/json'
        }
    
    def send_event(self, event_data):
        url = f"https://{self.console_ip}/api/siem/events"
        
        qradar_event = {
            "events": [{
                "qid": 55500001,  # Custom QID for ZehraSec events
                "magnitude": self.map_severity(event_data.get("severity")),
                "sourceip": event_data.get("src_ip"),
                "destinationip": event_data.get("dst_ip"),
                "eventname": event_data.get("threat_type"),
                "category": 18,  # Suspicious Activity
                "logsourceid": 123,  # ZehraSec log source ID
                "starttime": int(time.time() * 1000),
                "protocol": event_data.get("protocol", "TCP"),
                "payload": base64.b64encode(
                    json.dumps(event_data).encode()
                ).decode()
            }]
        }
        
        response = requests.post(url, headers=self.headers, 
                               json=qradar_event, verify=False)
        return response.status_code == 200
    
    def map_severity(self, severity):
        mapping = {
            "low": 3,
            "medium": 5,
            "high": 7,
            "critical": 10
        }
        return mapping.get(severity.lower(), 5)
```

### 📊 **Custom Monitoring APIs**

#### **REST API for Metrics**
```python
# monitoring_api.py
from flask import Flask, jsonify, request
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
import json

app = Flask(__name__)

@app.route('/api/v1/metrics')
def get_metrics():
    """Get Prometheus metrics"""
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

@app.route('/api/v1/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": time.time(),
        "version": "3.0.0",
        "uptime": get_uptime()
    })

@app.route('/api/v1/threats')
def get_threats():
    """Get recent threats"""
    threats = get_recent_threats(limit=request.args.get('limit', 100))
    return jsonify(threats)

@app.route('/api/v1/traffic')
def get_traffic():
    """Get traffic statistics"""
    stats = get_traffic_stats(
        start=request.args.get('start'),
        end=request.args.get('end')
    )
    return jsonify(stats)

@app.route('/api/v1/alerts', methods=['POST'])
def receive_alert():
    """Receive alerts from external systems"""
    alert_data = request.json
    process_external_alert(alert_data)
    return jsonify({"status": "received"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

---

## 📱 **Mobile Monitoring**

### 📲 **Mobile App Integration**

#### **Push Notifications Setup**
```python
# mobile_notifications.py
from pyfcm import FCMNotification
import json

class MobileNotifications:
    def __init__(self, api_key):
        self.push_service = FCMNotification(api_key=api_key)
    
    def send_threat_alert(self, device_tokens, threat_data):
        result = self.push_service.notify_multiple_devices(
            registration_ids=device_tokens,
            message_title="🚨 Security Alert",
            message_body=f"Threat detected: {threat_data['type']}",
            data_message={
                "type": "threat_alert",
                "severity": threat_data["severity"],
                "timestamp": threat_data["timestamp"],
                "details": json.dumps(threat_data)
            },
            sound="alert.wav",
            badge=1
        )
        return result
    
    def send_system_status(self, device_tokens, status):
        color = "#28a745" if status == "healthy" else "#dc3545"
        
        result = self.push_service.notify_multiple_devices(
            registration_ids=device_tokens,
            message_title="System Status Update",
            message_body=f"ZehraSec status: {status}",
            data_message={
                "type": "system_status",
                "status": status,
                "timestamp": time.time()
            },
            color=color
        )
        return result
```

#### **Mobile Dashboard API**
```python
# mobile_api.py
@app.route('/api/mobile/v1/dashboard')
def mobile_dashboard():
    """Optimized dashboard data for mobile"""
    return jsonify({
        "status": get_system_status(),
        "threats_today": get_threat_count_today(),
        "traffic_summary": get_traffic_summary(),
        "top_threats": get_top_threats(limit=5),
        "alerts": get_active_alerts(limit=10),
        "performance": {
            "cpu": get_cpu_usage(),
            "memory": get_memory_usage(),
            "uptime": get_uptime()
        }
    })

@app.route('/api/mobile/v1/threats')
def mobile_threats():
    """Mobile-optimized threats list"""
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 20))
    
    threats = get_threats_paginated(page, limit)
    return jsonify({
        "threats": threats,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": get_total_threats()
        }
    })
```

---

## 🔧 **Performance Tuning**

### ⚡ **Monitoring Performance Optimization**

#### **Metric Collection Optimization**
```python
# optimized_metrics.py
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import time

class OptimizedMetricsCollector:
    def __init__(self, max_workers=10):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.metrics_cache = {}
        self.cache_ttl = 30  # seconds
    
    async def collect_metrics_async(self):
        """Asynchronously collect metrics from multiple sources"""
        tasks = [
            self.collect_system_metrics(),
            self.collect_network_metrics(),
            self.collect_threat_metrics(),
            self.collect_performance_metrics()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self.merge_metrics(results)
    
    def collect_with_cache(self, metric_name, collector_func):
        """Collect metrics with caching"""
        current_time = time.time()
        
        if (metric_name in self.metrics_cache and 
            current_time - self.metrics_cache[metric_name]['timestamp'] < self.cache_ttl):
            return self.metrics_cache[metric_name]['data']
        
        data = collector_func()
        self.metrics_cache[metric_name] = {
            'data': data,
            'timestamp': current_time
        }
        
        return data
    
    def batch_export_metrics(self, metrics_list):
        """Batch export metrics to reduce API calls"""
        batch_size = 100
        for i in range(0, len(metrics_list), batch_size):
            batch = metrics_list[i:i + batch_size]
            self.export_metrics_batch(batch)
```

#### **Database Optimization**
```sql
-- Monitoring database optimization
-- Create indexes for faster queries
CREATE INDEX idx_metrics_timestamp ON metrics(timestamp);
CREATE INDEX idx_threats_severity ON threats(severity, timestamp);
CREATE INDEX idx_traffic_src_ip ON traffic_logs(src_ip, timestamp);

-- Partition tables by date
CREATE TABLE metrics_2025_06 PARTITION OF metrics
FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');

-- Optimize queries with materialized views
CREATE MATERIALIZED VIEW threat_summary AS
SELECT 
    date_trunc('hour', timestamp) as hour,
    threat_type,
    severity,
    COUNT(*) as count,
    AVG(confidence_score) as avg_confidence
FROM threats 
WHERE timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY hour, threat_type, severity;

-- Refresh materialized view periodically
CREATE OR REPLACE FUNCTION refresh_threat_summary()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY threat_summary;
END;
$$ LANGUAGE plpgsql;

-- Schedule refresh
SELECT cron.schedule('refresh-threat-summary', '*/5 * * * *', 'SELECT refresh_threat_summary();');
```

---

## 🆘 **Troubleshooting Monitoring**

### ❌ **Common Issues**

#### **High Memory Usage**
```bash
# Check monitoring memory usage
ps aux | grep -E "(prometheus|grafana|alertmanager)" | awk '{sum+=$6} END {print "Total Memory: " sum/1024 "MB"}'

# Optimize Prometheus retention
prometheus --storage.tsdb.retention.time=15d --storage.tsdb.retention.size=10GB

# Clean up old metrics
curl -X POST http://localhost:9090/api/v1/admin/tsdb/delete_series?match[]={__name__=~"old_metric_.*"}
```

#### **Missing Metrics**
```bash
# Check metrics endpoint
curl -s http://localhost:9091/metrics | grep zehrasec | head -10

# Verify Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.health != "up")'

# Test network connectivity
telnet prometheus-server 9090
```

#### **Alert Fatigue**
```yaml
# Optimize alert rules to reduce noise
- alert: HighThreatDetectionRate
  expr: rate(zehrasec_threats_detected_total[5m]) > 50  # Increased threshold
  for: 10m  # Increased duration
  labels:
    severity: warning
  annotations:
    summary: "Sustained high threat detection rate"
    description: "{{ $value }} threats per second for over 10 minutes"
```

### 🔧 **Performance Issues**

#### **Slow Dashboard Loading**
```javascript
// Optimize Grafana dashboard queries
{
  "targets": [
    {
      "expr": "sum(rate(zehrasec_threats_detected_total[5m]))",
      "intervalFactor": 2,
      "maxDataPoints": 100,
      "step": 60
    }
  ]
}

// Use recording rules for complex queries
# prometheus.yml
rule_files:
  - "recording_rules.yml"
```

#### **Recording Rules**
```yaml
# recording_rules.yml
groups:
  - name: zehrasec.recording
    interval: 30s
    rules:
      - record: zehrasec:threat_rate_5m
        expr: rate(zehrasec_threats_detected_total[5m])
        
      - record: zehrasec:traffic_rate_5m
        expr: sum(rate(zehrasec_bytes_total[5m])) by (direction)
        
      - record: zehrasec:system_health
        expr: |
          (
            (zehrasec_cpu_usage_percent < 80) and
            (zehrasec_memory_usage_bytes / 1024 / 1024 / 1024 < 6) and
            (up{job="zehrasec-firewall"} == 1)
          )
```

---

## 📚 **Best Practices**

### ✅ **Monitoring Best Practices**

#### **Metric Design**
1. **Use consistent naming conventions**
   - Prefix: `zehrasec_`
   - Snake_case for metric names
   - Descriptive suffixes (`_total`, `_seconds`, `_bytes`)

2. **Label design**
   - Keep cardinality low (< 10 values per label)
   - Use meaningful label names
   - Avoid timestamps in labels

3. **Alert design**
   - Focus on symptoms, not causes
   - Use rate() for counters
   - Set appropriate thresholds and durations

#### **Dashboard Design**
1. **Information hierarchy**
   - Most important metrics at the top
   - Use consistent time ranges
   - Group related metrics

2. **Visual design**
   - Use colors meaningfully
   - Consistent units and scales
   - Clear legends and labels

3. **Performance optimization**
   - Limit query complexity
   - Use recording rules for expensive queries
   - Implement proper caching

---

## 📞 **Support Resources**

### 🆘 **Monitoring Support**
- **Monitoring Issues**: monitoring@zehrasec.com
- **Dashboard Support**: dashboards@zehrasec.com
- **Integration Help**: integrations@zehrasec.com

### 📚 **Documentation**
- **[Grafana Documentation](21-Logging-Guide.md)** - Log management guide
- **[Performance Guide](18-Performance-Optimization.md)** - System optimization
- **[Troubleshooting Guide](16-Troubleshooting-Guide.md)** - General troubleshooting

### 🎓 **Training**
- **Monitoring Workshop**: https://training.zehrasec.com/monitoring
- **Grafana Masterclass**: https://training.zehrasec.com/grafana
- **Prometheus Training**: https://training.zehrasec.com/prometheus

---

**Copyright © 2025 ZehraSec - Yashab Alam**  
**All Rights Reserved**

---
