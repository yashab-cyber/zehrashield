# Integration Guide

## Overview

This comprehensive integration guide covers how to integrate ZehraSec Advanced Firewall with various third-party systems, security tools, and enterprise infrastructure. It includes configuration examples, API usage, and best practices for seamless integration.

## Table of Contents

1. [SIEM Integration](#siem-integration)
2. [Identity and Access Management](#identity-and-access-management)
3. [Network Management Systems](#network-management-systems)
4. [Threat Intelligence Platforms](#threat-intelligence-platforms)
5. [SOAR Platforms](#soar-platforms)
6. [Cloud Services Integration](#cloud-services-integration)
7. [DevOps and CI/CD Integration](#devops-and-cicd-integration)
8. [Database Integration](#database-integration)
9. [Monitoring and Analytics](#monitoring-and-analytics)
10. [Custom Integrations](#custom-integrations)

## SIEM Integration

### Splunk Integration

#### Installation and Configuration

```bash
# Install Splunk Universal Forwarder
wget -O splunkforwarder.tgz "https://download.splunk.com/products/universalforwarder/releases/8.2.0/linux/splunkforwarder-8.2.0-linux.tgz"
tar -xzf splunkforwarder.tgz -C /opt/
/opt/splunkforwarder/bin/splunk start --accept-license
```

#### Inputs Configuration
```ini
# /opt/splunkforwarder/etc/apps/zehrasec/local/inputs.conf
[monitor:///var/log/zehrasec/firewall.log]
index = zehrasec_firewall
sourcetype = zehrasec:firewall
host = firewall-01

[monitor:///var/log/zehrasec/threats.log]
index = zehrasec_threats
sourcetype = zehrasec:threat
host = firewall-01

[monitor:///var/log/zehrasec/audit.log]
index = zehrasec_audit
sourcetype = zehrasec:audit
host = firewall-01
```

#### Props Configuration
```ini
# /opt/splunkforwarder/etc/apps/zehrasec/local/props.conf
[zehrasec:firewall]
DATETIME_CONFIG = CURRENT
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
category = Network & Security
description = ZehraSec Firewall Logs

[zehrasec:threat]
DATETIME_CONFIG = CURRENT
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
category = Security
description = ZehraSec Threat Detection Logs
```

#### Search Queries
```spl
# Top blocked IPs
index=zehrasec_firewall action=block 
| top limit=20 src_ip 
| eval percentage=round(percent,2)

# Threat detection over time
index=zehrasec_threats 
| timechart span=1h count by threat_type

# Failed authentication attempts
index=zehrasec_audit action=login_failed 
| stats count by user src_ip 
| sort -count
```

### QRadar Integration

#### DSM Configuration
```xml
<!-- ZehraSec DSM Configuration -->
<device-extension xmlns="com.q1labs.schemas.dsm">
    <pattern id="ZehraSec-Pattern">
        <matcher field="devicetype">ZehraSec</matcher>
    </pattern>
    
    <event-match-single>
        <pattern-match>
            <pattern>^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+(\S+)\s+zehrasec\[\d+\]:\s+(\w+):\s+(.*)$</pattern>
            <group-match name="EventTime" match-number="1"/>
            <group-match name="SourceIP" match-number="2"/>
            <group-match name="Severity" match-number="3"/>
            <group-match name="Message" match-number="4"/>
        </pattern-match>
    </event-match-single>
</device-extension>
```

#### Log Source Configuration
```json
{
  "log_source": {
    "name": "ZehraSec Advanced Firewall",
    "type": "ZehraSec",
    "protocol": "syslog",
    "ip": "192.168.1.100",
    "port": 514,
    "format": "LEEF",
    "parsing": {
      "datetime_format": "ISO8601",
      "field_delimiter": "|",
      "key_value_delimiter": "="
    }
  }
}
```

### IBM Security QRadar LEEF Format

```python
# Python script to send LEEF formatted logs
import socket
import datetime

def send_leef_log(severity, event_type, message):
    leef_format = f"LEEF:2.0|ZehraSec|Advanced Firewall|2.0|{event_type}|devTime={datetime.datetime.now().isoformat()}|severity={severity}|msg={message}"
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(leef_format.encode(), ('qradar.company.com', 514))
    sock.close()

# Example usage
send_leef_log('High', 'ThreatDetected', 'Malware detected in network traffic')
```

## Identity and Access Management

### Active Directory Integration

#### LDAP Configuration
```json
{
  "ldap": {
    "servers": [
      {
        "host": "dc1.company.com",
        "port": 636,
        "ssl": true,
        "start_tls": false
      },
      {
        "host": "dc2.company.com",
        "port": 636,
        "ssl": true,
        "start_tls": false
      }
    ],
    "bind_dn": "CN=ZehraSec Service,OU=Service Accounts,DC=company,DC=com",
    "bind_password": "secure_password",
    "search_base": "DC=company,DC=com",
    "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
    "group_filter": "(&(objectClass=group)(member={user_dn}))",
    "attributes": {
      "username": "sAMAccountName",
      "email": "mail",
      "full_name": "displayName",
      "groups": "memberOf"
    }
  }
}
```

#### Group Mapping
```json
{
  "group_mapping": {
    "CN=Domain Admins,CN=Users,DC=company,DC=com": "admin",
    "CN=Network Operators,OU=Groups,DC=company,DC=com": "operator",
    "CN=Security Team,OU=Groups,DC=company,DC=com": "security_analyst",
    "CN=Domain Users,CN=Users,DC=company,DC=com": "viewer"
  }
}
```

### SAML 2.0 Integration

#### Service Provider Configuration
```xml
<!-- SAML SP Configuration -->
<EntityDescriptor entityID="https://firewall.company.com/saml/metadata">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <KeyInfo>
                <X509Data>
                    <X509Certificate>MIICertificateData...</X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
        <AssertionConsumerService 
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="https://firewall.company.com/saml/acs"
            index="0"/>
    </SPSSODescriptor>
</EntityDescriptor>
```

### OAuth 2.0 / OpenID Connect

```json
{
  "oauth2": {
    "provider": "auth0",
    "client_id": "your_client_id",
    "client_secret": "your_client_secret",
    "discovery_url": "https://your-tenant.auth0.com/.well-known/openid_configuration",
    "scopes": ["openid", "profile", "email"],
    "redirect_uri": "https://firewall.company.com/oauth/callback",
    "token_validation": {
      "verify_signature": true,
      "verify_audience": true,
      "verify_issuer": true
    }
  }
}
```

## Network Management Systems

### SNMP Integration

#### SNMP Configuration
```json
{
  "snmp": {
    "version": "v3",
    "port": 161,
    "security": {
      "username": "zehrasec_monitor",
      "auth_protocol": "SHA",
      "auth_password": "auth_password",
      "priv_protocol": "AES128",
      "priv_password": "priv_password"
    },
    "managers": [
      "192.168.1.10",
      "192.168.1.11"
    ],
    "mib_modules": [
      "ZehraSec-MIB",
      "IF-MIB",
      "HOST-RESOURCES-MIB"
    ]
  }
}
```

#### Custom MIB Definition
```asn1
-- ZehraSec-MIB.mib
ZehraSec-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Counter32, Gauge32, Integer32
        FROM SNMPv2-SMI;

zehraSecMIB MODULE-IDENTITY
    LAST-UPDATED "202312010000Z"
    ORGANIZATION "ZehraSec"
    CONTACT-INFO "support@zehrasec.com"
    DESCRIPTION "MIB for ZehraSec Advanced Firewall"
    ::= { enterprises 12345 }

-- Firewall Statistics
firewallStats OBJECT IDENTIFIER ::= { zehraSecMIB 1 }

packetsProcessed OBJECT-TYPE
    SYNTAX Counter32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Total packets processed"
    ::= { firewallStats 1 }

threatsBlocked OBJECT-TYPE
    SYNTAX Counter32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Total threats blocked"
    ::= { firewallStats 2 }

END
```

### NetConf Integration

```xml
<!-- NetConf Configuration Template -->
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <zehrasec-config xmlns="http://zehrasec.com/ns/config">
        <firewall>
            <interfaces>
                <interface>
                    <name>eth0</name>
                    <enabled>true</enabled>
                    <ip-address>192.168.1.100</ip-address>
                    <netmask>255.255.255.0</netmask>
                </interface>
            </interfaces>
            <rules>
                <rule>
                    <id>1</id>
                    <action>allow</action>
                    <source>192.168.1.0/24</source>
                    <destination>any</destination>
                    <port>80</port>
                </rule>
            </rules>
        </firewall>
    </zehrasec-config>
</config>
```

## Threat Intelligence Platforms

### STIX/TAXII Integration

```python
# TAXII Client Integration
from taxii2client.v20 import Server, Collection
import json

def fetch_threat_intelligence():
    server = Server("https://threat-intel.company.com/taxii2/")
    api_root = server.api_roots[0]
    collections = api_root.collections
    
    for collection in collections:
        if collection.title == "Malware Indicators":
            objects = collection.get_objects()
            for obj in objects:
                if obj.type == "indicator":
                    process_indicator(obj)

def process_indicator(indicator):
    config = {
        "rule_id": f"TI_{indicator.id}",
        "pattern": indicator.pattern,
        "labels": indicator.labels,
        "confidence": indicator.confidence,
        "valid_from": indicator.valid_from.isoformat(),
        "action": "block" if "malicious-activity" in indicator.labels else "alert"
    }
    
    # Add to ZehraSec threat intelligence
    add_threat_indicator(config)
```

### VirusTotal Integration

```python
import requests
import hashlib

class VirusTotalIntegration:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
    
    def check_file_hash(self, file_hash):
        url = f"{self.base_url}/file/report"
        params = {
            'apikey': self.api_key,
            'resource': file_hash
        }
        
        response = requests.get(url, params=params)
        if response.status_code == 200:
            result = response.json()
            return {
                'malicious': result['positives'] > 0,
                'detection_ratio': f"{result['positives']}/{result['total']}",
                'scan_date': result['scan_date']
            }
    
    def check_ip(self, ip_address):
        url = f"{self.base_url}/ip-address/report"
        params = {
            'apikey': self.api_key,
            'ip': ip_address
        }
        
        response = requests.get(url, params=params)
        return response.json()
```

### MISP Integration

```python
from pymisp import PyMISP

class MISPIntegration:
    def __init__(self, url, key):
        self.misp = PyMISP(url, key, ssl=True)
    
    def get_attributes(self, event_id=None, type_attribute=None):
        attributes = self.misp.search(
            controller='attributes',
            eventid=event_id,
            type_attribute=type_attribute,
            to_ids=True
        )
        return attributes
    
    def create_event(self, title, description, threat_level=3):
        event = self.misp.new_event(
            distribution=0,
            threat_level_id=threat_level,
            analysis=1,
            info=title
        )
        
        event['Event']['analysis'] = 1
        event['Event']['published'] = False
        
        return self.misp.add_event(event)
```

## SOAR Platforms

### Phantom/Splunk SOAR Integration

```python
# Phantom Playbook Integration
import phantom.rules as phantom
import phantom.utils as ph_utils

def on_start(container):
    phantom.debug('Starting ZehraSec Integration Playbook')
    
    # Get firewall data
    firewall_data = get_firewall_alerts()
    
    # Process each alert
    for alert in firewall_data:
        if alert['severity'] == 'high':
            block_ip_address(alert['source_ip'])
            create_incident_ticket(alert)

def block_ip_address(ip_address):
    action_results = phantom.act(
        action="block ip",
        app="zehrasec",
        parameters=[{"ip": ip_address}],
        callback=block_ip_callback
    )

def create_incident_ticket(alert):
    ticket_data = {
        "title": f"High Severity Alert: {alert['event_type']}",
        "description": alert['description'],
        "priority": "high",
        "assignee": "security_team"
    }
    
    phantom.act(
        action="create ticket",
        app="servicenow",
        parameters=[ticket_data]
    )
```

### Demisto/Cortex XSOAR Integration

```python
# Demisto Integration Script
import demistomock as demisto
from CommonServerPython import *

def main():
    try:
        # Get ZehraSec alerts
        alerts = get_zehrasec_alerts()
        
        for alert in alerts:
            # Create incident in Demisto
            incident = {
                'name': f"ZehraSec Alert: {alert['type']}",
                'type': 'Security Alert',
                'severity': map_severity(alert['severity']),
                'details': alert['description'],
                'labels': [
                    {'type': 'Source', 'value': alert['source_ip']},
                    {'type': 'Destination', 'value': alert['dest_ip']},
                    {'type': 'Alert Type', 'value': alert['type']}
                ]
            }
            
            demisto.createIncidents([incident])
            
    except Exception as e:
        return_error(f"Failed to process ZehraSec alerts: {str(e)}")

def map_severity(zehrasec_severity):
    mapping = {
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4
    }
    return mapping.get(zehrasec_severity, 2)

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
```

## Cloud Services Integration

### AWS Integration

#### CloudWatch Logs
```json
{
  "cloudwatch_logs": {
    "log_group": "/aws/zehrasec/firewall",
    "log_stream": "firewall-{instance-id}",
    "region": "us-east-1",
    "credentials": {
      "access_key_id": "AKIA...",
      "secret_access_key": "...",
      "session_token": "..."
    },
    "log_format": "json",
    "batch_size": 100,
    "batch_timeout": 5
  }
}
```

#### S3 Log Storage
```python
import boto3
import gzip
import json
from datetime import datetime

class S3LogStorage:
    def __init__(self, bucket_name, region='us-east-1'):
        self.s3_client = boto3.client('s3', region_name=region)
        self.bucket_name = bucket_name
    
    def upload_logs(self, logs, log_type='firewall'):
        timestamp = datetime.now().strftime('%Y/%m/%d/%H')
        key = f"zehrasec-logs/{log_type}/{timestamp}/logs.gz"
        
        # Compress logs
        compressed_data = gzip.compress(
            '\n'.join([json.dumps(log) for log in logs]).encode()
        )
        
        # Upload to S3
        self.s3_client.put_object(
            Bucket=self.bucket_name,
            Key=key,
            Body=compressed_data,
            ContentType='application/gzip'
        )
```

### Azure Integration

#### Azure Monitor
```json
{
  "azure_monitor": {
    "workspace_id": "your-workspace-id",
    "shared_key": "your-shared-key",
    "log_type": "ZehraSecFirewall",
    "api_version": "2016-04-01",
    "time_generated_field": "timestamp"
  }
}
```

#### Azure Sentinel
```kusto
// KQL Query for Azure Sentinel
ZehraSecFirewall_CL
| where TimeGenerated > ago(24h)
| where EventType_s == "ThreatDetected"
| summarize count() by SourceIP_s, ThreatType_s
| order by count_ desc
```

### Google Cloud Integration

#### Cloud Logging
```python
from google.cloud import logging
import json

def send_to_cloud_logging(log_data):
    client = logging.Client()
    logger = client.logger('zehrasec-firewall')
    
    logger.log_struct(
        log_data,
        severity='INFO',
        labels={
            'component': 'firewall',
            'environment': 'production'
        }
    )
```

## DevOps and CI/CD Integration

### Jenkins Integration

```groovy
// Jenkins Pipeline for ZehraSec Configuration Deployment
pipeline {
    agent any
    
    stages {
        stage('Validate Configuration') {
            steps {
                script {
                    sh 'zehrasec-cli config validate --file config/production.json'
                }
            }
        }
        
        stage('Test Configuration') {
            steps {
                script {
                    sh 'zehrasec-cli config test --config config/production.json'
                }
            }
        }
        
        stage('Deploy to Staging') {
            steps {
                script {
                    sh 'zehrasec-cli deploy --environment staging --config config/production.json'
                }
            }
        }
        
        stage('Run Integration Tests') {
            steps {
                script {
                    sh 'pytest tests/integration/'
                }
            }
        }
        
        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            steps {
                script {
                    input 'Deploy to production?'
                    sh 'zehrasec-cli deploy --environment production --config config/production.json'
                }
            }
        }
    }
    
    post {
        failure {
            emailext (
                subject: "ZehraSec Deployment Failed",
                body: "Build failed. Check Jenkins for details.",
                to: "devops@company.com"
            )
        }
    }
}
```

### GitLab CI/CD Integration

```yaml
# .gitlab-ci.yml
stages:
  - validate
  - test
  - deploy

variables:
  ZEHRASEC_CONFIG: "config/production.json"

validate_config:
  stage: validate
  script:
    - zehrasec-cli config validate --file $ZEHRASEC_CONFIG
  only:
    - merge_requests
    - main

test_config:
  stage: test
  script:
    - zehrasec-cli config test --config $ZEHRASEC_CONFIG
    - pytest tests/
  coverage: '/TOTAL.*\s+(\d+%)$/'

deploy_staging:
  stage: deploy
  script:
    - zehrasec-cli deploy --environment staging --config $ZEHRASEC_CONFIG
  environment:
    name: staging
    url: https://staging-fw.company.com
  only:
    - main

deploy_production:
  stage: deploy
  script:
    - zehrasec-cli deploy --environment production --config $ZEHRASEC_CONFIG
  environment:
    name: production
    url: https://fw.company.com
  when: manual
  only:
    - main
```

## Database Integration

### PostgreSQL Integration

```python
import psycopg2
import json
from datetime import datetime

class PostgreSQLIntegration:
    def __init__(self, host, database, user, password):
        self.connection_string = f"host={host} dbname={database} user={user} password={password}"
    
    def log_event(self, event_data):
        conn = psycopg2.connect(self.connection_string)
        cursor = conn.cursor()
        
        insert_query = """
        INSERT INTO firewall_events (timestamp, event_type, source_ip, destination_ip, action, details)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        
        cursor.execute(insert_query, (
            datetime.now(),
            event_data['event_type'],
            event_data['source_ip'],
            event_data['destination_ip'],
            event_data['action'],
            json.dumps(event_data['details'])
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
```

### Elasticsearch Integration

```python
from elasticsearch import Elasticsearch
import json

class ElasticsearchIntegration:
    def __init__(self, hosts, username=None, password=None):
        if username and password:
            self.es = Elasticsearch(
                hosts,
                http_auth=(username, password),
                verify_certs=True
            )
        else:
            self.es = Elasticsearch(hosts)
    
    def index_log(self, log_data, index_name='zehrasec-logs'):
        doc = {
            '@timestamp': log_data.get('timestamp'),
            'event_type': log_data.get('event_type'),
            'source_ip': log_data.get('source_ip'),
            'destination_ip': log_data.get('destination_ip'),
            'action': log_data.get('action'),
            'details': log_data.get('details')
        }
        
        self.es.index(index=index_name, body=doc)
    
    def search_logs(self, query, index_name='zehrasec-logs'):
        search_body = {
            "query": {
                "match": {
                    "event_type": query
                }
            }
        }
        
        return self.es.search(index=index_name, body=search_body)
```

## Monitoring and Analytics

### Grafana Integration

```json
{
  "datasources": [
    {
      "name": "ZehraSec Metrics",
      "type": "prometheus",
      "url": "http://localhost:9090",
      "access": "proxy",
      "isDefault": true
    }
  ],
  "dashboards": [
    {
      "title": "ZehraSec Firewall Overview",
      "panels": [
        {
          "title": "Throughput",
          "type": "graph",
          "targets": [
            {
              "expr": "rate(zehrasec_bytes_total[5m])",
              "legendFormat": "{{interface}}"
            }
          ]
        },
        {
          "title": "Threat Detection Rate",
          "type": "stat",
          "targets": [
            {
              "expr": "rate(zehrasec_threats_detected_total[1h])"
            }
          ]
        }
      ]
    }
  ]
}
```

### Prometheus Metrics

```python
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Define metrics
packets_processed = Counter('zehrasec_packets_processed_total', 'Total packets processed')
bytes_transferred = Counter('zehrasec_bytes_total', 'Total bytes transferred', ['direction'])
connection_count = Gauge('zehrasec_active_connections', 'Number of active connections')
threat_detection_rate = Counter('zehrasec_threats_detected_total', 'Total threats detected', ['type'])
processing_time = Histogram('zehrasec_processing_time_seconds', 'Time spent processing packets')

def update_metrics(packet_data):
    packets_processed.inc()
    bytes_transferred.labels(direction='ingress').inc(packet_data['size'])
    
    if packet_data.get('threat_detected'):
        threat_detection_rate.labels(type=packet_data['threat_type']).inc()

# Start metrics server
start_http_server(8000)
```

## Custom Integrations

### REST API Integration Template

```python
import requests
import json
from datetime import datetime

class CustomAPIIntegration:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def send_alert(self, alert_data):
        endpoint = f"{self.base_url}/alerts"
        
        payload = {
            'timestamp': datetime.now().isoformat(),
            'source': 'ZehraSec Advanced Firewall',
            'severity': alert_data['severity'],
            'message': alert_data['message'],
            'metadata': alert_data.get('metadata', {})
        }
        
        response = requests.post(
            endpoint,
            headers=self.headers,
            data=json.dumps(payload)
        )
        
        return response.status_code == 200
    
    def get_threat_intelligence(self):
        endpoint = f"{self.base_url}/threat-intelligence"
        
        response = requests.get(endpoint, headers=self.headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            return None

# Usage example
integration = CustomAPIIntegration('https://api.security-platform.com', 'your-api-key')

alert = {
    'severity': 'high',
    'message': 'Suspicious network activity detected',
    'metadata': {
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.5',
        'protocol': 'TCP',
        'port': 443
    }
}

integration.send_alert(alert)
```

### Webhook Integration

```python
from flask import Flask, request, jsonify
import hmac
import hashlib
import json

app = Flask(__name__)
WEBHOOK_SECRET = 'your-webhook-secret'

@app.route('/webhook/zehrasec', methods=['POST'])
def handle_webhook():
    # Verify signature
    signature = request.headers.get('X-ZehraSec-Signature')
    if not verify_signature(request.data, signature):
        return jsonify({'error': 'Invalid signature'}), 401
    
    # Process webhook data
    data = request.json
    event_type = data.get('event_type')
    
    if event_type == 'threat_detected':
        handle_threat_detection(data)
    elif event_type == 'policy_violation':
        handle_policy_violation(data)
    
    return jsonify({'status': 'received'}), 200

def verify_signature(payload, signature):
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected}", signature)

def handle_threat_detection(data):
    # Custom threat handling logic
    print(f"Threat detected: {data['threat_type']} from {data['source_ip']}")
    
def handle_policy_violation(data):
    # Custom policy violation handling
    print(f"Policy violation: {data['policy']} by {data['user']}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

## Integration Testing

### Test Framework

```python
import unittest
import requests
import json

class IntegrationTest(unittest.TestCase):
    def setUp(self):
        self.base_url = 'http://localhost:8443'
        self.api_key = 'test-api-key'
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
    
    def test_siem_integration(self):
        # Test SIEM log forwarding
        response = requests.get(
            f"{self.base_url}/api/v1/integrations/siem/status",
            headers=self.headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['enabled'])
    
    def test_threat_intelligence_feed(self):
        # Test threat intelligence feed
        response = requests.get(
            f"{self.base_url}/api/v1/threat-intelligence/feeds",
            headers=self.headers
        )
        self.assertEqual(response.status_code, 200)
        feeds = response.json()
        self.assertGreater(len(feeds), 0)
    
    def test_webhook_delivery(self):
        # Test webhook delivery
        webhook_data = {
            'url': 'http://test-webhook.com/endpoint',
            'secret': 'test-secret',
            'events': ['threat_detected', 'policy_violation']
        }
        
        response = requests.post(
            f"{self.base_url}/api/v1/webhooks",
            headers=self.headers,
            data=json.dumps(webhook_data)
        )
        self.assertEqual(response.status_code, 201)

if __name__ == '__main__':
    unittest.main()
```

## Best Practices

1. **Authentication and Authorization**
   - Use strong authentication for all integrations
   - Implement proper access controls
   - Regular credential rotation

2. **Data Security**
   - Encrypt data in transit and at rest
   - Validate and sanitize all inputs
   - Implement rate limiting

3. **Error Handling**
   - Implement proper error handling
   - Log integration failures
   - Implement retry mechanisms

4. **Performance**
   - Use connection pooling
   - Implement caching where appropriate
   - Monitor integration performance

5. **Monitoring**
   - Monitor integration health
   - Set up alerting for failures
   - Track integration metrics

## Support and Resources

- **Integration Support**: integrations@zehrasec.com
- **API Documentation**: https://docs.zehrasec.com/api
- **Sample Code**: https://github.com/zehrasec/integration-examples
- **Community Forum**: https://community.zehrasec.com

---

*This guide provides comprehensive integration information for ZehraSec Advanced Firewall. For specific integration support, contact our integration team.*
