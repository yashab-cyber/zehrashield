# 22. Alerting & Notifications

![ZehraSec Alerting](https://img.shields.io/badge/🔔-Alerting%20System-orange?style=for-the-badge&logo=bell)

**Last Updated**: June 19, 2025 | **Version**: 3.0.0

---

## 📋 **Overview**

ZehraSec Advanced Firewall provides a comprehensive alerting and notification system that keeps administrators informed about security events, system status changes, and potential threats in real-time. This guide covers configuration, customization, and management of the alerting infrastructure.

---

## 🎯 **Alerting Architecture**

### **Multi-Channel Notification System**
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Event Engine  │───▶│  Alert Processor │───▶│ Notification    │
│                 │    │                  │    │ Dispatcher      │
│ • Threat Det.   │    │ • Rule Engine    │    │                 │
│ • System Events │    │ • Prioritization │    │ • Email         │
│ • Performance   │    │ • Correlation    │    │ • SMS           │
│ • Compliance    │    │ • Deduplication  │    │ • Webhook       │
└─────────────────┘    └──────────────────┘    │ • Slack/Teams   │
                                                │ • SIEM Forward  │
                                                └─────────────────┘
```

### **Alert Severity Levels**

| Level | Priority | Description | Response Time |
|-------|----------|-------------|---------------|
| **CRITICAL** | P0 | Immediate threat, system compromise | < 5 minutes |
| **HIGH** | P1 | Significant security event | < 15 minutes |
| **MEDIUM** | P2 | Suspicious activity, policy violation | < 1 hour |
| **LOW** | P3 | Informational, routine events | < 4 hours |
| **INFO** | P4 | System status, maintenance | Best effort |

---

## ⚙️ **Alert Configuration**

### **Basic Alert Setup**

```json
{
  "alerting": {
    "enabled": true,
    "global_settings": {
      "rate_limiting": {
        "enabled": true,
        "max_alerts_per_minute": 100,
        "burst_threshold": 10
      },
      "deduplication": {
        "enabled": true,
        "time_window": "5m",
        "similarity_threshold": 0.8
      },
      "escalation": {
        "enabled": true,
        "escalation_timeout": "30m",
        "max_escalation_levels": 3
      }
    },
    "channels": {
      "email": {
        "enabled": true,
        "smtp_server": "smtp.company.com",
        "smtp_port": 587,
        "smtp_tls": true,
        "from_address": "alerts@company.com",
        "recipients": [
          {
            "email": "admin@company.com",
            "severity_filter": ["CRITICAL", "HIGH"],
            "categories": ["security", "system"]
          },
          {
            "email": "team@company.com",
            "severity_filter": ["MEDIUM", "LOW"],
            "categories": ["all"]
          }
        ]
      },
      "sms": {
        "enabled": true,
        "provider": "twilio",
        "api_key": "your_api_key",
        "from_number": "+1234567890",
        "recipients": [
          {
            "phone": "+1987654321",
            "severity_filter": ["CRITICAL"],
            "time_restrictions": {
              "business_hours_only": false,
              "quiet_hours": {
                "start": "22:00",
                "end": "06:00"
              }
            }
          }
        ]
      },
      "webhook": {
        "enabled": true,
        "endpoints": [
          {
            "name": "security_team_webhook",
            "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
            "method": "POST",
            "headers": {
              "Content-Type": "application/json",
              "Authorization": "Bearer your_token"
            },
            "severity_filter": ["CRITICAL", "HIGH"],
            "retry_policy": {
              "max_retries": 3,
              "retry_delay": "30s"
            }
          }
        ]
      },
      "siem_forward": {
        "enabled": true,
        "siem_type": "splunk",
        "endpoint": "https://splunk.company.com:8088/services/collector",
        "token": "your_hec_token",
        "index": "zehrasec_alerts"
      }
    }
  }
}
```

### **Advanced Alert Rules**

```json
{
  "alert_rules": {
    "threat_detection": {
      "malware_detected": {
        "enabled": true,
        "severity": "CRITICAL",
        "conditions": {
          "event_type": "malware_detection",
          "confidence_threshold": 0.8
        },
        "message_template": "CRITICAL: Malware detected on {{host}} - {{malware_name}} (Confidence: {{confidence}})",
        "notification_channels": ["email", "sms", "webhook"],
        "escalation": {
          "enabled": true,
          "levels": [
            {
              "delay": "5m",
              "channels": ["sms"],
              "recipients": ["security_team"]
            },
            {
              "delay": "15m",
              "channels": ["email", "webhook"],
              "recipients": ["management"]
            }
          ]
        }
      },
      "suspicious_activity": {
        "enabled": true,
        "severity": "HIGH",
        "conditions": {
          "event_type": "anomaly_detection",
          "anomaly_score": {
            "min": 7.0,
            "max": 10.0
          },
          "frequency": {
            "count": 5,
            "time_window": "10m"
          }
        },
        "message_template": "HIGH: Suspicious activity detected - {{description}} (Score: {{anomaly_score}})"
      }
    },
    "system_monitoring": {
      "high_cpu_usage": {
        "enabled": true,
        "severity": "MEDIUM",
        "conditions": {
          "metric": "cpu_usage",
          "threshold": 90,
          "duration": "5m"
        },
        "message_template": "System Alert: High CPU usage detected - {{cpu_usage}}% for {{duration}}"
      },
      "memory_threshold": {
        "enabled": true,
        "severity": "MEDIUM",
        "conditions": {
          "metric": "memory_usage",
          "threshold": 85,
          "duration": "5m"
        },
        "message_template": "System Alert: High memory usage - {{memory_usage}}% ({{available_memory}} available)"
      },
      "disk_space_low": {
        "enabled": true,
        "severity": "HIGH",
        "conditions": {
          "metric": "disk_usage",
          "threshold": 90,
          "paths": ["/", "/var/log", "/opt/zehrasec"]
        },
        "message_template": "System Alert: Low disk space on {{path}} - {{usage}}% used ({{free_space}} available)"
      }
    },
    "compliance": {
      "policy_violation": {
        "enabled": true,
        "severity": "HIGH",
        "conditions": {
          "event_type": "policy_violation",
          "policy_categories": ["data_protection", "access_control"]
        },
        "message_template": "Compliance Alert: Policy violation detected - {{policy_name}} violated by {{user}} from {{source_ip}}"
      },
      "failed_audit": {
        "enabled": true,
        "severity": "CRITICAL",
        "conditions": {
          "event_type": "audit_failure",
          "audit_type": ["login", "privilege_escalation", "data_access"]
        },
        "message_template": "Audit Alert: Failed audit event - {{audit_type}} by {{user}} (Reason: {{failure_reason}})"
      }
    }
  }
}
```

---

## 🔔 **Notification Channels**

### **Email Notifications**

**Configuration Options**:
```json
{
  "email": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_security": "STARTTLS",
    "authentication": {
      "username": "alerts@company.com",
      "password": "app_password"
    },
    "templates": {
      "subject_template": "[ZehraSec] {{severity}} - {{alert_type}}",
      "body_template": "html",
      "include_details": true,
      "include_graphs": true,
      "attachment_logs": false
    },
    "delivery_options": {
      "batch_alerts": true,
      "batch_interval": "5m",
      "max_batch_size": 20,
      "priority_bypass": ["CRITICAL"]
    }
  }
}
```

**HTML Email Template**:
```html
<!DOCTYPE html>
<html>
<head>
    <style>
        .alert-critical { background-color: #dc3545; color: white; }
        .alert-high { background-color: #fd7e14; color: white; }
        .alert-medium { background-color: #ffc107; color: black; }
        .alert-low { background-color: #28a745; color: white; }
        .alert-info { background-color: #17a2b8; color: white; }
    </style>
</head>
<body>
    <div class="alert-{{severity_class}}">
        <h2>🛡️ ZehraSec Alert - {{severity}}</h2>
        <p><strong>Time:</strong> {{timestamp}}</p>
        <p><strong>Source:</strong> {{source_system}}</p>
        <p><strong>Category:</strong> {{category}}</p>
        <p><strong>Description:</strong> {{description}}</p>
        
        {{#if details}}
        <h3>Details</h3>
        <ul>
            {{#each details}}
            <li><strong>{{@key}}:</strong> {{this}}</li>
            {{/each}}
        </ul>
        {{/if}}
        
        <p><a href="{{console_url}}/alerts/{{alert_id}}">View in Console</a></p>
    </div>
</body>
</html>
```

### **SMS Notifications**

**Supported Providers**:
- **Twilio**: Full-featured SMS/MMS support
- **AWS SNS**: Reliable cloud messaging
- **Nexmo/Vonage**: Global SMS delivery
- **MessageBird**: Multi-channel messaging

**Configuration Example**:
```json
{
  "sms": {
    "provider": "twilio",
    "credentials": {
      "account_sid": "AC1234567890abcdef",
      "auth_token": "your_auth_token",
      "from_number": "+1234567890"
    },
    "message_settings": {
      "max_length": 160,
      "truncate_long_messages": true,
      "include_alert_id": true,
      "url_shortening": true
    },
    "delivery_restrictions": {
      "quiet_hours": {
        "enabled": true,
        "start": "22:00",
        "end": "06:00",
        "timezone": "UTC",
        "emergency_override": ["CRITICAL"]
      },
      "rate_limiting": {
        "max_per_hour": 10,
        "max_per_day": 50
      }
    }
  }
}
```

### **Webhook Notifications**

**Slack Integration**:
```json
{
  "webhook": {
    "slack": {
      "webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
      "channel": "#security-alerts",
      "username": "ZehraSec",
      "icon_emoji": ":shield:",
      "message_format": {
        "attachments": [
          {
            "color": "{{severity_color}}",
            "title": "{{alert_title}}",
            "text": "{{alert_description}}",
            "fields": [
              {
                "title": "Severity",
                "value": "{{severity}}",
                "short": true
              },
              {
                "title": "Source",
                "value": "{{source_ip}}",
                "short": true
              },
              {
                "title": "Time",
                "value": "{{timestamp}}",
                "short": true
              }
            ],
            "actions": [
              {
                "type": "button",
                "text": "View Details",
                "url": "{{console_url}}/alerts/{{alert_id}}"
              },
              {
                "type": "button",
                "text": "Acknowledge",
                "url": "{{api_url}}/alerts/{{alert_id}}/acknowledge"
              }
            ]
          }
        ]
      }
    }
  }
}
```

**Microsoft Teams Integration**:
```json
{
  "webhook": {
    "teams": {
      "webhook_url": "https://outlook.office.com/webhook/...",
      "message_format": {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "{{severity_hex_color}}",
        "summary": "ZehraSec Security Alert",
        "sections": [
          {
            "activityTitle": "🛡️ ZehraSec Alert",
            "activitySubtitle": "{{alert_type}} - {{severity}}",
            "activityImage": "https://zehrasec.com/logo.png",
            "text": "{{description}}",
            "facts": [
              {
                "name": "Source IP:",
                "value": "{{source_ip}}"
              },
              {
                "name": "Time:",
                "value": "{{timestamp}}"
              },
              {
                "name": "Rule:",
                "value": "{{rule_name}}"
              }
            ]
          }
        ],
        "potentialAction": [
          {
            "@type": "OpenUri",
            "name": "View in Console",
            "targets": [
              {
                "os": "default",
                "uri": "{{console_url}}/alerts/{{alert_id}}"
              }
            ]
          }
        ]
      }
    }
  }
}
```

---

## 📊 **Alert Management**

### **Alert Dashboard**

Access the alert management dashboard at: `https://localhost:8443/alerts`

**Key Features**:
- Real-time alert stream
- Alert filtering and search
- Bulk operations (acknowledge, dismiss, escalate)
- Alert analytics and trends
- Custom alert views

### **Alert States**

| State | Description | Actions Available |
|-------|-------------|-------------------|
| **NEW** | Just triggered, awaiting review | Acknowledge, Dismiss, Escalate |
| **ACKNOWLEDGED** | Reviewed by administrator | Resolve, Escalate, Add Note |
| **IN_PROGRESS** | Being investigated/resolved | Resolve, Add Note, Reassign |
| **RESOLVED** | Issue has been fixed | Archive, Reopen |
| **DISMISSED** | False positive/not actionable | Archive, Reopen |
| **ESCALATED** | Escalated to higher priority | De-escalate, Resolve |

### **Alert API Endpoints**

```bash
# Get all alerts
GET /api/v1/alerts?severity=CRITICAL&status=NEW&limit=50

# Get specific alert
GET /api/v1/alerts/{alert_id}

# Acknowledge alert
POST /api/v1/alerts/{alert_id}/acknowledge
{
  "user_id": "admin",
  "note": "Investigating suspicious activity"
}

# Resolve alert
POST /api/v1/alerts/{alert_id}/resolve
{
  "user_id": "admin",
  "resolution": "Blocked malicious IP address",
  "actions_taken": ["ip_blocked", "user_notified"]
}

# Bulk operations
POST /api/v1/alerts/bulk
{
  "action": "acknowledge",
  "alert_ids": ["alert_1", "alert_2", "alert_3"],
  "user_id": "admin",
  "note": "Mass acknowledgment after investigation"
}
```

---

## 🔧 **Advanced Configuration**

### **Alert Correlation**

```json
{
  "correlation": {
    "enabled": true,
    "rules": [
      {
        "name": "coordinated_attack",
        "description": "Multiple failed logins followed by successful login",
        "events": [
          {
            "type": "failed_login",
            "count": ">=3",
            "time_window": "5m"
          },
          {
            "type": "successful_login",
            "count": ">=1",
            "time_window": "2m",
            "same_source_ip": true
          }
        ],
        "output": {
          "severity": "HIGH",
          "category": "coordinated_attack",
          "message": "Potential brute force attack followed by successful compromise"
        }
      },
      {
        "name": "data_exfiltration",
        "description": "Large data transfer after privilege escalation",
        "events": [
          {
            "type": "privilege_escalation",
            "count": ">=1",
            "time_window": "10m"
          },
          {
            "type": "large_data_transfer",
            "count": ">=1",
            "time_window": "30m",
            "same_user": true,
            "threshold": "100MB"
          }
        ],
        "output": {
          "severity": "CRITICAL",
          "category": "data_exfiltration",
          "message": "Potential data exfiltration detected"
        }
      }
    ]
  }
}
```

### **Machine Learning Alert Enhancement**

```json
{
  "ml_alerting": {
    "enabled": true,
    "features": {
      "smart_deduplication": {
        "enabled": true,
        "similarity_model": "semantic",
        "threshold": 0.85
      },
      "alert_prioritization": {
        "enabled": true,
        "model": "gradient_boosting",
        "factors": [
          "severity",
          "source_reputation",
          "target_criticality",
          "historical_context",
          "threat_intelligence"
        ]
      },
      "adaptive_thresholds": {
        "enabled": true,
        "learning_period": "7d",
        "adjustment_sensitivity": 0.1
      },
      "false_positive_reduction": {
        "enabled": true,
        "feedback_learning": true,
        "confidence_threshold": 0.7
      }
    }
  }
}
```

### **Custom Alert Processors**

```python
# custom_alert_processor.py
from zehrasec.alerts import AlertProcessor, Alert

class CustomAlertProcessor(AlertProcessor):
    def __init__(self):
        super().__init__()
        self.name = "custom_processor"
    
    def process_alert(self, alert: Alert) -> Alert:
        # Custom processing logic
        if alert.severity == "CRITICAL":
            # Enrich with additional context
            alert.add_context("priority", "immediate")
            alert.add_context("escalation_required", True)
            
            # Custom notification logic
            self.send_executive_notification(alert)
        
        # Apply custom filtering
        if self.is_false_positive(alert):
            alert.status = "DISMISSED"
            alert.add_note("Automatically dismissed by custom processor")
        
        return alert
    
    def is_false_positive(self, alert: Alert) -> bool:
        # Custom false positive detection logic
        if alert.source_ip in self.trusted_ips:
            return True
        if alert.event_type == "port_scan" and alert.source_network == "internal":
            return True
        return False
    
    def send_executive_notification(self, alert: Alert):
        # Custom executive notification
        executive_emails = ["ceo@company.com", "ciso@company.com"]
        self.send_email(
            recipients=executive_emails,
            subject=f"CRITICAL Security Event Requiring Immediate Attention",
            body=self.format_executive_alert(alert),
            priority="urgent"
        )
```

---

## 📈 **Performance & Optimization**

### **Alert Performance Metrics**

```json
{
  "performance_monitoring": {
    "metrics": {
      "alert_processing_time": {
        "target": "< 100ms",
        "current_avg": "45ms",
        "threshold_warning": "80ms",
        "threshold_critical": "200ms"
      },
      "notification_delivery_time": {
        "email": "< 30s",
        "sms": "< 10s",
        "webhook": "< 5s"
      },
      "alert_throughput": {
        "target": "> 1000 alerts/minute",
        "current": "1250 alerts/minute"
      },
      "false_positive_rate": {
        "target": "< 5%",
        "current": "2.3%"
      }
    }
  }
}
```

### **Optimization Strategies**

1. **Alert Batching**: Group similar alerts to reduce notification fatigue
2. **Smart Filtering**: Use ML to filter out noise and false positives
3. **Caching**: Cache frequently accessed alert data
4. **Async Processing**: Process alerts asynchronously to avoid blocking
5. **Rate Limiting**: Prevent alert storms from overwhelming systems

---

## 🔍 **Troubleshooting**

### **Common Issues**

**Email Notifications Not Working**:
```bash
# Check SMTP configuration
curl -X GET https://localhost:8443/api/v1/alerts/test-email

# Verify SMTP connectivity
telnet smtp.company.com 587

# Check email logs
tail -f /opt/zehrasec/logs/email_notifications.log
```

**High Alert Volume**:
```bash
# Check alert statistics
curl -X GET https://localhost:8443/api/v1/alerts/stats

# Identify top alert sources
curl -X GET https://localhost:8443/api/v1/alerts/top-sources

# Adjust alert thresholds
python /opt/zehrasec/tools/alert_threshold_tuner.py --analyze --adjust
```

**Webhook Failures**:
```bash
# Test webhook connectivity
curl -X POST https://your-webhook-url \
  -H "Content-Type: application/json" \
  -d '{"test": "message"}'

# Check webhook logs
grep "webhook" /opt/zehrasec/logs/notifications.log

# Verify webhook configuration
curl -X GET https://localhost:8443/api/v1/alerts/webhook-config
```

---

## 🔗 **Related Documentation**

- [Monitoring Setup Guide](20-Monitoring-Setup.md)
- [Logging Configuration](21-Logging-Guide.md)
- [Reporting & Analytics](23-Reporting-Analytics.md)
- [Incident Response](27-Incident-Response.md)

---

**© 2025 ZehraSec. All rights reserved.**
