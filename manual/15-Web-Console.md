# ZehraSec Advanced Firewall - Web Console Guide

![Web Console](https://img.shields.io/badge/🌐-Web%20Console-green?style=for-the-badge)

**Version 1.0** | **ZehraSec Advanced Firewall v2.0+**

---

## 🌐 **Web Console Overview**

The ZehraSec Web Console provides a comprehensive, intuitive interface for managing your advanced firewall system. Built with modern web technologies, it offers real-time monitoring, configuration management, and detailed analytics.

### **Key Features**
- **Real-time Dashboard** with live threat monitoring
- **Interactive Configuration** with drag-and-drop rule builder
- **Advanced Analytics** with customizable charts and reports
- **Multi-language Support** (English, Spanish, French, German, etc.)
- **Mobile-responsive Design** for tablet and smartphone access
- **Dark/Light Theme** with customizable interface
- **Role-based Access Control** for team environments

---

## 🚀 **Accessing the Web Console**

### **Default Access**
```
URL: https://localhost:8080
Default Username: admin
Default Password: admin123
```

⚠️ **Security Warning**: Change default credentials immediately after first login!

### **Network Access**
```bash
# Local access only (default)
https://localhost:8080

# LAN access
https://YOUR_SERVER_IP:8080

# Custom domain (if configured)
https://firewall.yourdomain.com
```

### **SSL Certificate Setup**
```bash
# Generate self-signed certificate (development)
python web-console/generate_cert.py

# Use Let's Encrypt (production)
python web-console/setup_letsencrypt.py --domain yourdomain.com

# Import custom certificate
python web-console/import_cert.py --cert /path/to/cert.pem --key /path/to/key.pem
```

---

## 🎯 **Dashboard Overview**

### **Main Dashboard Components**

#### **1. System Status Panel**
- **Service Status**: All core services (Engine, AI, Intelligence, etc.)
- **System Health**: CPU, Memory, Disk, Network utilization
- **Uptime**: System and service uptime statistics
- **License**: Current license status and expiration

#### **2. Real-time Threat Monitor**
```
┌─────────────────────────────────────────────────────────┐
│ 🚨 LIVE THREAT MONITOR                                 │
├─────────────────────────────────────────────────────────┤
│ Active Threats: 23        Blocked Today: 1,247         │
│ High Risk IPs: 5          Quarantined: 89              │
│ ML Detections: 156        Zero-day Blocks: 3           │
└─────────────────────────────────────────────────────────┘
```

#### **3. Network Traffic Visualization**
- **Real-time Flow Diagram**: Interactive network topology
- **Bandwidth Monitor**: Upload/download graphs
- **Connection Map**: Geographic threat origin mapping
- **Protocol Analysis**: Traffic breakdown by protocol

#### **4. Quick Action Buttons**
- **Emergency Block**: Instantly block suspicious IPs
- **Policy Override**: Temporary rule modifications
- **System Maintenance**: Quick access to maintenance tools
- **Report Generator**: One-click security reports

---

## ⚙️ **Configuration Management**

### **Firewall Rules Management**

#### **Rule Builder Interface**
```
┌─────────────────────────────────────────────────────────┐
│ 🔧 RULE BUILDER                                        │
├─────────────────────────────────────────────────────────┤
│ Source: [Any ▼] [192.168.1.0/24]                      │
│ Destination: [Any ▼] [10.0.0.0/8]                     │
│ Protocol: [TCP ▼] Port: [80,443]                       │
│ Action: [Allow ▼] [Block] [Quarantine]                 │
│ Schedule: [Always ▼] [Business Hours]                  │
│ Priority: [Medium ▼] [High] [Low]                      │
│ [+ Add Condition] [Save Rule] [Test Rule]              │
└─────────────────────────────────────────────────────────┘
```

#### **Drag-and-Drop Rule Ordering**
- Visual rule priority management
- Real-time rule validation
- Conflict detection and resolution
- Rule group organization

#### **Advanced Rule Templates**
```json
{
  "templates": [
    {
      "name": "Block Malicious Countries",
      "description": "Block traffic from high-risk countries",
      "rules": [
        {
          "source_country": ["CN", "RU", "KP"],
          "action": "block",
          "log": true
        }
      ]
    },
    {
      "name": "Allow VPN Access",
      "description": "Allow VPN connections from trusted sources",
      "rules": [
        {
          "protocol": "udp",
          "port": 1194,
          "source": "trusted_vpn_range",
          "action": "allow"
        }
      ]
    }
  ]
}
```

### **AI & Machine Learning Configuration**

#### **ML Model Management**
```
┌─────────────────────────────────────────────────────────┐
│ 🤖 AI/ML CONFIGURATION                                 │
├─────────────────────────────────────────────────────────┤
│ Threat Detection Model: [Active ✓] [Accuracy: 94.7%]   │
│ Anomaly Detection: [Enabled ✓] [Sensitivity: Medium]   │
│ Behavioral Analysis: [Learning Mode] [Training: 72%]   │
│ Model Updates: [Auto ✓] [Last Update: 2h ago]         │
│                                                         │
│ [Retrain Models] [Export Model] [Import Model]         │
└─────────────────────────────────────────────────────────┘
```

#### **Training Data Management**
- Upload custom datasets
- Review and approve training samples
- Model performance metrics
- A/B testing for model improvements

---

## 📊 **Monitoring & Analytics**

### **Real-time Monitoring**

#### **Live Traffic Analysis**
```javascript
// Real-time WebSocket connection for live data
const ws = new WebSocket('wss://localhost:8080/api/ws/live-traffic');
ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    updateTrafficChart(data);
    updateThreatMap(data.threats);
    updateStatistics(data.stats);
};
```

#### **Customizable Dashboards**
- **Widget Library**: 50+ pre-built monitoring widgets
- **Custom Layouts**: Drag-and-drop dashboard designer
- **Data Sources**: Multiple data source integration
- **Export Options**: PDF, PNG, CSV export capabilities

### **Historical Analytics**

#### **Trend Analysis**
```
Time Range: [Last 24h ▼] [Custom Range]

┌─────────────────────────────────────────────────────────┐
│ 📈 THREAT TRENDS                                       │
├─────────────────────────────────────────────────────────┤
│     Threats                                             │
│ 500 ┼─╮                                                │
│ 400 ┤ ╰─╮                                              │
│ 300 ┤   ╰──╮                                           │
│ 200 ┤      ╰─╮                                         │
│ 100 ┤        ╰──────────────────                       │
│   0 └┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─│
│     00 02 04 06 08 10 12 14 16 18 20 22 24            │
└─────────────────────────────────────────────────────────┘
```

#### **Advanced Filtering**
- Multi-dimensional data filtering
- Custom query builder
- Saved filter presets
- Scheduled report generation

---

## 🔐 **Security & User Management**

### **User Account Management**

#### **Role-based Access Control**
```
┌─────────────────────────────────────────────────────────┐
│ 👥 USER MANAGEMENT                                     │
├─────────────────────────────────────────────────────────┤
│ User: john.admin@company.com                           │
│ Role: [Administrator ▼]                                │
│ Permissions:                                           │
│   [✓] View Dashboard      [✓] Modify Rules             │
│   [✓] View Reports        [✓] System Configuration     │
│   [✓] User Management     [✗] Emergency Override       │
│                                                         │
│ [Save Changes] [Reset Password] [Disable Account]      │
└─────────────────────────────────────────────────────────┘
```

#### **Available Roles**
- **Super Administrator**: Full system access
- **Administrator**: Standard admin functions
- **Security Analyst**: Monitoring and analysis
- **Operator**: Day-to-day operations
- **Viewer**: Read-only access
- **Custom Roles**: Define custom permission sets

### **Authentication Methods**

#### **Multi-factor Authentication (MFA)**
```bash
# Enable MFA for user
curl -X POST https://localhost:8080/api/users/mfa/enable \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"method": "totp", "backup_codes": true}'

# Supported MFA methods:
# - TOTP (Google Authenticator, Authy)
# - SMS verification
# - Email verification
# - Hardware keys (FIDO2/WebAuthn)
```

#### **Single Sign-On (SSO) Integration**
- **SAML 2.0** integration
- **OAuth 2.0/OpenID Connect** support
- **Active Directory/LDAP** authentication
- **Azure AD** integration
- **Google Workspace** integration

---

## 🛠️ **Advanced Features**

### **API Integration Panel**

#### **API Key Management**
```
┌─────────────────────────────────────────────────────────┐
│ 🔑 API KEYS                                            │
├─────────────────────────────────────────────────────────┤
│ Key Name: Mobile App Integration                       │
│ Key: zs_live_1234567890abcdef...                       │
│ Permissions: [Read ✓] [Write ✓] [Delete ✗]            │
│ Rate Limit: 1000 req/min                               │
│ Expires: 2024-12-31                                    │
│                                                         │
│ [Generate New Key] [Revoke] [Edit Permissions]         │
└─────────────────────────────────────────────────────────┘
```

#### **Webhook Configuration**
```json
{
  "webhooks": [
    {
      "name": "Slack Notifications",
      "url": "https://hooks.slack.com/services/...",
      "events": ["threat_detected", "system_alert"],
      "enabled": true,
      "secret": "your_webhook_secret"
    },
    {
      "name": "SIEM Integration",
      "url": "https://your-siem.com/api/events",
      "events": ["all"],
      "enabled": true,
      "headers": {
        "Authorization": "Bearer token"
      }
    }
  ]
}
```

### **Custom Plugin Management**

#### **Plugin Store**
```
┌─────────────────────────────────────────────────────────┐
│ 🔌 PLUGIN STORE                                        │
├─────────────────────────────────────────────────────────┤
│ [🎯] Threat Intelligence Pro     [Install] [★★★★★]     │
│      Enhanced threat feeds with 50+ sources            │
│                                                         │
│ [📊] Advanced Analytics          [Installed] [★★★★☆]   │
│      Custom dashboards and reporting                   │
│                                                         │
│ [🔍] Deep Packet Inspector       [Install] [★★★★★]     │
│      Advanced protocol analysis                        │
│                                                         │
│ [Upload Custom Plugin] [Developer Console]             │
└─────────────────────────────────────────────────────────┘
```

---

## 📱 **Mobile Web Interface**

### **Responsive Design**
The web console automatically adapts to mobile devices with:
- **Touch-optimized Controls**: Large buttons and swipe gestures
- **Simplified Navigation**: Collapsible menu system
- **Essential Widgets**: Critical information prioritized
- **Offline Mode**: Basic functionality when disconnected

### **Mobile-specific Features**
```javascript
// Mobile notification support
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js');
  
  // Push notification setup
  Notification.requestPermission().then(function(permission) {
    if (permission === 'granted') {
      subscribeToAlerts();
    }
  });
}
```

---

## 🔧 **Customization Options**

### **Theme Customization**
```css
/* Custom CSS for corporate branding */
:root {
  --primary-color: #1e3a5f;
  --secondary-color: #4a90a4;
  --accent-color: #87ceeb;
  --background-color: #f5f5f5;
  --text-color: #333333;
}

.logo {
  content: url('/assets/company-logo.png');
}
```

### **White-label Configuration**
```json
{
  "branding": {
    "company_name": "Your Company Name",
    "logo_url": "/assets/custom-logo.png",
    "favicon_url": "/assets/favicon.ico",
    "primary_color": "#1e3a5f",
    "login_background": "/assets/login-bg.jpg",
    "custom_css": "/assets/custom.css"
  }
}
```

---

## 🚨 **Troubleshooting Web Console Issues**

### **Common Issues**

#### **1. Cannot Access Web Console**
```bash
# Check if service is running
systemctl status zehrasec-firewall

# Check port availability
netstat -tulpn | grep :8080

# Test connectivity
curl -k https://localhost:8080/api/health
```

#### **2. SSL Certificate Errors**
```bash
# Regenerate self-signed certificate
python web-console/generate_cert.py --force

# Check certificate validity
openssl x509 -in /opt/zehrasec/ssl/cert.pem -text -noout
```

#### **3. Performance Issues**
```bash
# Check system resources
top -p $(pgrep -f "web-console")

# Monitor web console logs
tail -f /var/log/zehrasec/web-console.log

# Enable debug mode
export ZEHRASEC_DEBUG=1
systemctl restart zehrasec-firewall
```

### **Browser Compatibility**
| Browser | Version | Support Level |
|---------|---------|---------------|
| **Chrome** | 90+ | ✅ Full Support |
| **Firefox** | 88+ | ✅ Full Support |
| **Safari** | 14+ | ✅ Full Support |
| **Edge** | 90+ | ✅ Full Support |
| **Mobile Safari** | 14+ | ✅ Mobile Optimized |
| **Chrome Mobile** | 90+ | ✅ Mobile Optimized |

---

## 🔄 **Web Console API Reference**

### **Authentication Endpoints**
```bash
# Login
POST /api/auth/login
{
  "username": "admin",
  "password": "password",
  "mfa_code": "123456"
}

# Refresh token
POST /api/auth/refresh
{
  "refresh_token": "your_refresh_token"
}

# Logout
POST /api/auth/logout
```

### **Real-time Data Endpoints**
```bash
# WebSocket connection for live data
WSS /api/ws/live-traffic
WSS /api/ws/system-stats
WSS /api/ws/threat-alerts

# REST endpoints for current status
GET /api/status/system
GET /api/status/threats
GET /api/status/network
```

---

## 📋 **Web Console Checklist**

### **Initial Setup**
- [ ] Change default admin password
- [ ] Configure SSL certificate
- [ ] Set up user accounts and roles
- [ ] Customize dashboard widgets
- [ ] Configure notification settings
- [ ] Test mobile access
- [ ] Set up backup authentication

### **Security Hardening**
- [ ] Enable MFA for all admin accounts
- [ ] Configure session timeout
- [ ] Set up IP whitelist for admin access
- [ ] Enable audit logging
- [ ] Configure HTTPS-only access
- [ ] Set up fail2ban for brute force protection

### **Performance Optimization**
- [ ] Enable gzip compression
- [ ] Configure caching headers
- [ ] Optimize database queries
- [ ] Set up CDN for static assets
- [ ] Monitor resource usage
- [ ] Configure load balancing (if needed)

---

## 📞 **Web Console Support**

For web console specific issues:

- **General Support**: webconsole-support@zehrasec.com
- **API Documentation**: [API Guide](07-API-Documentation.md)
- **Custom Development**: developers@zehrasec.com
- **Enterprise Features**: enterprise@zehrasec.com

---

**© 2024 ZehraSec. All rights reserved.**

*Web console features may vary by license level. Contact sales for enterprise feature information.*
