# 05-Web-Console-Guide.md - ZehraSec Advanced Firewall

![Web Console](https://img.shields.io/badge/🌐-Web%20Console%20Guide-blue?style=for-the-badge&logo=web)

**Version 3.0.0** | **Updated: June 19, 2025** | **Copyright © 2025 ZehraSec - Yashab Alam**

---

## 🌐 **Overview**

The ZehraSec Web Console is a comprehensive, responsive web interface that provides complete control and monitoring of your firewall system. This guide covers all features, functionality, and best practices for using the web console effectively.

---

## 🚀 **Accessing the Web Console**

### 🔗 **Connection Details**
- **Default URL**: `https://localhost:8443`
- **Alternative URLs**: 
  - `https://[firewall-ip]:8443`
  - `https://zehrasec.local:8443`
- **Default Credentials**: 
  - Username: `admin`
  - Password: `zehrasec123` (change immediately)

### 🔐 **Login Process**

#### **1. Initial Login**
```
┌─────────────────────────────────────┐
│         ZehraSec Firewall           │
│       Advanced Web Console          │
├─────────────────────────────────────┤
│ Username: [________________]        │
│ Password: [________________]        │
│ [x] Remember me                     │
│ [ ] Use 2FA Token                   │
├─────────────────────────────────────┤
│           [LOGIN]                   │
│      [Forgot Password?]             │
└─────────────────────────────────────┘
```

#### **2. First-Time Setup**
- Change default password
- Configure 2FA (recommended)
- Set security questions
- Configure notification preferences

---

## 🎛️ **Dashboard Overview**

### 📊 **Main Dashboard**

#### **Header Section**
```
┌─ ZehraSec 🛡️ ─── Status: ACTIVE ─── User: admin ───────┐
│ [🏠 Dashboard] [⚙️ Config] [🔍 Monitor] [📊 Reports] [❓ Help] │
└────────────────────────────────────────────────────────────┘
```

#### **Status Cards**
```
┌─────────────┬─────────────┬─────────────┬─────────────┐
│  🛡️ Status   │  📊 Traffic  │  🚨 Threats  │  📈 CPU     │
│   ACTIVE    │   2.5 Gbps  │   127 Block │   15%      │
│   ✅ OK      │   ↗️ +12%    │   🔴 3 High  │   🟢 Normal │
└─────────────┴─────────────┴─────────────┴─────────────┘
```

### 🗺️ **Navigation Menu**

#### **Main Sections**
1. **🏠 Dashboard** - System overview and quick stats
2. **🛡️ Security** - Threat detection and response
3. **⚙️ Configuration** - System and policy settings
4. **🔍 Monitoring** - Real-time traffic and logs
5. **📊 Reports** - Analytics and compliance reports
6. **👥 Users** - User and access management
7. **🔧 Tools** - Diagnostic and maintenance tools
8. **❓ Help** - Documentation and support

---

## 🛡️ **Security Dashboard**

### 🚨 **Threat Overview**

#### **Real-Time Threat Map**
```html
<div class="threat-map">
  <div class="world-map">
    <!-- Interactive SVG world map -->
    <circle cx="100" cy="50" r="5" class="threat-high"/>
    <circle cx="200" cy="80" r="3" class="threat-medium"/>
  </div>
  <div class="threat-legend">
    🔴 High Severity: 15 threats
    🟡 Medium Severity: 43 threats
    🟢 Low Severity: 128 threats
  </div>
</div>
```

#### **Threat Timeline**
```
┌─ Last 24 Hours ─────────────────────────────────────────┐
│ 00:00 ████████████████████████████████████████████ 247 │
│ 04:00 ██████████████████████████████████████ 198      │
│ 08:00 ████████████████████████████████████████████ 267 │
│ 12:00 ██████████████████████████████████████████ 234   │
│ 16:00 ████████████████████████████████████████████ 245 │
│ 20:00 ██████████████████████████████████████████ 221   │
└─────────────────────────────────────────────────────────┘
```

### 🎯 **Active Threats Panel**

#### **High Priority Threats**
```
┌─ Active Threats (High Priority) ───────────────────────┐
│ 🔴 DDoS Attack Detected                               │
│    Source: 192.168.1.100 → Target: Web Server        │
│    Started: 14:32:15  Duration: 00:45:32             │
│    [Block] [Investigate] [Add to Whitelist]          │
├───────────────────────────────────────────────────────┤
│ 🔴 Malware Communication                             │
│    Host: DESKTOP-123 → C2: malicious-domain.com      │
│    Protocol: HTTPS  Port: 443                        │
│    [Quarantine] [Block Domain] [Investigate]         │
└───────────────────────────────────────────────────────┘
```

#### **Threat Actions**
- **🚫 Block**: Immediately block the threat
- **🔍 Investigate**: Open detailed investigation panel
- **⚡ Auto-Response**: Trigger automated response
- **📝 Create Ticket**: Generate incident ticket
- **📧 Alert Team**: Send notification to security team

---

## 📊 **Traffic Monitoring**

### 🌊 **Real-Time Traffic**

#### **Bandwidth Usage**
```
┌─ Network Traffic (Real-Time) ──────────────────────────┐
│                                                        │
│ Inbound  ████████████████████████████ 850 Mbps       │
│          ████████████████████████████████████████████ │
│                                                        │
│ Outbound ██████████████████████ 420 Mbps             │
│          ████████████████████████████████████████████ │
│                                                        │
│ Internal ████████████████ 320 Mbps                   │
│          ████████████████████████████████████████████ │
└────────────────────────────────────────────────────────┘
```

#### **Protocol Distribution**
```html
<div class="protocol-pie-chart">
  <canvas id="protocolChart" width="300" height="300"></canvas>
  <div class="protocol-legend">
    <div>🟦 HTTP/HTTPS: 65%</div>
    <div>🟨 Email (SMTP/POP3): 15%</div>
    <div>🟩 File Transfer: 10%</div>
    <div>🟪 Database: 7%</div>
    <div>🟫 Other: 3%</div>
  </div>
</div>
```

### 🔍 **Traffic Analysis**

#### **Top Talkers**
```
┌─ Top Talkers (Last Hour) ──────────────────────────────┐
│ Rank │ IP Address      │ Bytes      │ Sessions │ Risk  │
├──────┼─────────────────┼────────────┼──────────┼───────┤
│  1   │ 192.168.1.100   │ 2.3 GB     │   1,247  │ 🟢 Low │
│  2   │ 10.0.0.50       │ 1.8 GB     │     892  │ 🟢 Low │
│  3   │ 172.16.0.25     │ 1.2 GB     │     634  │ 🟡 Med │
│  4   │ 192.168.2.200   │ 987 MB     │     445  │ 🔴 High│
│  5   │ 10.0.1.15       │ 756 MB     │     321  │ 🟢 Low │
└──────┴─────────────────┴────────────┴──────────┴───────┘
```

#### **Session Details**
```javascript
// Session drill-down functionality
function showSessionDetails(sessionId) {
  return {
    sessionId: sessionId,
    startTime: "2025-06-19 14:32:15",
    duration: "00:15:32",
    source: "192.168.1.100:45123",
    destination: "173.194.74.139:443",
    protocol: "HTTPS",
    bytesIn: "2.3 MB",
    bytesOut: "156 KB",
    packetsIn: 1847,
    packetsOut: 234,
    application: "Google Chrome",
    riskScore: 15,
    flags: ["SSL_ENCRYPTED", "LEGITIMATE_TRAFFIC"]
  };
}
```

---

## ⚙️ **Configuration Management**

### 🔧 **Firewall Rules**

#### **Rule Management Interface**
```
┌─ Firewall Rules ───────────────────────────────────────┐
│ [+ Add Rule] [📄 Import] [💾 Export] [🔄 Reload]       │
├───────────────────────────────────────────────────────┤
│ ☑️ │ # │ Name          │ Action │ Source      │ Dest   │
├───┼───┼───────────────┼────────┼─────────────┼────────┤
│ ✅ │ 1 │ Allow HTTP    │ ALLOW  │ Any         │ :80    │
│ ✅ │ 2 │ Allow HTTPS   │ ALLOW  │ Any         │ :443   │
│ ✅ │ 3 │ Block Malware │ BLOCK  │ Bad_IPs     │ Any    │
│ ❌ │ 4 │ Test Rule     │ LOG    │ 192.168.1.0 │ Any    │
├───┼───┼───────────────┼────────┼─────────────┼────────┤
│ [Edit] [Delete] [Duplicate] [Move Up] [Move Down]     │
└───────────────────────────────────────────────────────┘
```

#### **Rule Editor**
```html
<form class="rule-editor">
  <div class="rule-basic">
    <label>Rule Name:</label>
    <input type="text" value="Allow Web Traffic"/>
    
    <label>Action:</label>
    <select>
      <option>ALLOW</option>
      <option>BLOCK</option>
      <option>LOG</option>
      <option>QUARANTINE</option>
    </select>
  </div>
  
  <div class="rule-conditions">
    <h3>Conditions</h3>
    <div class="condition-group">
      <label>Source:</label>
      <input type="text" placeholder="Any, IP, Range, or Group"/>
      
      <label>Destination:</label>
      <input type="text" placeholder="Any, IP, Range, or Group"/>
      
      <label>Port/Service:</label>
      <input type="text" placeholder="80, 443, HTTP, HTTPS"/>
      
      <label>Protocol:</label>
      <select>
        <option>Any</option>
        <option>TCP</option>
        <option>UDP</option>
        <option>ICMP</option>
      </select>
    </div>
  </div>
  
  <div class="rule-advanced">
    <h3>Advanced Options</h3>
    <label><input type="checkbox"/> Enable logging</label>
    <label><input type="checkbox"/> Apply to encrypted traffic</label>
    <label><input type="checkbox"/> Rate limiting</label>
    <label><input type="checkbox"/> Geo-blocking</label>
  </div>
  
  <div class="rule-actions">
    <button type="submit">Save Rule</button>
    <button type="button">Test Rule</button>
    <button type="button">Cancel</button>
  </div>
</form>
```

### 🎛️ **System Configuration**

#### **Network Settings**
```html
<div class="network-config">
  <section>
    <h3>Interface Configuration</h3>
    <div class="interface-list">
      <div class="interface">
        <h4>eth0 (External)</h4>
        <label>IP Address:</label>
        <input type="text" value="192.168.1.100"/>
        <label>Subnet Mask:</label>
        <input type="text" value="255.255.255.0"/>
        <label>Gateway:</label>
        <input type="text" value="192.168.1.1"/>
        <label><input type="checkbox" checked/> Monitor Mode</label>
      </div>
    </div>
  </section>
  
  <section>
    <h3>DNS Configuration</h3>
    <label>Primary DNS:</label>
    <input type="text" value="8.8.8.8"/>
    <label>Secondary DNS:</label>
    <input type="text" value="8.8.4.4"/>
    <label><input type="checkbox"/> Enable DNS filtering</label>
    <label><input type="checkbox"/> Block malicious domains</label>
  </section>
</div>
```

---

## 🤖 **AI/ML Management**

### 🧠 **Model Status**

#### **Active Models Dashboard**
```
┌─ AI/ML Models Status ──────────────────────────────────┐
│ Model Name             │ Status  │ Accuracy │ Updated │
├────────────────────────┼─────────┼──────────┼─────────┤
│ Threat Detection v3.2  │ ✅ Active│   97.3%  │ 2h ago  │
│ Behavior Analysis v2.1 │ ✅ Active│   94.8%  │ 6h ago  │
│ Anomaly Detection v1.8 │ 🟡 Train │   91.2%  │ 1d ago  │
│ Malware Classification │ ✅ Active│   98.7%  │ 4h ago  │
│ Traffic Prediction     │ ✅ Active│   89.4%  │ 8h ago  │
└────────────────────────┴─────────┴──────────┴─────────┘
```

#### **Model Training Console**
```html
<div class="ml-training">
  <h3>Model Training</h3>
  <div class="training-progress">
    <h4>Threat Detection Model - Training in Progress</h4>
    <div class="progress-bar">
      <div class="progress" style="width: 65%">65%</div>
    </div>
    <div class="training-stats">
      <span>Samples Processed: 125,847 / 200,000</span>
      <span>Current Accuracy: 96.2%</span>
      <span>ETA: 2h 15m</span>
    </div>
    <button class="btn-stop">Stop Training</button>
  </div>
  
  <div class="training-history">
    <h4>Training History</h4>
    <canvas id="trainingChart" width="600" height="300"></canvas>
  </div>
</div>
```

### 🎯 **Threat Intelligence**

#### **Intelligence Feeds**
```
┌─ Threat Intelligence Feeds ───────────────────────────┐
│ Feed Name          │ Status │ Last Update │ Indicators │
├────────────────────┼────────┼─────────────┼────────────┤
│ ZehraSec Intel     │ ✅ OK   │ 5m ago      │   847,293  │
│ AlienVault OTX     │ ✅ OK   │ 15m ago     │   234,567  │
│ Emerging Threats   │ ✅ OK   │ 23m ago     │   156,789  │
│ Microsoft Security │ 🟡 Slow │ 2h ago      │   89,432   │
│ Custom Feed #1     │ ❌ Down │ 6h ago      │   12,345   │
└────────────────────┴────────┴─────────────┴────────────┘
[🔄 Refresh All] [➕ Add Feed] [⚙️ Configure]
```

---

## 📊 **Reports and Analytics**

### 📈 **Executive Dashboard**

#### **Key Performance Indicators**
```html
<div class="kpi-dashboard">
  <div class="kpi-card">
    <h3>Security Effectiveness</h3>
    <div class="kpi-value">99.7%</div>
    <div class="kpi-trend">↗️ +0.3%</div>
  </div>
  
  <div class="kpi-card">
    <h3>Threats Blocked</h3>
    <div class="kpi-value">15,247</div>
    <div class="kpi-trend">↗️ +12%</div>
  </div>
  
  <div class="kpi-card">
    <h3>System Uptime</h3>
    <div class="kpi-value">99.99%</div>
    <div class="kpi-trend">➡️ Stable</div>
  </div>
  
  <div class="kpi-card">
    <h3>Performance Score</h3>
    <div class="kpi-value">94/100</div>
    <div class="kpi-trend">↗️ +2</div>
  </div>
</div>
```

### 📋 **Report Generator**

#### **Custom Report Builder**
```html
<form class="report-builder">
  <div class="report-config">
    <h3>Report Configuration</h3>
    
    <label>Report Type:</label>
    <select name="reportType">
      <option>Security Summary</option>
      <option>Traffic Analysis</option>
      <option>Compliance Report</option>
      <option>Performance Report</option>
      <option>Custom Report</option>
    </select>
    
    <label>Time Period:</label>
    <select name="timePeriod">
      <option>Last 24 Hours</option>
      <option>Last 7 Days</option>
      <option>Last 30 Days</option>
      <option>Custom Range</option>
    </select>
    
    <label>Format:</label>
    <div class="format-options">
      <label><input type="radio" name="format" value="pdf"/> PDF</label>
      <label><input type="radio" name="format" value="excel"/> Excel</label>
      <label><input type="radio" name="format" value="html"/> HTML</label>
      <label><input type="radio" name="format" value="json"/> JSON</label>
    </div>
  </div>
  
  <div class="report-sections">
    <h3>Include Sections</h3>
    <label><input type="checkbox" checked/> Executive Summary</label>
    <label><input type="checkbox" checked/> Threat Analysis</label>
    <label><input type="checkbox" checked/> Traffic Statistics</label>
    <label><input type="checkbox"/> Performance Metrics</label>
    <label><input type="checkbox"/> Compliance Status</label>
    <label><input type="checkbox"/> Recommendations</label>
  </div>
  
  <div class="report-actions">
    <button type="submit">Generate Report</button>
    <button type="button">Schedule Report</button>
    <button type="button">Save Template</button>
  </div>
</form>
```

---

## 👥 **User Management**

### 🔐 **User Administration**

#### **User List**
```
┌─ User Management ──────────────────────────────────────┐
│ [➕ Add User] [📥 Import] [📤 Export] [🔄 Sync AD]     │
├───────────────────────────────────────────────────────┤
│ Username    │ Role       │ Last Login │ Status │ 2FA  │
├─────────────┼────────────┼────────────┼────────┼──────┤
│ admin       │ Super Admin│ 5m ago     │ ✅ Act  │ ✅ On │
│ security01  │ Security   │ 2h ago     │ ✅ Act  │ ✅ On │
│ operator01  │ Operator   │ 1d ago     │ ✅ Act  │ ❌ Off│
│ viewer01    │ Read-Only  │ 3d ago     │ 🟡 Idle │ ✅ On │
│ temp_user   │ Temp Access│ Never      │ ❌ Dis  │ ❌ Off│
└─────────────┴────────────┴────────────┴────────┴──────┘
```

#### **Role-Based Access Control**
```json
{
  "roles": {
    "super_admin": {
      "permissions": ["*"],
      "description": "Full system access"
    },
    "security_analyst": {
      "permissions": [
        "view_threats",
        "manage_rules",
        "generate_reports",
        "respond_incidents"
      ],
      "restrictions": ["no_system_config"]
    },
    "operator": {
      "permissions": [
        "view_dashboard",
        "view_logs",
        "basic_config"
      ],
      "restrictions": ["no_user_management", "no_system_config"]
    },
    "read_only": {
      "permissions": [
        "view_dashboard",
        "view_reports"
      ],
      "restrictions": ["no_config_changes"]
    }
  }
}
```

---

## 🔧 **Tools and Utilities**

### 🔍 **Diagnostic Tools**

#### **Network Diagnostics**
```html
<div class="diagnostic-tools">
  <div class="tool-section">
    <h3>Network Connectivity</h3>
    <div class="tool-grid">
      <button onclick="runPing()">🏓 Ping Test</button>
      <button onclick="runTraceroute()">🛤️ Traceroute</button>
      <button onclick="runPortScan()">🔍 Port Scan</button>
      <button onclick="runBandwidthTest()">📊 Bandwidth Test</button>
    </div>
  </div>
  
  <div class="tool-output">
    <h4>Tool Output</h4>
    <pre id="toolOutput" class="console-output">
Ready to run diagnostic tools...
    </pre>
  </div>
</div>
```

#### **System Health Check**
```javascript
function runSystemHealthCheck() {
  const healthChecks = [
    { name: "CPU Usage", status: "OK", value: "15%" },
    { name: "Memory Usage", status: "OK", value: "68%" },
    { name: "Disk Space", status: "WARNING", value: "85%" },
    { name: "Network Interfaces", status: "OK", value: "All Up" },
    { name: "Service Status", status: "OK", value: "All Running" },
    { name: "Database", status: "OK", value: "Connected" },
    { name: "Log Rotation", status: "OK", value: "Working" }
  ];
  
  return healthChecks;
}
```

### 📝 **Log Viewer**

#### **Real-Time Log Stream**
```html
<div class="log-viewer">
  <div class="log-controls">
    <select id="logLevel">
      <option>All Levels</option>
      <option>ERROR</option>
      <option>WARN</option>
      <option>INFO</option>
      <option>DEBUG</option>
    </select>
    
    <input type="text" id="logFilter" placeholder="Filter logs..."/>
    
    <button onclick="pauseLogs()">⏸️ Pause</button>
    <button onclick="clearLogs()">🗑️ Clear</button>
    <button onclick="exportLogs()">📤 Export</button>
  </div>
  
  <div class="log-content">
    <pre id="logStream" class="log-stream">
2025-06-19 14:32:15 [INFO] Firewall started successfully
2025-06-19 14:32:16 [INFO] Loading threat intelligence feeds
2025-06-19 14:32:17 [WARN] High CPU usage detected: 85%
2025-06-19 14:32:18 [ERROR] Failed to connect to threat feed: timeout
2025-06-19 14:32:19 [INFO] Connection restored to threat feed
    </pre>
  </div>
</div>
```

---

## 📱 **Mobile Responsiveness**

### 📲 **Mobile Interface**

#### **Responsive Design**
```css
/* Mobile-first responsive design */
@media (max-width: 768px) {
  .dashboard-grid {
    grid-template-columns: 1fr;
  }
  
  .navigation {
    transform: translateX(-100%);
    transition: transform 0.3s ease;
  }
  
  .navigation.open {
    transform: translateX(0);
  }
  
  .status-cards {
    flex-direction: column;
  }
  
  .threat-map {
    height: 200px;
  }
}
```

#### **Touch-Optimized Controls**
```html
<div class="mobile-controls">
  <button class="mobile-menu-btn" onclick="toggleMobileMenu()">
    ☰ Menu
  </button>
  
  <div class="quick-actions">
    <button class="quick-action" onclick="blockThreat()">
      🚫 Block
    </button>
    <button class="quick-action" onclick="viewAlerts()">
      🚨 Alerts
    </button>
    <button class="quick-action" onclick="systemStatus()">
      ⚡ Status
    </button>
  </div>
</div>
```

---

## ⚙️ **Customization Options**

### 🎨 **Theme and Layout**

#### **Theme Selection**
```html
<div class="theme-settings">
  <h3>Appearance Settings</h3>
  
  <div class="theme-options">
    <label>
      <input type="radio" name="theme" value="dark"/>
      🌙 Dark Theme
    </label>
    <label>
      <input type="radio" name="theme" value="light" checked/>
      ☀️ Light Theme
    </label>
    <label>
      <input type="radio" name="theme" value="auto"/>
      🔄 Auto (System)
    </label>
  </div>
  
  <div class="layout-options">
    <h4>Dashboard Layout</h4>
    <label>
      <input type="radio" name="layout" value="grid" checked/>
      📊 Grid Layout
    </label>
    <label>
      <input type="radio" name="layout" value="list"/>
      📋 List Layout
    </label>
    <label>
      <input type="radio" name="layout" value="compact"/>
      📱 Compact Layout
    </label>
  </div>
</div>
```

#### **Custom CSS Support**
```css
/* Custom CSS for branded interface */
:root {
  --primary-color: #007bff;
  --secondary-color: #6c757d;
  --success-color: #28a745;
  --warning-color: #ffc107;
  --danger-color: #dc3545;
  
  --company-logo: url('/assets/company-logo.png');
  --header-bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.header {
  background: var(--header-bg);
}

.logo::before {
  content: var(--company-logo);
}
```

---

## 🚨 **Emergency Access**

### 🆘 **Emergency Console**

#### **Emergency Access Mode**
```html
<div class="emergency-mode">
  <div class="emergency-banner">
    🚨 EMERGENCY ACCESS MODE ACTIVATED 🚨
  </div>
  
  <div class="emergency-controls">
    <button class="emergency-btn block-all">
      🚫 BLOCK ALL TRAFFIC
    </button>
    
    <button class="emergency-btn allow-all">
      ✅ ALLOW ALL TRAFFIC
    </button>
    
    <button class="emergency-btn quarantine">
      🏥 QUARANTINE MODE
    </button>
    
    <button class="emergency-btn safe-mode">
      🛡️ SAFE MODE
    </button>
  </div>
  
  <div class="emergency-status">
    <h3>Current Status</h3>
    <ul>
      <li>🔴 All external traffic blocked</li>
      <li>🟡 Internal traffic monitored</li>
      <li>🟢 Management access allowed</li>
      <li>📧 Security team notified</li>
    </ul>
  </div>
</div>
```

---

## 🔧 **Browser Compatibility**

### 🌐 **Supported Browsers**

#### **Compatibility Matrix**
```
┌─────────────────┬─────────┬─────────┬─────────┬─────────┐
│ Browser         │ Version │ Desktop │ Mobile  │ Status  │
├─────────────────┼─────────┼─────────┼─────────┼─────────┤
│ Chrome          │ 90+     │ ✅ Full  │ ✅ Full  │ ✅ Best  │
│ Firefox         │ 88+     │ ✅ Full  │ ✅ Full  │ ✅ Good  │
│ Safari          │ 14+     │ ✅ Full  │ ✅ Full  │ ✅ Good  │
│ Edge            │ 90+     │ ✅ Full  │ ✅ Full  │ ✅ Good  │
│ Opera           │ 76+     │ ✅ Full  │ ✅ Full  │ ✅ Good  │
│ IE 11           │ -       │ ❌ None  │ ❌ None  │ ❌ EOL   │
└─────────────────┴─────────┴─────────┴─────────┴─────────┘
```

#### **Feature Detection**
```javascript
// Feature detection and graceful degradation
function checkBrowserSupport() {
  const features = {
    webSocket: typeof WebSocket !== 'undefined',
    canvas: !!document.createElement('canvas').getContext,
    localStorage: typeof Storage !== 'undefined',
    flexbox: CSS.supports('display', 'flex'),
    grid: CSS.supports('display', 'grid')
  };
  
  return features;
}
```

---

## 📊 **Performance Optimization**

### ⚡ **Web Console Performance**

#### **Optimization Techniques**
```javascript
// Lazy loading for large datasets
function lazyLoadTable(tableId, pageSize = 100) {
  const table = document.getElementById(tableId);
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        loadNextPage(tableId, pageSize);
      }
    });
  });
  
  observer.observe(table.querySelector('.loading-trigger'));
}

// WebSocket for real-time updates
class RealTimeUpdater {
  constructor(endpoint) {
    this.ws = new WebSocket(endpoint);
    this.setupEventHandlers();
  }
  
  setupEventHandlers() {
    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.updateUI(data);
    };
  }
  
  updateUI(data) {
    // Efficient DOM updates
    requestAnimationFrame(() => {
      this.updateCounters(data.counters);
      this.updateCharts(data.charts);
      this.updateAlerts(data.alerts);
    });
  }
}
```

---

## 🆘 **Troubleshooting Web Console**

### ❌ **Common Issues**

#### **Cannot Access Web Console**
```bash
# Check service status
sudo systemctl status zehrasec-web

# Check port binding
sudo netstat -tlnp | grep 8443

# Check SSL certificate
openssl s_client -connect localhost:8443 -servername localhost

# Check firewall rules
sudo iptables -L | grep 8443
```

#### **Slow Performance**
```javascript
// Performance monitoring
function monitorPerformance() {
  // Monitor page load time
  const loadTime = performance.timing.loadEventEnd - 
                   performance.timing.navigationStart;
  
  // Monitor memory usage
  const memoryInfo = performance.memory;
  
  // Send metrics to monitoring system
  sendMetrics({
    loadTime: loadTime,
    memoryUsage: memoryInfo.usedJSHeapSize,
    timestamp: Date.now()
  });
}
```

#### **Authentication Issues**
```
Common Solutions:
1. Clear browser cache and cookies
2. Check system time synchronization
3. Verify SSL certificate validity
4. Reset user password via CLI
5. Check LDAP/AD connectivity (if configured)
```

---

## 📚 **Additional Resources**

### 📖 **Related Documentation**
- **[Configuration Guide](04-Configuration-Guide.md)** - Detailed configuration options
- **[API Documentation](07-API-Documentation.md)** - REST API reference
- **[Troubleshooting Guide](16-Troubleshooting-Guide.md)** - Common issues and solutions
- **[User Management](manual/user-management.md)** - User administration

### 🎓 **Training Materials**
- **Video Tutorials**: https://training.zehrasec.com/web-console
- **Interactive Demo**: https://demo.zehrasec.com
- **Certification Course**: https://certification.zehrasec.com

### 🆘 **Support**
- **Web Console Support**: webconsole@zehrasec.com
- **Technical Support**: support@zehrasec.com
- **Community Forum**: https://forum.zehrasec.com

---

**Copyright © 2025 ZehraSec - Yashab Alam**  
**All Rights Reserved**

---
