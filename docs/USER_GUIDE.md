# ZehraShield User Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [Web Dashboard](#web-dashboard)
3. [Security Layers](#security-layers)
4. [Device Management](#device-management)
5. [Incident Response](#incident-response)
6. [Reports and Analytics](#reports-and-analytics)
7. [Configuration](#configuration)
8. [Troubleshooting](#troubleshooting)

## Getting Started

### Accessing ZehraShield

1. **Web Interface**: Open your browser and navigate to `https://your-server-ip:8443`
2. **Default Credentials**: 
   - Username: `admin`
   - Password: `admin123` (change immediately after first login)
3. **First Login**: You'll be prompted to change the default password

### Dashboard Overview

The main dashboard provides:
- **Real-time Statistics**: Current threat level, blocked attacks, network activity
- **Security Status**: Status of all 6 security layers
- **Recent Events**: Latest security events and alerts
- **System Health**: Performance metrics and resource usage

## Web Dashboard

### Navigation

The dashboard is organized into several main sections:

#### Dashboard (Home)
- Real-time security overview
- Key performance indicators
- Quick action buttons
- System status widgets

#### Events
- View all security events
- Filter by severity, type, time range
- Export events for analysis
- Acknowledge events

#### Incidents
- Manage security incidents
- Create new incidents from events
- Track incident resolution
- View incident timeline

#### Devices
- Network device inventory
- Device authorization status
- Network scanning
- Device risk assessment

#### Logs
- System and security logs
- Real-time log monitoring
- Log search and filtering
- Log export capabilities

#### Reports
- Generate security reports
- Schedule automated reports
- Export in multiple formats
- Email report distribution

#### Configuration
- System settings
- Security layer configuration
- Performance tuning
- Alert settings

## Security Layers

ZehraShield implements a 6-layer security architecture:

### Layer 1: Packet Filtering
**Purpose**: Basic network packet inspection and filtering

**Features**:
- IP-based filtering
- Port-based rules
- Protocol filtering
- Geo-blocking capabilities

**Configuration**:
1. Navigate to Configuration → Security Layers → Layer 1
2. Enable/disable the layer
3. Set filtering mode (Monitor, Block, Strict)
4. Configure custom rules

### Layer 2: Application Gateway
**Purpose**: Deep packet inspection and application-level filtering

**Features**:
- HTTP/HTTPS inspection
- Application protocol analysis
- Content filtering
- Malware detection

**Configuration**:
1. Access Layer 2 settings in Configuration
2. Set detection sensitivity
3. Configure application rules
4. Enable/disable specific protocols

### Layer 3: Intrusion Detection/Prevention (IDS/IPS)
**Purpose**: Detect and prevent known attack patterns

**Features**:
- Signature-based detection
- Behavioral analysis
- Automatic rule updates
- Real-time blocking

**Configuration**:
1. Enable IDS/IPS in Layer 3 settings
2. Configure rule update frequency
3. Set detection thresholds
4. Manage custom rules

### Layer 4: Threat Intelligence
**Purpose**: Leverage external threat feeds for enhanced protection

**Features**:
- Multiple threat intelligence feeds
- IP reputation checking
- Domain blacklisting
- Automated feed updates

**Configuration**:
1. Configure threat intelligence feeds
2. Set update intervals
3. Manage feed priorities
4. Custom threat indicators

### Layer 5: Network Access Control (NAC)
**Purpose**: Control device access to the network

**Features**:
- Device discovery and profiling
- Authorization policies
- Quarantine capabilities
- Guest network management

**Configuration**:
1. Set device authorization policies
2. Configure auto-quarantine rules
3. Manage device classifications
4. Set access control policies

### Layer 6: SIEM Integration
**Purpose**: Centralized logging and correlation

**Features**:
- Log aggregation
- Event correlation
- External SIEM integration
- Compliance reporting

**Configuration**:
1. Configure SIEM endpoints
2. Set log export formats
3. Define correlation rules
4. Schedule compliance reports

## Device Management

### Device Discovery

ZehraShield automatically discovers network devices through:
- **Passive Discovery**: Monitor network traffic
- **Active Scanning**: Network scans for device identification
- **DHCP Monitoring**: Track DHCP assignments

### Device Authorization

1. **View Devices**: Navigate to Devices section
2. **Review New Devices**: Check unauthorized devices list
3. **Authorize Devices**: 
   - Select device
   - Click "Authorize"
   - Set device type and risk level
4. **Block Devices**: Use "Block" action for unauthorized devices

### Network Scanning

1. **Manual Scan**: 
   - Click "Network Scan" button
   - Enter IP range (e.g., 192.168.1.0/24)
   - Select scan type
   - Start scan
2. **Review Results**: Add discovered devices to inventory
3. **Schedule Scans**: Set up automated scanning

## Incident Response

### Creating Incidents

1. **From Events**:
   - View event details
   - Click "Create Incident"
   - Fill incident information
2. **Manual Creation**:
   - Navigate to Incidents
   - Click "New Incident"
   - Complete incident form

### Managing Incidents

1. **Assignment**: Assign incidents to team members
2. **Status Tracking**: Update incident status
3. **Documentation**: Add notes and evidence
4. **Resolution**: Mark incidents as resolved

### Incident Workflow

1. **Detection**: Event triggers incident creation
2. **Analysis**: Investigate incident details
3. **Containment**: Block threats and isolate systems
4. **Recovery**: Restore normal operations
5. **Lessons Learned**: Document findings and improvements

## Reports and Analytics

### Pre-built Reports

- **Security Summary**: Overall security posture
- **Incident Report**: Detailed incident analysis
- **Network Analysis**: Traffic patterns and anomalies
- **Performance Report**: System performance metrics

### Custom Reports

1. **Navigate to Reports**
2. **Click "Generate Report"**
3. **Configure Options**:
   - Report type
   - Time period
   - Include sections
   - Output format
4. **Generate and Download**

### Scheduled Reports

1. **Click "Schedule Report"**
2. **Set Parameters**:
   - Report name
   - Frequency (daily, weekly, monthly)
   - Recipients
   - Format
3. **Enable Schedule**

## Configuration

### General Settings

- **System Name**: Customize system identification
- **Administrator Email**: Primary contact
- **Timezone**: Set system timezone
- **Session Timeout**: Web session duration
- **Security Options**: SSL/TLS, MFA settings

### Performance Tuning

- **Memory Limits**: Adjust memory allocation
- **Thread Limits**: Configure concurrent processing
- **Cache Settings**: Optimize caching for performance
- **Processing Timeouts**: Set operation timeouts

### Alert Configuration

1. **Email Settings**:
   - SMTP server configuration
   - Authentication details
   - Test email functionality
2. **Alert Levels**:
   - Enable/disable severity levels
   - Configure notification recipients
   - Set alert thresholds

## Troubleshooting

### Common Issues

#### Cannot Access Web Interface
**Symptoms**: Browser cannot connect to dashboard
**Solutions**:
1. Check if ZehraShield service is running: `sudo systemctl status zehrashield`
2. Verify firewall allows port 8443: `sudo ufw status`
3. Check logs: `sudo journalctl -u zehrashield -f`

#### High CPU Usage
**Symptoms**: System performance degradation
**Solutions**:
1. Check Configuration → Performance settings
2. Reduce thread count if necessary
3. Review enabled security layers
4. Check for large log files

#### Missing Network Devices
**Symptoms**: Devices not appearing in inventory
**Solutions**:
1. Run manual network scan
2. Check network connectivity
3. Verify DHCP monitoring is enabled
4. Review device discovery settings

#### False Positives
**Symptoms**: Legitimate traffic being blocked
**Solutions**:
1. Review Layer 3 sensitivity settings
2. Add whitelist entries for trusted IPs
3. Adjust ML model thresholds
4. Create custom allow rules

### Log Analysis

1. **Access Logs**: Navigate to Logs section
2. **Filter Logs**: Use filters to narrow down issues
3. **Export Logs**: Download logs for external analysis
4. **Real-time Monitoring**: Enable auto-refresh for live monitoring

### Performance Monitoring

1. **Dashboard Metrics**: Monitor real-time statistics
2. **Resource Usage**: Check memory and CPU utilization
3. **Processing Times**: Review operation performance
4. **Network Throughput**: Monitor traffic handling

### Getting Support

1. **Documentation**: Check this guide and API reference
2. **Logs**: Collect relevant log files
3. **Error Reports**: Use built-in error reporting
4. **Contact Support**: Email support@zehrasec.com with:
   - System configuration
   - Error messages
   - Steps to reproduce issue
   - Log files (if applicable)

### Updates and Maintenance

1. **System Updates**: Regular OS and package updates
2. **Threat Intelligence**: Automatic feed updates
3. **Rule Updates**: IDS/IPS signature updates
4. **Backup Configuration**: Regular config backups
5. **Log Rotation**: Automated log management

## Best Practices

### Security
- Change default passwords immediately
- Enable MFA for all users
- Regularly review device authorizations
- Monitor security events daily
- Update threat intelligence feeds

### Performance
- Tune performance settings for your environment
- Monitor resource usage regularly
- Implement log rotation
- Use appropriate cache settings
- Scale resources as needed

### Maintenance
- Schedule regular configuration backups
- Review and update security policies
- Train staff on incident response procedures
- Test disaster recovery procedures
- Keep system documentation updated

## Advanced Features

### API Integration
- RESTful API for external integrations
- WebSocket for real-time updates
- SDK available for custom applications
- Webhook support for external notifications

### Machine Learning
- Behavioral analysis for anomaly detection
- Predictive threat modeling
- Custom model training
- Performance optimization

### High Availability
- Multi-node deployment support
- Load balancing configuration
- Failover procedures
- Data synchronization

For additional help, consult the [API Reference](API_REFERENCE.md) or contact ZehraSec support.
