# ZehraShield Frequently Asked Questions (FAQ)

This document answers common questions about ZehraShield Advanced Enterprise Firewall System.

## Table of Contents

1. [General Questions](#general-questions)
2. [Installation & Setup](#installation--setup)
3. [Configuration](#configuration)
4. [Security Features](#security-features)
5. [Performance](#performance)
6. [Management & Monitoring](#management--monitoring)
7. [Troubleshooting](#troubleshooting)
8. [Enterprise Features](#enterprise-features)
9. [Compliance & Certifications](#compliance--certifications)
10. [Licensing & Support](#licensing--support)

## General Questions

### Q: What is ZehraShield?
**A:** ZehraShield is an advanced enterprise firewall system developed by Yashab Alam for ZehraSec. It provides comprehensive network security through a 6-layer security architecture, including packet filtering, application gateway, IDS/IPS, threat intelligence, network access control, and SIEM integration.

### Q: What makes ZehraShield different from other firewalls?
**A:** ZehraShield offers:
- **6-Layer Security Architecture**: Comprehensive protection at multiple levels
- **Machine Learning Integration**: AI-powered threat detection and behavioral analysis
- **Real-time Threat Intelligence**: Integration with multiple threat feeds
- **Advanced Web Console**: Modern, responsive management interface
- **Enterprise-grade SIEM Integration**: Seamless security event management
- **Open Source**: Transparent, auditable, and customizable code

### Q: What platforms does ZehraShield support?
**A:** ZehraShield officially supports:
- **Linux**: Ubuntu 18.04+, CentOS 7+, RHEL 7+, Debian 9+
- **Windows**: Windows Server 2016+, Windows 10+ (limited features)
- **macOS**: macOS 10.14+ (development/testing only)
- **Android**: Android 8.0+ (mobile management app)

### Q: Is ZehraShield suitable for small businesses?
**A:** Yes! ZehraShield scales from small offices to enterprise data centers. The configuration can be simplified for smaller deployments while maintaining enterprise-grade security.

### Q: Can ZehraShield replace my existing firewall?
**A:** ZehraShield can operate as a primary firewall or complement existing security infrastructure. It's designed to integrate with existing network architectures and security tools.

## Installation & Setup

### Q: What are the minimum system requirements?
**A:** Minimum requirements:
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4 GB
- **Storage**: 20 GB free space
- **Network**: 1 Gbps network interface
- **OS**: Linux with kernel 3.10+

Recommended for production:
- **CPU**: 8+ cores, 3.0+ GHz
- **RAM**: 16+ GB
- **Storage**: 100+ GB SSD
- **Network**: 10 Gbps+ interfaces

### Q: How long does installation take?
**A:** Installation typically takes:
- **Basic Installation**: 15-30 minutes
- **Full Enterprise Setup**: 1-2 hours
- **Custom Configuration**: 2-4 hours

### Q: Can I install ZehraShield in a virtual environment?
**A:** Yes, ZehraShield supports:
- **VMware vSphere/ESXi**
- **Hyper-V**
- **KVM/QEMU**
- **Docker containers**
- **Cloud platforms** (AWS, Azure, GCP)

### Q: Do I need root access for installation?
**A:** Yes, root access is required for:
- Installing system packages
- Configuring network interfaces
- Setting up system services
- Creating firewall rules

However, the web console and CLI tools can be used with non-root accounts.

### Q: Can I install ZehraShield offline?
**A:** Yes, an offline installation package is available for enterprise customers. Contact support for offline installation media.

## Configuration

### Q: How do I configure ZehraShield for my network?
**A:** Configuration involves:
1. **Network Interface Setup**: Specify monitoring interfaces
2. **Rule Configuration**: Define firewall rules and policies
3. **Layer Configuration**: Enable/disable security layers
4. **Integration Setup**: Configure SIEM, threat feeds, etc.

See the [User Guide](USER_GUIDE.md) for detailed instructions.

### Q: Can I import rules from my existing firewall?
**A:** ZehraShield supports importing rules from:
- **iptables/netfilter**
- **pfSense**
- **Cisco ASA**
- **Juniper SRX**
- **Custom CSV/JSON formats**

### Q: How do I backup my configuration?
**A:** Use the CLI tool:
```bash
zehrashield-cli config backup --path /backup/config.json
```
Or use the web console: **Settings → Backup → Create Backup**

### Q: Can I use ZehraShield with IPv6?
**A:** Yes, ZehraShield fully supports IPv6:
- IPv6 packet filtering
- IPv6 threat detection
- Dual-stack (IPv4/IPv6) environments
- IPv6-specific rules and policies

### Q: How do I configure high availability?
**A:** High availability requires:
1. **Multiple ZehraShield instances** in active/passive configuration
2. **Shared configuration storage** (database cluster)
3. **Load balancer** for web console access
4. **Network failover** configuration

Enterprise support includes HA setup assistance.

## Security Features

### Q: What types of threats can ZehraShield detect?
**A:** ZehraShield detects:
- **Network attacks**: DDoS, port scans, flood attacks
- **Malware**: Known signatures and behavioral patterns
- **Intrusions**: Unauthorized access attempts
- **Data exfiltration**: Suspicious outbound traffic
- **Zero-day threats**: Using ML behavioral analysis
- **APT activities**: Advanced persistent threat indicators

### Q: How accurate is the threat detection?
**A:** ZehraShield achieves:
- **Detection Rate**: >95% for known threats
- **False Positive Rate**: <2% with proper tuning
- **Zero-day Detection**: 70-85% depending on threat type

Accuracy improves over time through machine learning.

### Q: Can I whitelist trusted applications/IPs?
**A:** Yes, ZehraShield supports:
- **IP whitelisting**: Trusted source/destination IPs
- **Application whitelisting**: Known good applications
- **User-based rules**: Rules based on authenticated users
- **Time-based rules**: Rules active during specific times
- **Geo-IP whitelisting**: Allow traffic from specific countries

### Q: How does the machine learning component work?
**A:** ZehraShield's ML engine:
1. **Collects traffic patterns** and behavioral data
2. **Trains models** on known good/bad traffic
3. **Detects anomalies** in real-time traffic
4. **Adapts to new threats** automatically
5. **Reduces false positives** through continuous learning

### Q: Is my data sent to external servers?
**A:** No, ZehraShield processes all data locally. Optional threat intelligence feeds download signatures, but your traffic data never leaves your network unless explicitly configured for SIEM integration.

## Performance

### Q: What throughput can ZehraShield handle?
**A:** Performance depends on hardware and configuration:
- **Small deployment**: 1-5 Gbps
- **Medium deployment**: 5-20 Gbps
- **Large deployment**: 20-100+ Gbps (with proper hardware)

### Q: Does ZehraShield add latency to network traffic?
**A:** Typical latency impact:
- **Layer 1 (Packet Filter)**: <1ms
- **All layers enabled**: 2-5ms
- **ML analysis**: 1-3ms additional

Total latency is usually under 10ms for most configurations.

### Q: How much resources does ZehraShield consume?
**A:** Resource usage (typical):
- **CPU**: 10-30% on 4-core system
- **RAM**: 2-8 GB depending on traffic volume
- **Storage**: 100MB-1GB per day for logs
- **Network**: Minimal overhead (monitoring only)

### Q: Can ZehraShield handle high-speed networks?
**A:** Yes, with proper hardware:
- **10 Gbps**: Standard with modern hardware
- **25/40 Gbps**: Requires high-end hardware
- **100 Gbps**: Requires specialized hardware and configuration

Contact professional services for high-speed deployments.

## Management & Monitoring

### Q: How do I monitor ZehraShield status?
**A:** Multiple monitoring options:
- **Web Console**: Real-time dashboard
- **CLI Tool**: `zehrashield-cli status`
- **SNMP**: For integration with monitoring systems
- **API**: RESTful API for custom monitoring
- **Logs**: Comprehensive logging system

### Q: Can I manage multiple ZehraShield instances?
**A:** Yes, through:
- **Centralized web console**: Manage multiple instances
- **API integration**: Programmatic management
- **Configuration templates**: Deploy consistent configurations
- **Group policies**: Apply policies to multiple instances

### Q: What reporting capabilities are available?
**A:** ZehraShield provides:
- **Security reports**: Threat summaries, blocked attacks
- **Performance reports**: Throughput, latency, resource usage
- **Compliance reports**: Audit trails, policy compliance
- **Custom reports**: User-defined report templates
- **Scheduled reports**: Automated report generation

### Q: How do I get real-time alerts?
**A:** Alert options include:
- **Email notifications**
- **SMS alerts** (via third-party services)
- **SNMP traps**
- **Webhook notifications**
- **SIEM integration**
- **Mobile app notifications**

### Q: Can I integrate ZehraShield with my existing tools?
**A:** Yes, ZehraShield integrates with:
- **SIEM systems**: Splunk, QRadar, ArcSight, Elastic
- **Monitoring tools**: Nagios, Zabbix, PRTG
- **Ticketing systems**: ServiceNow, JIRA
- **Cloud platforms**: AWS Security Hub, Azure Sentinel

## Troubleshooting

### Q: ZehraShield won't start. What should I check?
**A:** Check these common issues:
1. **Configuration file**: `zehrashield-cli config validate`
2. **Port conflicts**: `sudo netstat -tulpn | grep 8080`
3. **Permissions**: Check file and directory permissions
4. **Dependencies**: Ensure all Python packages are installed
5. **Logs**: Check `/var/log/zehrashield/` for error messages

### Q: Web console is not accessible. How do I fix it?
**A:** Troubleshooting steps:
1. **Service status**: `systemctl status zehrashield`
2. **Port availability**: `curl http://localhost:8080`
3. **Firewall rules**: Check if port 8080 is blocked
4. **Browser issues**: Try different browser or incognito mode
5. **SSL certificates**: Check certificate validity

### Q: Performance is poor. How can I optimize it?
**A:** Optimization strategies:
1. **Disable unnecessary layers** in configuration
2. **Tune packet processing** limits
3. **Optimize system settings** (network buffers, CPU affinity)
4. **Upgrade hardware** if bottlenecked
5. **Review rule complexity** and optimize

### Q: I'm getting too many false positives. How do I reduce them?
**A:** Reduce false positives by:
1. **Tuning detection thresholds** in ML configuration
2. **Adding whitelist entries** for trusted sources
3. **Training ML models** with your specific traffic
4. **Adjusting rule sensitivity** settings
5. **Reviewing and customizing** threat intelligence feeds

## Enterprise Features

### Q: What enterprise features are available?
**A:** Enterprise features include:
- **High availability clustering**
- **Centralized management console**
- **Advanced reporting and analytics**
- **Custom threat intelligence feeds**
- **Professional support and services**
- **Compliance reporting templates**
- **Priority updates and patches**

### Q: How do I get enterprise licensing?
**A:** Contact ZehraSec sales:
- **Website**: https://zehrasec.com/contact
- **Email**: sales@zehrasec.com
- **Phone**: Available on website

### Q: Is professional installation available?
**A:** Yes, ZehraSec offers:
- **Remote installation**: Via secure connection
- **On-site installation**: Professional services team
- **Custom deployment**: Tailored to your environment
- **Training services**: Staff training and certification
- **Ongoing support**: 24/7 enterprise support

### Q: Can I get custom features developed?
**A:** Yes, ZehraSec provides:
- **Custom development services**
- **Integration consulting**
- **Specialized modules** for unique requirements
- **Performance optimization** services

## Compliance & Certifications

### Q: What compliance frameworks does ZehraShield support?
**A:** ZehraShield helps with:
- **PCI DSS**: Payment card industry compliance
- **HIPAA**: Healthcare data protection
- **SOX**: Financial reporting compliance
- **GDPR**: European data protection regulation
- **ISO 27001**: Information security management
- **NIST**: Cybersecurity framework

### Q: Is ZehraShield certified by security organizations?
**A:** ZehraShield is pursuing certifications:
- **Common Criteria**: EAL4+ evaluation in progress
- **FIPS 140-2**: Cryptographic module validation
- **CSA**: Cloud Security Alliance certification

### Q: Can ZehraShield help with audit requirements?
**A:** Yes, ZehraShield provides:
- **Audit trails**: Comprehensive logging of all activities
- **Compliance reports**: Pre-configured compliance templates
- **Evidence collection**: Automated evidence gathering
- **Retention policies**: Configurable log retention periods

## Licensing & Support

### Q: What is the licensing model?
**A:** ZehraShield uses a dual licensing model:
- **Open Source**: GNU GPL v3 for community use
- **Commercial**: Proprietary license for enterprise features

### Q: Is ZehraShield free?
**A:** The core ZehraShield firewall is open source and free. Enterprise features, support, and services require commercial licensing.

### Q: What support options are available?
**A:** Support tiers:
- **Community**: GitHub issues, documentation, forums
- **Professional**: Email support, knowledge base
- **Enterprise**: 24/7 phone support, dedicated engineer
- **Premium**: On-site support, custom SLAs

### Q: How do I report security vulnerabilities?
**A:** Report security issues to:
- **Email**: security@zehrasec.com
- **PGP Key**: Available on website
- **Bug Bounty**: Program details on website

Please do not report security issues on public GitHub issues.

### Q: Where can I get training?
**A:** Training options:
- **Online courses**: Available on ZehraSec website
- **Certification programs**: ZehraShield Administrator certification
- **Webinars**: Regular training webinars
- **On-site training**: Custom training for teams

### Q: How often are updates released?
**A:** Release schedule:
- **Security updates**: As needed (emergency releases)
- **Minor updates**: Monthly
- **Major releases**: Quarterly
- **LTS versions**: Annually (Long Term Support)

---

## Still Have Questions?

If you can't find the answer to your question here, please:

1. **Check the documentation**: [Complete documentation](README.md)
2. **Search GitHub issues**: Existing issues and solutions
3. **Contact support**: Based on your support tier
4. **Join the community**: Forums and discussion groups

**For urgent security issues, always contact security@zehrasec.com directly.**

---

*This FAQ is updated regularly. Last updated: June 2025*
