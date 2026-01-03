# 🛡️ Threat Log Analyzer

<div align="center">

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-Tool-red.svg)
![Real-time](https://img.shields.io/badge/Monitoring-Real--time-success)

**Real-time log analysis tool for SOC operations - Detects 8+ threat types with automated alerting and comprehensive reporting**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-real-world-examples) • [Author](#-author)

</div>

---

## 🎯 The Problem

**SOC analysts waste 60-70% of their time manually parsing logs for security threats.**

In a typical SOC environment:
- ❌ Manual log review takes 2-4 hours per incident
- ❌ Critical threats get buried in noise (false negatives)
- ❌ No real-time alerting for active attacks
- ❌ Inconsistent threat detection across analysts
- ❌ Delayed response to brute force and injection attacks

## ✅ The Solution

**Automated threat detection engine that processes logs in real-time and alerts on critical patterns.**

This tool helps SOC teams:
- ✅ **Reduce MTTD** (Mean Time To Detect) from hours to seconds
- ✅ **Automate pattern matching** for 8+ common attack types
- ✅ **Real-time monitoring** with instant alerts
- ✅ **Standardize detection** across all analysts
- ✅ **Generate reports** for incident response and compliance

## 💼 How It Helps in Enterprise SOC

| Use Case | Traditional Approach | With This Tool |
|----------|---------------------|----------------|
| **Brute Force Detection** | Manual grep through auth logs | Instant alert with IP tracking |
| **SQL Injection Analysis** | Search for SQL keywords | Pattern-based detection with severity |
| **Incident Response** | Copy-paste log snippets | Automated HTML/JSON reports |
| **Threat Intelligence** | Manual IP correlation | Automatic IP ranking by attempts |
| **Compliance Reporting** | Manual log aggregation | One-click comprehensive reports |

---

## ✨ Features

### 🔍 Multi-Pattern Threat Detection
Identifies **8+ types** of security threats:
- **Brute force attacks** (failed login patterns)
- **SQL injection attempts** (UNION, SELECT, DROP patterns)
- **XSS attacks** (script injection, alert patterns)
- **Path traversal** (../, directory manipulation)
- **Command injection** (shell command patterns)
- **Port scanning** (rapid connection attempts)
- **Unauthorized access** (403, 401, access denied)
- **Malware signatures** (known malware keywords)

### ⚡ Real-Time Monitoring
- Watch log files and directories in real-time
- Instant alerts when threats are detected
- File position tracking (no duplicate processing)
- Multi-directory monitoring support

### 📊 Comprehensive Reporting
- **Console output** with color-coded severity
- **JSON reports** for SIEM integration
- **HTML reports** with visual statistics
- **IP tracking** and ranking by attack frequency
- **Severity classification** (CRITICAL, HIGH, MEDIUM, LOW)

### 🎯 Security Recommendations
Actionable advice based on detected threats:
- Rate limiting and account lockout policies
- Multi-factor authentication (MFA) recommendations
- Firewall rules for blocking malicious IPs
- IDS/IPS configuration suggestions

---

## 📋 Requirements

- Python 3.7+
- watchdog (for real-time monitoring)
- colorama (for colored terminal output)

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Hemant617/threat-log-analyzer.git
cd threat-log-analyzer

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### 1️⃣ Analyze a Single Log File

```bash
python cli.py analyze /var/log/auth.log
```

**Output:**
```
================================================================================
ANALYSIS SUMMARY
================================================================================
Total Threats Detected: 47
Unique Threat Types: 5

Threat Breakdown:
  - brute_force: 23 (HIGH)
  - unauthorized_access: 12 (MEDIUM)
  - port_scan: 8 (MEDIUM)
  - sql_injection: 3 (CRITICAL)
  - xss_attack: 1 (HIGH)

Severity Distribution:
  - CRITICAL: 3
  - HIGH: 31
  - MEDIUM: 12
  - LOW: 1

Top Attacking IPs:
  - 192.168.1.100: 15 attempts
  - 10.0.0.50: 12 attempts
  - 203.0.113.45: 8 attempts
```

---

### 2️⃣ Export Report to JSON (SIEM Integration)

```bash
python cli.py analyze /var/log/auth.log -o report.json
```

**JSON Output Structure:**
```json
{
  "summary": {
    "total_threats": 47,
    "unique_types": 5,
    "severity_distribution": {
      "CRITICAL": 3,
      "HIGH": 31,
      "MEDIUM": 12,
      "LOW": 1
    }
  },
  "threats": [
    {
      "type": "sql_injection",
      "severity": "CRITICAL",
      "line": "192.168.1.100 - - [01/Jan/2026] \"GET /api?id=1' UNION SELECT * FROM users--\"",
      "ip": "192.168.1.100",
      "timestamp": "2026-01-01T12:34:56Z"
    }
  ],
  "top_ips": {
    "192.168.1.100": 15,
    "10.0.0.50": 12
  }
}
```

---

### 3️⃣ Generate HTML Report (Management Reporting)

```bash
python cli.py analyze /var/log/auth.log --html report.html
```

**HTML Report Includes:**
- 📊 Visual summary cards with threat counts
- 🎨 Color-coded severity indicators
- 📈 Threat breakdown tables
- 🌍 Top attacking IPs with attempt counts
- 💡 Security recommendations
- 📱 Responsive design for mobile viewing

---

### 4️⃣ Real-Time Monitoring (Active SOC Operations)

```bash
# Monitor single directory
python cli.py monitor -d /var/log

# Monitor multiple directories
python cli.py monitor -d /var/log -d /home/user/logs -d /opt/app/logs
```

**Real-time Output:**
```
[2026-01-03 18:30:45] ALERT: Brute force attack detected!
  IP: 192.168.1.100
  File: /var/log/auth.log
  Pattern: Failed password for root from 192.168.1.100

[2026-01-03 18:31:12] ALERT: SQL injection attempt detected!
  IP: 10.0.0.50
  File: /var/log/apache/access.log
  Pattern: UNION SELECT * FROM users
```

---

### 5️⃣ Scan Entire Directory (Batch Processing)

```bash
python cli.py scan /var/log -o combined_report.json
```

---

## 📊 Real-World Examples

### Example 1: Detecting Brute Force Attack

**Input Log (`/var/log/auth.log`):**
```
Jan  3 18:30:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan  3 18:30:03 server sshd[12346]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan  3 18:30:05 server sshd[12347]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan  3 18:30:07 server sshd[12348]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan  3 18:30:09 server sshd[12349]: Failed password for admin from 192.168.1.100 port 22 ssh2
```

**Command:**
```bash
python cli.py analyze /var/log/auth.log
```

**Output:**
```
================================================================================
THREAT DETECTED: Brute Force Attack
================================================================================
Severity: HIGH
IP Address: 192.168.1.100
Attempts: 5 failed logins in 10 seconds
Target Accounts: root, admin

Recommendation:
  - Implement account lockout after 3 failed attempts
  - Enable fail2ban to block IP after 5 failures
  - Consider implementing MFA for SSH access
  - Block IP 192.168.1.100 at firewall level
```

---

### Example 2: Detecting SQL Injection

**Input Log (`/var/log/apache/access.log`):**
```
192.168.1.100 - - [03/Jan/2026:18:30:45 +0000] "GET /api/users?id=1' UNION SELECT * FROM users-- HTTP/1.1" 200 1234
10.0.0.50 - - [03/Jan/2026:18:31:12 +0000] "POST /login.php?user=admin' OR '1'='1 HTTP/1.1" 200 567
```

**Command:**
```bash
python cli.py analyze /var/log/apache/access.log --html sql_injection_report.html
```

**Output:**
```
================================================================================
THREAT DETECTED: SQL Injection Attempt
================================================================================
Severity: CRITICAL
IP Address: 192.168.1.100
Pattern: UNION SELECT * FROM users--
Endpoint: /api/users

Severity: CRITICAL
IP Address: 10.0.0.50
Pattern: admin' OR '1'='1
Endpoint: /login.php

Recommendations:
  - Implement parameterized queries immediately
  - Enable Web Application Firewall (WAF)
  - Block IPs: 192.168.1.100, 10.0.0.50
  - Review database access logs for data exfiltration
  - Conduct security audit of /api/users and /login.php endpoints
```

---

### Example 3: Real-Time Monitoring Dashboard

**Command:**
```bash
python cli.py monitor -d /var/log
```

**Live Output:**
```
================================================================================
REAL-TIME LOG MONITORING
================================================================================
Monitoring directories:
  - /var/log

Press Ctrl+C to stop monitoring...

[18:30:45] ✓ Monitoring started
[18:30:46] 📁 Watching: /var/log/auth.log
[18:30:46] 📁 Watching: /var/log/apache/access.log
[18:30:46] 📁 Watching: /var/log/syslog

[18:31:12] 🚨 ALERT: Brute Force Attack
           IP: 192.168.1.100
           File: /var/log/auth.log
           Severity: HIGH

[18:31:45] 🚨 ALERT: SQL Injection Attempt
           IP: 10.0.0.50
           File: /var/log/apache/access.log
           Severity: CRITICAL

[18:32:03] 🚨 ALERT: Port Scan Detected
           IP: 203.0.113.45
           File: /var/log/syslog
           Severity: MEDIUM

Total Alerts: 3
Active Monitoring: 3 files
Uptime: 00:01:17
```

---

## 🔧 Module Overview

### `threat_analyzer.py` - Core Analysis Engine
- Parses log files using regex patterns
- Detects multiple threat types simultaneously
- Scores threats by severity (CRITICAL → LOW)
- Generates comprehensive threat reports
- Tracks IP addresses and attack patterns

### `log_monitor.py` - Real-Time Monitoring System
- Watches log directories for file changes
- Processes new log entries instantly
- Triggers alerts for detected threats
- Maintains file position tracking (no duplicates)
- Supports multi-directory monitoring

### `report_generator.py` - Report Generation Module
- Creates beautiful HTML reports with CSS styling
- Formats data for visualization
- Generates severity-based color coding
- Provides actionable security insights
- Exports JSON for SIEM integration

### `cli.py` - Command-Line Interface
- Multiple analysis modes (analyze, monitor, scan)
- Flexible output options (console, JSON, HTML)
- Batch processing capabilities
- User-friendly commands with help text

---

## 🎯 Threat Detection Patterns

| Threat Type | Severity | Detection Pattern | Example |
|------------|----------|-------------------|---------|
| **SQL Injection** | CRITICAL | `UNION`, `SELECT`, `DROP`, `--`, `'OR'1'='1` | `?id=1' UNION SELECT * FROM users--` |
| **Command Injection** | CRITICAL | `;`, `&&`, `\|`, `$(`, `` ` `` | `; cat /etc/passwd` |
| **Malware Signature** | CRITICAL | `trojan`, `ransomware`, `backdoor` | `trojan.exe detected` |
| **XSS Attack** | HIGH | `<script>`, `alert(`, `onerror=` | `<script>alert('XSS')</script>` |
| **Brute Force** | HIGH | `failed password`, `authentication failure` | `Failed password for root` |
| **Path Traversal** | HIGH | `../`, `..\\`, `%2e%2e` | `GET /../../../etc/passwd` |
| **Port Scan** | MEDIUM | `connection refused`, `port scan` | `Connection attempt on port 22` |
| **Unauthorized Access** | MEDIUM | `403`, `401`, `access denied` | `403 Forbidden` |

---

## 🔐 Security Recommendations

Based on detected threats, the analyzer provides actionable recommendations:

### For Brute Force Attacks:
- ✅ Implement rate limiting (max 5 attempts per minute)
- ✅ Enable account lockout after 3 failed attempts
- ✅ Deploy fail2ban or similar IP blocking tools
- ✅ Require multi-factor authentication (MFA)
- ✅ Monitor for distributed brute force attacks

### For SQL Injection:
- ✅ Use parameterized queries and prepared statements
- ✅ Implement input validation and sanitization
- ✅ Enable Web Application Firewall (WAF)
- ✅ Apply principle of least privilege for database access
- ✅ Conduct regular security code reviews

### For XSS Attacks:
- ✅ Implement Content Security Policy (CSP)
- ✅ Encode user input before rendering
- ✅ Use HTTPOnly and Secure flags for cookies
- ✅ Deploy XSS protection headers
- ✅ Validate and sanitize all user inputs

### For Port Scanning:
- ✅ Configure firewall rules to block suspicious IPs
- ✅ Implement intrusion detection system (IDS)
- ✅ Use port knocking for sensitive services
- ✅ Monitor for reconnaissance activities
- ✅ Enable rate limiting on connection attempts

---

## 📁 Project Structure

```
threat-log-analyzer/
├── threat_analyzer.py      # Core analysis engine
├── log_monitor.py          # Real-time monitoring
├── report_generator.py     # HTML report generation
├── cli.py                  # Command-line interface
├── requirements.txt        # Python dependencies
├── README.md              # Documentation
├── examples/              # Example log files
│   ├── sample.log         # Sample log with threats
│   ├── auth.log           # SSH authentication logs
│   └── access.log         # Apache access logs
└── tests/                 # Unit tests
    └── test_analyzer.py   # Test suite
```

---

## 🧪 Testing

### Run the test suite:
```bash
python -m pytest tests/
```

### Test with sample log file:
```bash
python cli.py analyze examples/sample.log --html test_report.html
```

### Generate test data:
```bash
# Create a test log with various threats
cat > test.log << EOF
Jan  3 18:30:01 server sshd[12345]: Failed password for root from 192.168.1.100
Jan  3 18:30:03 server apache: GET /api?id=1' UNION SELECT * FROM users--
Jan  3 18:30:05 server apache: GET /search?q=<script>alert('XSS')</script>
EOF

python cli.py analyze test.log
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👨‍💻 Author

**Hemant Kaushal**  
🔐 Aspiring SOC Analyst | Security Automation | Threat Detection

- 📧 Email: hemuh877@gmail.com
- 💼 LinkedIn: [linkedin.com/in/hemantkaushal](https://linkedin.com/in/hemantkaushal)
- 💻 GitHub: [@Hemant617](https://github.com/Hemant617)
- 📱 Phone: +91 96342 22262
- 🌐 Portfolio: [hemant617.github.io](https://hemant617.github.io/)

### 🎓 Certifications
- Deloitte Cyber Job Simulation (Forage, Nov 2025)
- Deloitte Data Analytics Job Simulation (Forage, Nov 2025)
- Cisco Introduction to Cybersecurity (Nov 2025)

### 🚀 Other Security Projects
- [VirusTotal Automated Scanner](https://github.com/Hemant617/virustotal-automated-scanner) - Enterprise malware scanning with 70+ AV engines
- [VulnScan Pro](https://github.com/Hemant617/vulnscan-pro) - Automated vulnerability scanner for small businesses
- [View All Projects](https://github.com/Hemant617)

---

## 🙏 Acknowledgments

- Built with Python 3
- Uses watchdog for file monitoring
- Inspired by modern SIEM solutions (Splunk, ELK, QRadar)
- Threat patterns based on OWASP Top 10 and MITRE ATT&CK

---

<div align="center">

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Always ensure you have permission before analyzing logs or monitoring systems.

**⭐ If you find this project useful, please consider giving it a star!**

**🤝 Open to collaboration on SOC automation and security tooling projects**

</div>
