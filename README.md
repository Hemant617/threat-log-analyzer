# 🛡️ Threat Log Analyzer

<div align="center">

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-Tool-red.svg)

**A powerful Python-based security tool for analyzing system logs, detecting threats, and generating comprehensive security reports with real-time monitoring capabilities.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Author](#-author)

</div>

---

## ✨ Features

- **Multi-Pattern Threat Detection**: Identifies 8+ types of security threats including:
  - Brute force attacks
  - SQL injection attempts
  - XSS attacks
  - Path traversal
  - Command injection
  - Port scanning
  - Unauthorized access attempts
  - Malware signatures

- **Real-Time Monitoring**: Watch log files in real-time and get instant alerts
- **Comprehensive Reports**: Generate detailed JSON, TXT, and HTML reports
- **IP Tracking**: Identify and rank attacking IP addresses
- **Severity Classification**: Automatic threat severity scoring (CRITICAL, HIGH, MEDIUM, LOW)
- **Security Recommendations**: Get actionable security advice based on findings
- **Batch Processing**: Scan entire directories of log files

## 📋 Requirements

- Python 3.7+
- watchdog (for real-time monitoring)
- colorama (for colored terminal output)

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/Hemant617/threat-log-analyzer.git
cd threat-log-analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## 💻 Usage

### Analyze a Single Log File

```bash
python cli.py analyze /var/log/auth.log
```

### Export Report to JSON

```bash
python cli.py analyze /var/log/auth.log -o report.json
```

### Generate HTML Report

```bash
python cli.py analyze /var/log/auth.log --html report.html
```

### Real-Time Monitoring

```bash
python cli.py monitor -d /var/log -d /home/user/logs
```

### Scan Entire Directory

```bash
python cli.py scan /var/log -o combined_report.json
```

## 📊 Report Examples

### Console Output
```
================================================================================
ANALYSIS SUMMARY
================================================================================
Total Threats Detected: 47
Unique Threat Types: 5

Threat Breakdown:
  - brute_force: 23
  - unauthorized_access: 12
  - port_scan: 8
  - sql_injection: 3
  - xss_attack: 1

Severity Distribution:
  - CRITICAL: 3
  - HIGH: 31
  - MEDIUM: 12
  - LOW: 1

Top Attacking IPs:
  - 192.168.1.100: 15 attempts
  - 10.0.0.50: 12 attempts
```

### HTML Report
The HTML report includes:
- Visual summary cards
- Interactive threat breakdown tables
- Severity distribution charts
- Top attacking IPs list
- Security recommendations

## 🔧 Module Overview

### `threat_analyzer.py`
Core analysis engine that:
- Parses log files using regex patterns
- Detects multiple threat types
- Scores threats by severity
- Generates comprehensive reports

### `log_monitor.py`
Real-time monitoring system that:
- Watches log directories for changes
- Processes new log entries instantly
- Triggers alerts for detected threats
- Maintains file position tracking

### `report_generator.py`
Report generation module that:
- Creates beautiful HTML reports
- Formats data for visualization
- Generates severity-based styling
- Provides actionable insights

### `cli.py`
Command-line interface providing:
- Multiple analysis modes
- Flexible output options
- Batch processing capabilities
- User-friendly commands

## 🎯 Threat Detection Patterns

| Threat Type | Severity | Description |
|------------|----------|-------------|
| SQL Injection | CRITICAL | Detects SQL injection attempts in logs |
| Command Injection | CRITICAL | Identifies command injection patterns |
| Malware Signature | CRITICAL | Finds malware-related keywords |
| XSS Attack | HIGH | Detects cross-site scripting attempts |
| Brute Force | HIGH | Identifies failed login patterns |
| Path Traversal | HIGH | Finds directory traversal attempts |
| Port Scan | MEDIUM | Detects port scanning activity |
| Unauthorized Access | MEDIUM | Identifies access denial patterns |

## 🔐 Security Recommendations

Based on detected threats, the analyzer provides recommendations such as:
- Implement rate limiting and account lockout policies
- Enable multi-factor authentication (MFA)
- Use parameterized queries and prepared statements
- Implement Content Security Policy (CSP)
- Configure firewall rules to block suspicious IPs
- Implement intrusion detection system (IDS)

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
│   └── sample.log
└── tests/                 # Unit tests
    └── test_analyzer.py
```

## 🧪 Testing

Run the test suite:
```bash
python -m pytest tests/
```

Test with sample log file:
```bash
python cli.py analyze examples/sample.log --html test_report.html
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Author

**Hemant Kaushal**

- 🔐 Cybersecurity Analyst | SOC Operations | Incident Response
- 📧 Email: hemuh877@gmail.com
- 💼 LinkedIn: [linkedin.com/in/hemantkaushal](https://linkedin.com/in/hemantkaushal)
- 💻 GitHub: [@Hemant617](https://github.com/Hemant617)
- 📱 Phone: +91 96342 22262

### 🎓 Certifications
- Deloitte Cyber Job Simulation (Forage)
- Deloitte Data Analytics Job Simulation (Forage)
- Cisco Introduction to Cybersecurity

### 🚀 Other Projects
- [VirusTotal Automated Scanner](https://github.com/Hemant617/virustotal-automated-scanner)
- [View All Projects](https://github.com/Hemant617)

## 🙏 Acknowledgments

- Built with Python 3
- Uses watchdog for file monitoring
- Inspired by modern SIEM solutions

---

<div align="center">

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Always ensure you have permission before analyzing logs or monitoring systems.

**⭐ If you find this project useful, please consider giving it a star!**

Made with ❤️ by [Hemant Kaushal](https://github.com/Hemant617)

</div>
