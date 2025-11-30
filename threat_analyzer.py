#!/usr/bin/env python3
"""
Threat Log Analyzer - Main Module
Analyzes system logs for security threats and anomalies
"""

import re
import json
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple
import hashlib


class ThreatAnalyzer:
    """Main class for analyzing security threats in log files"""
    
    def __init__(self):
        self.threat_patterns = {
            'brute_force': r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
            'sql_injection': r'(union.*select|select.*from|insert.*into|drop.*table)',
            'xss_attack': r'(<script|javascript:|onerror=|onload=)',
            'path_traversal': r'(\.\./|\.\.\\)',
            'command_injection': r'(;|\||&|`|\$\()',
            'port_scan': r'SYN.*(\d+\.\d+\.\d+\.\d+).*port (\d+)',
            'unauthorized_access': r'(403|401|Unauthorized|Access Denied)',
            'malware_signature': r'(trojan|virus|malware|ransomware|backdoor)',
        }
        
        self.threat_scores = {
            'brute_force': 7,
            'sql_injection': 9,
            'xss_attack': 8,
            'path_traversal': 7,
            'command_injection': 9,
            'port_scan': 6,
            'unauthorized_access': 5,
            'malware_signature': 10,
        }
        
        self.results = defaultdict(list)
        self.ip_frequency = defaultdict(int)
        self.timeline = []
        
    def analyze_log_file(self, filepath: str) -> Dict:
        """Analyze a log file for threats"""
        print(f"[*] Analyzing log file: {filepath}")
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                self._analyze_line(line, line_num)
                
            return self._generate_report()
            
        except FileNotFoundError:
            return {"error": f"File not found: {filepath}"}
        except Exception as e:
            return {"error": f"Error analyzing file: {str(e)}"}
    
    def _analyze_line(self, line: str, line_num: int):
        """Analyze a single log line for threats"""
        for threat_type, pattern in self.threat_patterns.items():
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                threat_data = {
                    'line_number': line_num,
                    'threat_type': threat_type,
                    'severity': self._get_severity(threat_type),
                    'score': self.threat_scores[threat_type],
                    'matched_text': match.group(0),
                    'full_line': line.strip(),
                    'timestamp': self._extract_timestamp(line)
                }
                
                # Extract IP if present
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if ip_match:
                    ip = ip_match.group(0)
                    threat_data['ip_address'] = ip
                    self.ip_frequency[ip] += 1
                
                self.results[threat_type].append(threat_data)
                self.timeline.append(threat_data)
    
    def _extract_timestamp(self, line: str) -> str:
        """Extract timestamp from log line"""
        # Common log timestamp patterns
        patterns = [
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',
            r'\w{3} \d{2} \d{2}:\d{2}:\d{2}',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        return "Unknown"
    
    def _get_severity(self, threat_type: str) -> str:
        """Get severity level based on threat score"""
        score = self.threat_scores.get(threat_type, 0)
        if score >= 9:
            return "CRITICAL"
        elif score >= 7:
            return "HIGH"
        elif score >= 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_report(self) -> Dict:
        """Generate comprehensive threat analysis report"""
        total_threats = sum(len(threats) for threats in self.results.values())
        
        report = {
            'summary': {
                'total_threats_detected': total_threats,
                'unique_threat_types': len(self.results),
                'analysis_timestamp': datetime.now().isoformat(),
                'threat_breakdown': {k: len(v) for k, v in self.results.items()}
            },
            'threats_by_type': dict(self.results),
            'top_attacking_ips': self._get_top_ips(10),
            'severity_distribution': self._get_severity_distribution(),
            'timeline': sorted(self.timeline, key=lambda x: x['line_number']),
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _get_top_ips(self, limit: int) -> List[Tuple[str, int]]:
        """Get top attacking IP addresses"""
        return sorted(self.ip_frequency.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def _get_severity_distribution(self) -> Dict[str, int]:
        """Get distribution of threats by severity"""
        distribution = defaultdict(int)
        for threats in self.results.values():
            for threat in threats:
                distribution[threat['severity']] += 1
        return dict(distribution)
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if 'brute_force' in self.results:
            recommendations.append("Implement rate limiting and account lockout policies")
            recommendations.append("Enable multi-factor authentication (MFA)")
        
        if 'sql_injection' in self.results:
            recommendations.append("Use parameterized queries and prepared statements")
            recommendations.append("Implement input validation and sanitization")
        
        if 'xss_attack' in self.results:
            recommendations.append("Implement Content Security Policy (CSP)")
            recommendations.append("Sanitize and encode user inputs")
        
        if 'port_scan' in self.results:
            recommendations.append("Configure firewall rules to block suspicious IPs")
            recommendations.append("Implement intrusion detection system (IDS)")
        
        if len(self.ip_frequency) > 0:
            recommendations.append("Block or monitor high-frequency attacking IPs")
        
        return recommendations
    
    def export_report(self, report: Dict, output_file: str, format: str = 'json'):
        """Export report to file"""
        try:
            if format == 'json':
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"[+] Report exported to {output_file}")
            elif format == 'txt':
                with open(output_file, 'w') as f:
                    self._write_text_report(f, report)
                print(f"[+] Report exported to {output_file}")
        except Exception as e:
            print(f"[-] Error exporting report: {str(e)}")
    
    def _write_text_report(self, f, report: Dict):
        """Write human-readable text report"""
        f.write("=" * 80 + "\n")
        f.write("THREAT LOG ANALYSIS REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        # Summary
        f.write("SUMMARY\n")
        f.write("-" * 80 + "\n")
        for key, value in report['summary'].items():
            f.write(f"{key}: {value}\n")
        f.write("\n")
        
        # Severity Distribution
        f.write("SEVERITY DISTRIBUTION\n")
        f.write("-" * 80 + "\n")
        for severity, count in report['severity_distribution'].items():
            f.write(f"{severity}: {count}\n")
        f.write("\n")
        
        # Top Attacking IPs
        f.write("TOP ATTACKING IP ADDRESSES\n")
        f.write("-" * 80 + "\n")
        for ip, count in report['top_attacking_ips']:
            f.write(f"{ip}: {count} attempts\n")
        f.write("\n")
        
        # Recommendations
        f.write("SECURITY RECOMMENDATIONS\n")
        f.write("-" * 80 + "\n")
        for i, rec in enumerate(report['recommendations'], 1):
            f.write(f"{i}. {rec}\n")


if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
    print("Threat Log Analyzer initialized")
