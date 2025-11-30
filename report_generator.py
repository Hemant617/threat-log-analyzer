#!/usr/bin/env python3
"""
Report Generator - Creates HTML reports from threat analysis
"""

from typing import Dict
from datetime import datetime


class ReportGenerator:
    """Generate HTML reports from threat analysis data"""
    
    def generate_html_report(self, report: Dict, output_file: str):
        """Generate comprehensive HTML report"""
        html = self._generate_html(report)
        
        with open(output_file, 'w') as f:
            f.write(html)
    
    def _generate_html(self, report: Dict) -> str:
        """Generate HTML content"""
        summary = report['summary']
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Log Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .stat-card h3 {{
            color: #667eea;
            font-size: 2em;
            margin-bottom: 10px;
        }}
        
        .stat-card p {{
            color: #666;
            font-size: 0.9em;
        }}
        
        .section {{
            margin-bottom: 30px;
        }}
        
        .section h2 {{
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        
        .threat-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        .threat-table th {{
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        
        .threat-table td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        
        .threat-table tr:hover {{
            background: #f5f7fa;
        }}
        
        .severity-critical {{
            background: #ff4444;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
        }}
        
        .severity-high {{
            background: #ff8800;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
        }}
        
        .severity-medium {{
            background: #ffbb33;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
        }}
        
        .severity-low {{
            background: #00C851;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
        }}
        
        .recommendations {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border-left: 5px solid #667eea;
        }}
        
        .recommendations ul {{
            list-style-position: inside;
            margin-top: 10px;
        }}
        
        .recommendations li {{
            padding: 8px 0;
            color: #555;
        }}
        
        .ip-list {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
        }}
        
        .ip-item {{
            padding: 8px;
            margin: 5px 0;
            background: white;
            border-radius: 5px;
            display: flex;
            justify-content: space-between;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Threat Log Analysis Report</h1>
            <p>Generated on {summary['analysis_timestamp']}</p>
        </div>
        
        <div class="content">
            <div class="summary-grid">
                <div class="stat-card">
                    <h3>{summary['total_threats_detected']}</h3>
                    <p>Total Threats Detected</p>
                </div>
                <div class="stat-card">
                    <h3>{summary['unique_threat_types']}</h3>
                    <p>Unique Threat Types</p>
                </div>
                <div class="stat-card">
                    <h3>{len(report.get('top_attacking_ips', []))}</h3>
                    <p>Attacking IP Addresses</p>
                </div>
            </div>
            
            <div class="section">
                <h2>📊 Threat Breakdown</h2>
                <table class="threat-table">
                    <thead>
                        <tr>
                            <th>Threat Type</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_threat_breakdown_rows(summary)}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>⚠️ Severity Distribution</h2>
                <table class="threat-table">
                    <thead>
                        <tr>
                            <th>Severity Level</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_severity_rows(report['severity_distribution'])}
                    </tbody>
                </table>
            </div>
            
            {self._generate_top_ips_section(report.get('top_attacking_ips', []))}
            
            <div class="section">
                <h2>💡 Security Recommendations</h2>
                <div class="recommendations">
                    <ul>
                        {self._generate_recommendations_list(report.get('recommendations', []))}
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Threat Log Analyzer v1.0 | Generated by Python Security Tools</p>
        </div>
    </div>
</body>
</html>"""
        return html
    
    def _generate_threat_breakdown_rows(self, summary: Dict) -> str:
        """Generate threat breakdown table rows"""
        total = summary['total_threats_detected']
        rows = []
        
        for threat_type, count in summary['threat_breakdown'].items():
            percentage = (count / total * 100) if total > 0 else 0
            rows.append(f"""
                <tr>
                    <td>{threat_type.replace('_', ' ').title()}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
            """)
        
        return ''.join(rows)
    
    def _generate_severity_rows(self, severity_dist: Dict) -> str:
        """Generate severity distribution table rows"""
        rows = []
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        
        for severity in severity_order:
            count = severity_dist.get(severity, 0)
            if count > 0:
                rows.append(f"""
                    <tr>
                        <td><span class="severity-{severity.lower()}">{severity}</span></td>
                        <td>{count}</td>
                    </tr>
                """)
        
        return ''.join(rows)
    
    def _generate_top_ips_section(self, top_ips: list) -> str:
        """Generate top attacking IPs section"""
        if not top_ips:
            return ""
        
        ip_items = []
        for ip, count in top_ips[:10]:
            ip_items.append(f"""
                <div class="ip-item">
                    <span><strong>{ip}</strong></span>
                    <span>{count} attempts</span>
                </div>
            """)
        
        return f"""
            <div class="section">
                <h2>🌐 Top Attacking IP Addresses</h2>
                <div class="ip-list">
                    {''.join(ip_items)}
                </div>
            </div>
        """
    
    def _generate_recommendations_list(self, recommendations: list) -> str:
        """Generate recommendations list items"""
        return ''.join([f"<li>{rec}</li>" for rec in recommendations])


if __name__ == "__main__":
    print("Report Generator module")
