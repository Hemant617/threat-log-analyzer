#!/usr/bin/env python3
"""
Threat Log Analyzer - Command Line Interface
"""

import argparse
import sys
import os
from threat_analyzer import ThreatAnalyzer
from log_monitor import LogMonitor
from report_generator import ReportGenerator


def analyze_command(args):
    """Handle analyze command"""
    analyzer = ThreatAnalyzer()
    
    print(f"[*] Analyzing log file: {args.file}")
    report = analyzer.analyze_log_file(args.file)
    
    if 'error' in report:
        print(f"[-] Error: {report['error']}")
        return 1
    
    # Display summary
    print("\n" + "=" * 80)
    print("ANALYSIS SUMMARY")
    print("=" * 80)
    print(f"Total Threats Detected: {report['summary']['total_threats_detected']}")
    print(f"Unique Threat Types: {report['summary']['unique_threat_types']}")
    print("\nThreat Breakdown:")
    for threat_type, count in report['summary']['threat_breakdown'].items():
        print(f"  - {threat_type}: {count}")
    
    print("\nSeverity Distribution:")
    for severity, count in report['severity_distribution'].items():
        print(f"  - {severity}: {count}")
    
    if report['top_attacking_ips']:
        print("\nTop Attacking IPs:")
        for ip, count in report['top_attacking_ips'][:5]:
            print(f"  - {ip}: {count} attempts")
    
    # Export report if requested
    if args.output:
        format_type = 'json' if args.output.endswith('.json') else 'txt'
        analyzer.export_report(report, args.output, format_type)
    
    # Generate HTML report if requested
    if args.html:
        generator = ReportGenerator()
        generator.generate_html_report(report, args.html)
        print(f"[+] HTML report generated: {args.html}")
    
    return 0


def monitor_command(args):
    """Handle monitor command"""
    directories = args.directories if args.directories else ['/var/log']
    
    print("[*] Starting real-time log monitoring...")
    print(f"[*] Monitoring directories: {', '.join(directories)}")
    
    monitor = LogMonitor(directories)
    monitor.start()
    
    return 0


def scan_command(args):
    """Handle scan command - scan multiple files"""
    analyzer = ThreatAnalyzer()
    all_reports = []
    
    print(f"[*] Scanning directory: {args.directory}")
    
    if not os.path.exists(args.directory):
        print(f"[-] Directory not found: {args.directory}")
        return 1
    
    log_files = [f for f in os.listdir(args.directory) if f.endswith('.log')]
    
    if not log_files:
        print("[-] No log files found in directory")
        return 1
    
    print(f"[*] Found {len(log_files)} log files")
    
    for log_file in log_files:
        filepath = os.path.join(args.directory, log_file)
        print(f"\n[*] Analyzing: {log_file}")
        report = analyzer.analyze_log_file(filepath)
        
        if 'error' not in report:
            all_reports.append({
                'file': log_file,
                'report': report
            })
            print(f"    Threats found: {report['summary']['total_threats_detected']}")
    
    # Generate combined report
    if args.output:
        combined_report = {
            'scan_directory': args.directory,
            'total_files_scanned': len(all_reports),
            'files': all_reports
        }
        
        import json
        with open(args.output, 'w') as f:
            json.dump(combined_report, f, indent=2)
        print(f"\n[+] Combined report saved to: {args.output}")
    
    return 0


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Threat Log Analyzer - Security log analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single log file
  python cli.py analyze /var/log/auth.log
  
  # Analyze and export report
  python cli.py analyze /var/log/auth.log -o report.json
  
  # Generate HTML report
  python cli.py analyze /var/log/auth.log --html report.html
  
  # Monitor logs in real-time
  python cli.py monitor -d /var/log -d /home/user/logs
  
  # Scan entire directory
  python cli.py scan /var/log -o combined_report.json
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a log file')
    analyze_parser.add_argument('file', help='Path to log file')
    analyze_parser.add_argument('-o', '--output', help='Output file for report')
    analyze_parser.add_argument('--html', help='Generate HTML report')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Monitor logs in real-time')
    monitor_parser.add_argument('-d', '--directories', action='append', 
                               help='Directories to monitor (can specify multiple)')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan directory for log files')
    scan_parser.add_argument('directory', help='Directory to scan')
    scan_parser.add_argument('-o', '--output', help='Output file for combined report')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Execute command
    if args.command == 'analyze':
        return analyze_command(args)
    elif args.command == 'monitor':
        return monitor_command(args)
    elif args.command == 'scan':
        return scan_command(args)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
