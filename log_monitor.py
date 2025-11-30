#!/usr/bin/env python3
"""
Real-time Log Monitor
Monitors log files in real-time for security threats
"""

import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threat_analyzer import ThreatAnalyzer
from datetime import datetime


class LogFileHandler(FileSystemEventHandler):
    """Handler for log file changes"""
    
    def __init__(self, analyzer: ThreatAnalyzer, alert_callback=None):
        self.analyzer = analyzer
        self.alert_callback = alert_callback
        self.file_positions = {}
        
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
            
        if event.src_path.endswith('.log'):
            self._process_new_lines(event.src_path)
    
    def _process_new_lines(self, filepath: str):
        """Process new lines added to log file"""
        try:
            # Get current file size
            current_size = os.path.getsize(filepath)
            
            # Get last known position
            last_position = self.file_positions.get(filepath, 0)
            
            if current_size < last_position:
                # File was truncated or rotated
                last_position = 0
            
            if current_size > last_position:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    
                    for line in new_lines:
                        self._analyze_line_realtime(line, filepath)
                    
                    self.file_positions[filepath] = f.tell()
                    
        except Exception as e:
            print(f"[-] Error processing {filepath}: {str(e)}")
    
    def _analyze_line_realtime(self, line: str, filepath: str):
        """Analyze a single line in real-time"""
        threats_found = []
        
        for threat_type, pattern in self.analyzer.threat_patterns.items():
            import re
            if re.search(pattern, line, re.IGNORECASE):
                threat_data = {
                    'timestamp': datetime.now().isoformat(),
                    'file': filepath,
                    'threat_type': threat_type,
                    'severity': self.analyzer._get_severity(threat_type),
                    'line': line.strip()
                }
                threats_found.append(threat_data)
                
                # Trigger alert
                if self.alert_callback:
                    self.alert_callback(threat_data)
                else:
                    self._default_alert(threat_data)
        
        return threats_found
    
    def _default_alert(self, threat_data: Dict):
        """Default alert handler"""
        print(f"\n[!] THREAT DETECTED [{threat_data['severity']}]")
        print(f"    Type: {threat_data['threat_type']}")
        print(f"    Time: {threat_data['timestamp']}")
        print(f"    File: {threat_data['file']}")
        print(f"    Line: {threat_data['line'][:100]}...")


class LogMonitor:
    """Real-time log monitoring system"""
    
    def __init__(self, log_directories: List[str], alert_callback=None):
        self.log_directories = log_directories
        self.analyzer = ThreatAnalyzer()
        self.handler = LogFileHandler(self.analyzer, alert_callback)
        self.observer = Observer()
        
    def start(self):
        """Start monitoring log directories"""
        print("[*] Starting log monitor...")
        
        for directory in self.log_directories:
            if os.path.exists(directory):
                self.observer.schedule(self.handler, directory, recursive=True)
                print(f"[+] Monitoring: {directory}")
            else:
                print(f"[-] Directory not found: {directory}")
        
        self.observer.start()
        print("[+] Log monitor started. Press Ctrl+C to stop.")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop monitoring"""
        print("\n[*] Stopping log monitor...")
        self.observer.stop()
        self.observer.join()
        print("[+] Log monitor stopped")


if __name__ == "__main__":
    # Example usage
    monitor = LogMonitor(['/var/log', './logs'])
    monitor.start()
