#!/usr/bin/env python3
"""
Unit tests for Threat Log Analyzer
"""

import unittest
import os
import sys
import tempfile
import json

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from threat_analyzer import ThreatAnalyzer


class TestThreatAnalyzer(unittest.TestCase):
    """Test cases for ThreatAnalyzer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = ThreatAnalyzer()
        self.test_log_content = """
2025-11-30 10:15:23 [WARNING] Failed password for admin from 192.168.1.100 port 22
2025-11-30 10:16:45 [ERROR] SQL injection: SELECT * FROM users UNION SELECT password
2025-11-30 10:17:12 [ERROR] XSS attempt: <script>alert('test')</script>
2025-11-30 10:18:33 [WARNING] Path traversal: ../../etc/passwd
2025-11-30 10:19:45 [ERROR] Command injection: ; rm -rf /
        """
    
    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly"""
        self.assertIsNotNone(self.analyzer)
        self.assertEqual(len(self.analyzer.threat_patterns), 8)
        self.assertEqual(len(self.analyzer.threat_scores), 8)
    
    def test_threat_pattern_detection(self):
        """Test threat patterns are detected"""
        # Create temporary log file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write(self.test_log_content)
            temp_file = f.name
        
        try:
            report = self.analyzer.analyze_log_file(temp_file)
            
            # Check report structure
            self.assertIn('summary', report)
            self.assertIn('threats_by_type', report)
            self.assertIn('severity_distribution', report)
            
            # Check threats detected
            self.assertGreater(report['summary']['total_threats_detected'], 0)
            self.assertIn('brute_force', report['threats_by_type'])
            self.assertIn('sql_injection', report['threats_by_type'])
            
        finally:
            os.unlink(temp_file)
    
    def test_severity_classification(self):
        """Test severity levels are assigned correctly"""
        self.assertEqual(self.analyzer._get_severity('sql_injection'), 'CRITICAL')
        self.assertEqual(self.analyzer._get_severity('brute_force'), 'HIGH')
        self.assertEqual(self.analyzer._get_severity('unauthorized_access'), 'MEDIUM')
    
    def test_ip_extraction(self):
        """Test IP addresses are extracted correctly"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write("Failed login from 192.168.1.100\n")
            f.write("Failed login from 192.168.1.100\n")
            f.write("Failed login from 10.0.0.50\n")
            temp_file = f.name
        
        try:
            report = self.analyzer.analyze_log_file(temp_file)
            top_ips = report['top_attacking_ips']
            
            self.assertGreater(len(top_ips), 0)
            self.assertEqual(top_ips[0][0], '192.168.1.100')
            self.assertEqual(top_ips[0][1], 2)
            
        finally:
            os.unlink(temp_file)
    
    def test_recommendations_generation(self):
        """Test security recommendations are generated"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write("Failed password for admin from 192.168.1.100\n")
            temp_file = f.name
        
        try:
            report = self.analyzer.analyze_log_file(temp_file)
            recommendations = report['recommendations']
            
            self.assertGreater(len(recommendations), 0)
            self.assertTrue(any('rate limiting' in rec.lower() for rec in recommendations))
            
        finally:
            os.unlink(temp_file)
    
    def test_report_export_json(self):
        """Test JSON report export"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write(self.test_log_content)
            log_file = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            output_file = f.name
        
        try:
            report = self.analyzer.analyze_log_file(log_file)
            self.analyzer.export_report(report, output_file, 'json')
            
            # Verify JSON file was created and is valid
            self.assertTrue(os.path.exists(output_file))
            with open(output_file, 'r') as f:
                loaded_report = json.load(f)
            self.assertEqual(loaded_report['summary']['total_threats_detected'], 
                           report['summary']['total_threats_detected'])
            
        finally:
            os.unlink(log_file)
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_empty_log_file(self):
        """Test handling of empty log file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            temp_file = f.name
        
        try:
            report = self.analyzer.analyze_log_file(temp_file)
            self.assertEqual(report['summary']['total_threats_detected'], 0)
            
        finally:
            os.unlink(temp_file)
    
    def test_nonexistent_file(self):
        """Test handling of nonexistent file"""
        report = self.analyzer.analyze_log_file('/nonexistent/file.log')
        self.assertIn('error', report)


class TestThreatPatterns(unittest.TestCase):
    """Test individual threat pattern detection"""
    
    def setUp(self):
        self.analyzer = ThreatAnalyzer()
    
    def test_sql_injection_pattern(self):
        """Test SQL injection pattern detection"""
        test_lines = [
            "SELECT * FROM users UNION SELECT password",
            "INSERT INTO admin VALUES ('hacker')",
            "DROP TABLE users",
        ]
        
        for line in test_lines:
            self.analyzer._analyze_line(line, 1)
        
        self.assertGreater(len(self.analyzer.results['sql_injection']), 0)
    
    def test_xss_pattern(self):
        """Test XSS pattern detection"""
        test_lines = [
            "<script>alert('XSS')</script>",
            "javascript:alert(1)",
            "<img onerror='alert(1)'>",
        ]
        
        for line in test_lines:
            self.analyzer._analyze_line(line, 1)
        
        self.assertGreater(len(self.analyzer.results['xss_attack']), 0)
    
    def test_brute_force_pattern(self):
        """Test brute force pattern detection"""
        line = "Failed password for admin from 192.168.1.100 port 22"
        self.analyzer._analyze_line(line, 1)
        
        self.assertGreater(len(self.analyzer.results['brute_force']), 0)


if __name__ == '__main__':
    unittest.main()
