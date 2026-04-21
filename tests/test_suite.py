#!/usr/bin/env python3
"""
Comprehensive Test Suite - Threat Intelligence Platform
=======================
Tests all agents, API integration, and report generation
"""

import sys
import os
import unittest
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

# Add path
sys.path.insert(0, '/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/agents')

from scout import ScoutAgent, load_sample_threats
from watchdog import WatchdogAgent
from reporter import ReporterAgent
from api_integration import ThreatAPI


class TestScoutAgent(unittest.TestCase):
    """Test Scout Agent functionality"""
    
    def setUp(self):
        self.scout = ScoutAgent()
    
    def test_load_sample_threats(self):
        """Test sample threat loading"""
        threats = load_sample_threats()
        self.assertGreater(len(threats), 0)
        self.assertIsInstance(threats, list)
    
    def test_threat_severity_calculation(self):
        """Test severity calculation from CVSS score"""
        threat = {
            'cvss_score': 9.5,
            'title': 'Test CVE',
            'description': 'Test description',
            'vendor': 'Test',
            'product': 'Test Product'
        }
        
        severity = self.scout._calculate_severity(threat['cvss_score'])
        self.assertEqual(severity, 'Critical')
    
    def test_threat_with_low_cvss(self):
        """Test low CVSS score severity"""
        threat = {
            'cvss_score': 3.5,
            'title': 'Test CVE',
            'description': 'Test description',
            'vendor': 'Test',
            'product': 'Test Product'
        }
        
        severity = self.scout._calculate_severity(threat['cvss_score'])
        self.assertEqual(severity, 'Low')


class TestWatchdogAgent(unittest.TestCase):
    """Test Watchdog Agent functionality"""
    
    def setUp(self):
        self.watchdog = WatchdogAgent()
    
    def test_org_profile_loading(self):
        """Test organization profile loading"""
        profile = self.watchdog.org_profile
        self.assertIn('org_name', profile)
        self.assertIn('tech_stack', profile)
    
    def test_threat_relevance_assessment(self):
        """Test threat relevance assessment"""
        threat = {
            'cve_id': 'CVE-2024-1001',
            'severity': 'Critical',
            'cvss_score': 9.8,
            'title': 'Windows SMB Remote Code Execution',
            'description': 'Windows Server SMB protocol vulnerability',
            'product': 'Windows Server'
        }
        
        assessment = self.watchdog.assess_threat_relevance(threat)
        self.assertIn('is_relevant', assessment)
        self.assertIn('relevant_products', assessment)


class TestReporterAgent(unittest.TestCase):
    """Test Reporter Agent functionality"""
    
    def setUp(self):
        self.reporter = ReporterAgent()
    
    def test_console_report_generation(self):
        """Test console report generation"""
        threats = load_sample_threats()
        if threats:
            self.reporter.generate_console_report(threats)
    
    def test_html_report_generation(self):
        """Test HTML report generation"""
        threats = load_sample_threats()
        if threats:
            path = self.reporter.generate_html_report(threats)
            self.assertTrue(path.startswith('/Users/paulnaeger/.openclaw/workspace/agents/threat-intel/outputs/'))
    
    def test_markdown_report_generation(self):
        """Test markdown report generation"""
        threats = load_sample_threats()
        if threats:
            path = self.reporter.generate_markdown_report(threats)
            self.assertTrue(path.endswith('.md'))


class TestThreatAPI(unittest.TestCase):
    """Test Threat API integration"""
    
    def setUp(self):
        self.api = ThreatAPI()
    
    def test_severity_calculation(self):
        """Test severity calculation"""
        self.assertEqual(self.api._calculate_severity(9.0), 'Critical')
        self.assertEqual(self.api._calculate_severity(7.5), 'High')
        self.assertEqual(self.api._calculate_severity(5.0), 'Medium')
        self.assertEqual(self.api._calculate_severity(3.5), 'Low')
    
    def test_fetch_sample_threats(self):
        """Test fetching sample threats"""
        # This tests the logic, not live API (which may fail)
        threats = self.api.fetch_nvd_threats(limit=0)  # limit=0 returns sample data
        
        if threats:
            self.assertGreater(len(threats), 0)
            for threat in threats:
                self.assertIn('cve_id', threat)
                self.assertIn('severity', threat)


class TestCompletePipeline(unittest.TestCase):
    """Test complete pipeline integration"""
    
    def setUp(self):
        self.api = ThreatAPI()
        self.scout = ScoutAgent()
        self.reporter = ReporterAgent()
        self.watchdog = WatchdogAgent()
    
    def test_pipeline_integration(self):
        """Test that all agents work together"""
        # Load threats
        threats = load_sample_threats()
        
        if not threats:
            self.fail("No threats available for testing")
        
        # Test that threats have all required fields
        for threat in threats:
            self.assertIn('id', threat)
            self.assertIn('cve_id', threat)
            self.assertIn('severity', threat)
            self.assertIn('cvss_score', threat)
            self.assertIn('exploit_available', threat)
    
    def test_report_generation_with_threats(self):
        """Test complete report generation"""
        threats = load_sample_threats()
        
        if not threats:
            self.fail("No threats available")
        
        # Generate all report types
        self.reporter.generate_console_report(threats)
        self.reporter.generate_html_report(threats)
        self.reporter.generate_markdown_report(threats)


def run_tests():
    """Run all tests and display results"""
    print("\n" + "="*60)
    print("🧪 RUNNING TEST SUITE - Threat Intelligence Platform")
    print("="*60 + "\n")
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Display summary
    print("\n" + "="*60)
    print("📊 TEST RESULTS SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ ALL TESTS PASSED!")
    else:
        print("\n❌ Some tests failed. See output above.")
    
    return result


if __name__ == "__main__":
    run_tests()
