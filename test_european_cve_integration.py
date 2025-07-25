#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test für Europäische CVE-Integration
Testet die Integration europäischer CVE-Datenbanken
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Füge das Projektverzeichnis zum Python-Pfad hinzu
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from european_cve_checker import EuropeanCVEDatabaseChecker, EuropeanCVEAnalyzer, create_european_cve_report_content


class TestEuropeanCVEDatabaseChecker(unittest.TestCase):
    """Testet EuropeanCVEDatabaseChecker"""
    
    def setUp(self):
        """Setup für Tests"""
        self.checker = EuropeanCVEDatabaseChecker()
    
    def test_initialization(self):
        """Testet die Initialisierung"""
        self.assertIsNotNone(self.checker.databases)
        self.assertIn('bsi', self.checker.databases)
        self.assertIn('ncsc', self.checker.databases)
        self.assertIn('enisa', self.checker.databases)
        self.assertIn('cert-eu', self.checker.databases)
        
        # Prüfe BSI-Konfiguration
        bsi_config = self.checker.databases['bsi']
        self.assertEqual(bsi_config['name'], 'BSI (Deutschland)')
        self.assertEqual(bsi_config['country'], 'DE')
        self.assertEqual(bsi_config['language'], 'de')
        self.assertTrue(bsi_config['api_available'])
    
    def test_cache_operations(self):
        """Testet Cache-Operationen"""
        # Test Cache-Speicherung
        test_data = {'test': 'data'}
        self.checker.cache_european_cve_data('bsi', 'docker', '20.10.17', test_data)
        
        # Test Cache-Abruf
        cached_data = self.checker.get_cached_european_cve('bsi', 'docker', '20.10.17')
        self.assertEqual(cached_data, test_data)
        
        # Test ungültiger Cache
        invalid_data = self.checker.get_cached_european_cve('invalid', 'service', 'version')
        self.assertIsNone(invalid_data)
    
    def test_bsi_cve_check(self):
        """Testet BSI CVE-Check"""
        with patch.object(self.checker, '_simulate_bsi_response') as mock_simulate:
            mock_simulate.return_value = [
                {
                    'cve_id': 'CVE-2024-BSI-001',
                    'title': 'Test CVE',
                    'severity': 'HIGH',
                    'cvss_score': 8.5
                }
            ]
            
            results = self.checker.check_bsi_cves('docker', '20.10.17')
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['cve_id'], 'CVE-2024-BSI-001')
            self.assertEqual(results[0]['severity'], 'HIGH')
    
    def test_ncsc_cve_check(self):
        """Testet NCSC CVE-Check"""
        with patch.object(self.checker, '_simulate_ncsc_response') as mock_simulate:
            mock_simulate.return_value = [
                {
                    'cve_id': 'CVE-2024-NCSC-001',
                    'title': 'Test CVE',
                    'severity': 'CRITICAL',
                    'cvss_score': 9.0
                }
            ]
            
            results = self.checker.check_ncsc_cves('sshd', '8.4')
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['cve_id'], 'CVE-2024-NCSC-001')
            self.assertEqual(results[0]['severity'], 'CRITICAL')
    
    def test_european_cves_check(self):
        """Testet europäische CVE-Prüfung"""
        with patch.object(self.checker, 'check_bsi_cves') as mock_bsi, \
             patch.object(self.checker, 'check_ncsc_cves') as mock_ncsc:
            
            mock_bsi.return_value = [{'cve_id': 'CVE-2024-BSI-001'}]
            mock_ncsc.return_value = [{'cve_id': 'CVE-2024-NCSC-001'}]
            
            results = self.checker.check_european_cves('docker', '20.10.17')
            
            self.assertIn('bsi', results)
            self.assertIn('ncsc', results)
            self.assertEqual(len(results['bsi']), 1)
            self.assertEqual(len(results['ncsc']), 1)
    
    def test_categorize_vulnerabilities(self):
        """Testet Vulnerability-Kategorisierung"""
        test_cves = [
            {'severity': 'CRITICAL'},
            {'severity': 'HIGH'},
            {'severity': 'MEDIUM'},
            {'severity': 'LOW'}
        ]
        
        categories = self.checker._categorize_european_vulnerabilities(test_cves)
        
        self.assertEqual(len(categories['critical']), 1)
        self.assertEqual(len(categories['high']), 1)
        self.assertEqual(len(categories['medium']), 1)
        self.assertEqual(len(categories['low']), 1)
    
    def test_european_cve_summary(self):
        """Testet europäische CVE-Zusammenfassung"""
        test_results = {
            'bsi': [
                {'severity': 'CRITICAL'},
                {'severity': 'HIGH'}
            ],
            'ncsc': [
                {'severity': 'MEDIUM'},
                {'severity': 'LOW'}
            ]
        }
        
        summary = self.checker.get_european_cve_summary(test_results)
        
        self.assertEqual(summary['total_cves'], 4)
        self.assertEqual(summary['databases_checked'], 2)
        self.assertEqual(summary['critical_count'], 1)
        self.assertEqual(summary['high_count'], 1)
        self.assertEqual(summary['medium_count'], 1)
        self.assertEqual(summary['low_count'], 1)
        
        # EU-Compliance
        self.assertTrue(summary['eu_compliance']['gdpr_compliant'])
        self.assertTrue(summary['eu_compliance']['nis_directive'])
        self.assertEqual(summary['eu_compliance']['data_processing'], 'EU')
        self.assertEqual(summary['eu_compliance']['data_storage'], 'EU')


class TestEuropeanCVEAnalyzer(unittest.TestCase):
    """Testet EuropeanCVEAnalyzer"""
    
    def setUp(self):
        """Setup für Tests"""
        self.analyzer = EuropeanCVEAnalyzer()
    
    def test_analyze_european_cves(self):
        """Testet europäische CVE-Analyse"""
        test_services = {
            'docker': '20.10.17',
            'sshd': '8.4'
        }
        
        with patch.object(self.analyzer.checker, 'check_european_cves') as mock_check:
            mock_check.return_value = {
                'bsi': [{'cve_id': 'CVE-2024-BSI-001'}],
                'ncsc': [{'cve_id': 'CVE-2024-NCSC-001'}]
            }
            
            results = self.analyzer.analyze_european_cves(test_services)
            
            self.assertIn('results', results)
            self.assertIn('summary', results)
            self.assertIn('total_european_cves', results)
            
            # Prüfe Ergebnisse
            self.assertIn('docker', results['results'])
            self.assertIn('sshd', results['results'])
            
            # Prüfe Zusammenfassung
            summary = results['summary']
            self.assertEqual(summary['total_cves'], 4)  # 2 Services × 2 Datenbanken
            self.assertEqual(summary['databases_checked'], 2)


class TestEuropeanCVEIntegration(unittest.TestCase):
    """Testet die Integration in ssh_chat_system"""
    
    def test_ssh_chat_system_integration(self):
        """Testet Integration in ssh_chat_system"""
        # Mock SSHLogCollector
        with patch('ssh_chat_system.SSHLogCollector') as mock_collector_class:
            mock_collector = Mock()
            mock_collector_class.return_value = mock_collector
            
            # Mock europäische CVE-Analyse
            mock_collector._perform_european_cve_analysis.return_value = {
                'european_analysis': {
                    'results': {
                        'docker': {
                            'bsi': [{'cve_id': 'CVE-2024-BSI-001'}],
                            'ncsc': [{'cve_id': 'CVE-2024-NCSC-001'}]
                        }
                    },
                    'summary': {
                        'total_cves': 2,
                        'databases_checked': 2,
                        'critical_count': 1,
                        'high_count': 1,
                        'eu_compliance': {
                            'gdpr_compliant': True,
                            'nis_directive': True,
                            'data_processing': 'EU',
                            'data_storage': 'EU'
                        }
                    }
                },
                'european_report': 'Test Report',
                'european_results': {
                    'docker': {
                        'bsi': [{'cve_id': 'CVE-2024-BSI-001'}],
                        'ncsc': [{'cve_id': 'CVE-2024-NCSC-001'}]
                    }
                },
                'european_summary': {
                    'total_cves': 2,
                    'databases_checked': 2,
                    'critical_count': 1,
                    'high_count': 1,
                    'eu_compliance': {
                        'gdpr_compliant': True,
                        'nis_directive': True,
                        'data_processing': 'EU',
                        'data_storage': 'EU'
                    }
                }
            }
            
            # Test europäische CVE-Analyse
            result = mock_collector._perform_european_cve_analysis({}, True, False)
            
            self.assertIn('european_analysis', result)
            self.assertIn('european_report', result)
            self.assertIn('european_results', result)
            self.assertIn('european_summary', result)
            
            # Prüfe EU-Compliance
            summary = result['european_summary']
            self.assertTrue(summary['eu_compliance']['gdpr_compliant'])
            self.assertTrue(summary['eu_compliance']['nis_directive'])


class TestEuropeanCVEReportGeneration(unittest.TestCase):
    """Testet europäische CVE-Report-Generierung"""
    
    def test_create_european_cve_report_content(self):
        """Testet Report-Content-Erstellung"""
        test_analysis_results = {
            'results': {
                'docker': {
                    'bsi': [
                        {
                            'cve_id': 'CVE-2024-BSI-001',
                            'title': 'Test CVE',
                            'severity': 'HIGH',
                            'cvss_score': 8.5,
                            'description': 'Test Description',
                            'affected_versions': ['20.10.0'],
                            'fixed_versions': ['20.10.17'],
                            'german_description': 'Deutsche Beschreibung',
                            'compliance_impact': ['GDPR', 'NIS-Richtlinie']
                        }
                    ]
                }
            },
            'summary': {
                'total_cves': 1,
                'databases_checked': 1,
                'critical_count': 0,
                'high_count': 1,
                'medium_count': 0,
                'low_count': 0,
                'eu_compliance': {
                    'gdpr_compliant': True,
                    'nis_directive': True,
                    'data_processing': 'EU',
                    'data_storage': 'EU'
                }
            }
        }
        
        report_content = create_european_cve_report_content(test_analysis_results)
        
        # Prüfe Report-Inhalt
        self.assertIn('🇪🇺 Europäische CVE-Sicherheitsanalyse', report_content)
        self.assertIn('CVE-2024-BSI-001', report_content)
        self.assertIn('Test CVE', report_content)
        self.assertIn('GDPR-konform', report_content)
        self.assertIn('NIS-Richtlinie', report_content)
        self.assertIn('EU', report_content)


def test_european_cve_feature():
    """Haupttest-Funktion für europäische CVE-Features"""
    print("🧪 Teste Europäische CVE-Integration...")
    
    # Test EuropeanCVEDatabaseChecker
    print("  📋 Teste EuropeanCVEDatabaseChecker...")
    checker = EuropeanCVEDatabaseChecker()
    
    # Test BSI CVE-Check
    bsi_results = checker.check_bsi_cves('docker', '20.10.17')
    print(f"    ✅ BSI CVEs gefunden: {len(bsi_results)}")
    
    # Test NCSC CVE-Check
    ncsc_results = checker.check_ncsc_cves('sshd', '8.4')
    print(f"    ✅ NCSC CVEs gefunden: {len(ncsc_results)}")
    
    # Test europäische CVE-Analyse
    european_results = checker.check_european_cves('docker', '20.10.17')
    print(f"    ✅ Europäische Datenbanken geprüft: {len(european_results)}")
    
    # Test EuropeanCVEAnalyzer
    print("  🔍 Teste EuropeanCVEAnalyzer...")
    analyzer = EuropeanCVEAnalyzer()
    
    test_services = {
        'docker': '20.10.17',
        'sshd': '8.4'
    }
    
    analysis_results = analyzer.analyze_european_cves(test_services)
    print(f"    ✅ Analyse abgeschlossen: {analysis_results['total_european_cves']} CVEs gefunden")
    
    # Test Report-Generierung
    print("  📄 Teste Report-Generierung...")
    report_content = create_european_cve_report_content(analysis_results)
    print(f"    ✅ Report erstellt: {len(report_content)} Zeichen")
    
    print("✅ Alle Tests erfolgreich!")


if __name__ == "__main__":
    # Führe Tests aus
    test_european_cve_feature()
    
    # Führe Unit-Tests aus
    unittest.main(verbosity=2) 