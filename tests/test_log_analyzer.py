#!/usr/bin/env python3
"""
Tests für den macOS Logfile-Analysator
"""

import unittest
import tempfile
import os
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import sys
import shutil

# Füge das Hauptverzeichnis zum Python-Pfad hinzu
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_analyzer import LogAnalyzer, LogEntry, LogLevel, Anomaly
from config import Config


class TestLogLevel(unittest.TestCase):
    """Tests für LogLevel Enum"""
    
    def test_log_level_values(self):
        """Testet LogLevel-Werte"""
        self.assertEqual(LogLevel.INFO.value, "INFO")
        self.assertEqual(LogLevel.WARNING.value, "WARNING")
        self.assertEqual(LogLevel.ERROR.value, "ERROR")
        self.assertEqual(LogLevel.CRITICAL.value, "CRITICAL")


class TestLogEntry(unittest.TestCase):
    """Tests für LogEntry Dataclass"""
    
    def test_log_entry_creation(self):
        """Testet LogEntry-Erstellung"""
        timestamp = datetime.now()
        entry = LogEntry(
            timestamp=timestamp,
            level=LogLevel.ERROR,
            source="test",
            message="Test message",
            raw_line="raw test line",
            priority_score=5.0
        )
        
        self.assertEqual(entry.timestamp, timestamp)
        self.assertEqual(entry.level, LogLevel.ERROR)
        self.assertEqual(entry.source, "test")
        self.assertEqual(entry.message, "Test message")
        self.assertEqual(entry.raw_line, "raw test line")
        self.assertEqual(entry.priority_score, 5.0)


class TestAnomaly(unittest.TestCase):
    """Tests für Anomaly Dataclass"""
    
    def test_anomaly_creation(self):
        """Testet Anomaly-Erstellung"""
        anomaly = Anomaly(
            description="Test anomaly",
            severity=LogLevel.CRITICAL,
            affected_components=["system", "kernel"],
            recommendations=["Restart system", "Check hardware"],
            evidence=["Error log line 1", "Error log line 2"],
            priority_score=15.0
        )
        
        self.assertEqual(anomaly.description, "Test anomaly")
        self.assertEqual(anomaly.severity, LogLevel.CRITICAL)
        self.assertEqual(anomaly.affected_components, ["system", "kernel"])
        self.assertEqual(anomaly.recommendations, ["Restart system", "Check hardware"])
        self.assertEqual(anomaly.evidence, ["Error log line 1", "Error log line 2"])
        self.assertEqual(anomaly.priority_score, 15.0)


class TestLogAnalyzer(unittest.TestCase):
    """Tests für LogAnalyzer Klasse"""
    
    def setUp(self):
        """Setup für jeden Test"""
        self.analyzer = LogAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Cleanup nach jedem Test"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_analyzer_initialization(self):
        """Testet LogAnalyzer-Initialisierung"""
        self.assertEqual(self.analyzer.ollama_url, "http://localhost:11434")
        self.assertEqual(len(self.analyzer.log_entries), 0)
        self.assertEqual(len(self.analyzer.anomalies), 0)
        self.assertIsInstance(self.analyzer.system_info, dict)
    
    @patch('log_analyzer.os.uname')
    @patch('log_analyzer.psutil.cpu_count')
    @patch('log_analyzer.psutil.virtual_memory')
    @patch('log_analyzer.psutil.disk_usage')
    def test_get_system_info(self, mock_disk, mock_memory, mock_cpu, mock_uname):
        """Testet System-Informationen-Sammlung"""
        # Mock-System-Informationen
        mock_uname.return_value = Mock(nodename="test-host", release="22.6.0")
        mock_cpu.return_value = 8
        mock_memory.return_value = Mock(total=16 * 1024**3)  # 16 GB
        mock_disk.return_value = Mock(percent=67.0)
        
        system_info = self.analyzer._get_system_info()
        
        self.assertEqual(system_info["hostname"], "test-host")
        self.assertEqual(system_info["os_version"], "22.6.0")
        self.assertEqual(system_info["cpu_count"], 8)
        self.assertEqual(system_info["memory_total"], 16 * 1024**3)
        self.assertEqual(system_info["disk_usage"], 67.0)
    
    @patch('log_analyzer.requests.get')
    def test_check_ollama_connection_success(self, mock_get):
        """Testet erfolgreiche Ollama-Verbindung"""
        mock_get.return_value = Mock(status_code=200)
        
        result = self.analyzer._check_ollama_connection()
        
        self.assertTrue(result)
        mock_get.assert_called_once_with("http://localhost:11434/api/tags", timeout=5)
    
    @patch('log_analyzer.requests.get')
    def test_check_ollama_connection_failure(self, mock_get):
        """Testet fehlgeschlagene Ollama-Verbindung"""
        mock_get.side_effect = Exception("Connection failed")
        
        result = self.analyzer._check_ollama_connection()
        
        self.assertFalse(result)
    
    def test_parse_log_line_standard_format(self):
        """Testet Parsing von Standard-Log-Format"""
        log_line = "Jan 15 14:30:22 test-host kernel[0]: Test error message"
        entry = self.analyzer._parse_log_line(log_line, "system")
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source, "system")
        self.assertEqual(entry.level, LogLevel.ERROR)
        self.assertIn("Test error message", entry.message)
    
    def test_parse_log_line_iso_format(self):
        """Testet Parsing von ISO-Log-Format"""
        log_line = "2024-01-15 14:30:22 ERROR Test error message"
        entry = self.analyzer._parse_log_line(log_line, "system")
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source, "system")
        self.assertEqual(entry.level, LogLevel.ERROR)
    
    def test_parse_log_line_critical(self):
        """Testet Parsing von kritischen Log-Einträgen"""
        log_line = "Jan 15 14:30:22 test-host kernel panic detected"
        entry = self.analyzer._parse_log_line(log_line, "system")
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.level, LogLevel.CRITICAL)
    
    def test_parse_log_line_warning(self):
        """Testet Parsing von Warnungs-Log-Einträgen"""
        log_line = "Jan 15 14:30:22 test-host WARNING: High memory usage"
        entry = self.analyzer._parse_log_line(log_line, "system")
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.level, LogLevel.WARNING)
    
    def test_calculate_priority_score_critical(self):
        """Testet Prioritäts-Score-Berechnung für kritische Einträge"""
        line = "kernel panic detected in system"
        score = self.analyzer._calculate_priority_score(line, LogLevel.CRITICAL, "system")
        
        self.assertGreater(score, 10.0)  # Mindestens 10 für CRITICAL
    
    def test_calculate_priority_score_security_source(self):
        """Testet Prioritäts-Score-Berechnung für Sicherheits-Logs"""
        line = "authentication failed"
        score = self.analyzer._calculate_priority_score(line, LogLevel.ERROR, "security")
        
        # Sicherheits-Logs haben 1.5x Gewichtung
        self.assertGreater(score, 5.0)
    
    def test_calculate_priority_score_with_keywords(self):
        """Testet Prioritäts-Score-Berechnung mit Schlüsselwörtern"""
        line = "disk full error detected"
        score = self.analyzer._calculate_priority_score(line, LogLevel.ERROR, "system")
        
        # Sollte zusätzliche Punkte für "disk full" bekommen
        self.assertGreater(score, 5.0)
    
    def test_read_log_file(self):
        """Testet Log-Datei-Lesen"""
        # Erstelle temporäre Log-Datei
        log_file = os.path.join(self.temp_dir, "test.log")
        with open(log_file, 'w') as f:
            f.write("Jan 15 14:30:22 test-host ERROR: Test error\n")
            f.write("Jan 15 14:31:22 test-host WARNING: Test warning\n")
        
        self.analyzer._read_log_file(log_file, "test", 24)
        
        self.assertEqual(len(self.analyzer.log_entries), 2)
        self.assertEqual(self.analyzer.log_entries[0].level, LogLevel.ERROR)
        self.assertEqual(self.analyzer.log_entries[1].level, LogLevel.WARNING)
    
    def test_read_log_file_nonexistent(self):
        """Testet Lesen nicht-existierender Log-Datei"""
        self.analyzer._read_log_file("/nonexistent/file.log", "test", 24)
        
        # Sollte keine Fehler werfen und keine Einträge hinzufügen
        self.assertEqual(len(self.analyzer.log_entries), 0)
    
    @patch('log_analyzer.requests.post')
    def test_analyze_with_ollama_success(self, mock_post):
        """Testet erfolgreiche Ollama-Analyse"""
        # Mock-Log-Einträge hinzufügen
        self.analyzer.log_entries = [
            LogEntry(
                timestamp=datetime.now(),
                level=LogLevel.ERROR,
                source="system",
                message="Test error",
                raw_line="Test error",
                priority_score=7.0
            )
        ]
        
        # Mock-Ollama-Antwort
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": json.dumps({
                "anomalies": [
                    {
                        "description": "Test anomaly",
                        "severity": "ERROR",
                        "affected_components": ["system"],
                        "recommendations": ["Fix the issue"],
                        "evidence": ["Test error"]
                    }
                ]
            })
        }
        mock_post.return_value = mock_response
        
        # Mock-Ollama-Verbindung
        with patch.object(self.analyzer, '_check_ollama_connection', return_value=True):
            self.analyzer.analyze_with_ollama()
        
        self.assertEqual(len(self.analyzer.anomalies), 1)
        self.assertEqual(self.analyzer.anomalies[0].description, "Test anomaly")
    
    @patch('log_analyzer.requests.post')
    def test_analyze_with_ollama_failure(self, mock_post):
        """Testet fehlgeschlagene Ollama-Analyse"""
        mock_post.side_effect = Exception("Connection failed")
        
        # Mock-Log-Einträge hinzufügen
        self.analyzer.log_entries = [
            LogEntry(
                timestamp=datetime.now(),
                level=LogLevel.ERROR,
                source="system",
                message="Test error",
                raw_line="Test error",
                priority_score=7.0
            )
        ]
        
        # Mock-Ollama-Verbindung
        with patch.object(self.analyzer, '_check_ollama_connection', return_value=True):
            self.analyzer.analyze_with_ollama()
        
        # Sollte keine Anomalien hinzufügen bei Fehler
        self.assertEqual(len(self.analyzer.anomalies), 0)
    
    def test_calculate_anomaly_priority(self):
        """Testet Anomalie-Prioritäts-Berechnung"""
        anomaly_data = {
            "recommendations": ["Fix 1", "Fix 2"],
            "evidence": ["Evidence 1", "Evidence 2", "Evidence 3"]
        }
        
        score = self.analyzer._calculate_anomaly_priority(LogLevel.CRITICAL, anomaly_data)
        
        # CRITICAL (10) + 2 recommendations (1.0) + 3 evidence (0.9) = 11.9
        self.assertAlmostEqual(score, 11.9, places=1)
    
    def test_create_analysis_prompt(self):
        """Testet Analyse-Prompt-Erstellung"""
        logs = [
            LogEntry(
                timestamp=datetime.now(),
                level=LogLevel.ERROR,
                source="system",
                message="Test error message",
                raw_line="Test error message",
                priority_score=7.0
            )
        ]
        
        prompt = self.analyzer._create_analysis_prompt(logs)
        
        self.assertIn("macOS-Systemadministrator", prompt)
        self.assertIn("Test error message", prompt)
        self.assertIn("JSON-Format", prompt)


class TestConfig(unittest.TestCase):
    """Tests für Config Klasse"""
    
    def test_config_validation(self):
        """Testet Konfigurations-Validierung"""
        self.assertTrue(Config.validate_config())
    
    def test_get_log_sources(self):
        """Testet Log-Quellen-Abruf"""
        sources = Config.get_log_sources()
        self.assertIsInstance(sources, list)
        self.assertGreater(len(sources), 0)
    
    def test_get_critical_keywords(self):
        """Testet kritische Schlüsselwörter"""
        keywords = Config.get_critical_keywords()
        self.assertIn("kernel panic", keywords)
        self.assertIn("fatal", keywords)
    
    def test_get_warning_keywords(self):
        """Testet Warnungs-Schlüsselwörter"""
        keywords = Config.get_warning_keywords()
        self.assertIn("warning", keywords)
        self.assertIn("timeout", keywords)
    
    def test_get_source_weight(self):
        """Testet Quellen-Gewichtung"""
        self.assertEqual(Config.get_source_weight("security"), 1.5)
        self.assertEqual(Config.get_source_weight("filesystem"), 1.3)
        self.assertEqual(Config.get_source_weight("unknown"), 1.0)
    
    def test_get_log_level_score(self):
        """Testet Log-Level-Scores"""
        self.assertEqual(Config.get_log_level_score("CRITICAL"), 10.0)
        self.assertEqual(Config.get_log_level_score("ERROR"), 5.0)
        self.assertEqual(Config.get_log_level_score("WARNING"), 3.0)
        self.assertEqual(Config.get_log_level_score("INFO"), 1.0)
        self.assertEqual(Config.get_log_level_score("UNKNOWN"), 1.0)
    
    def test_get_color(self):
        """Testet Farb-Zuordnung"""
        self.assertEqual(Config.get_color("CRITICAL"), "red")
        self.assertEqual(Config.get_color("ERROR"), "orange")
        self.assertEqual(Config.get_color("WARNING"), "yellow")
        self.assertEqual(Config.get_color("INFO"), "blue")
        self.assertEqual(Config.get_color("UNKNOWN"), "white")


class TestIntegration(unittest.TestCase):
    """Integrationstests"""
    
    def setUp(self):
        """Setup für Integrationstests"""
        self.analyzer = LogAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Cleanup nach Integrationstests"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_full_analysis_workflow(self):
        """Testet vollständigen Analyse-Workflow"""
        # Erstelle Test-Logs
        log_file = os.path.join(self.temp_dir, "system.log")
        with open(log_file, 'w') as f:
            f.write("Jan 15 14:30:22 test-host kernel panic detected\n")
            f.write("Jan 15 14:31:22 test-host WARNING: High memory usage\n")
            f.write("Jan 15 14:32:22 test-host ERROR: Authentication failed\n")
        
        # Sammle Logs
        self.analyzer._read_log_file(log_file, "system", 24)
        
        # Überprüfe Log-Sammlung
        self.assertEqual(len(self.analyzer.log_entries), 3)
        
        # Überprüfe Priorisierung
        critical_logs = [log for log in self.analyzer.log_entries if log.level == LogLevel.CRITICAL]
        self.assertEqual(len(critical_logs), 1)
        self.assertIn("kernel panic", critical_logs[0].message)
        
        # Überprüfe Prioritäts-Scores
        scores = [log.priority_score for log in self.analyzer.log_entries]
        self.assertTrue(max(scores) >= 10.0)  # Mindestens ein kritischer Score
    
    @patch('log_analyzer.requests.post')
    def test_ollama_integration(self, mock_post):
        """Testet Ollama-Integration"""
        # Mock-Logs
        self.analyzer.log_entries = [
            LogEntry(
                timestamp=datetime.now(),
                level=LogLevel.CRITICAL,
                source="system",
                message="kernel panic detected",
                raw_line="kernel panic detected",
                priority_score=15.0
            )
        ]
        
        # Mock-Ollama-Antwort
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": json.dumps({
                "anomalies": [
                    {
                        "description": "Kernel panic detected",
                        "severity": "CRITICAL",
                        "affected_components": ["kernel", "system"],
                        "recommendations": ["Restart system", "Check hardware"],
                        "evidence": ["kernel panic detected"]
                    }
                ],
                "summary": "Critical kernel panic detected"
            })
        }
        mock_post.return_value = mock_response
        
        # Mock-Ollama-Verbindung
        with patch.object(self.analyzer, '_check_ollama_connection', return_value=True):
            self.analyzer.analyze_with_ollama()
        
        # Überprüfe Ergebnisse
        self.assertEqual(len(self.analyzer.anomalies), 1)
        anomaly = self.analyzer.anomalies[0]
        self.assertEqual(anomaly.description, "Kernel panic detected")
        self.assertEqual(anomaly.severity, LogLevel.CRITICAL)
        self.assertIn("kernel", anomaly.affected_components)
        self.assertIn("Restart system", anomaly.recommendations)


if __name__ == '__main__':
    # Erstelle Test-Verzeichnis falls es nicht existiert
    os.makedirs('tests', exist_ok=True)
    
    # Führe Tests aus
    unittest.main(verbosity=2) 