#!/usr/bin/env python3
"""
Tests für den SSH-Log-Collector
"""

import unittest
import tempfile
import os
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock, mock_open
import sys
import shutil

# Füge das Hauptverzeichnis zum Python-Pfad hinzu
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssh_log_collector import SSHLogCollector, LinuxLogAnalyzer
from log_analyzer import LogEntry, LogLevel


class TestSSHLogCollector(unittest.TestCase):
    """Tests für SSHLogCollector Klasse"""
    
    def setUp(self):
        """Setup für jeden Test"""
        self.collector = SSHLogCollector(
            host="test-host",
            username="testuser",
            password="testpass",
            port=22
        )
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Cleanup nach jedem Test"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        if hasattr(self, 'collector') and self.collector.temp_dir:
            shutil.rmtree(self.collector.temp_dir, ignore_errors=True)
    
    def test_collector_initialization(self):
        """Testet SSHLogCollector-Initialisierung"""
        self.assertEqual(self.collector.host, "test-host")
        self.assertEqual(self.collector.username, "testuser")
        self.assertEqual(self.collector.password, "testpass")
        self.assertEqual(self.collector.port, 22)
        self.assertIsNone(self.collector.ssh_client)
        self.assertIsNone(self.collector.sftp_client)
    
    @patch('ssh_log_collector.paramiko.SSHClient')
    def test_connect_success(self, mock_ssh_client):
        """Testet erfolgreiche SSH-Verbindung"""
        # Mock SSH-Client
        mock_client = Mock()
        mock_ssh_client.return_value = mock_client
        
        # Mock erfolgreiche Verbindung
        mock_stdin = Mock()
        mock_stdout = Mock()
        mock_stderr = Mock()
        mock_stdout.read.return_value = b"SSH connection successful"
        mock_stdout.channel.recv_exit_status.return_value = 0
        
        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)
        mock_client.open_sftp.return_value = Mock()
        
        result = self.collector.connect()
        
        self.assertTrue(result)
        mock_client.connect.assert_called_once()
        mock_client.set_missing_host_key_policy.assert_called_once()
    
    @patch('ssh_log_collector.paramiko.SSHClient')
    def test_connect_failure(self, mock_ssh_client):
        """Testet fehlgeschlagene SSH-Verbindung"""
        # Mock SSH-Client mit Fehler
        mock_client = Mock()
        mock_ssh_client.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection failed")
        
        result = self.collector.connect()
        
        self.assertFalse(result)
    
    @patch('ssh_log_collector.paramiko.SSHClient')
    def test_get_system_info(self, mock_ssh_client):
        """Testet System-Informationen-Sammlung"""
        # Mock SSH-Client
        mock_client = Mock()
        mock_ssh_client.return_value = mock_client
        self.collector.ssh_client = mock_client
        
        # Mock-Befehle
        commands = {
            'hostname': 'test-hostname',
            'os_version': 'Ubuntu 20.04.3 LTS',
            'kernel_version': '5.4.0-74-generic',
            'cpu_cores': '8',
            'memory_total': '16G',
            'disk_usage': '67%',
            'uptime': '2 days, 3 hours, 45 minutes',
        }
        
        def mock_exec_command(command):
            mock_stdin = Mock()
            mock_stdout = Mock()
            mock_stderr = Mock()
            
            # Simuliere verschiedene Befehle
            for key, value in commands.items():
                if key in command:
                    mock_stdout.read.return_value = value.encode('utf-8')
                    break
            else:
                mock_stdout.read.return_value = b""
            
            return mock_stdin, mock_stdout, mock_stderr
        
        mock_client.exec_command.side_effect = mock_exec_command
        
        system_info = self.collector.get_system_info()
        
        self.assertIsInstance(system_info, dict)
        self.assertEqual(system_info['hostname'], 'test-hostname')
        self.assertEqual(system_info['os_version'], 'Ubuntu 20.04.3 LTS')
        self.assertEqual(system_info['kernel_version'], '5.4.0-74-generic')
    
    @patch('ssh_log_collector.paramiko.SSHClient')
    def test_collect_logs(self, mock_ssh_client):
        """Testet Log-Sammlung"""
        # Mock SSH-Client
        mock_client = Mock()
        mock_ssh_client.return_value = mock_client
        self.collector.ssh_client = mock_client
        
        # Mock-Befehle für Log-Sammlung
        def mock_exec_command(command):
            mock_stdin = Mock()
            mock_stdout = Mock()
            mock_stderr = Mock()
            
            if 'test -f' in command:
                mock_stdout.read.return_value = b"exists"
            elif 'tail' in command:
                mock_stdout.read.return_value = b"2024-01-15 14:30:22 ERROR Test error\n2024-01-15 14:31:22 WARNING Test warning"
            else:
                mock_stdout.read.return_value = b""
            
            return mock_stdin, mock_stdout, mock_stderr
        
        mock_client.exec_command.side_effect = mock_exec_command
        
        # Mock temporäres Verzeichnis
        with patch('tempfile.mkdtemp', return_value=self.temp_dir):
            with patch('os.path.exists', return_value=True):
                result = self.collector.collect_logs(hours_back=24)
        
        self.assertEqual(result, self.temp_dir)
    
    def test_create_archive(self):
        """Testet Archiv-Erstellung"""
        # Erstelle temporäres Verzeichnis mit Test-Dateien
        test_dir = os.path.join(self.temp_dir, "test_logs")
        os.makedirs(test_dir)
        
        # Erstelle Test-Dateien
        test_files = ["system.log", "auth.log", "kernel.log"]
        for file in test_files:
            with open(os.path.join(test_dir, file), 'w') as f:
                f.write(f"Test content for {file}")
        
        self.collector.temp_dir = test_dir
        
        archive_path = self.collector.create_archive()
        
        self.assertIsNotNone(archive_path)
        self.assertTrue(os.path.exists(archive_path))
        self.assertTrue(archive_path.endswith('.tar.gz'))
    
    def test_cleanup(self):
        """Testet Cleanup-Funktionalität"""
        # Erstelle temporäres Verzeichnis
        test_dir = os.path.join(self.temp_dir, "test_cleanup")
        os.makedirs(test_dir)
        
        # Erstelle Test-Datei
        test_file = os.path.join(test_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("Test content")
        
        self.collector.temp_dir = test_dir
        
        # Überprüfe dass Verzeichnis existiert
        self.assertTrue(os.path.exists(test_dir))
        
        # Führe Cleanup aus
        self.collector.cleanup()
        
        # Überprüfe dass Verzeichnis gelöscht wurde
        self.assertFalse(os.path.exists(test_dir))


class TestLinuxLogAnalyzer(unittest.TestCase):
    """Tests für LinuxLogAnalyzer Klasse"""
    
    def setUp(self):
        """Setup für jeden Test"""
        self.analyzer = LinuxLogAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Cleanup nach jedem Test"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_analyzer_initialization(self):
        """Testet LinuxLogAnalyzer-Initialisierung"""
        self.assertEqual(self.analyzer.ollama_url, "http://localhost:11434")
        self.assertEqual(len(self.analyzer.log_entries), 0)
        self.assertEqual(len(self.analyzer.anomalies), 0)
        self.assertEqual(self.analyzer.linux_system_info, {})
    
    def test_determine_log_source(self):
        """Testet Log-Quellen-Bestimmung"""
        test_cases = [
            ("auth.log", "security"),
            ("secure", "security"),
            ("kernel.log", "kernel"),
            ("syslog", "system"),
            ("apache_access.log", "web"),
            ("nginx_error.log", "web"),
            ("mysql_error.log", "database"),
            ("mail.log", "mail"),
            ("cron", "cron"),
            ("journalctl_0.log", "systemd"),
            ("network_interfaces.txt", "network"),
            ("process_processes.txt", "processes"),
            ("unknown.log", "unknown"),
        ]
        
        for filename, expected_source in test_cases:
            source = self.analyzer._determine_log_source(filename)
            self.assertEqual(source, expected_source, f"Failed for {filename}")
    
    def test_parse_linux_log_line_standard_format(self):
        """Testet Parsing von Standard-Linux-Log-Format"""
        log_line = "Jan 15 14:30:22 test-host kernel[0]: Test error message"
        entry = self.analyzer._parse_linux_log_line(log_line, "system", "test.log", 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source, "system")
        self.assertEqual(entry.level, LogLevel.ERROR)
        self.assertIn("Test error message", entry.message)
    
    def test_parse_linux_log_line_iso_format(self):
        """Testet Parsing von ISO-Log-Format"""
        log_line = "2024-01-15 14:30:22 ERROR Test error message"
        entry = self.analyzer._parse_linux_log_line(log_line, "system", "test.log", 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source, "system")
        self.assertEqual(entry.level, LogLevel.ERROR)
    
    def test_parse_linux_log_line_critical(self):
        """Testet Parsing von kritischen Linux-Log-Einträgen"""
        log_line = "Jan 15 14:30:22 test-host kernel panic detected"
        entry = self.analyzer._parse_linux_log_line(log_line, "kernel", "test.log", 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.level, LogLevel.CRITICAL)
    
    def test_parse_linux_log_line_warning(self):
        """Testet Parsing von Warnungs-Linux-Log-Einträgen"""
        log_line = "Jan 15 14:30:22 test-host WARNING: High memory usage"
        entry = self.analyzer._parse_linux_log_line(log_line, "system", "test.log", 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.level, LogLevel.WARNING)
    
    def test_calculate_linux_priority_score_critical(self):
        """Testet Prioritäts-Score-Berechnung für kritische Linux-Einträge"""
        line = "kernel panic detected in system"
        score = self.analyzer._calculate_linux_priority_score(line, LogLevel.CRITICAL, "kernel")
        
        self.assertGreater(score, 10.0)  # Mindestens 10 für CRITICAL
    
    def test_calculate_linux_priority_score_security_source(self):
        """Testet Prioritäts-Score-Berechnung für Sicherheits-Logs"""
        line = "authentication failed"
        score = self.analyzer._calculate_linux_priority_score(line, LogLevel.ERROR, "security")
        
        # Sicherheits-Logs haben 1.8x Gewichtung
        self.assertGreater(score, 5.0)
    
    def test_calculate_linux_priority_score_with_keywords(self):
        """Testet Prioritäts-Score-Berechnung mit Linux-Schlüsselwörtern"""
        line = "out of memory error detected"
        score = self.analyzer._calculate_linux_priority_score(line, LogLevel.ERROR, "system")
        
        # Sollte zusätzliche Punkte für "out of memory" bekommen
        self.assertGreater(score, 5.0)
    
    def test_analyze_linux_logs(self):
        """Testet Linux-Log-Analyse"""
        # Erstelle Test-Log-Dateien
        log_files = [
            ("system.log", "Jan 15 14:30:22 test-host ERROR: Test error\nJan 15 14:31:22 test-host WARNING: Test warning"),
            ("auth.log", "Jan 15 14:32:22 test-host authentication failed"),
            ("kernel.log", "Jan 15 14:33:22 test-host kernel panic detected"),
        ]
        
        for filename, content in log_files:
            file_path = os.path.join(self.temp_dir, filename)
            with open(file_path, 'w') as f:
                f.write(content)
        
        system_info = {
            'hostname': 'test-host',
            'os_version': 'Ubuntu 20.04',
            'kernel_version': '5.4.0-74-generic',
        }
        
        self.analyzer.analyze_linux_logs(self.temp_dir, system_info)
        
        # Überprüfe dass Logs analysiert wurden
        self.assertGreater(len(self.analyzer.log_entries), 0)
        
        # Überprüfe verschiedene Log-Quellen
        sources = [entry.source for entry in self.analyzer.log_entries]
        self.assertIn('system', sources)
        self.assertIn('security', sources)
        self.assertIn('kernel', sources)
        
        # Überprüfe Log-Level
        levels = [entry.level for entry in self.analyzer.log_entries]
        self.assertIn(LogLevel.ERROR, levels)
        self.assertIn(LogLevel.WARNING, levels)
        self.assertIn(LogLevel.CRITICAL, levels)
    
    def test_create_linux_analysis_prompt(self):
        """Testet Linux-Analyse-Prompt-Erstellung"""
        # Mock-Logs
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
        
        # Mock-System-Informationen
        self.analyzer.linux_system_info = {
            'hostname': 'test-host',
            'os_version': 'Ubuntu 20.04',
            'kernel_version': '5.4.0-74-generic',
        }
        
        prompt = self.analyzer._create_linux_analysis_prompt(logs)
        
        self.assertIn("Linux-Systemadministrator", prompt)
        self.assertIn("Test error message", prompt)
        self.assertIn("test-host", prompt)
        self.assertIn("Ubuntu 20.04", prompt)
        self.assertIn("JSON-Format", prompt)


class TestIntegration(unittest.TestCase):
    """Integrationstests für SSH-Log-Collector"""
    
    def setUp(self):
        """Setup für Integrationstests"""
        self.collector = SSHLogCollector(
            host="test-host",
            username="testuser",
            password="testpass"
        )
        self.analyzer = LinuxLogAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Cleanup nach Integrationstests"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        if hasattr(self, 'collector') and self.collector.temp_dir:
            shutil.rmtree(self.collector.temp_dir, ignore_errors=True)
    
    @patch('ssh_log_collector.paramiko.SSHClient')
    def test_full_workflow(self, mock_ssh_client):
        """Testet vollständigen Workflow"""
        # Mock SSH-Client
        mock_client = Mock()
        mock_ssh_client.return_value = mock_client
        self.collector.ssh_client = mock_client
        
        # Mock-System-Informationen
        def mock_exec_command(command):
            mock_stdin = Mock()
            mock_stdout = Mock()
            mock_stderr = Mock()
            
            if 'hostname' in command:
                mock_stdout.read.return_value = b"test-host"
            elif 'os-release' in command:
                mock_stdout.read.return_value = b"Ubuntu 20.04.3 LTS"
            elif 'uname -r' in command:
                mock_stdout.read.return_value = b"5.4.0-74-generic"
            elif 'test -f' in command:
                mock_stdout.read.return_value = b"exists"
            elif 'tail' in command:
                mock_stdout.read.return_value = b"2024-01-15 14:30:22 ERROR Test error"
            else:
                mock_stdout.read.return_value = b""
            
            return mock_stdin, mock_stdout, mock_stderr
        
        mock_client.exec_command.side_effect = mock_exec_command
        
        # Mock-Verbindung
        mock_client.open_sftp.return_value = Mock()
        
        # Teste Verbindung
        result = self.collector.connect()
        self.assertTrue(result)
        
        # Sammle System-Informationen
        system_info = self.collector.get_system_info()
        self.assertEqual(system_info['hostname'], 'test-host')
        
        # Sammle Logs
        with patch('tempfile.mkdtemp', return_value=self.temp_dir):
            with patch('os.path.exists', return_value=True):
                log_dir = self.collector.collect_logs(hours_back=24)
        
        self.assertEqual(log_dir, self.temp_dir)
        
        # Analysiere Logs
        self.analyzer.analyze_linux_logs(log_dir, system_info)
        
        # Überprüfe Ergebnisse
        self.assertGreater(len(self.analyzer.log_entries), 0)
        
        # Überprüfe dass Logs korrekt kategorisiert wurden
        error_logs = [log for log in self.analyzer.log_entries if log.level == LogLevel.ERROR]
        self.assertGreater(len(error_logs), 0)
    
    def test_archive_creation_and_cleanup(self):
        """Testet Archiv-Erstellung und Cleanup"""
        # Erstelle Test-Logs
        test_logs_dir = os.path.join(self.temp_dir, "test_logs")
        os.makedirs(test_logs_dir)
        
        # Erstelle verschiedene Log-Dateien
        log_files = {
            "system.log": "System log content",
            "auth.log": "Auth log content",
            "kernel.log": "Kernel log content",
        }
        
        for filename, content in log_files.items():
            with open(os.path.join(test_logs_dir, filename), 'w') as f:
                f.write(content)
        
        self.collector.temp_dir = test_logs_dir
        
        # Erstelle Archiv
        archive_path = self.collector.create_archive()
        
        # Überprüfe Archiv
        self.assertIsNotNone(archive_path)
        self.assertTrue(os.path.exists(archive_path))
        
        # Teste Archiv-Inhalt
        import tarfile
        with tarfile.open(archive_path, 'r:gz') as tar:
            members = tar.getmembers()
            self.assertGreater(len(members), 0)
        
        # Teste Cleanup
        self.collector.cleanup()
        self.assertFalse(os.path.exists(test_logs_dir))


if __name__ == '__main__':
    # Erstelle Test-Verzeichnis falls es nicht existiert
    os.makedirs('tests', exist_ok=True)
    
    # Führe Tests aus
    unittest.main(verbosity=2) 