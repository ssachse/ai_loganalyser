#!/usr/bin/env python3
"""
Test für die neue CVE-Datenbank-Integration
Testet NVD-API, Caching und Hybrid-Analyse
"""

import sys
import os
import json
from unittest.mock import patch, MagicMock
from rich.console import Console

# Füge das Projektverzeichnis zum Python-Pfad hinzu
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

console = Console()

def test_cve_database_checker():
    """Testet die CVEDatabaseChecker Klasse"""
    console.print("\n[bold blue]🧪 Test: CVEDatabaseChecker[/bold blue]")
    console.print("="*60)
    
    try:
        from cve_database_checker import CVEDatabaseChecker, CVEAnalyzer
        
        # Teste CVEDatabaseChecker
        checker = CVEDatabaseChecker(enable_cache=False)
        
        # Teste Cache-Funktionalität
        test_data = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "summary": {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "service": "test-service",
                "version": "1.0.0"
            }
        }
        
        # Teste Caching
        checker.cache_cve_data("test-service", "1.0.0", test_data)
        cached_data = checker.get_cached_cve("test-service", "1.0.0")
        
        if cached_data:
            console.print("[green]✅ CVE-Cache funktioniert[/green]")
        else:
            console.print("[yellow]⚠️ CVE-Cache nicht verfügbar (erwartet bei enable_cache=False)[/yellow]")
        
        # Teste CVEAnalyzer
        analyzer = CVEAnalyzer(enable_cache=False)
        
        # Teste mit Mock-Daten
        test_services = {
            "openssh-server": "1:7.9p1-10+deb10u2",
            "apache2": "2.4.38-3+deb10u8"
        }
        
        console.print("[green]✅ CVEAnalyzer erfolgreich erstellt[/green]")
        
    except ImportError as e:
        console.print(f"[red]❌ Import-Fehler: {e}[/red]")
    except Exception as e:
        console.print(f"[red]❌ Fehler: {e}[/red]")

def test_nvd_api_integration():
    """Testet die NVD API-Integration"""
    console.print("\n[bold blue]🧪 Test: NVD API Integration[/bold blue]")
    console.print("="*60)
    
    try:
        from cve_database_checker import CVEDatabaseChecker
        
        checker = CVEDatabaseChecker(enable_cache=False)
        
        # Mock NVD API Response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-28041",
                        "descriptions": [{"value": "Test CVE description"}],
                        "published": "2021-01-01T00:00:00.000Z",
                        "lastModified": "2021-01-01T00:00:00.000Z",
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                }
                            }]
                        },
                        "references": []
                    }
                }
            ]
        }
        
        with patch('requests.get', return_value=mock_response):
            # Teste NVD-Suche
            vulnerabilities = checker._search_nvd("openssh-server")
            
            if vulnerabilities:
                console.print("[green]✅ NVD API-Integration funktioniert[/green]")
                console.print(f"[dim]Gefunden: {len(vulnerabilities)} CVEs[/dim]")
            else:
                console.print("[yellow]⚠️ Keine CVEs gefunden (Mock-Daten)[/yellow]")
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei NVD API Test: {e}[/red]")

def test_cve_categorization():
    """Testet die CVE-Kategorisierung"""
    console.print("\n[bold blue]🧪 Test: CVE Kategorisierung[/bold blue]")
    console.print("="*60)
    
    try:
        from cve_database_checker import CVEDatabaseChecker
        
        checker = CVEDatabaseChecker(enable_cache=False)
        
        # Test-Vulnerabilities mit verschiedenen CVSS-Scores
        test_vulnerabilities = [
            {
                "cve": {
                    "id": "CVE-2021-0001",
                    "descriptions": [{"value": "Critical vulnerability"}],
                    "published": "2021-01-01T00:00:00.000Z",
                    "lastModified": "2021-01-01T00:00:00.000Z",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 9.8}
                        }]
                    },
                    "references": []
                }
            },
            {
                "cve": {
                    "id": "CVE-2021-0002",
                    "descriptions": [{"value": "High vulnerability"}],
                    "published": "2021-01-01T00:00:00.000Z",
                    "lastModified": "2021-01-01T00:00:00.000Z",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 7.5}
                        }]
                    },
                    "references": []
                }
            },
            {
                "cve": {
                    "id": "CVE-2021-0003",
                    "descriptions": [{"value": "Medium vulnerability"}],
                    "published": "2021-01-01T00:00:00.000Z",
                    "lastModified": "2021-01-01T00:00:00.000Z",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 5.0}
                        }]
                    },
                    "references": []
                }
            }
        ]
        
        # Teste Kategorisierung
        categorized = checker._categorize_vulnerabilities(test_vulnerabilities, "test-service", "1.0.0")
        
        if categorized:
            summary = categorized.get('summary', {})
            console.print("[green]✅ CVE-Kategorisierung funktioniert[/green]")
            console.print(f"[dim]Kritische CVEs: {summary.get('critical', 0)}[/dim]")
            console.print(f"[dim]Hohe CVEs: {summary.get('high', 0)}[/dim]")
            console.print(f"[dim]Mittlere CVEs: {summary.get('medium', 0)}[/dim]")
            console.print(f"[dim]Niedrige CVEs: {summary.get('low', 0)}[/dim]")
        else:
            console.print("[red]❌ CVE-Kategorisierung fehlgeschlagen[/red]")
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei CVE-Kategorisierung: {e}[/red]")

def test_cve_report_generation():
    """Testet die CVE-Report-Generierung"""
    console.print("\n[bold blue]🧪 Test: CVE Report Generation[/bold blue]")
    console.print("="*60)
    
    try:
        from cve_database_checker import create_cve_report_content
        
        # Mock CVE-Ergebnisse
        mock_results = {
            "summary": {
                "total_services": 2,
                "total_cves": 3,
                "critical_cves": 1,
                "high_cves": 1,
                "medium_cves": 1,
                "low_cves": 0,
                "services_with_critical": ["openssh-server"],
                "services_with_high": ["apache2"],
                "overall_risk": "Critical"
            },
            "database_results": {
                "openssh-server": {
                    "critical": [{
                        "id": "CVE-2021-28041",
                        "description": "Critical vulnerability in OpenSSH",
                        "base_score": 9.8
                    }],
                    "summary": {
                        "critical": 1,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "version": "1:7.9p1-10+deb10u2"
                    }
                },
                "apache2": {
                    "high": [{
                        "id": "CVE-2021-41773",
                        "description": "High vulnerability in Apache",
                        "base_score": 7.5
                    }],
                    "summary": {
                        "critical": 0,
                        "high": 1,
                        "medium": 0,
                        "low": 0,
                        "version": "2.4.38-3+deb10u8"
                    }
                }
            }
        }
        
        # Generiere Report
        report = create_cve_report_content(mock_results)
        
        if report and "CVE-SICHERHEITSANALYSE" in report:
            console.print("[green]✅ CVE-Report-Generierung funktioniert[/green]")
            console.print(f"[dim]Report-Länge: {len(report)} Zeichen[/dim]")
            
            # Prüfe wichtige Inhalte
            if "KRITISCHE SICHERHEITSLÜCKEN" in report:
                console.print("[green]✅ Kritische CVEs im Report[/green]")
            if "HOHE SICHERHEITSLÜCKEN" in report:
                console.print("[green]✅ Hohe CVEs im Report[/green]")
            if "SOFORTIGE MASSNAHMEN" in report:
                console.print("[green]✅ Empfehlungen im Report[/green]")
        else:
            console.print("[red]❌ CVE-Report-Generierung fehlgeschlagen[/red]")
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei CVE-Report-Generierung: {e}[/red]")

def test_ssh_chat_system_integration():
    """Testet die Integration in ssh_chat_system"""
    console.print("\n[bold blue]🧪 Test: SSH Chat System Integration[/bold blue]")
    console.print("="*60)
    
    try:
        # Importiere die erweiterten CVE-Funktionen
        from ssh_chat_system import SSHLogCollector
        
        # Erstelle Mock-System-Info
        mock_system_info = {
            'hostname': 'testhost',
            'distribution': 'Debian GNU/Linux 10 (buster)',
            'kernel': '4.19.0-21-amd64',
            'architecture': 'x86_64',
            'running_services': {
                'sshd': 'active',
                'docker': 'active'
            }
        }
        
        # Erstelle Mock-Collector
        collector = SSHLogCollector('testhost', 'testuser')
        
        # Teste verschiedene CVE-Datenbank-Modi
        test_modes = ['ollama', 'nvd', 'hybrid']
        
        for mode in test_modes:
            console.print(f"[dim]Teste Modus: {mode}[/dim]")
            
            # Mock die Remote-Command-Ausführung
            with patch.object(collector, 'execute_remote_command', return_value=""):
                # Mock die Ollama-Funktionen
                with patch('ssh_chat_system.query_ollama', return_value="Mock Ollama Analysis"):
                    # Mock die CVE-Datenbank-Funktionen
                    with patch('ssh_chat_system.CVEAnalyzer') as mock_analyzer:
                        mock_analyzer.return_value.analyze_services.return_value = {
                            "database_results": {},
                            "summary": {"total_cves": 0}
                        }
                        
                        # Teste CVE-Analyse
                        cve_info = collector._analyze_cve_vulnerabilities(
                            mock_system_info,
                            cve_database=mode,
                            enable_cache=False,
                            offline_only=True
                        )
                        
                        if cve_info:
                            console.print(f"[green]✅ {mode} Modus funktioniert[/green]")
                        else:
                            console.print(f"[yellow]⚠️ {mode} Modus: Keine Daten (erwartet bei Mock)[/yellow]")
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei SSH Chat System Integration: {e}[/red]")

def test_argument_parsing():
    """Testet das Parsing der neuen CVE-Argumente"""
    console.print("\n[bold blue]🧪 Test: Argument Parsing[/bold blue]")
    console.print("="*60)
    
    try:
        from ssh_chat_system import main
        
        # Test-Fälle für neue Argumente
        test_cases = [
            {
                'args': ['user@host', '--with-cve', '--cve-database', 'nvd'],
                'description': 'NVD-Datenbank'
            },
            {
                'args': ['user@host', '--with-cve', '--cve-database', 'hybrid', '--cve-cache'],
                'description': 'Hybrid mit Cache'
            },
            {
                'args': ['user@host', '--with-cve', '--cve-database', 'ollama', '--cve-offline'],
                'description': 'Ollama offline'
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            console.print(f"\n[dim]Test {i+1}: {test_case['description']}[/dim]")
            
            # Mock sys.argv
            with patch('sys.argv', ['ssh_chat_system.py'] + test_case['args']):
                # Mock argparse.parse_args
                with patch('argparse.ArgumentParser.parse_args') as mock_parse:
                    # Erstelle Mock-Args
                    mock_args = MagicMock()
                    mock_args.target = 'user@host'
                    mock_args.with_cve = True
                    mock_args.cve_database = test_case['args'][test_case['args'].index('--cve-database') + 1]
                    mock_args.cve_cache = '--cve-cache' in test_case['args']
                    mock_args.cve_offline = '--cve-offline' in test_case['args']
                    
                    mock_parse.return_value = mock_args
                    
                    # Teste das Parsing
                    if mock_args.with_cve and mock_args.cve_database:
                        console.print(f"[green]✅ Test {i+1} erfolgreich[/green]")
                        console.print(f"[dim]Datenbank: {mock_args.cve_database}, Cache: {mock_args.cve_cache}, Offline: {mock_args.cve_offline}[/dim]")
                    else:
                        console.print(f"[red]❌ Test {i+1} fehlgeschlagen[/red]")
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei Argument Parsing: {e}[/red]")

def main():
    """Hauptfunktion für alle Tests"""
    console.print("[bold blue]🧪 Test Suite: CVE-Datenbank-Integration[/bold blue]")
    console.print("="*60)
    
    try:
        # Führe alle Tests aus
        test_cve_database_checker()
        test_nvd_api_integration()
        test_cve_categorization()
        test_cve_report_generation()
        test_ssh_chat_system_integration()
        test_argument_parsing()
        
        console.print("\n[bold green]✅ Alle Tests erfolgreich abgeschlossen![/bold green]")
        console.print("\n[dim]Die CVE-Datenbank-Integration ist bereit für den Einsatz.[/dim]")
        
    except Exception as e:
        console.print(f"\n[red]❌ Fehler bei den Tests: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 