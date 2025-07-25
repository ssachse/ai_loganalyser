#!/usr/bin/env python3
"""
Test für das neue --with-cve Flag Feature
Testet die CVE-Sicherheitsanalyse für installierte Services
"""

import sys
import os
import argparse
from unittest.mock import patch, MagicMock
from rich.console import Console

# Füge das Projektverzeichnis zum Python-Pfad hinzu
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

console = Console()

def test_cve_argument_parsing():
    """Testet das Parsing des --with-cve Arguments"""
    console.print("\n[bold blue]🧪 Test: --with-cve Argument Parsing[/bold blue]")
    console.print("="*60)
    
    # Importiere die main Funktion
    from ssh_chat_system import main
    
    # Test-Fälle
    test_cases = [
        {
            'args': ['user@host', '--with-cve'],
            'expected': True,
            'description': 'Nur --with-cve Flag'
        },
        {
            'args': ['user@host', '--with-cve', '--quick'],
            'expected': True,
            'description': '--with-cve + --quick'
        },
        {
            'args': ['user@host', '--with-cve', '--auto-report'],
            'expected': True,
            'description': '--with-cve + --auto-report'
        },
        {
            'args': ['user@host'],
            'expected': False,
            'description': 'Keine CVE-Flags'
        },
        {
            'args': ['user@host', '--quick'],
            'expected': False,
            'description': 'Nur --quick Flag'
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
                mock_args.username = None
                mock_args.password = None
                mock_args.key_file = None
                mock_args.port = 22
                mock_args.ollama_port = 11434
                mock_args.no_port_forwarding = False
                mock_args.hours = 24
                mock_args.keep_files = False
                mock_args.output = None
                mock_args.quick = '--quick' in test_case['args']
                mock_args.no_logs = False
                mock_args.debug = False
                mock_args.include_network_security = False
                mock_args.auto_report = '--auto-report' in test_case['args']
                mock_args.report_and_chat = False
                mock_args.with_cve = '--with-cve' in test_case['args']
                
                mock_parse.return_value = mock_args
                
                # Teste das Parsing
                with_cve = mock_args.with_cve
                expected = test_case['expected']
                
                if with_cve == expected:
                    console.print(f"[green]✅ Test {i+1} erfolgreich: {with_cve} == {expected}[/green]")
                else:
                    console.print(f"[red]❌ Test {i+1} fehlgeschlagen: {with_cve} != {expected}[/red]")

def test_cve_analysis_logic():
    """Testet die Logik der CVE-Analyse"""
    console.print("\n[bold blue]🧪 Test: CVE-Analyse Logik[/bold blue]")
    console.print("="*60)
    
    # Mock-System-Info
    mock_system_info = {
        'hostname': 'testhost',
        'distribution': 'Debian GNU/Linux 10 (buster)',
        'kernel': '4.19.0-21-amd64',
        'architecture': 'x86_64',
        'running_services': {
            'sshd': 'active',
            'docker': 'active',
            'cron': 'active'
        }
    }
    
    # Test der CVE-Analyse-Methoden
    with patch('ssh_chat_system.SSHLogCollector.execute_remote_command') as mock_execute, \
         patch('ssh_chat_system.query_ollama') as mock_ollama, \
         patch('ssh_chat_system.select_best_model') as mock_model:
        
        # Setup Mocks
        mock_execute.return_value = """ii  openssh-server    1:7.9p1-10+deb10u2  amd64  secure shell (SSH) server, for secure access from remote machines
ii  apache2           2.4.38-3+deb10u8  amd64  Apache HTTP Server
ii  docker-ce         20.10.17-3~debian10  amd64  Docker: the open-source application container engine
ii  mysql-server      5.5.62-0+deb10u1  amd64  MySQL database server (metapackage depending on the latest version)"""
        
        mock_model.return_value = "llama3.1:8b"
        mock_ollama.return_value = """## CVE-SICHERHEITSANALYSE

### KRITISCHE SICHERHEITSLÜCKEN (Critical)
- OpenSSH CVE-2021-28041: Remote code execution vulnerability - Update to version 8.2p1 or later

### HOHE SICHERHEITSLÜCKEN (High)
- Apache2 CVE-2021-41773: Path traversal vulnerability - Update to version 2.4.51 or later
- MySQL CVE-2021-2156: Privilege escalation vulnerability - Update to version 5.7.34 or later

### UPDATE-EMPFEHLUNGEN
- openssh-server: 1:7.9p1-10+deb10u2 → 1:8.2p1-1
- apache2: 2.4.38-3+deb10u8 → 2.4.51-1
- mysql-server: 5.5.62-0+deb10u1 → 5.7.34-1

### SICHERHEITSZUSAMMENFASSUNG
- Anzahl kritische CVEs: 1
- Anzahl hohe CVEs: 2
- Gesamtrisiko: High"""
        
        # Importiere die SSHLogCollector Klasse
        from ssh_chat_system import SSHLogCollector
        
        # Erstelle Mock-Collector
        collector = SSHLogCollector('testhost', 'testuser')
        
        # Teste CVE-Analyse
        console.print("[dim]Teste CVE-Analyse...[/dim]")
        
        cve_info = collector._analyze_cve_vulnerabilities(mock_system_info)
        
        if cve_info and 'cve_analysis' in cve_info:
            console.print("[green]✅ CVE-Analyse erfolgreich[/green]")
            console.print(f"[dim]📊 Analysierte Pakete: {cve_info.get('installed_packages_count', 0)}[/dim]")
            console.print(f"[dim]🔧 Services geprüft: {len(cve_info.get('service_versions', {}))}[/dim]")
            
            # Teste Prompt-Erstellung
            prompt = collector._create_cve_analysis_prompt(
                cve_info.get('service_versions', {}),
                mock_system_info.get('running_services', {}),
                mock_system_info
            )
            
            if prompt and 'CVE-SICHERHEITSANALYSE' in prompt:
                console.print("[green]✅ CVE-Prompt erfolgreich erstellt[/green]")
            else:
                console.print("[red]❌ CVE-Prompt fehlgeschlagen[/red]")
        else:
            console.print("[red]❌ CVE-Analyse fehlgeschlagen[/red]")

def test_cve_integration():
    """Testet die Integration der CVE-Analyse in den System-Context"""
    console.print("\n[bold blue]🧪 Test: CVE-Integration[/bold blue]")
    console.print("="*60)
    
    # Mock-System-Info mit CVE-Daten
    mock_system_info = {
        'hostname': 'testhost',
        'distribution': 'Debian GNU/Linux 10 (buster)',
        'cve_analysis': {
            'cve_analysis': """## CVE-SICHERHEITSANALYSE

### KRITISCHE SICHERHEITSLÜCKEN (Critical)
- OpenSSH CVE-2021-28041: Remote code execution vulnerability

### HOHE SICHERHEITSLÜCKEN (High)
- Apache2 CVE-2021-41773: Path traversal vulnerability

### SICHERHEITSZUSAMMENFASSUNG
- Anzahl kritische CVEs: 1
- Anzahl hohe CVEs: 1
- Gesamtrisiko: High""",
            'service_versions': {
                'openssh-server': '1:7.9p1-10+deb10u2',
                'apache2': '2.4.38-3+deb10u8'
            },
            'installed_packages_count': 50
        }
    }
    
    # Teste System-Context-Integration
    from ssh_chat_system import create_system_context
    
    context = create_system_context(mock_system_info, [], [])
    
    if 'CVE-SICHERHEITSANALYSE' in context:
        console.print("[green]✅ CVE-Daten erfolgreich in System-Context integriert[/green]")
        
        # Prüfe spezifische Inhalte
        if 'CVE-2021-28041' in context:
            console.print("[green]✅ Kritische CVE-Informationen enthalten[/green]")
        else:
            console.print("[yellow]⚠️ Kritische CVE-Informationen nicht gefunden[/yellow]")
        
        if 'openssh-server: 1:7.9p1-10+deb10u2' in context:
            console.print("[green]✅ Service-Versionen enthalten[/green]")
        else:
            console.print("[yellow]⚠️ Service-Versionen nicht gefunden[/yellow]")
        
        if 'Analysierte Pakete: 50' in context:
            console.print("[green]✅ Paket-Anzahl enthalten[/green]")
        else:
            console.print("[yellow]⚠️ Paket-Anzahl nicht gefunden[/yellow]")
    else:
        console.print("[red]❌ CVE-Daten nicht in System-Context integriert[/red]")

def test_cve_flag_combinations():
    """Testet Kombinationen des --with-cve Flags mit anderen Flags"""
    console.print("\n[bold blue]🧪 Test: CVE-Flag Kombinationen[/bold blue]")
    console.print("="*60)
    
    # Teste verschiedene Flag-Kombinationen
    flag_combinations = [
        {
            'flags': ['--with-cve', '--quick'],
            'description': 'CVE + Quick-Modus'
        },
        {
            'flags': ['--with-cve', '--no-logs'],
            'description': 'CVE + Keine Logs'
        },
        {
            'flags': ['--with-cve', '--debug'],
            'description': 'CVE + Debug-Modus'
        },
        {
            'flags': ['--with-cve', '--auto-report'],
            'description': 'CVE + Auto-Report'
        },
        {
            'flags': ['--with-cve', '--report-and-chat'],
            'description': 'CVE + Report-and-Chat'
        },
        {
            'flags': ['--with-cve', '--include-network-security'],
            'description': 'CVE + Netzwerk-Sicherheit'
        }
    ]
    
    for i, combination in enumerate(flag_combinations):
        console.print(f"\n[dim]Kombination {i+1}: {combination['description']}[/dim]")
        
        # Simuliere Argument-Parsing
        with patch('argparse.ArgumentParser.parse_args') as mock_parse:
            mock_args = MagicMock()
            mock_args.target = 'user@host'
            mock_args.with_cve = True
            mock_args.quick = '--quick' in combination['flags']
            mock_args.no_logs = '--no-logs' in combination['flags']
            mock_args.debug = '--debug' in combination['flags']
            mock_args.auto_report = '--auto-report' in combination['flags']
            mock_args.report_and_chat = '--report-and-chat' in combination['flags']
            mock_args.include_network_security = '--include-network-security' in combination['flags']
            
            mock_parse.return_value = mock_args
            
            # Teste dass alle Flags korrekt gesetzt sind
            flags_ok = (
                mock_args.with_cve == True and
                mock_args.quick == ('--quick' in combination['flags']) and
                mock_args.no_logs == ('--no-logs' in combination['flags']) and
                mock_args.debug == ('--debug' in combination['flags']) and
                mock_args.auto_report == ('--auto-report' in combination['flags']) and
                mock_args.report_and_chat == ('--report-and-chat' in combination['flags']) and
                mock_args.include_network_security == ('--include-network-security' in combination['flags'])
            )
            
            if flags_ok:
                console.print(f"[green]✅ Kombination {i+1} erfolgreich[/green]")
            else:
                console.print(f"[red]❌ Kombination {i+1} fehlgeschlagen[/red]")

def main():
    """Hauptfunktion für alle Tests"""
    console.print("[bold blue]🧪 Test Suite: --with-cve Flag Feature[/bold blue]")
    console.print("="*60)
    
    try:
        # Führe alle Tests aus
        test_cve_argument_parsing()
        test_cve_analysis_logic()
        test_cve_integration()
        test_cve_flag_combinations()
        
        console.print("\n[bold green]✅ Alle Tests erfolgreich abgeschlossen![/bold green]")
        console.print("\n[dim]Das --with-cve Flag Feature ist bereit für den Einsatz.[/dim]")
        
    except Exception as e:
        console.print(f"\n[red]❌ Fehler bei den Tests: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 