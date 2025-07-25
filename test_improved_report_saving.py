#!/usr/bin/env python3
"""
Test für verbesserte Report-Speicherung
"""

import sys
import os
sys.path.append('.')

from ssh_chat_system import (
    save_system_report, create_system_report_prompt, query_ollama, 
    select_best_model, create_system_context
)
from rich.console import Console

console = Console()

def test_improved_report_saving():
    """Testet die verbesserte Report-Speicherung"""
    
    # Test 1: Normale system_info
    console.print("[bold blue]🧪 Teste verbesserte Report-Speicherung...[/bold blue]")
    
    system_info = {
        'hostname': 'test-host',
        'distro_pretty_name': 'Debian GNU/Linux 12 (bookworm)',
        'kernel_version': '6.1.0-13-amd64',
        'architecture': 'x86_64',
        'cpu_info': 'Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz',
        'cpu_cores': '12',
        'memory_total': '32G',
        'uptime': 'up 5 days, 2:30',
        'timezone': 'Europe/Berlin',
        'root_usage_percent': '45%',
        'root_total': '500G',
        'root_used': '225G',
        'root_available': '275G',
        'cpu_usage_percent': '15.2%',
        'memory_usage_percent': '67.8%',
        'load_average_1min': '1.45',
        'package_manager': 'apt',
        'installed_packages_count': '2847',
        'available_updates': '23',
        'important_services_status': {
            'ssh': 'active (running)',
            'docker': 'active (running)',
            'nginx': 'active (running)',
            'postgresql': 'active (running)'
        },
        'current_users': '2 users',
        'user_login_stats': 'admin: 15 logins, user1: 8 logins',
        'failed_logins_by_user': 'root: 3 failed attempts',
        'docker_detected': True,
        'docker_containers': '3 containers running',
        'docker_images': '12 images',
        'kubernetes_detected': False,
        'proxmox_detected': False
    }
    
    # Mock log_entries und anomalies
    log_entries = []
    anomalies = []
    
    console.print("\n[bold]Test 1: Normale system_info[/bold]")
    try:
        test_content = "**Test-Report**\n\nDies ist ein Test-Report mit verbesserter Fehlerbehandlung."
        filename = save_system_report(test_content, system_info)
        console.print(f"[green]✅ Erfolgreich gespeichert: {filename}[/green]")
        
        if os.path.exists(filename):
            console.print(f"[green]✅ Datei existiert: {filename}[/green]")
            # Lösche Test-Datei
            os.remove(filename)
            console.print(f"[dim]🗑️ Test-Datei gelöscht[/dim]")
        else:
            console.print(f"[red]❌ Datei existiert nicht: {filename}[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Fehler: {e}[/red]")
    
    # Test 2: system_info ohne hostname (Fallback-Test)
    console.print("\n[bold]Test 2: system_info ohne hostname (Fallback)[/bold]")
    try:
        system_info_no_hostname = {
            'ssh_host': '192.168.1.100',
            'distro_pretty_name': 'Ubuntu 22.04 LTS',
            'kernel_version': '5.15.0-91-generic'
        }
        
        test_content = "**Test-Report ohne Hostname**\n\nDies ist ein Test-Report ohne hostname."
        filename = save_system_report(test_content, system_info_no_hostname)
        console.print(f"[green]✅ Erfolgreich gespeichert: {filename}[/green]")
        
        if os.path.exists(filename):
            console.print(f"[green]✅ Datei existiert: {filename}[/green]")
            # Lösche Test-Datei
            os.remove(filename)
            console.print(f"[dim]🗑️ Test-Datei gelöscht[/dim]")
        else:
            console.print(f"[red]❌ Datei existiert nicht: {filename}[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Fehler: {e}[/red]")
    
    # Test 3: Fehlerhafte Eingaben
    console.print("\n[bold]Test 3: Fehlerhafte Eingaben[/bold]")
    
    # Test 3a: Leerer report_content
    try:
        filename = save_system_report("", system_info)
        console.print(f"[red]❌ Sollte fehlschlagen: {filename}[/red]")
    except Exception as e:
        console.print(f"[green]✅ Korrekt abgefangen: {e}[/green]")
    
    # Test 3b: Kein system_info
    try:
        filename = save_system_report("Test", {})
        console.print(f"[red]❌ Sollte fehlschlagen: {filename}[/red]")
    except Exception as e:
        console.print(f"[green]✅ Korrekt abgefangen: {e}[/green]")
    
    # Test 3c: Falsche Typen
    try:
        filename = save_system_report(123, system_info)
        console.print(f"[red]❌ Sollte fehlschlagen: {filename}[/red]")
    except Exception as e:
        console.print(f"[green]✅ Korrekt abgefangen: {e}[/green]")
    
    # Test 4: Vollständiger Report mit echten Daten
    console.print("\n[bold]Test 4: Vollständiger Report[/bold]")
    try:
        # Erstelle system_context
        system_context = create_system_context(system_info, log_entries, anomalies, focus_network_security=False)
        
        # Erstelle report_prompt
        report_prompt = create_system_report_prompt(system_context)
        
        # Modell-Auswahl
        model = select_best_model(complex_analysis=True, for_menu=False)
        
        # Mock query_ollama
        def mock_query_ollama(prompt, model=None, complex_analysis=False):
            return """**Systembericht und Maßnahmenkatalog**
==============================

### Schritt 1: Analysiere die Systeminformationen

| ID | Thema | Beschreibung |
| --- | --- | --- |
| 1.1 | System-Performance | CPU: 15.2%, RAM: 67.8%, Load: 1.45 - System läuft stabil |
| 1.2 | Speicherplatz | Root: 45% Auslastung (225G von 500G) - ausreichend Platz |
| 1.3 | Services | 4 wichtige Services laufen: ssh, docker, nginx, postgresql |
| 1.4 | Docker | 3 Container laufen, 12 Images vorhanden |
| 1.5 | Updates | 23 Updates verfügbar - Wartung erforderlich |

### Schritt 2: Maßnahmenkatalog

#### Quick Wins
- System-Updates durchführen (23 verfügbar)
- Docker-Container-Status überprüfen

#### Mid-Term
- Sicherheitsaudit für SSH-Zugriffe
- Docker-Image-Cleanup

#### Long-Term
- Monitoring-System implementieren
- Backup-Strategie überprüfen"""
        
        # Temporär ersetzen
        original_query_ollama = query_ollama
        import ssh_chat_system
        ssh_chat_system.query_ollama = mock_query_ollama
        
        # Generiere Report
        report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
        
        if report_content:
            # Speichere Report
            filename = save_system_report(report_content, system_info)
            console.print(f"[green]✅ Vollständiger Report gespeichert: {filename}[/green]")
            
            if os.path.exists(filename):
                console.print(f"[green]✅ Datei existiert: {filename}[/green]")
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                    console.print(f"[dim]📄 Dateiinhalt (erste 300 Zeichen): {content[:300]}...[/dim]")
                # Lösche Test-Datei
                os.remove(filename)
                console.print(f"[dim]🗑️ Test-Datei gelöscht[/dim]")
            else:
                console.print(f"[red]❌ Datei existiert nicht: {filename}[/red]")
        else:
            console.print(f"[red]❌ Keine Antwort von Ollama erhalten[/red]")
        
        # Stelle original query_ollama wieder her
        ssh_chat_system.query_ollama = original_query_ollama
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei vollständigem Report: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")

if __name__ == "__main__":
    test_improved_report_saving() 