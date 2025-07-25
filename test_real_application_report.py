#!/usr/bin/env python3
"""
Test für echte Anwendung - Report-Speicherung
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

def test_real_application_report():
    """Testet die Report-Speicherung wie in der echten Anwendung"""
    
    # Mock system_info wie in der echten Anwendung
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
    
    # Mock log_entries und anomalies (leer für Test)
    log_entries = []
    anomalies = []
    
    console.print("[bold blue]🧪 Teste echte Anwendung - Report-Speicherung...[/bold blue]")
    
    # Test 1: System-Context erstellen (wie in der echten Anwendung)
    console.print("\n[bold]Test 1: System-Context erstellen[/bold]")
    try:
        system_context = create_system_context(system_info, log_entries, anomalies, focus_network_security=False)
        console.print(f"[green]✅ System-Context erstellt (Länge: {len(system_context)} Zeichen)[/green]")
        console.print(f"[dim]📄 Context (erste 500 Zeichen): {system_context[:500]}...[/dim]")
    except Exception as e:
        console.print(f"[red]❌ Fehler bei create_system_context: {e}[/red]")
        return
    
    # Test 2: Report-Prompt erstellen
    console.print("\n[bold]Test 2: Report-Prompt erstellen[/bold]")
    try:
        report_prompt = create_system_report_prompt(system_context)
        console.print(f"[green]✅ Report-Prompt erstellt (Länge: {len(report_prompt)} Zeichen)[/green]")
        console.print(f"[dim]📄 Prompt (erste 300 Zeichen): {report_prompt[:300]}...[/dim]")
    except Exception as e:
        console.print(f"[red]❌ Fehler bei create_system_report_prompt: {e}[/red]")
        return
    
    # Test 3: Modell-Auswahl
    console.print("\n[bold]Test 3: Modell-Auswahl[/bold]")
    try:
        model = select_best_model(complex_analysis=True, for_menu=False)
        console.print(f"[green]✅ Modell ausgewählt: {model}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Fehler bei select_best_model: {e}[/red]")
        return
    
    # Test 4: Ollama-Abfrage (Mock)
    console.print("\n[bold]Test 4: Ollama-Abfrage (Mock)[/bold]")
    try:
        # Mock query_ollama für Test
        def mock_query_ollama(prompt, model=None, complex_analysis=False):
            return """**Systembericht und Maßnahmenkatalog**
==============================

### Schritt 1: Analysiere die Systeminformationen und extrahiere zentrale Ziele, Komponenten, Probleme, Risiken und Abhängigkeiten

| ID | Thema | Beschreibung |
| --- | --- | --- |
| 1.1 | System-Performance | CPU: 15.2%, RAM: 67.8%, Load: 1.45 - System läuft stabil |
| 1.2 | Speicherplatz | Root: 45% Auslastung (225G von 500G) - ausreichend Platz |
| 1.3 | Services | 4 wichtige Services laufen: ssh, docker, nginx, postgresql |
| 1.4 | Docker | 3 Container laufen, 12 Images vorhanden |
| 1.5 | Updates | 23 Updates verfügbar - Wartung erforderlich |

### Schritt 2: Ordne alle Erkenntnisse nach Themenblöcken

#### Infrastruktur
- System läuft stabil mit moderater Auslastung
- Speicherplatz ist ausreichend
- Docker-Umgebung ist aktiv

#### Sicherheit
- SSH-Service läuft
- 3 fehlgeschlagene Root-Login-Versuche

#### Wartung
- 23 System-Updates verfügbar

### Schritt 3: Bewertung nach Impact und Aufwand

| ID | Thema | Impact | Aufwand |
| --- | --- | --- | --- |
| 1.1 | System-Performance | niedrig | niedrig |
| 1.2 | Speicherplatz | niedrig | niedrig |
| 1.3 | Services | mittel | niedrig |
| 1.4 | Docker | mittel | mittel |
| 1.5 | Updates | hoch | mittel |

### Schritt 4: Maßnahmenkatalog

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
        
        report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
        console.print(f"[green]✅ Mock-Report generiert (Länge: {len(report_content)} Zeichen)[/green]")
        
        # Stelle original query_ollama wieder her
        ssh_chat_system.query_ollama = original_query_ollama
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei Mock-Report: {e}[/red]")
        return
    
    # Test 5: Report speichern (wie in der echten Anwendung)
    console.print("\n[bold]Test 5: Report speichern[/bold]")
    try:
        console.print(f"[dim]💾 Speichere Bericht...[/dim]")
        filename = save_system_report(report_content, system_info)
        console.print(f"[green]✅ Bericht erfolgreich gespeichert![/green]")
        console.print(f"[green]📄 Datei: {filename}[/green]")
        
        # Prüfe ob Datei existiert
        if os.path.exists(filename):
            console.print(f"[green]✅ Datei existiert: {filename}[/green]")
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                console.print(f"[dim]📄 Dateiinhalt (erste 300 Zeichen): {content[:300]}...[/dim]")
        else:
            console.print(f"[red]❌ Datei existiert nicht: {filename}[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Fehler beim Speichern des Berichts: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")

if __name__ == "__main__":
    test_real_application_report() 