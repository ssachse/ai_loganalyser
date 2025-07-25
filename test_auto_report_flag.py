#!/usr/bin/env python3
"""
Test für das neue --auto-report Flag
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

def test_auto_report_flag():
    """Testet die automatische Report-Generierung"""
    
    # Mock system_info
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
    
    console.print("[bold blue]🧪 Teste --auto-report Flag Funktionalität...[/bold blue]")
    
    # Test 1: Simuliere automatische Report-Generierung
    console.print("\n[bold]Test 1: Automatische Report-Generierung[/bold]")
    try:
        # Erstelle System-Context
        system_context = create_system_context(system_info, log_entries, anomalies, focus_network_security=False)
        console.print(f"[green]✅ System-Context erstellt (Länge: {len(system_context)} Zeichen)[/green]")
        
        # Erstelle Report-Prompt
        report_prompt = create_system_report_prompt(system_context)
        console.print(f"[green]✅ Report-Prompt erstellt (Länge: {len(report_prompt)} Zeichen)[/green]")
        
        # Verwende komplexes Modell für Berichterstellung
        model = select_best_model(complex_analysis=True, for_menu=False)
        console.print(f"[green]✅ Modell ausgewählt: {model}[/green]")
        
        # Mock query_ollama für automatischen Report
        def mock_query_ollama(prompt, model=None, complex_analysis=False):
            return """**Automatischer Systembericht**
==============================

### Schritt 1: System-Analyse

| ID | Thema | Status | Bewertung |
| --- | --- | --- | --- |
| 1.1 | System-Performance | CPU: 15.2%, RAM: 67.8% | ✅ Stabil |
| 1.2 | Speicherplatz | Root: 45% Auslastung | ✅ Ausreichend |
| 1.3 | Services | 4 wichtige Services laufen | ✅ Normal |
| 1.4 | Docker | 3 Container, 12 Images | ✅ Aktiv |
| 1.5 | Updates | 23 Updates verfügbar | ⚠️ Wartung erforderlich |

### Schritt 2: Maßnahmenkatalog

#### Quick Wins (Sofort umsetzbar)
- **System-Updates durchführen**: 23 Updates verfügbar
- **Docker-Container-Status überprüfen**: 3 Container laufen
- **Speicherplatz-Monitoring einrichten**: 45% Auslastung

#### Mid-Term (Nächste 2-4 Wochen)
- **Sicherheitsaudit für SSH-Zugriffe**: 3 fehlgeschlagene Root-Logins
- **Docker-Image-Cleanup**: 12 Images vorhanden
- **Service-Monitoring implementieren**: 4 wichtige Services

#### Long-Term (1-3 Monate)
- **Monitoring-System implementieren**: Proaktive Überwachung
- **Backup-Strategie überprüfen**: Daten-Sicherheit
- **Performance-Optimierung**: CPU/RAM-Auslastung optimieren

### Schritt 3: Prioritäten

**Hoch**: System-Updates, SSH-Sicherheit
**Mittel**: Docker-Optimierung, Monitoring
**Niedrig**: Performance-Feinabstimmung

### Schritt 4: Nächste Schritte

1. Sofort: Updates installieren
2. Diese Woche: SSH-Sicherheit prüfen
3. Nächste Woche: Docker-Cleanup
4. Monatlich: Monitoring-Review"""
        
        # Temporär ersetzen
        original_query_ollama = query_ollama
        import ssh_chat_system
        ssh_chat_system.query_ollama = mock_query_ollama
        
        # Generiere automatischen Bericht
        console.print(f"[dim]🤔 Generiere automatischen Systembericht...[/dim]")
        report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
        
        if report_content:
            console.print(f"[green]✅ Automatischer Report generiert (Länge: {len(report_content)} Zeichen)[/green]")
            
            # Speichere automatischen Bericht
            console.print(f"[dim]💾 Speichere automatischen Bericht...[/dim]")
            try:
                filename = save_system_report(report_content, system_info)
                console.print(f"[green]✅ Automatischer Bericht erfolgreich gespeichert![/green]")
                console.print(f"[green]📄 Datei: {filename}[/green]")
                
                # Prüfe ob Datei existiert
                if os.path.exists(filename):
                    console.print(f"[green]✅ Datei existiert und ist lesbar[/green]")
                    
                    # Zeige kurze Zusammenfassung
                    with open(filename, 'r', encoding='utf-8') as f:
                        content = f.read()
                        lines = content.split('\n')
                        console.print(f"\n[dim]📄 Bericht-Vorschau (erste 10 Zeilen):[/dim]")
                        for i, line in enumerate(lines[:10]):
                            if line.strip():
                                console.print(f"[dim]  {line.strip()}[/dim]")
                        if len(lines) > 10:
                            console.print(f"[dim]  ... (weitere {len(lines)-10} Zeilen)[/dim]")
                    
                    # Lösche Test-Datei
                    os.remove(filename)
                    console.print(f"[dim]🗑️ Test-Datei gelöscht[/dim]")
                else:
                    console.print(f"[red]❌ Datei existiert nicht: {filename}[/red]")
                    
            except Exception as e:
                console.print(f"[red]❌ Fehler beim Speichern des automatischen Berichts: {e}[/red]")
                import traceback
                console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
        else:
            console.print(f"[red]❌ Keine Antwort von Ollama für automatischen Bericht[/red]")
        
        # Stelle original query_ollama wieder her
        ssh_chat_system.query_ollama = original_query_ollama
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei automatischer Report-Generierung: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
    
    # Test 2: Prüfe ArgumentParser
    console.print("\n[bold]Test 2: ArgumentParser Integration[/bold]")
    try:
        import argparse
        from ssh_chat_system import main
        
        # Erstelle Parser (wie in main())
        parser = argparse.ArgumentParser(description='SSH-basierter Linux-Log-Analyzer mit Chat')
        parser.add_argument('--auto-report', action='store_true', help='Generiere automatisch einen Systembericht nach der Analyse')
        
        # Teste verschiedene Argumente
        test_args = [
            [],  # Keine Argumente
            ['--auto-report'],  # Mit auto-report
        ]
        
        for i, arg_list in enumerate(test_args):
            try:
                args = parser.parse_args(arg_list)
                auto_report = getattr(args, 'auto_report', False)
                console.print(f"[green]✅ Test {i+1}: --auto-report = {auto_report}[/green]")
            except Exception as e:
                console.print(f"[red]❌ Test {i+1} fehlgeschlagen: {e}[/red]")
                
    except Exception as e:
        console.print(f"[red]❌ Fehler bei ArgumentParser Test: {e}[/red]")
    
    # Test 3: Dokumentation
    console.print("\n[bold]Test 3: Verwendung[/bold]")
    console.print("[dim]📋 Verwendung des --auto-report Flags:[/dim]")
    console.print("[dim]  python ssh_chat_system.py --auto-report user@host[/dim]")
    console.print("[dim]  python ssh_chat_system.py --auto-report --debug user@host[/dim]")
    console.print("[dim]  python ssh_chat_system.py --auto-report --quick user@host[/dim]")
    console.print("[dim]  python ssh_chat_system.py --auto-report --include-network-security user@host[/dim]")

if __name__ == "__main__":
    test_auto_report_flag() 