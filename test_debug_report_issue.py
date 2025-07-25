#!/usr/bin/env python3
"""
Debug-Test für Report-Speicherung Problem
"""

import sys
import os
sys.path.append('.')

from ssh_chat_system import (
    save_system_report, create_system_report_prompt, query_ollama, 
    select_best_model, create_system_context, start_interactive_chat
)
from rich.console import Console

console = Console()

def test_debug_report_issue():
    """Debug-Test für das Report-Speicherung Problem"""
    
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
    
    console.print("[bold blue]🔍 Debug-Test für Report-Speicherung Problem...[/bold blue]")
    
    # Test 1: Prüfe ob system_info die richtigen Felder hat
    console.print("\n[bold]Test 1: system_info Validierung[/bold]")
    required_fields = ['hostname', 'distro_pretty_name', 'kernel_version']
    for field in required_fields:
        if field in system_info:
            console.print(f"[green]✅ {field}: {system_info[field]}[/green]")
        else:
            console.print(f"[red]❌ {field}: FEHLT[/red]")
    
    # Test 2: Prüfe save_system_report direkt
    console.print("\n[bold]Test 2: Direkte save_system_report Test[/bold]")
    try:
        test_content = "**Debug-Test-Report**\n\nDies ist ein Debug-Test."
        filename = save_system_report(test_content, system_info)
        console.print(f"[green]✅ Direkte Speicherung erfolgreich: {filename}[/green]")
        
        if os.path.exists(filename):
            console.print(f"[green]✅ Datei existiert: {filename}[/green]")
            # Lösche Test-Datei
            os.remove(filename)
            console.print(f"[dim]🗑️ Test-Datei gelöscht[/dim]")
        else:
            console.print(f"[red]❌ Datei existiert nicht: {filename}[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Fehler bei direkter Speicherung: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
    
    # Test 3: Simuliere die echte Chat-Logik
    console.print("\n[bold]Test 3: Chat-Logik Simulation[/bold]")
    try:
        # Erstelle system_context
        system_context = create_system_context(system_info, log_entries, anomalies, focus_network_security=False)
        console.print(f"[green]✅ System-Context erstellt (Länge: {len(system_context)} Zeichen)[/green]")
        
        # Erstelle report_prompt
        report_prompt = create_system_report_prompt(system_context)
        console.print(f"[green]✅ Report-Prompt erstellt (Länge: {len(report_prompt)} Zeichen)[/green]")
        
        # Modell-Auswahl
        model = select_best_model(complex_analysis=True, for_menu=False)
        console.print(f"[green]✅ Modell ausgewählt: {model}[/green]")
        
        # Mock query_ollama
        def mock_query_ollama(prompt, model=None, complex_analysis=False):
            return "**Debug-Report**\n\nDies ist ein Debug-Report für die Problem-Analyse."
        
        # Temporär ersetzen
        original_query_ollama = query_ollama
        import ssh_chat_system
        ssh_chat_system.query_ollama = mock_query_ollama
        
        # Generiere Report (wie in der echten Anwendung)
        console.print(f"[dim]🔄 Generiere detaillierten Systembericht...[/dim]")
        report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
        console.print(f"[green]✅ Report generiert (Länge: {len(report_content)} Zeichen)[/green]")
        
        if report_content:
            # Speichere Bericht (wie in der echten Anwendung)
            console.print(f"[dim]💾 Speichere Bericht...[/dim]")
            try:
                filename = save_system_report(report_content, system_info)
                console.print(f"[green]✅ Bericht erfolgreich gespeichert![/green]")
                console.print(f"[green]📄 Datei: {filename}[/green]")
                
                if os.path.exists(filename):
                    console.print(f"[green]✅ Datei existiert: {filename}[/green]")
                    # Lösche Test-Datei
                    os.remove(filename)
                    console.print(f"[dim]🗑️ Test-Datei gelöscht[/dim]")
                else:
                    console.print(f"[red]❌ Datei existiert nicht: {filename}[/red]")
                    
            except Exception as e:
                console.print(f"[red]❌ Fehler beim Speichern des Berichts: {e}[/red]")
                import traceback
                console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
        else:
            console.print(f"[red]❌ Keine Antwort von Ollama erhalten[/red]")
        
        # Stelle original query_ollama wieder her
        ssh_chat_system.query_ollama = original_query_ollama
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei Chat-Logik Simulation: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
    
    # Test 4: Prüfe Verzeichnis-Berechtigungen
    console.print("\n[bold]Test 4: Verzeichnis-Berechtigungen[/bold]")
    reports_dir = "system_reports"
    if os.path.exists(reports_dir):
        console.print(f"[green]✅ Verzeichnis existiert: {reports_dir}[/green]")
        try:
            # Test-Schreibzugriff
            test_file = os.path.join(reports_dir, "test_write_permission.tmp")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            console.print(f"[green]✅ Schreibzugriff funktioniert[/green]")
        except Exception as e:
            console.print(f"[red]❌ Schreibzugriff fehlgeschlagen: {e}[/red]")
    else:
        console.print(f"[yellow]⚠️ Verzeichnis existiert nicht: {reports_dir}[/yellow]")
        try:
            os.makedirs(reports_dir)
            console.print(f"[green]✅ Verzeichnis erstellt: {reports_dir}[/green]")
        except Exception as e:
            console.print(f"[red]❌ Verzeichnis-Erstellung fehlgeschlagen: {e}[/red]")

if __name__ == "__main__":
    test_debug_report_issue() 