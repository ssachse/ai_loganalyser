#!/usr/bin/env python3
"""
Test für os Import Fix
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

def test_os_import_fix():
    """Testet ob der os Import Fehler behoben ist"""
    
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
    
    console.print("[bold blue]🧪 Teste os Import Fix...[/bold blue]")
    
    # Test 1: Simuliere automatische Report-Generierung (wie in der echten Anwendung)
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
            return """**Test-Report für os Import Fix**
==============================

### System-Analyse
- Hostname: test-host
- Distribution: Debian GNU/Linux 12 (bookworm)
- Kernel: 6.1.0-13-amd64

### Maßnahmenkatalog
- System-Updates durchführen
- Docker-Container-Status überprüfen
- Monitoring implementieren"""
        
        # Temporär ersetzen
        original_query_ollama = query_ollama
        import ssh_chat_system
        ssh_chat_system.query_ollama = mock_query_ollama
        
        # Generiere automatischen Bericht (wie in der echten Anwendung)
        console.print(f"[dim]🤔 Generiere automatischen Systembericht...[/dim]")
        report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
        
        if report_content:
            console.print(f"[green]✅ Automatischer Report generiert (Länge: {len(report_content)} Zeichen)[/green]")
            
            # Speichere automatischen Bericht (wie in der echten Anwendung)
            console.print(f"[dim]💾 Speichere automatischen Bericht...[/dim]")
            try:
                filename = save_system_report(report_content, system_info)
                console.print(f"[green]✅ Automatischer Bericht erfolgreich gespeichert![/green]")
                console.print(f"[green]📄 Datei: {filename}[/green]")
                
                # Prüfe ob Datei existiert (hier war der os Import Fehler)
                if os.path.exists(filename):
                    console.print(f"[green]✅ Datei existiert und ist lesbar[/green]")
                    
                    # Zeige kurze Zusammenfassung
                    with open(filename, 'r', encoding='utf-8') as f:
                        content = f.read()
                        lines = content.split('\n')
                        console.print(f"\n[dim]📄 Bericht-Vorschau (erste 5 Zeilen):[/dim]")
                        for i, line in enumerate(lines[:5]):
                            if line.strip():
                                console.print(f"[dim]  {line.strip()}[/dim]")
                    
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
    
    # Test 2: Prüfe os Import direkt
    console.print("\n[bold]Test 2: os Import Test[/bold]")
    try:
        # Teste verschiedene os Operationen
        current_dir = os.getcwd()
        console.print(f"[green]✅ os.getcwd() funktioniert: {current_dir}[/green]")
        
        # Teste os.path.exists
        test_file = "test_os_import_fix.py"
        if os.path.exists(test_file):
            console.print(f"[green]✅ os.path.exists() funktioniert: {test_file} existiert[/green]")
        else:
            console.print(f"[red]❌ os.path.exists() fehlgeschlagen: {test_file} existiert nicht[/red]")
        
        # Teste os.path.join
        test_path = os.path.join("system_reports", "test.md")
        console.print(f"[green]✅ os.path.join() funktioniert: {test_path}[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei os Import Test: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
    
    # Test 3: Simuliere den exakten Fehler
    console.print("\n[bold]Test 3: Exakter Fehler-Simulation[/bold]")
    try:
        # Simuliere die automatische Report-Generierung wie in der echten Anwendung
        def simulate_auto_report():
            # Erstelle System-Context
            system_context = create_system_context(system_info, log_entries, anomalies, focus_network_security=False)
            
            # Erstelle Report-Prompt
            report_prompt = create_system_report_prompt(system_context)
            
            # Modell-Auswahl
            model = select_best_model(complex_analysis=True, for_menu=False)
            
            # Mock query_ollama
            def mock_query_ollama(prompt, model=None, complex_analysis=False):
                return "**Test-Report**\n\nDies ist ein Test-Report."
            
            # Temporär ersetzen
            original_query_ollama = query_ollama
            import ssh_chat_system
            ssh_chat_system.query_ollama = mock_query_ollama
            
            # Generiere Bericht
            report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
            
            if report_content:
                # Speichere Bericht
                filename = save_system_report(report_content, system_info)
                
                # Prüfe ob Datei existiert (hier war der Fehler)
                if os.path.exists(filename):
                    console.print(f"[green]✅ Datei existiert: {filename}[/green]")
                    os.remove(filename)
                else:
                    console.print(f"[red]❌ Datei existiert nicht: {filename}[/red]")
            
            # Stelle original query_ollama wieder her
            ssh_chat_system.query_ollama = original_query_ollama
        
        simulate_auto_report()
        console.print(f"[green]✅ Exakte Fehler-Simulation erfolgreich[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei exakter Fehler-Simulation: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")

if __name__ == "__main__":
    test_os_import_fix() 