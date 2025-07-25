#!/usr/bin/env python3
"""
Test für echte Ollama-Verbindung und Report-Generierung
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

def test_ollama_connection():
    """Testet die echte Ollama-Verbindung"""
    
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
    
    console.print("[bold blue]🔍 Teste echte Ollama-Verbindung...[/bold blue]")
    
    # Test 1: Verfügbare Modelle prüfen
    console.print("\n[bold]Test 1: Verfügbare Modelle[/bold]")
    try:
        from ssh_chat_system import get_available_models
        models = get_available_models()
        console.print(f"[green]✅ Verfügbare Modelle: {len(models)} gefunden[/green]")
        for model in models:
            console.print(f"[dim]  - {model.get('name', 'Unbekannt')} ({model.get('size', 'Unbekannt')})[/dim]")
    except Exception as e:
        console.print(f"[red]❌ Fehler beim Abrufen der Modelle: {e}[/red]")
        return
    
    # Test 2: Modell-Auswahl
    console.print("\n[bold]Test 2: Modell-Auswahl[/bold]")
    try:
        model = select_best_model(complex_analysis=True, for_menu=False)
        console.print(f"[green]✅ Modell ausgewählt: {model}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Fehler bei Modell-Auswahl: {e}[/red]")
        return
    
    # Test 3: Einfache Ollama-Abfrage
    console.print("\n[bold]Test 3: Einfache Ollama-Abfrage[/bold]")
    try:
        simple_prompt = "Antworte nur mit 'OK' wenn du funktionierst."
        response = query_ollama(simple_prompt, model=model, complex_analysis=False)
        if response:
            console.print(f"[green]✅ Ollama-Antwort erhalten: {response[:100]}...[/green]")
        else:
            console.print(f"[red]❌ Keine Antwort von Ollama[/red]")
            return
    except Exception as e:
        console.print(f"[red]❌ Fehler bei Ollama-Abfrage: {e}[/red]")
        return
    
    # Test 4: System-Context erstellen
    console.print("\n[bold]Test 4: System-Context erstellen[/bold]")
    try:
        system_context = create_system_context(system_info, log_entries, anomalies, focus_network_security=False)
        console.print(f"[green]✅ System-Context erstellt (Länge: {len(system_context)} Zeichen)[/green]")
    except Exception as e:
        console.print(f"[red]❌ Fehler bei System-Context: {e}[/red]")
        return
    
    # Test 5: Report-Prompt erstellen
    console.print("\n[bold]Test 5: Report-Prompt erstellen[/bold]")
    try:
        report_prompt = create_system_report_prompt(system_context)
        console.print(f"[green]✅ Report-Prompt erstellt (Länge: {len(report_prompt)} Zeichen)[/green]")
    except Exception as e:
        console.print(f"[red]❌ Fehler bei Report-Prompt: {e}[/red]")
        return
    
    # Test 6: Report mit echten Ollama generieren
    console.print("\n[bold]Test 6: Report mit echten Ollama generieren[/bold]")
    try:
        console.print(f"[dim]🔄 Generiere detaillierten Systembericht...[/dim]")
        report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
        
        if report_content:
            console.print(f"[green]✅ Report generiert (Länge: {len(report_content)} Zeichen)[/green]")
            console.print(f"[dim]📄 Report (erste 200 Zeichen): {report_content[:200]}...[/dim]")
            
            # Test 7: Report speichern
            console.print("\n[bold]Test 7: Report speichern[/bold]")
            console.print(f"[dim]💾 Speichere Bericht...[/dim]")
            try:
                filename = save_system_report(report_content, system_info)
                console.print(f"[green]✅ Bericht erfolgreich gespeichert![/green]")
                console.print(f"[green]📄 Datei: {filename}[/green]")
                
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
        else:
            console.print(f"[red]❌ Keine Antwort von Ollama für Report[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Fehler bei Report-Generierung: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")

if __name__ == "__main__":
    test_ollama_connection() 