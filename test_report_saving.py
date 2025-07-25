#!/usr/bin/env python3
"""
Test für Report-Speicherung
"""

import sys
import os
sys.path.append('.')

from ssh_chat_system import save_system_report, create_system_report_prompt, query_ollama, select_best_model
from rich.console import Console

console = Console()

def test_report_saving():
    """Testet die Report-Speicherung"""
    
    # Mock system_info
    system_info = {
        'hostname': 'test-host',
        'distro_pretty_name': 'Debian GNU/Linux 12 (bookworm)',
        'kernel_version': '6.1.0-13-amd64',
        'ssh_host': 'test-host',
        'ssh_user': 'test-user'
    }
    
    # Mock system_context
    system_context = """
    **System-Informationen**
    - Hostname: test-host
    - Distribution: Debian GNU/Linux 12 (bookworm)
    - Kernel: 6.1.0-13-amd64
    
    **Docker-Status**
    - 1 Container läuft: my-prf
    - Image: registry.gitlab.com/profiflitzer-gmbh/my-profiflitzer:latest
    
    **System-Updates**
    - 166 Updates verfügbar
    
    **Performance**
    - CPU: 0.0%
    - RAM: 12.2%
    - Load: 1.45
    """
    
    console.print("[bold blue]🧪 Teste Report-Speicherung...[/bold blue]")
    
    # Test 1: Direkte save_system_report Funktion
    console.print("\n[bold]Test 1: Direkte save_system_report Funktion[/bold]")
    try:
        test_content = "**Test-Report**\n\nDies ist ein Test-Report."
        filename = save_system_report(test_content, system_info)
        console.print(f"[green]✅ Erfolgreich gespeichert: {filename}[/green]")
        
        # Prüfe ob Datei existiert
        if os.path.exists(filename):
            console.print(f"[green]✅ Datei existiert: {filename}[/green]")
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                console.print(f"[dim]📄 Dateiinhalt (erste 200 Zeichen): {content[:200]}...[/dim]")
        else:
            console.print(f"[red]❌ Datei existiert nicht: {filename}[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Fehler bei save_system_report: {e}[/red]")
    
    # Test 2: Report-Prompt erstellen
    console.print("\n[bold]Test 2: Report-Prompt erstellen[/bold]")
    try:
        report_prompt = create_system_report_prompt(system_context)
        console.print(f"[green]✅ Report-Prompt erstellt (Länge: {len(report_prompt)} Zeichen)[/green]")
        console.print(f"[dim]📄 Prompt (erste 300 Zeichen): {report_prompt[:300]}...[/dim]")
    except Exception as e:
        console.print(f"[red]❌ Fehler bei create_system_report_prompt: {e}[/red]")
    
    # Test 3: Modell-Auswahl
    console.print("\n[bold]Test 3: Modell-Auswahl[/bold]")
    try:
        model = select_best_model(complex_analysis=True, for_menu=False)
        console.print(f"[green]✅ Modell ausgewählt: {model}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Fehler bei select_best_model: {e}[/red]")
    
    # Test 4: Ollama-Abfrage (ohne echte Verbindung)
    console.print("\n[bold]Test 4: Ollama-Abfrage (Mock)[/bold]")
    try:
        # Mock query_ollama für Test
        def mock_query_ollama(prompt, model=None, complex_analysis=False):
            return "**Mock-Report**\n\nDies ist ein Mock-Report für Testzwecke."
        
        # Temporär ersetzen
        original_query_ollama = query_ollama
        import ssh_chat_system
        ssh_chat_system.query_ollama = mock_query_ollama
        
        report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
        console.print(f"[green]✅ Mock-Report generiert (Länge: {len(report_content)} Zeichen)[/green]")
        
        # Speichere Mock-Report
        filename = save_system_report(report_content, system_info)
        console.print(f"[green]✅ Mock-Report gespeichert: {filename}[/green]")
        
        # Stelle original query_ollama wieder her
        ssh_chat_system.query_ollama = original_query_ollama
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei Mock-Report: {e}[/red]")
    
    # Test 5: Prüfe system_reports Verzeichnis
    console.print("\n[bold]Test 5: system_reports Verzeichnis[/bold]")
    reports_dir = "system_reports"
    if os.path.exists(reports_dir):
        files = os.listdir(reports_dir)
        console.print(f"[green]✅ Verzeichnis existiert: {reports_dir}[/green]")
        console.print(f"[dim]📁 Dateien: {files}[/dim]")
    else:
        console.print(f"[red]❌ Verzeichnis existiert nicht: {reports_dir}[/red]")

if __name__ == "__main__":
    test_report_saving() 