#!/usr/bin/env python3
"""
Test für Chat-Logik Report-Speicherung
"""

import sys
import os
sys.path.append('.')

from ssh_chat_system import (
    save_system_report, create_system_report_prompt, query_ollama, 
    select_best_model, get_shortcuts, interpolate_user_input_to_shortcut
)
from rich.console import Console

console = Console()

def test_chat_report_logic():
    """Testet die komplette Chat-Logik für Report-Shortcuts"""
    
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
    
    console.print("[bold blue]🧪 Teste Chat-Logik für Report-Shortcuts...[/bold blue]")
    
    # Hole Shortcuts
    shortcuts = get_shortcuts()
    console.print(f"[dim]📋 Verfügbare Shortcuts: {list(shortcuts.keys())}[/dim]")
    
    # Test verschiedene Eingaben
    test_inputs = ['report', 'bericht', 'r1', 't1']
    
    for user_input in test_inputs:
        console.print(f"\n[bold]Teste Eingabe: '{user_input}'[/bold]")
        
        user_input_lower = user_input.lower()
        original_input = user_input
        interpolated_shortcut = None
        shortcut_used = False
        
        # Simuliere die Chat-Logik
        console.print(f"[dim]🔍 Prüfe direkten Shortcut: {user_input_lower} in shortcuts[/dim]")
        
        if user_input_lower in shortcuts:
            shortcut_info = shortcuts[user_input_lower]
            user_input = shortcut_info['question']
            complex_analysis = shortcut_info['complex']
            cache_key = shortcut_info['cache_key']
            shortcut_used = True
            interpolated_shortcut = user_input_lower  # Setze interpolated_shortcut für direkte Shortcuts
            
            console.print(f"[green]✅ Direkter Shortcut gefunden: {user_input_lower}[/green]")
            console.print(f"[dim]📋 Shortcut Info: {shortcut_info}[/dim]")
        else:
            console.print(f"[yellow]⚠️ Kein direkter Shortcut gefunden[/yellow]")
            
            # Intelligente Abfrage-Interpolation
            interpolated_shortcut = interpolate_user_input_to_shortcut(user_input_lower, shortcuts)
            if interpolated_shortcut:
                try:
                    shortcut_info = shortcuts[interpolated_shortcut]
                    user_input = shortcut_info['question']
                    complex_analysis = shortcut_info['complex']
                    cache_key = shortcut_info['cache_key']
                    shortcut_used = True
                    
                    console.print(f"[green]✅ Interpolierter Shortcut: {original_input} → {interpolated_shortcut}[/green]")
                    console.print(f"[dim]📋 Shortcut Info: {shortcut_info}[/dim]")
                    
                except KeyError as e:
                    console.print(f"[red]❌ Fehler: Shortcut '{interpolated_shortcut}' nicht gefunden[/red]")
                    continue
            else:
                console.print(f"[red]❌ Kein Shortcut gefunden für: {user_input_lower}[/red]")
                continue
        
        # Prüfe Report-Logik
        console.print(f"[dim]🔍 Prüfe Report-Logik: original_input='{original_input}', interpolated_shortcut='{interpolated_shortcut}'[/dim]")
        
        if original_input == 'report' or (interpolated_shortcut and interpolated_shortcut == 'report'):
            console.print(f"[green]✅ Report-Logik wird ausgeführt![/green]")
            
            # Simuliere Report-Generierung
            console.print(f"[dim]🔄 Generiere detaillierten Systembericht...[/dim]")
            
            # Erstelle spezialisierten Prompt für Bericht
            report_prompt = create_system_report_prompt(system_context)
            
            # Verwende komplexes Modell für Berichterstellung
            model = select_best_model(complex_analysis=True, for_menu=False)
            console.print(f"[dim]🔄 Wechsle zu komplexem Modell für detaillierte Berichterstellung...[/dim]")
            
            # Mock query_ollama für Test
            def mock_query_ollama(prompt, model=None, complex_analysis=False):
                return f"**Mock-Report für {user_input}**\n\nDies ist ein Mock-Report für Testzwecke."
            
            # Temporär ersetzen
            original_query_ollama = query_ollama
            import ssh_chat_system
            ssh_chat_system.query_ollama = mock_query_ollama
            
            # Generiere Bericht
            console.print(f"[dim]🤔 Denke nach...[/dim]")
            report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
            
            if report_content:
                # Speichere Bericht
                console.print(f"[dim]💾 Speichere Bericht...[/dim]")
                try:
                    filename = save_system_report(report_content, system_info)
                    console.print(f"[green]✅ Bericht erfolgreich gespeichert![/green]")
                    console.print(f"[green]📄 Datei: {filename}[/green]")
                    
                    # Prüfe ob Datei existiert
                    if os.path.exists(filename):
                        console.print(f"[green]✅ Datei existiert: {filename}[/green]")
                    else:
                        console.print(f"[red]❌ Datei existiert nicht: {filename}[/red]")
                        
                except Exception as e:
                    console.print(f"[red]❌ Fehler beim Speichern des Berichts: {e}[/red]")
            else:
                console.print(f"[red]❌ Keine Antwort von Ollama erhalten[/red]")
            
            # Stelle original query_ollama wieder her
            ssh_chat_system.query_ollama = original_query_ollama
            
        else:
            console.print(f"[yellow]⚠️ Report-Logik wird NICHT ausgeführt[/yellow]")
            console.print(f"[dim]🔍 Bedingung: original_input=='report' ({original_input == 'report'}) oder interpolated_shortcut=='report' ({interpolated_shortcut == 'report'})[/dim]")

if __name__ == "__main__":
    test_chat_report_logic() 