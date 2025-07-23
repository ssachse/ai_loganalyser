#!/usr/bin/env python3
"""
Beispiel-Verwendung für den macOS Logfile-Analysator
Zeigt sowohl lokale als auch SSH-basierte Analyse
"""

import os
import sys
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Importiere die Analysatoren
from log_analyzer import LogAnalyzer
from ssh_log_collector import SSHLogCollector, LinuxLogAnalyzer

console = Console()

def example_local_analysis():
    """Beispiel für lokale macOS-Analyse"""
    console.print(Panel(
        "[bold blue]Beispiel: Lokale macOS-Log-Analyse[/bold blue]\n"
        "Dieses Beispiel zeigt, wie Sie lokale macOS-Logs analysieren können.",
        border_style="blue"
    ))
    
    # Erstelle Analysator
    analyzer = LogAnalyzer()
    
    # Überprüfe Ollama-Verbindung
    if not analyzer._check_ollama_connection():
        console.print("[red]❌ Ollama ist nicht erreichbar. Bitte starten Sie Ollama.[/red]")
        return False
    
    console.print("[green]✅ Ollama-Verbindung erfolgreich[/green]")
    
    # Sammle Logs (nur die letzten 2 Stunden für das Beispiel)
    console.print("[blue]Sammle lokale Logs...[/blue]")
    analyzer.collect_logs(hours_back=2)
    
    if not analyzer.log_entries:
        console.print("[yellow]Keine Logs in den letzten 2 Stunden gefunden.[/yellow]")
        return True
    
    console.print(f"[green]✓ {len(analyzer.log_entries)} Log-Einträge gesammelt[/green]")
    
    # Analysiere mit Ollama
    console.print("[blue]Analysiere mit Ollama...[/blue]")
    analyzer.analyze_with_ollama()
    
    # Zeige Ergebnisse
    analyzer.display_results()
    
    return True

def example_ssh_analysis():
    """Beispiel für SSH-basierte Linux-Analyse"""
    console.print(Panel(
        "[bold blue]Beispiel: SSH-basierte Linux-Log-Analyse[/bold blue]\n"
        "Dieses Beispiel zeigt, wie Sie Linux-Logs über SSH sammeln und analysieren können.\n"
        "Hinweis: Sie benötigen SSH-Zugriff auf ein Linux-System.",
        border_style="blue"
    ))
    
    # Beispiel-Konfiguration (ändern Sie diese Werte)
    host = "example-server.com"
    username = "admin"
    password = None  # Wird abgefragt
    key_file = None  # Oder Pfad zu SSH-Key
    
    console.print(f"[dim]Beispiel-Konfiguration:[/dim]")
    console.print(f"  Host: {host}")
    console.print(f"  Username: {username}")
    console.print(f"  SSH-Key: {key_file or 'Passwort-Abfrage'}")
    
    # Frage nach Bestätigung
    if not console.input("\n[yellow]Möchten Sie fortfahren? (y/N): [/yellow]").lower().startswith('y'):
        console.print("[yellow]SSH-Analyse übersprungen.[/yellow]")
        return True
    
    # Erstelle SSH-Collector
    collector = SSHLogCollector(
        host=host,
        username=username,
        password=password,
        key_file=key_file
    )
    
    try:
        # Verbinde mit Zielsystem
        if not collector.connect():
            console.print("[red]❌ SSH-Verbindung fehlgeschlagen[/red]")
            return False
        
        # Sammle System-Informationen
        system_info = collector.get_system_info()
        console.print(f"[green]✓ Verbunden mit: {system_info.get('hostname', host)}[/green]")
        
        # Sammle Logs (nur die letzten 2 Stunden für das Beispiel)
        log_directory = collector.collect_logs(hours_back=2)
        
        if not log_directory or not os.path.exists(log_directory):
            console.print("[red]❌ Keine Logs gesammelt[/red]")
            return False
        
        # Erstelle Linux-Log-Analyzer
        analyzer = LinuxLogAnalyzer()
        
        # Überprüfe Ollama-Verbindung
        if not analyzer._check_ollama_connection():
            console.print("[red]❌ Ollama ist nicht erreichbar. Bitte starten Sie Ollama.[/red]")
            return False
        
        # Analysiere Linux-Logs
        analyzer.analyze_linux_logs(log_directory, system_info)
        
        if not analyzer.log_entries:
            console.print("[yellow]Keine Log-Einträge gefunden.[/yellow]")
            return True
        
        # Analysiere mit Ollama
        analyzer.analyze_with_ollama()
        
        # Zeige Ergebnisse
        analyzer.display_results()
        
        # Erstelle Archiv
        archive_path = collector.create_archive()
        if archive_path:
            console.print(f"[green]✓ Logs archiviert in: {archive_path}[/green]")
        
        return True
        
    except Exception as e:
        console.print(f"[red]Fehler bei SSH-Analyse: {e}[/red]")
        return False
    finally:
        collector.disconnect()
        collector.cleanup()

def show_usage_examples():
    """Zeigt Verwendungsbeispiele"""
    console.print(Panel(
        "[bold green]Verwendungsbeispiele[/bold green]\n"
        "Hier sind einige praktische Beispiele für die Verwendung des Logfile-Analysators:",
        border_style="green"
    ))
    
    examples = [
        {
            "title": "Lokale macOS-Analyse",
            "command": "sudo python3 log_analyzer.py",
            "description": "Analysiert lokale macOS-System-Logs"
        },
        {
            "title": "SSH-Linux-Analyse",
            "command": "python3 ssh_log_collector.py user@hostname",
            "description": "Sammelt und analysiert Linux-Logs über SSH"
        },
        {
            "title": "Mit SSH-Key",
            "command": "python3 ssh_log_collector.py user@hostname --key-file ~/.ssh/id_rsa",
            "description": "Verwendet SSH-Key für Authentifizierung"
        },
        {
            "title": "Erweiterte Analyse",
            "command": "python3 ssh_log_collector.py user@hostname --hours 48 --output results.json",
            "description": "48 Stunden zurück, Ergebnisse in JSON speichern"
        },
        {
            "title": "Tests ausführen",
            "command": "python3 run_tests.py",
            "description": "Führt alle Tests aus"
        },
        {
            "title": "Coverage-Analyse",
            "command": "python3 run_tests.py --coverage",
            "description": "Führt Tests mit Code-Coverage aus"
        }
    ]
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Anwendung", style="cyan", width=20)
    table.add_column("Befehl", style="white", width=50)
    table.add_column("Beschreibung", style="yellow", width=40)
    
    for example in examples:
        table.add_row(
            example["title"],
            example["command"],
            example["description"]
        )
    
    console.print(table)

def show_configuration_examples():
    """Zeigt Konfigurationsbeispiele"""
    console.print(Panel(
        "[bold green]Konfigurationsbeispiele[/bold green]\n"
        "Hier sind einige Konfigurationsoptionen:",
        border_style="green"
    ))
    
    config_examples = [
        {
            "setting": "Ollama-Modell ändern",
            "command": "export OLLAMA_MODEL=mistral",
            "description": "Verwendet Mistral statt Llama2"
        },
        {
            "setting": "Analyse-Zeitraum",
            "command": "export DEFAULT_HOURS_BACK=72",
            "description": "Analysiert die letzten 72 Stunden"
        },
        {
            "setting": "Ollama-URL",
            "command": "export OLLAMA_URL=http://192.168.1.100:11434",
            "description": "Verwendet entfernte Ollama-Instanz"
        },
        {
            "setting": "Prioritäts-Schwelle",
            "command": "export HIGH_PRIORITY_THRESHOLD=3.0",
            "description": "Niedrigere Schwelle für mehr Anomalien"
        }
    ]
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Einstellung", style="cyan", width=20)
    table.add_column("Umgebungsvariable", style="white", width=40)
    table.add_column("Beschreibung", style="yellow", width=40)
    
    for config in config_examples:
        table.add_row(
            config["setting"],
            config["command"],
            config["description"]
        )
    
    console.print(table)

def main():
    """Hauptfunktion"""
    console.print("[bold blue]macOS Logfile-Analysator - Beispiele[/bold blue]")
    console.print("="*60)
    
    # Zeige Verwendungsbeispiele
    show_usage_examples()
    
    console.print("\n")
    
    # Zeige Konfigurationsbeispiele
    show_configuration_examples()
    
    console.print("\n")
    
    # Frage nach Beispiel-Ausführung
    if console.input("[yellow]Möchten Sie die Beispiele ausführen? (y/N): [/yellow]").lower().startswith('y'):
        console.print("\n")
        
        # Lokale Analyse
        success1 = example_local_analysis()
        
        console.print("\n" + "="*60 + "\n")
        
        # SSH-Analyse
        success2 = example_ssh_analysis()
        
        # Zusammenfassung
        console.print("\n[bold]Zusammenfassung:[/bold]")
        console.print(f"  Lokale Analyse: {'✅ Erfolgreich' if success1 else '❌ Fehlgeschlagen'}")
        console.print(f"  SSH-Analyse: {'✅ Erfolgreich' if success2 else '❌ Fehlgeschlagen'}")
    
    console.print("\n[green]Beispiele abgeschlossen![/green]")

if __name__ == "__main__":
    main() 