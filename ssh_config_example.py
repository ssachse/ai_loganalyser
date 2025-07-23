#!/usr/bin/env python3
"""
Beispiel für SSH-Konfiguration mit Port-Forwarding für Ollama
Zeigt verschiedene Möglichkeiten, SSH Port-Forwarding zu nutzen
"""

import os
import sys
import subprocess
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax

console = Console()

def show_ssh_config_examples():
    """Zeigt SSH-Konfigurationsbeispiele"""
    console.print(Panel(
        "[bold blue]SSH-Konfiguration mit Port-Forwarding für Ollama[/bold blue]\n"
        "Diese Beispiele zeigen, wie Sie SSH Port-Forwarding für die Log-Analyse einrichten können.",
        border_style="blue"
    ))
    
    # SSH Config Beispiele
    ssh_config_examples = [
        {
            "title": "Basis SSH-Config",
            "description": "Einfache Konfiguration für einen Server",
            "config": """Host myserver
    HostName 192.168.1.100
    User admin
    Port 22
    LocalForward 11434 localhost:11434
    IdentityFile ~/.ssh/id_rsa"""
        },
        {
            "title": "Multi-Server Konfiguration",
            "description": "Konfiguration für mehrere Server",
            "config": """# Produktions-Server
Host prod-server
    HostName prod.example.com
    User admin
    LocalForward 11434 localhost:11434
    IdentityFile ~/.ssh/prod_key

# Test-Server
Host test-server
    HostName test.example.com
    User admin
    LocalForward 11435 localhost:11434
    IdentityFile ~/.ssh/test_key

# Backup-Server
Host backup-server
    HostName backup.example.com
    User admin
    LocalForward 11436 localhost:11434
    IdentityFile ~/.ssh/backup_key"""
        },
        {
            "title": "Erweiterte Konfiguration",
            "description": "Mit zusätzlichen Sicherheitsoptionen",
            "config": """Host secure-server
    HostName secure.example.com
    User admin
    Port 2222
    LocalForward 11434 localhost:11434
    IdentityFile ~/.ssh/secure_key
    ServerAliveInterval 60
    ServerAliveCountMax 3
    Compression yes
    TCPKeepAlive yes"""
        }
    ]
    
    for example in ssh_config_examples:
        console.print(f"\n[bold cyan]{example['title']}[/bold cyan]")
        console.print(f"[dim]{example['description']}[/dim]")
        
        syntax = Syntax(example['config'], "ssh", theme="monokai")
        console.print(syntax)
        
        console.print("")

def show_usage_examples():
    """Zeigt Verwendungsbeispiele"""
    console.print(Panel(
        "[bold green]Verwendungsbeispiele mit SSH Port-Forwarding[/bold green]\n"
        "Hier sind praktische Beispiele für die Verwendung:",
        border_style="green"
    ))
    
    usage_examples = [
        {
            "scenario": "Einfache Verbindung",
            "command": "ssh myserver",
            "description": "Verbindet sich und richtet automatisch Port-Forwarding ein"
        },
        {
            "scenario": "Log-Analyse mit SSH-Config",
            "command": "python3 ssh_log_collector.py admin@myserver",
            "description": "Verwendet SSH-Config-Host für automatisches Port-Forwarding"
        },
        {
            "scenario": "Alternative Syntax",
            "command": "python3 ssh_log_collector.py myserver --username admin",
            "description": "Separate Argumente für Host und Benutzername"
        },
        {
            "scenario": "Manuelles Port-Forwarding",
            "command": "ssh -L 11434:localhost:11434 user@server",
            "description": "Manuelles Port-Forwarding ohne SSH-Config"
        },
        {
            "scenario": "Mehrere Server parallel",
            "command": "python3 ssh_log_collector.py admin@prod-server &\npython3 ssh_log_collector.py admin@test-server &",
            "description": "Analysiert mehrere Server parallel"
        },
        {
            "scenario": "Ohne Port-Forwarding",
            "command": "python3 ssh_log_collector.py user@server --no-port-forwarding",
            "description": "Verwendet lokale Ollama-Instanz"
        }
    ]
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Szenario", style="cyan", width=25)
    table.add_column("Befehl", style="white", width=50)
    table.add_column("Beschreibung", style="yellow", width=40)
    
    for example in usage_examples:
        table.add_row(
            example["scenario"],
            example["command"],
            example["description"]
        )
    
    console.print(table)

def show_ssh_config_setup():
    """Zeigt Setup-Anweisungen für SSH-Config"""
    console.print(Panel(
        "[bold yellow]SSH-Config Setup[/bold yellow]\n"
        "So richten Sie SSH Port-Forwarding ein:",
        border_style="yellow"
    ))
    
    setup_steps = [
        {
            "step": "1. SSH-Config-Datei öffnen",
            "command": "nano ~/.ssh/config",
            "description": "Erstellt oder bearbeitet die SSH-Config-Datei"
        },
        {
            "step": "2. Host-Konfiguration hinzufügen",
            "command": """Host myserver
    HostName your-server.com
    User your-username
    LocalForward 11434 localhost:11434
    IdentityFile ~/.ssh/your_key""",
            "description": "Fügt Host-Konfiguration mit Port-Forwarding hinzu"
        },
        {
            "step": "3. Berechtigungen setzen",
            "command": "chmod 600 ~/.ssh/config",
            "description": "Setzt korrekte Berechtigungen für SSH-Config"
        },
        {
            "step": "4. Verbindung testen",
            "command": "ssh myserver",
            "description": "Testet die SSH-Verbindung und Port-Forwarding"
        },
        {
            "step": "5. Ollama-Verbindung testen",
            "command": "curl http://localhost:11434/api/tags",
            "description": "Überprüft ob Ollama über Port-Forwarding erreichbar ist"
        }
    ]
    
    for step in setup_steps:
        console.print(f"\n[bold]{step['step']}[/bold]")
        console.print(f"[dim]{step['description']}[/dim]")
        
        if step['command'].startswith('Host'):
            syntax = Syntax(step['command'], "ssh", theme="monokai")
            console.print(syntax)
        else:
            console.print(f"[green]$ {step['command']}[/green]")

def check_ssh_config():
    """Überprüft die aktuelle SSH-Konfiguration"""
    console.print(Panel(
        "[bold blue]SSH-Konfiguration überprüfen[/bold blue]",
        border_style="blue"
    ))
    
    ssh_config_path = Path.home() / ".ssh" / "config"
    
    if not ssh_config_path.exists():
        console.print("[yellow]⚠️  SSH-Config-Datei nicht gefunden[/yellow]")
        console.print(f"[dim]Erwarteter Pfad: {ssh_config_path}[/dim]")
        return False
    
    try:
        with open(ssh_config_path, 'r') as f:
            config_content = f.read()
        
        console.print(f"[green]✅ SSH-Config gefunden: {ssh_config_path}[/green]")
        
        # Suche nach Port-Forwarding-Konfigurationen
        if "LocalForward" in config_content:
            console.print("[green]✅ Port-Forwarding-Konfigurationen gefunden[/green]")
            
            # Zeige relevante Zeilen
            lines = config_content.split('\n')
            relevant_lines = []
            
            for i, line in enumerate(lines):
                if "LocalForward" in line or "Host" in line:
                    relevant_lines.append(f"{i+1:3d}: {line}")
            
            if relevant_lines:
                console.print("\n[bold]Relevante Konfigurationen:[/bold]")
                for line in relevant_lines[:10]:  # Zeige max. 10 Zeilen
                    console.print(f"[dim]{line}[/dim]")
        else:
            console.print("[yellow]⚠️  Keine Port-Forwarding-Konfigurationen gefunden[/yellow]")
        
        return True
        
    except Exception as e:
        console.print(f"[red]❌ Fehler beim Lesen der SSH-Config: {e}[/red]")
        return False

def test_ollama_connection():
    """Testet die Ollama-Verbindung"""
    console.print(Panel(
        "[bold blue]Ollama-Verbindung testen[/bold blue]",
        border_style="blue"
    ))
    
    try:
        import requests
        
        # Teste lokale Ollama-Verbindung
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        
        if response.status_code == 200:
            console.print("[green]✅ Ollama ist auf localhost:11434 erreichbar[/green]")
            
            # Zeige verfügbare Modelle
            try:
                models = response.json().get('models', [])
                if models:
                    console.print(f"[green]Verfügbare Modelle: {len(models)}[/green]")
                    for model in models[:5]:  # Zeige erste 5 Modelle
                        console.print(f"[dim]  • {model.get('name', 'Unbekannt')}[/dim]")
                else:
                    console.print("[yellow]⚠️  Keine Modelle gefunden[/yellow]")
            except:
                console.print("[dim]Modelle konnten nicht abgerufen werden[/dim]")
            
            return True
        else:
            console.print(f"[red]❌ Ollama antwortet mit Status {response.status_code}[/red]")
            return False
            
    except requests.exceptions.ConnectionError:
        console.print("[red]❌ Ollama ist nicht erreichbar auf localhost:11434[/red]")
        console.print("[yellow]Hinweis: Stellen Sie sicher, dass Ollama läuft oder SSH Port-Forwarding aktiv ist[/yellow]")
        return False
    except Exception as e:
        console.print(f"[red]❌ Fehler beim Testen der Ollama-Verbindung: {e}[/red]")
        return False

def create_ssh_config_template():
    """Erstellt eine SSH-Config-Vorlage"""
    console.print(Panel(
        "[bold green]SSH-Config-Vorlage erstellen[/bold green]",
        border_style="green"
    ))
    
    ssh_config_path = Path.home() / ".ssh" / "config"
    
    if ssh_config_path.exists():
        if not Confirm.ask("SSH-Config existiert bereits. Überschreiben?"):
            return False
    
    template = """# SSH-Config für Log-Analyse mit Ollama Port-Forwarding
# Diese Konfiguration ermöglicht automatisches Port-Forwarding für Ollama

# Beispiel-Server (ändern Sie die Werte entsprechend)
Host example-server
    HostName your-server.example.com
    User your-username
    Port 22
    LocalForward 11434 localhost:11434
    IdentityFile ~/.ssh/your_private_key
    ServerAliveInterval 60
    ServerAliveCountMax 3

# Produktions-Server
Host prod-server
    HostName prod.example.com
    User admin
    LocalForward 11434 localhost:11434
    IdentityFile ~/.ssh/prod_key

# Test-Server
Host test-server
    HostName test.example.com
    User admin
    LocalForward 11434 localhost:11434
    IdentityFile ~/.ssh/test_key

# Backup-Server
Host backup-server
    HostName backup.example.com
    User admin
    LocalForward 11434 localhost:11434
    IdentityFile ~/.ssh/backup_key
"""
    
    try:
        # Erstelle .ssh-Verzeichnis falls es nicht existiert
        ssh_config_path.parent.mkdir(mode=0o700, exist_ok=True)
        
        with open(ssh_config_path, 'w') as f:
            f.write(template)
        
        # Setze korrekte Berechtigungen
        os.chmod(ssh_config_path, 0o600)
        
        console.print(f"[green]✅ SSH-Config-Vorlage erstellt: {ssh_config_path}[/green]")
        console.print("[yellow]⚠️  Bitte passen Sie die Konfiguration an Ihre Server an![/yellow]")
        
        return True
        
    except Exception as e:
        console.print(f"[red]❌ Fehler beim Erstellen der SSH-Config: {e}[/red]")
        return False

def main():
    """Hauptfunktion"""
    console.print("[bold blue]SSH-Konfiguration mit Port-Forwarding für Ollama[/bold blue]")
    console.print("="*70)
    
    # Zeige SSH-Config-Beispiele
    show_ssh_config_examples()
    
    console.print("\n")
    
    # Zeige Verwendungsbeispiele
    show_usage_examples()
    
    console.print("\n")
    
    # Überprüfe aktuelle Konfiguration
    check_ssh_config()
    
    console.print("\n")
    
    # Teste Ollama-Verbindung
    test_ollama_connection()
    
    console.print("\n")
    
    # Zeige Setup-Anweisungen
    show_ssh_config_setup()
    
    console.print("\n")
    
    # Frage nach SSH-Config-Erstellung
    if Confirm.ask("Möchten Sie eine SSH-Config-Vorlage erstellen?"):
        create_ssh_config_template()
    
    console.print("\n[bold green]Setup abgeschlossen![/bold green]")
    console.print("\n[bold]Nächste Schritte:[/bold]")
    console.print("1. Passen Sie die SSH-Config an Ihre Server an")
    console.print("2. Testen Sie die Verbindung: ssh your-server")
    console.print("3. Führen Sie die Log-Analyse aus: python3 ssh_log_collector.py user@server")

if __name__ == "__main__":
    main() 