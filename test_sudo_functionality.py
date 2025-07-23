#!/usr/bin/env python3
"""
Test-Skript für die intelligente Sudo-Funktionalität
Demonstriert die automatische Sudo-Erkennung und sichere Befehlsausführung
"""

import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from ssh_chat_system import SSHLogCollector

console = Console()

def test_sudo_functionality():
    """Testet die Sudo-Funktionalität des SSHLogCollectors"""
    
    console.print(Panel.fit(
        "[bold blue]🔐 Test der intelligenten Sudo-Funktionalität[/bold blue]\n"
        "Dieses Skript testet die automatische Sudo-Erkennung und sichere Befehlsausführung.",
        title="Sudo-Test"
    ))
    
    # Prüfe ob SSH-Verbindungsdaten verfügbar sind
    host = os.getenv('SSH_HOST')
    username = os.getenv('SSH_USER')
    key_file = os.getenv('SSH_KEY_FILE')
    password = os.getenv('SSH_PASSWORD')
    
    if not host or not username:
        console.print("[red]❌ SSH-Verbindungsdaten nicht gefunden![/red]")
        console.print("Bitte setzen Sie die Umgebungsvariablen:")
        console.print("  export SSH_HOST='ihr-server.com'")
        console.print("  export SSH_USER='ihr-username'")
        console.print("  export SSH_KEY_FILE='/path/to/key' (optional)")
        console.print("  export SSH_PASSWORD='ihr-passwort' (optional)")
        return False
    
    try:
        # SSHLogCollector initialisieren
        collector = SSHLogCollector(
            host=host,
            username=username,
            password=password,
            key_file=key_file
        )
        
        console.print(f"[green]✅ Verbinde zu {username}@{host}...[/green]")
        
        # Teste Sudo-Verfügbarkeit
        console.print("\n[bold]🔍 Teste Sudo-Verfügbarkeit...[/bold]")
        sudo_info = collector.test_sudo_availability()
        
        # Erstelle Tabelle für Sudo-Status
        table = Table(title="Sudo-Status")
        table.add_column("Eigenschaft", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Details", style="yellow")
        
        table.add_row("Sudo verfügbar", 
                     "✅ Ja" if sudo_info['available'] else "❌ Nein",
                     "sudo-Befehl gefunden" if sudo_info['available'] else "sudo nicht installiert")
        
        table.add_row("Passwortlos", 
                     "✅ Ja" if sudo_info['passwordless'] else "❌ Nein",
                     "sudo -n true erfolgreich" if sudo_info['passwordless'] else "Passwort erforderlich")
        
        table.add_row("Getestete Befehle", 
                     f"{len(sudo_info['tested_commands'])}", 
                     ", ".join(sudo_info['tested_commands']))
        
        table.add_row("Erfolgreiche Befehle", 
                     f"{len(sudo_info['safe_commands'])}", 
                     ", ".join(sudo_info['safe_commands']) if sudo_info['safe_commands'] else "Keine")
        
        console.print(table)
        
        # Teste verschiedene Befehle
        console.print("\n[bold]🧪 Teste verschiedene Befehle...[/bold]")
        
        test_commands = [
            # Normale Befehle (sollten ohne Sudo funktionieren)
            ("ls /tmp", "Normales Verzeichnis-Listing"),
            ("whoami", "Aktueller Benutzer"),
            ("pwd", "Aktuelles Verzeichnis"),
            
            # Befehle die möglicherweise Sudo benötigen
            ("ls /var/log", "System-Logs (möglicherweise Sudo erforderlich)"),
            ("cat /etc/hostname", "Hostname (möglicherweise Sudo erforderlich)"),
            ("df -h", "Speicherplatz (möglicherweise Sudo erforderlich)"),
            
            # Gefährliche Befehle (sollten niemals mit Sudo ausgeführt werden)
            ("rm -rf /tmp/test", "Gefährlicher Lösch-Befehl"),
            ("systemctl restart ssh", "Gefährlicher Service-Befehl"),
            ("useradd testuser", "Gefährlicher User-Befehl")
        ]
        
        results_table = Table(title="Befehls-Test-Ergebnisse")
        results_table.add_column("Befehl", style="cyan", width=30)
        results_table.add_column("Beschreibung", style="blue", width=40)
        results_table.add_column("Ergebnis", style="green", width=20)
        results_table.add_column("Sudo verwendet", style="yellow", width=15)
        
        for cmd, desc in test_commands:
            console.print(f"[dim]Teste: {cmd}[/dim]")
            
            # Führe Befehl aus
            result = collector.execute_remote_command(cmd)
            
            # Bestimme ob Sudo verwendet wurde (basierend auf der Implementierung)
            sudo_used = "❌ Nein"
            if result and sudo_info['passwordless']:
                # Bei erfolgreichem Ergebnis und verfügbarem Sudo könnte es verwendet worden sein
                # (In der realen Implementierung würde das getrackt werden)
                sudo_used = "✅ Möglicherweise"
            
            status = "✅ Erfolg" if result else "❌ Fehler"
            
            results_table.add_row(
                cmd[:28] + "..." if len(cmd) > 30 else cmd,
                desc,
                status,
                sudo_used
            )
        
        console.print(results_table)
        
        # Zeige Fehler-Zusammenfassung
        console.print("\n[bold]📊 Fehler-Zusammenfassung:[/bold]")
        collector.print_error_summary()
        
        # Sicherheitshinweise
        console.print("\n[bold green]🔒 Sicherheitshinweise:[/bold green]")
        console.print("• Das System verwendet niemals Sudo für Lösch- oder Modifikationsbefehle")
        console.print("• Nur lesende Befehle werden mit erhöhten Rechten ausgeführt")
        console.print("• Bei Sudo-Problemen wird automatisch auf normalen Modus zurückgegriffen")
        console.print("• Alle Sudo-Operationen werden transparent protokolliert")
        
        return True
        
    except Exception as e:
        console.print(f"[red]❌ Fehler beim Testen: {e}[/red]")
        return False

if __name__ == "__main__":
    success = test_sudo_functionality()
    sys.exit(0 if success else 1) 