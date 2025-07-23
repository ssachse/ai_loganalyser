#!/usr/bin/env python3
"""
Schneller Test für die Netzwerk-Sicherheitsanalyse
Testet nur die wichtigsten Komponenten für schnelle Überprüfung
"""

import os
import sys
import argparse
from rich.console import Console
from rich.table import Table

# Importiere den SSH-Collector
from ssh_chat_system import SSHLogCollector

console = Console()

def test_network_security_quick(host: str, username: str, key_file: str = None, port: int = 22, include_dns: bool = False):
    """Führt eine schnelle Netzwerk-Sicherheitsanalyse durch"""
    
    console.print("[bold blue]🔒 Schnelle Netzwerk-Sicherheitsanalyse[/bold blue]")
    console.print("="*60)
    
    # Erstelle SSH-Collector
    collector = SSHLogCollector(
        host=host,
        username=username,
        key_file=key_file,
        port=port
    )
    
    try:
        # Teste SSH-Verbindung
        console.print(f"[blue]🔗 Verbinde zu {username}@{host}:{port}...[/blue]")
        if not collector.connect():
            console.print("[red]❌ SSH-Verbindung fehlgeschlagen[/red]")
            return False
        
        console.print("[green]✅ SSH-Verbindung erfolgreich[/green]")
        
        # 1. Schnelle interne Service-Analyse
        console.print("\n[dim]Analysiere lauschende Services...[/dim]")
        internal_services = collector.analyze_listening_services()
        
        if not internal_services:
            console.print("[red]❌ Interne Service-Analyse fehlgeschlagen[/red]")
            return False
        
        # Zeige Schnellübersicht
        service_mapping = internal_services.get('service_mapping', {})
        all_ip_addresses = internal_services.get('all_ip_addresses', [])
        
        console.print(f"[green]✅ {len(service_mapping)} lauschende Services gefunden[/green]")
        console.print(f"[green]✅ {len(all_ip_addresses)} IP-Adressen gefunden[/green]")
        
        # 2. Schnelle externe Tests (nur wenn Services vorhanden)
        if all_ip_addresses and service_mapping and len(service_mapping) > 0:
            internal_ports = list(service_mapping.keys())
            
            console.print(f"\n[dim]Teste externe Erreichbarkeit...[/dim]")
            external_tests = collector.test_external_accessibility(all_ip_addresses, internal_ports, include_dns)
            
            if external_tests:
                reachable_ports = external_tests.get('reachable_ports', [])
                console.print(f"[green]✅ {len(reachable_ports)} extern erreichbare Services gefunden[/green]")
                
                # 3. Schnelle Sicherheitsbewertung
                console.print(f"\n[dim]Erstelle Sicherheitsbewertung...[/dim]")
                security_assessment = collector.assess_network_security(internal_services, external_tests)
                
                if security_assessment:
                    risk_level = security_assessment.get('risk_level', 'unknown')
                    exposed_count = len(security_assessment.get('exposed_services', []))
                    security_score = security_assessment.get('security_score', 0)
                    
                    # Zeige Schnellübersicht
                    summary_table = Table(title="Sicherheits-Übersicht", show_header=True, header_style="bold magenta")
                    summary_table.add_column("Metrik", style="cyan", width=20)
                    summary_table.add_column("Wert", style="green", width=15)
                    
                    summary_data = [
                        ("Lauschende Services", len(service_mapping)),
                        ("IP-Adressen", len(all_ip_addresses)),
                        ("Extern erreichbar", len(reachable_ports)),
                        ("Exponierte Services", exposed_count),
                        ("Risiko-Level", risk_level.upper()),
                        ("Sicherheits-Score", f"{security_score}/100")
                    ]
                    
                    for metric, value in summary_data:
                        summary_table.add_row(metric, str(value))
                    
                    console.print(summary_table)
                    
                    # Zeige wichtigste Empfehlungen
                    recommendations = security_assessment.get('recommendations', [])
                    if recommendations:
                        high_priority = [r for r in recommendations if r.get('priority') == 'high']
                        if high_priority:
                            console.print(f"\n[bold red]⚠️  {len(high_priority)} hochprioritäre Empfehlungen:[/bold red]")
                            for i, rec in enumerate(high_priority[:3], 1):  # Zeige nur Top 3
                                console.print(f"{i}. {rec.get('title', 'Unbekannt')}")
                        else:
                            console.print(f"\n[green]✅ Keine hochprioritären Probleme gefunden[/green]")
                    
                    console.print(f"\n[green]✅ Schnelle Analyse abgeschlossen![/green]")
                    return True
                else:
                    console.print("[red]❌ Sicherheitsbewertung fehlgeschlagen[/red]")
                    return False
            else:
                console.print("[red]❌ Externe Tests fehlgeschlagen[/red]")
                return False
        else:
            if not all_ip_addresses:
                console.print("[yellow]⚠️ Keine IP-Adressen gefunden[/yellow]")
            elif not service_mapping or len(service_mapping) == 0:
                console.print("[yellow]⚠️ Keine lauschenden Services gefunden[/yellow]")
            else:
                console.print("[yellow]⚠️ Unbekannter Zustand[/yellow]")
            return True
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei der Analyse: {e}[/red]")
        return False
    finally:
        # Cleanup
        collector.cleanup()

def main():
    """Hauptfunktion"""
    parser = argparse.ArgumentParser(description='Schneller Test für Netzwerk-Sicherheitsanalyse')
    parser.add_argument('target', help='Ziel-Server (user@host oder host)')
    parser.add_argument('--username', help='SSH-Benutzername (falls nicht in target angegeben)')
    parser.add_argument('--key-file', help='Pfad zur SSH-Key-Datei')
    parser.add_argument('--port', type=int, default=22, help='SSH-Port (Standard: 22)')
    parser.add_argument('--include-dns', action='store_true', help='DNS-basierte Tests einschließen')
    
    args = parser.parse_args()
    
    # Parse target (user@host oder host)
    if '@' in args.target:
        username, host = args.target.split('@', 1)
    else:
        host = args.target
        username = args.username
    
    if not username:
        console.print("[red]❌ Benutzername fehlt. Verwenden Sie 'user@host' oder --username[/red]")
        return 1
    
    # Führe schnelle Analyse durch
    success = test_network_security_quick(
        host=host,
        username=username,
        key_file=args.key_file,
        port=args.port,
        include_dns=args.include_dns
    )
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 