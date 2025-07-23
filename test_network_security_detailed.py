#!/usr/bin/env python3
"""
Detaillierter Test für die Netzwerk-Sicherheitsanalyse
Testet alle Komponenten und zeigt detaillierte Ergebnisse
"""

import os
import sys
import json
import argparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# Importiere den SSH-Collector
from ssh_chat_system import SSHLogCollector

console = Console()

def test_network_security_detailed(host: str, username: str, key_file: str = None, port: int = 22, include_dns: bool = False):
    """Führt eine detaillierte Netzwerk-Sicherheitsanalyse durch"""
    
    console.print("[bold blue]🔒 Detaillierte Netzwerk-Sicherheitsanalyse[/bold blue]")
    console.print("="*80)
    
    # Erstelle SSH-Collector
    collector = SSHLogCollector(
        host=host,
        username=username,
        key_file=key_file,
        port=port
    )
    
    try:
        # Teste SSH-Verbindung
        console.print(f"[blue]🔗 Teste SSH-Verbindung zu {username}@{host}:{port}...[/blue]")
        if not collector.connect():
            console.print("[red]❌ SSH-Verbindung fehlgeschlagen[/red]")
            return False
        
        console.print("[green]✅ SSH-Verbindung erfolgreich[/green]")
        
        # 1. Teste interne Service-Analyse
        console.print("\n[bold cyan]1️⃣ Interne Service-Analyse[/bold cyan]")
        console.print("-" * 50)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Analysiere lauschende Services...", total=None)
            
            internal_services = collector.analyze_listening_services()
            progress.update(task, completed=True)
        
        # Zeige interne Service-Ergebnisse
        if internal_services and isinstance(internal_services, dict):
            console.print("[green]✅ Interne Service-Analyse erfolgreich[/green]")
            
            # Service-Mapping
            service_mapping = internal_services.get('service_mapping', {})
            if service_mapping:
                service_table = Table(title="Lauschende Services", show_header=True, header_style="bold magenta")
                service_table.add_column("Port", style="cyan", width=8)
                service_table.add_column("Service", style="green", width=20)
                service_table.add_column("Status", style="yellow", width=15)
                service_table.add_column("Details", style="white", width=30)
                
                for port, service_info in service_mapping.items():
                    service_name = service_info.get('service', 'Unbekannt')
                    status = service_info.get('status', 'Unbekannt')
                    details = service_info.get('details', '')
                    
                    service_table.add_row(str(port), service_name, status, details[:30])
                
                console.print(service_table)
            
            # IP-Adressen
            all_ip_addresses = internal_services.get('all_ip_addresses', [])
            if all_ip_addresses:
                ip_table = Table(title="Gefundene IP-Adressen", show_header=True, header_style="bold magenta")
                ip_table.add_column("IP-Adresse", style="cyan", width=20)
                ip_table.add_column("Interface", style="green", width=15)
                ip_table.add_column("Typ", style="yellow", width=10)
                
                for ip_info in all_ip_addresses:
                    if isinstance(ip_info, dict):
                        ip_table.add_row(
                            ip_info.get('ip', 'Unbekannt'),
                            ip_info.get('interface', 'Unbekannt'),
                            ip_info.get('type', 'Unbekannt')
                        )
                    else:
                        ip_table.add_row(str(ip_info), 'Unbekannt', 'Unbekannt')
                
                console.print(ip_table)
            
            # Firewall-Status
            firewall_status = internal_services.get('firewall_status', {})
            if firewall_status and isinstance(firewall_status, dict):
                console.print("\n[bold cyan]Firewall-Status:[/bold cyan]")
                for fw_name, fw_status in firewall_status.items():
                    if isinstance(fw_status, dict):
                        status_icon = "🟢" if fw_status.get('active', False) else "🔴"
                        console.print(f"{status_icon} {fw_name}: {fw_status.get('status', 'Unbekannt')}")
                    else:
                        console.print(f"🔵 {fw_name}: {fw_status}")
        
        else:
            if isinstance(internal_services, str):
                console.print(f"[red]❌ Interne Service-Analyse fehlgeschlagen: {internal_services}[/red]")
            else:
                console.print("[red]❌ Interne Service-Analyse fehlgeschlagen[/red]")
            return False
        
        # 2. Teste externe Erreichbarkeit
        console.print("\n[bold cyan]2️⃣ Externe Erreichbarkeitstests[/bold cyan]")
        console.print("-" * 50)
        
        if all_ip_addresses and service_mapping and len(service_mapping) > 0:
            internal_ports = list(service_mapping.keys())
            
            if internal_ports:
                # Verwende IP-Adressen direkt als Strings
                console.print(f"[dim]Teste {len(all_ip_addresses)} IP-Adressen auf {len(internal_ports)} Ports...[/dim]")
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    task = progress.add_task("Teste externe Erreichbarkeit...", total=len(all_ip_addresses) * len(internal_ports))
                    
                    external_tests = collector.test_external_accessibility(all_ip_addresses, internal_ports, include_dns)
                    progress.update(task, completed=True)
                
                # Zeige externe Test-Ergebnisse
                if external_tests:
                    console.print("[green]✅ Externe Erreichbarkeitstests erfolgreich[/green]")
                    
                    # Erreichbare Ports
                    reachable_ports = external_tests.get('reachable_ports', [])
                    reachable_hosts = external_tests.get('reachable_hosts', {})
                    
                    if reachable_ports:
                        reachable_table = Table(title="Extern erreichbare Services", show_header=True, header_style="bold magenta")
                        reachable_table.add_column("IP", style="cyan", width=20)
                        reachable_table.add_column("Port", style="green", width=8)
                        reachable_table.add_column("Service", style="yellow", width=20)
                        reachable_table.add_column("Banner", style="white", width=30)
                        
                        # Zeige erreichbare Ports für jeden Host
                        for host_ip, host_ports in reachable_hosts.items():
                            if host_ports:
                                for port in host_ports:
                                    service_name = collector._identify_service_by_port(port)
                                    banner = external_tests.get('service_versions', {}).get(port, '')[:30]
                                    reachable_table.add_row(
                                        host_ip,
                                        str(port),
                                        service_name,
                                        banner
                                    )
                        
                        console.print(reachable_table)
                    else:
                        console.print("[green]✅ Keine extern erreichbaren Services gefunden[/green]")
                    
                    # Host-spezifische Ergebnisse
                    host_results = external_tests.get('host_results', {})
                    if host_results:
                        console.print("\n[bold cyan]Host-spezifische Ergebnisse:[/bold cyan]")
                        for host_ip, host_data in host_results.items():
                            reachable_count = len(host_data.get('reachable_ports', []))
                            total_tested = len(host_data.get('tested_ports', []))
                            console.print(f"📡 {host_ip}: {reachable_count}/{total_tested} Ports erreichbar")
                
                else:
                    console.print("[red]❌ Externe Erreichbarkeitstests fehlgeschlagen[/red]")
                    return False
            else:
                console.print("[yellow]⚠️ Keine lauschenden Ports gefunden - überspringe externe Tests[/yellow]")
        else:
            if not all_ip_addresses:
                console.print("[yellow]⚠️ Keine IP-Adressen gefunden - überspringe externe Tests[/yellow]")
            elif not service_mapping or len(service_mapping) == 0:
                console.print("[yellow]⚠️ Keine lauschenden Services gefunden - überspringe externe Tests[/yellow]")
            else:
                console.print("[yellow]⚠️ Unbekannter Zustand - überspringe externe Tests[/yellow]")
        
        # 3. Teste Sicherheitsbewertung
        console.print("\n[bold cyan]3️⃣ Sicherheitsbewertung[/bold cyan]")
        console.print("-" * 50)
        
        if 'external_tests' in locals():
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Erstelle Sicherheitsbewertung...", total=None)
                
                security_assessment = collector.assess_network_security(internal_services, external_tests)
                progress.update(task, completed=True)
            
            # Zeige Sicherheitsbewertung
            if security_assessment:
                console.print("[green]✅ Sicherheitsbewertung erfolgreich[/green]")
                
                # Risiko-Level
                risk_level = security_assessment.get('risk_level', 'unknown')
                risk_color = {
                    'low': 'green',
                    'medium': 'yellow', 
                    'high': 'red',
                    'critical': 'red'
                }.get(risk_level, 'white')
                
                console.print(f"\n[bold {risk_color}]Risiko-Level: {risk_level.upper()}[/bold {risk_color}]")
                
                # Exponierte Services
                exposed_services = security_assessment.get('exposed_services', [])
                if exposed_services:
                    exposed_table = Table(title="Exponierte Services", show_header=True, header_style="bold magenta")
                    exposed_table.add_column("Port", style="green", width=8)
                    exposed_table.add_column("Service", style="yellow", width=20)
                    exposed_table.add_column("Risiko", style="red", width=15)
                    
                    for port in exposed_services:
                        service_name = collector._identify_service_by_port(port)
                        risk_level = 'Medium' if port in [22, 3306, 5432] else 'Low'
                        exposed_table.add_row(
                            str(port),
                            service_name,
                            risk_level
                        )
                    
                    console.print(exposed_table)
                else:
                    console.print("[green]✅ Keine exponierten Services gefunden[/green]")
                
                # Empfehlungen
                recommendations = security_assessment.get('recommendations', [])
                if recommendations:
                    console.print(f"\n[bold cyan]Empfehlungen ({len(recommendations)}):[/bold cyan]")
                    for i, rec in enumerate(recommendations, 1):
                        priority = rec.get('priority', 'medium')
                        priority_color = {
                            'high': 'red',
                            'medium': 'yellow',
                            'low': 'green'
                        }.get(priority, 'white')
                        
                        console.print(f"{i}. [{priority_color}]{rec.get('title', 'Unbekannt')}[/{priority_color}]")
                        console.print(f"   {rec.get('description', 'Keine Beschreibung')}")
                        if rec.get('action'):
                            console.print(f"   [dim]Aktion: {rec['action']}[/dim]")
                        console.print()
                
                # Sicherheits-Score
                security_score = security_assessment.get('security_score', 0)
                console.print(f"[bold cyan]Sicherheits-Score: {security_score}/100[/bold cyan]")
                
            else:
                console.print("[red]❌ Sicherheitsbewertung fehlgeschlagen[/red]")
                return False
        else:
            console.print("[yellow]⚠️ Keine externen Tests verfügbar - überspringe Sicherheitsbewertung[/yellow]")
        
        # 4. Erstelle Gesamtbericht
        console.print("\n[bold cyan]4️⃣ Gesamtbericht[/bold cyan]")
        console.print("-" * 50)
        
        # Sammle alle Daten
        complete_data = {
            'timestamp': datetime.now().isoformat(),
            'target': f"{username}@{host}:{port}",
            'internal_services': internal_services,
            'external_tests': external_tests if 'external_tests' in locals() else None,
            'security_assessment': security_assessment if 'security_assessment' in locals() else None
        }
        
        # Statistiken
        stats_table = Table(title="Analyse-Statistiken", show_header=True, header_style="bold magenta")
        stats_table.add_column("Metrik", style="cyan", width=25)
        stats_table.add_column("Wert", style="green", width=15)
        
        stats_data = [
            ("Gefundene IP-Adressen", len(all_ip_addresses)),
            ("Lauschende Ports", len(service_mapping)),
            ("Extern erreichbare Ports", len(external_tests.get('reachable_ports', [])) if 'external_tests' in locals() else 0),
            ("Exponierte Services", len(security_assessment.get('exposed_services', [])) if 'security_assessment' in locals() else 0),
            ("Empfehlungen", len(security_assessment.get('recommendations', [])) if 'security_assessment' in locals() else 0),
            ("Risiko-Level", risk_level if 'security_assessment' in locals() else 'N/A'),
            ("Sicherheits-Score", f"{security_assessment.get('security_score', 0)}/100" if 'security_assessment' in locals() else 'N/A')
        ]
        
        for metric, value in stats_data:
            stats_table.add_row(metric, str(value))
        
        console.print(stats_table)
        
        # Speichere Ergebnisse im system_reports Ordner
        os.makedirs('system_reports', exist_ok=True)
        output_file = f"system_reports/network_security_analysis_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(complete_data, f, indent=2, default=str)
        
        console.print(f"\n[green]✅ Detaillierte Analyse abgeschlossen![/green]")
        console.print(f"📄 Ergebnisse gespeichert in: {output_file}")
        
        return True
        
    except Exception as e:
        console.print(f"[red]❌ Fehler bei der Analyse: {e}[/red]")
        return False
    finally:
        # Cleanup
        collector.cleanup()

def main():
    """Hauptfunktion"""
    parser = argparse.ArgumentParser(description='Detaillierter Test für Netzwerk-Sicherheitsanalyse')
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
    
    # Führe detaillierte Analyse durch
    success = test_network_security_detailed(
        host=host,
        username=username,
        key_file=args.key_file,
        port=args.port,
        include_dns=args.include_dns
    )
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 