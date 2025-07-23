#!/usr/bin/env python3
"""
Testskript für die Netzwerk-Sicherheitsanalyse-Funktionalität
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ssh_chat_system import SSHLogCollector
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

console = Console()

def test_network_security_analysis():
    """Testet die Netzwerk-Sicherheitsanalyse-Funktionalität"""
    
    console.print(Panel.fit("🔍 Netzwerk-Sicherheitsanalyse Test", style="bold blue"))
    
    # Test-Konfiguration
    test_config = {
        'host': 'localhost',  # Ändern Sie dies zu Ihrem Test-System
        'username': 'root',
        'key_file': None
    }
    
    try:
        # Erstelle SSH-Verbindung
        console.print(f"[dim]🔗 Verbinde zu {test_config['host']}...[/dim]")
        collector = SSHLogCollector(**test_config)
        
        if not collector.connect():
            console.print(f"[red]❌ Verbindung zu {test_config['host']} fehlgeschlagen[/red]")
            return False
        
        console.print(f"[green]✅ Verbindung zu {test_config['host']} erfolgreich[/green]")
        
        # 1. Teste interne Service-Analyse
        console.print("\n[bold]1. Interne Service-Analyse[/bold]")
        internal_services = collector.analyze_listening_services()
        
        if 'error' in internal_services:
            console.print(f"[red]❌ Fehler bei Service-Analyse: {internal_services['error']}[/red]")
            return False
        
        # Zeige Service-Mapping
        if 'service_mapping' in internal_services:
            service_table = Table(title="Lauschende Services")
            service_table.add_column("Port", style="cyan")
            service_table.add_column("Address", style="green")
            service_table.add_column("Extern", style="yellow")
            
            for port, info in internal_services['service_mapping'].items():
                address = info.get('address', 'N/A')
                external = "Ja" if info.get('external', False) else "Nein"
                service_table.add_row(str(port), address, external)
            
            console.print(service_table)
        
        # Zeige Firewall-Status
        if 'firewall_status' in internal_services:
            firewall_status = internal_services['firewall_status']
            if firewall_status:
                console.print("\n[bold]Firewall-Status:[/bold]")
                for fw_type, status in firewall_status.items():
                    console.print(f"  • {fw_type}: Aktiv")
            else:
                console.print("\n[yellow]⚠️ Keine Firewall-Konfiguration gefunden[/yellow]")
        
        # 2. Teste externe Erreichbarkeit (alle IP-Adressen)
        all_ip_addresses = internal_services.get('all_ip_addresses', [])
        if all_ip_addresses:
            console.print(f"\n[bold]2. Externe Erreichbarkeit Test[/bold]")
            console.print(f"[dim]Teste von {len(all_ip_addresses)} IP-Adressen: {', '.join(all_ip_addresses)}[/dim]")
            
            # Teste nur die ersten 5 Ports für Performance
            test_ports = list(internal_services.get('service_mapping', {}).keys())[:5]
            
            if test_ports:
                external_tests = collector.test_external_accessibility(all_ip_addresses, test_ports)
                
                if 'error' in external_tests:
                    console.print(f"[red]❌ Fehler bei externer Erreichbarkeit: {external_tests['error']}[/red]")
                else:
                    reachable_ports = external_tests.get('reachable_ports', [])
                    reachable_hosts = external_tests.get('reachable_hosts', {})
                    reachable_hosts_count = sum(1 for host, ports in reachable_hosts.items() if ports)
                    
                    console.print(f"[green]✅ {len(reachable_ports)} von {len(test_ports)} Ports auf {reachable_hosts_count} Hosts erreichbar[/green]")
                    
                    if reachable_ports:
                        console.print(f"Erreichbare Ports: {', '.join(map(str, reachable_ports))}")
                    
                    # Zeige Host-spezifische Informationen
                    if reachable_hosts:
                        console.print("\n[bold]Host-spezifische Erreichbarkeit:[/bold]")
                        for host, ports in reachable_hosts.items():
                            if ports:
                                console.print(f"  {host}: {', '.join(map(str, ports))}")
                    
                    # Zeige Service-Versionen
                    service_versions = external_tests.get('service_versions', {})
                    if service_versions:
                        console.print("\n[bold]Service-Versionen:[/bold]")
                        for port, version in service_versions.items():
                            console.print(f"  Port {port}: {version}")
                    
                    # Zeige Sicherheitsprobleme
                    vuln_indicators = external_tests.get('vulnerability_indicators', [])
                    if vuln_indicators:
                        console.print("\n[bold red]Sicherheitsprobleme:[/bold red]")
                        for indicator in vuln_indicators:
                            console.print(f"  • {indicator}")
                    
                    # 3. Teste Sicherheitsbewertung
                    console.print(f"\n[bold]3. Sicherheitsbewertung[/bold]")
                    security_assessment = collector.assess_network_security(internal_services, external_tests)
                    
                    if 'error' in security_assessment:
                        console.print(f"[red]❌ Fehler bei Sicherheitsbewertung: {security_assessment['error']}[/red]")
                    else:
                        risk_level = security_assessment.get('risk_level', 'unknown')
                        exposed_services = security_assessment.get('exposed_services', [])
                        host_exposure = security_assessment.get('host_exposure', {})
                        recommendations = security_assessment.get('recommendations', [])
                        
                        # Risiko-Level mit Farbe
                        risk_colors = {
                            'low': 'green',
                            'medium': 'yellow', 
                            'high': 'red',
                            'critical': 'bold red'
                        }
                        risk_color = risk_colors.get(risk_level, 'white')
                        
                        console.print(f"[{risk_color}]Risiko-Level: {risk_level.upper()}[/{risk_color}]")
                        console.print(f"Exponierte Services: {len(exposed_services)}")
                        
                        # Zeige Host-spezifische Exposition
                        if host_exposure:
                            console.print("\n[bold]Host-spezifische Exposition:[/bold]")
                            for host, ports in host_exposure.items():
                                if ports:
                                    console.print(f"  {host}: {', '.join(map(str, ports))}")
                        
                        if recommendations:
                            console.print("\n[bold]Empfehlungen:[/bold]")
                            for rec in recommendations:
                                console.print(f"  • {rec}")
                        
                        compliance_issues = security_assessment.get('compliance_issues', [])
                        if compliance_issues:
                            console.print("\n[bold red]Compliance-Probleme:[/bold red]")
                            for issue in compliance_issues:
                                console.print(f"  • {issue}")
        else:
            console.print("\n[yellow]⚠️ Keine IP-Adressen gefunden - Überspringe externe Tests[/yellow]")
        
        # 4. Teste Sudo-Verfügbarkeit für Netzwerk-Tools
        console.print(f"\n[bold]4. Sudo-Verfügbarkeit für Netzwerk-Tools[/bold]")
        sudo_test = collector.test_sudo_availability()
        
        if 'error' in sudo_test:
            console.print(f"[red]❌ Fehler bei Sudo-Test: {sudo_test['error']}[/red]")
        else:
            sudo_available = sudo_test.get('sudo_available', False)
            if sudo_available:
                console.print("[green]✅ Sudo ohne Passwort verfügbar[/green]")
                
                # Teste Netzwerk-Tools mit Sudo
                network_tools = ['nmap', 'netstat', 'ss', 'iptables']
                for tool in network_tools:
                    tool_check = collector.execute_remote_command(f'which {tool}', force_sudo=True)
                    if tool_check:
                        console.print(f"  • {tool}: Verfügbar")
                    else:
                        console.print(f"  • {tool}: Nicht verfügbar")
            else:
                console.print("[yellow]⚠️ Sudo ohne Passwort nicht verfügbar[/yellow]")
        
        console.print(f"\n[green]✅ Netzwerk-Sicherheitsanalyse Test abgeschlossen[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red]❌ Unerwarteter Fehler: {e}[/red]")
        return False
    
    finally:
        if 'collector' in locals():
            collector.cleanup()

def test_shortcuts():
    """Testet die neuen Netzwerk-Sicherheits-Shortcuts"""
    
    console.print(Panel.fit("🔧 Shortcut-Test", style="bold blue"))
    
    # Importiere die Shortcuts
    from ssh_chat_system import start_interactive_chat
    
    # Verfügbare Shortcuts (aus der Chat-Logik)
    shortcuts = {
        'network-security': {
            'question': 'Führe eine vollständige Netzwerk-Sicherheitsanalyse durch',
            'complex': True,
            'cache_key': 'network_security'
        },
        'exposed-services': {
            'question': 'Identifiziere alle extern erreichbaren Services',
            'complex': False,
            'cache_key': 'exposed_services'
        },
        'port-scan': {
            'question': 'Führe einen schnellen Port-Scan durch',
            'complex': False,
            'cache_key': 'port_scan'
        },
        'service-test': {
            'question': 'Teste die Erreichbarkeit aller Services',
            'complex': False,
            'cache_key': 'service_test'
        }
    }
    
    # Teste Interpolation
    from ssh_chat_system import interpolate_user_input_to_shortcut
    
    test_inputs = [
        'netzwerk sicherheit',
        'network security',
        'firewall',
        'ports scan',
        'exposed services',
        'service test',
        'nmap',
        'telnet'
    ]
    
    console.print("\n[bold]Shortcut-Interpolation Tests:[/bold]")
    for test_input in test_inputs:
        result = interpolate_user_input_to_shortcut(test_input, shortcuts)
        if result:
            console.print(f"  '{test_input}' -> '{result}'")
        else:
            console.print(f"  '{test_input}' -> Keine Übereinstimmung")
    
    console.print(f"\n[green]✅ Shortcut-Test abgeschlossen[/green]")

if __name__ == "__main__":
    console.print(Panel.fit("🚀 Netzwerk-Sicherheitsanalyse Test Suite", style="bold green"))
    
    # Teste Shortcuts
    test_shortcuts()
    
    # Frage nach SSH-Verbindung
    console.print("\n[bold]Möchten Sie die vollständige Netzwerk-Sicherheitsanalyse testen?[/bold]")
    console.print("[dim]Dies erfordert eine SSH-Verbindung zu einem Test-System.[/dim]")
    
    try:
        response = input("Test ausführen? (j/n): ").lower().strip()
        if response in ['j', 'ja', 'y', 'yes']:
            test_network_security_analysis()
        else:
            console.print("[yellow]Test übersprungen[/yellow]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Test abgebrochen[/yellow]")
    
    console.print("\n[green]Test Suite beendet[/green]") 