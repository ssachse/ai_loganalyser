#!/usr/bin/env python3
"""
Test für vollständige System-Daten-Analyse
Zeigt alle verfügbaren Daten, die im Report verwendet werden sollten
"""

import sys
import os
sys.path.append('.')

from ssh_chat_system import create_system_context, create_system_report_prompt, query_ollama, select_best_model
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def test_complete_data():
    """Testet alle verfügbaren System-Daten"""
    
    console.print("[bold blue]🔍 Analysiere alle verfügbaren System-Daten...[/bold blue]")
    
    # Mock system_info mit ALLEN verfügbaren Daten
    system_info = {
        'hostname': 'app02.profiflitzer.de',
        'distro_pretty_name': 'Debian GNU/Linux 10 (buster)',
        'kernel_version': '4.19.0-21-amd64',
        'architecture': 'x86_64',
        'cpu_info': 'AMD EPYC 7702 64-Core Processor',
        'cpu_cores': '4',
        'memory_total': '7,8 GiB',
        'uptime': '64 days, 3 hours and 24 minutes',
        'timezone': 'Europe/Berlin',
        'root_usage_percent': '11.4%',
        'root_total': '500G',
        'root_used': '57G',
        'root_available': '443G',
        'cpu_usage_percent': '0.0%',
        'memory_usage_percent': '11.4%',
        'load_average_1min': '0.53',
        'load_average_5min': '0.48',
        'load_average_15min': '0.45',
        'package_manager': 'apt',
        'installed_packages_count': '2847',
        'available_updates': '166',
        'important_services_status': {
            'ssh': 'active (running)',
            'docker': 'active (running)',
            'nginx': 'active (running)',
            'postgresql': 'active (running)',
            'rsyslog': 'active (running)',
            'fail2ban': 'active (running)',
            'rsyncd': 'active (running)'
        },
        'current_users': '1 (root)',
        'user_login_stats': 'root: 1 login, letzte Anmeldung am 4. Juli um 14:33',
        'failed_logins_by_user': 'root: 0 failed attempts',
        'docker_detected': True,
        'docker_version': '20.10.17',
        'docker_info': 'Docker Engine - Community\n Version: 20.10.17\n API version: 1.41\n Go version: go1.17.11\n Git commit: 100c701\n Built: Mon Jun 6 23:05:12 2022\n OS/Arch: linux/amd64\n Context: default\n Experimental: false',
        'running_containers': '1 container running',
        'all_containers': '1 container total',
        'docker_containers': '1 container running',
        'docker_images': '18 images',
        'docker_volumes': '12 volumes',
        'docker_networks': '3 networks',
        'system_usage': 'Docker system usage:\nImages: 1.61GB\nContainers: 0.1GB\nVolumes: 0.5GB\nBuild cache: 0B',
        'kubernetes_detected': False,
        'proxmox_detected': False,
        'mailcow_detected': False,
        'postfix_detected': False,
        'mailserver_detected': False,
        'ssh_config': {
            'port': '22',
            'protocol': '2',
            'permit_root_login': 'no',
            'password_authentication': 'yes',
            'pubkey_authentication': 'yes',
            'max_auth_tries': '6',
            'client_alive_interval': '300'
        },
        'listening_services': [
            {'port': 22, 'service': 'ssh', 'process': 'sshd'},
            {'port': 80, 'service': 'http', 'process': 'nginx'},
            {'port': 443, 'service': 'https', 'process': 'nginx'},
            {'port': 5432, 'service': 'postgresql', 'process': 'postgres'},
            {'port': 8081, 'service': 'http-alt', 'process': 'docker-proxy'}
        ],
        'largest_directories': {
            '/home': '2.1G',
            '/var': '15.2G',
            '/tmp': '0.1G',
            '/var/log': '1.8G',
            '/var/lib/docker': '12.5G',
            '/var/cache/apt': '0.3G'
        },
        'largest_files': [
            '/var/log/rsyncd.log: 1.2G',
            '/var/log/syslog: 0.8G',
            '/var/log/auth.log: 0.3G',
            '/var/lib/docker/containers/abc123/abc123-json.log: 0.5G'
        ],
        'largest_files_by_directory': {
            '/var/log': [
                'rsyncd.log: 1.2G',
                'syslog: 0.8G',
                'auth.log: 0.3G',
                'kern.log: 0.1G'
            ],
            '/var/lib/docker': [
                'containers/abc123/abc123-json.log: 0.5G',
                'overlay2/def456/merged: 2.1G'
            ]
        },
        'recent_log_entries': [
            {'timestamp': '2025-07-24 19:05:23', 'level': 'INFO', 'message': 'Docker container my-prf started'},
            {'timestamp': '2025-07-24 18:58:12', 'level': 'INFO', 'message': 'SSH login successful for root'},
            {'timestamp': '2025-07-24 18:45:33', 'level': 'WARNING', 'message': 'High memory usage detected: 11.4%'},
            {'timestamp': '2025-07-24 18:30:45', 'level': 'INFO', 'message': 'System boot completed'}
        ],
        'anomalies': [
            {'type': 'low_cpu_usage', 'severity': 'low', 'description': 'CPU usage at 0.0% for extended period'},
            {'type': 'low_memory_usage', 'severity': 'low', 'description': 'Memory usage at 11.4%'},
            {'type': 'long_uptime', 'severity': 'medium', 'description': 'System uptime 64 days'}
        ],
        'process_info': 'Top processes by CPU:\n1. systemd (PID 1): 0.1%\n2. sshd (PID 1234): 0.0%\n3. nginx (PID 5678): 0.0%\n4. docker-proxy (PID 9012): 0.0%',
        'system_status': 'System is running normally\nAll services operational\nNo critical issues detected',
        'home_usage': '2.1G',
        'var_usage': '15.2G',
        'tmp_usage': '0.1G',
        'log_usage': '1.8G',
        'docker_usage': '12.5G',
        'apt_usage': '0.3G'
    }
    
    # Mock log_entries und anomalies
    log_entries = []
    anomalies = []
    
    console.print("\n[bold]Test 1: Analysiere verfügbare Daten[/bold]")
    
    # Zeige alle verfügbaren Schlüssel
    table = Table(title="Verfügbare System-Daten")
    table.add_column("Kategorie", style="cyan")
    table.add_column("Schlüssel", style="green")
    table.add_column("Wert", style="yellow")
    table.add_column("Typ", style="magenta")
    
    categories = {
        'System-Basis': ['hostname', 'distro_pretty_name', 'kernel_version', 'architecture', 'cpu_info', 'cpu_cores', 'memory_total', 'uptime', 'timezone'],
        'Performance': ['cpu_usage_percent', 'memory_usage_percent', 'load_average_1min', 'load_average_5min', 'load_average_15min'],
        'Speicherplatz': ['root_usage_percent', 'root_total', 'root_used', 'root_available', 'home_usage', 'var_usage', 'tmp_usage', 'log_usage', 'docker_usage', 'apt_usage'],
        'Services': ['important_services_status', 'package_manager', 'installed_packages_count', 'available_updates'],
        'Benutzer': ['current_users', 'user_login_stats', 'failed_logins_by_user'],
        'Docker': ['docker_detected', 'docker_version', 'docker_info', 'running_containers', 'all_containers', 'docker_containers', 'docker_images', 'docker_volumes', 'docker_networks', 'system_usage'],
        'Sicherheit': ['ssh_config', 'listening_services'],
        'Speicherplatz-Details': ['largest_directories', 'largest_files', 'largest_files_by_directory'],
        'Logs & Anomalien': ['recent_log_entries', 'anomalies', 'process_info', 'system_status']
    }
    
    for category, keys in categories.items():
        for key in keys:
            if key in system_info:
                value = system_info[key]
                if isinstance(value, dict):
                    value_str = f"Dict mit {len(value)} Einträgen"
                elif isinstance(value, list):
                    value_str = f"Liste mit {len(value)} Einträgen"
                elif isinstance(value, str) and len(value) > 100:
                    value_str = value[:100] + "..."
                else:
                    value_str = str(value)
                
                table.add_row(category, key, value_str, type(value).__name__)
    
    console.print(table)
    
    console.print(f"\n[bold]Test 2: Erstelle System-Context[/bold]")
    try:
        system_context = create_system_context(system_info, log_entries, anomalies, focus_network_security=False)
        console.print(f"[green]✅ System-Context erstellt (Länge: {len(system_context)} Zeichen)[/green]")
        
        # Zeige Ausschnitt des Contexts
        console.print(f"\n[dim]System-Context Ausschnitt (erste 1000 Zeichen):[/dim]")
        console.print(Panel(system_context[:1000] + "...", title="System-Context"))
        
    except Exception as e:
        console.print(f"[red]❌ Fehler beim Erstellen des System-Context: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
        return
    
    console.print(f"\n[bold]Test 3: Erstelle Report-Prompt[/bold]")
    try:
        report_prompt = create_system_report_prompt(system_context)
        console.print(f"[green]✅ Report-Prompt erstellt (Länge: {len(report_prompt)} Zeichen)[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Fehler beim Erstellen des Report-Prompts: {e}[/red]")
        return
    
    console.print(f"\n[bold]Test 4: Generiere vollständigen Report[/bold]")
    try:
        # Verwende komplexes Modell für Berichterstellung
        model = select_best_model(complex_analysis=True, for_menu=False)
        console.print(f"[dim]🔄 Verwende Modell: {model} für Report-Generierung[/dim]")
        
        # Generiere Bericht
        console.print(f"[dim]🤔 Generiere vollständigen Systembericht...[/dim]")
        report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
        
        if report_content:
            console.print(f"[green]✅ Vollständiger Report generiert (Länge: {len(report_content)} Zeichen)[/green]")
            
            # Zeige den Report
            console.print(f"\n[bold green]📄 VOLLSTÄNDIGER REPORT:[/bold green]")
            console.print("="*80)
            console.print(report_content)
            console.print("="*80)
            
            # Prüfe ob der Report alle wichtigen Daten enthält
            important_data_found = []
            important_data_missing = []
            
            important_keys = [
                'app02.profiflitzer.de', 'Debian GNU/Linux 10', 'AMD EPYC 7702', '7,8 GiB',
                '64 days', '11.4%', '0.0%', '166', 'Docker', '20.10.17', '1 container',
                'nginx', 'postgresql', 'ssh', 'rsyncd', '0.53', 'Europe/Berlin'
            ]
            
            for key in important_keys:
                if key in report_content:
                    important_data_found.append(key)
                else:
                    important_data_missing.append(key)
            
            console.print(f"\n[bold]Test 5: Prüfe Vollständigkeit des Reports[/bold]")
            if important_data_found:
                console.print(f"[green]✅ Gefundene wichtige Daten: {len(important_data_found)}[/green]")
                for data in important_data_found[:10]:  # Zeige nur erste 10
                    console.print(f"[dim]  ✅ {data}[/dim]")
            
            if important_data_missing:
                console.print(f"[red]❌ Fehlende wichtige Daten: {len(important_data_missing)}[/red]")
                for data in important_data_missing[:10]:  # Zeige nur erste 10
                    console.print(f"[dim]  ❌ {data}[/dim]")
            
            # Speichere Test-Report
            console.print(f"\n[bold]Test 6: Speichere vollständigen Test-Report[/bold]")
            try:
                from ssh_chat_system import save_system_report
                filename = save_system_report(report_content, system_info)
                console.print(f"[green]✅ Vollständiger Test-Report gespeichert: {filename}[/green]")
                
            except Exception as e:
                console.print(f"[red]❌ Fehler beim Speichern: {e}[/red]")
            
        else:
            console.print(f"[red]❌ Keine Antwort von Ollama erhalten[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Fehler bei Report-Generierung: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
    
    console.print(f"\n[bold green]✅ Vollständige Daten-Analyse abgeschlossen![/bold green]")

if __name__ == "__main__":
    test_complete_data() 