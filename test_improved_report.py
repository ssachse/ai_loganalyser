#!/usr/bin/env python3
"""
Test für verbesserten Report-Prompt
Verwendet spezifische System-Daten statt allgemeines "Gelaber"
"""

import sys
import os
sys.path.append('.')

from ssh_chat_system import (
    create_system_report_prompt, query_ollama, select_best_model,
    save_system_report
)
from rich.console import Console

console = Console()

def test_improved_report():
    """Testet den verbesserten Report-Prompt mit spezifischen Daten"""
    
    console.print("[bold blue]🧪 Teste verbesserten Report-Prompt...[/bold blue]")
    
    # Mock system_info mit spezifischen, realistischen Daten
    system_info = {
        'hostname': 'app02.profiflitzer.de',
        'distro_pretty_name': 'Debian GNU/Linux 10 (buster)',
        'kernel_version': '4.19.0-21-amd64',
        'architecture': 'x86_64',
        'cpu_info': 'Intel(R) Core(TM) i5-8400 CPU @ 2.80GHz',
        'cpu_cores': '6',
        'memory_total': '16G',
        'uptime': 'up 15 days, 3:42',
        'timezone': 'Europe/Berlin',
        'root_usage_percent': '78%',
        'root_total': '500G',
        'root_used': '390G',
        'root_available': '110G',
        'cpu_usage_percent': '45.2%',
        'memory_usage_percent': '82.7%',
        'load_average_1min': '2.15',
        'load_average_5min': '1.89',
        'load_average_15min': '1.67',
        'package_manager': 'apt',
        'installed_packages_count': '2847',
        'available_updates': '47',
        'important_services_status': {
            'ssh': 'active (running)',
            'docker': 'active (running)',
            'nginx': 'active (running)',
            'postgresql': 'active (running)',
            'rsyslog': 'active (running)',
            'fail2ban': 'active (running)'
        },
        'current_users': '3 users',
        'user_login_stats': 'admin: 23 logins, user1: 8 logins, user2: 5 logins',
        'failed_logins_by_user': 'root: 12 failed attempts, admin: 3 failed attempts',
        'docker_detected': True,
        'docker_containers': '5 containers running',
        'docker_images': '18 images',
        'docker_volumes': '12 volumes',
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
            'pubkey_authentication': 'yes'
        },
        'listening_services': [
            {'port': 22, 'service': 'ssh', 'process': 'sshd'},
            {'port': 80, 'service': 'http', 'process': 'nginx'},
            {'port': 443, 'service': 'https', 'process': 'nginx'},
            {'port': 5432, 'service': 'postgresql', 'process': 'postgres'},
            {'port': 8080, 'service': 'http-alt', 'process': 'docker-proxy'}
        ],
        'recent_log_entries': [
            {'timestamp': '2025-07-24 18:05:23', 'level': 'WARNING', 'message': 'High memory usage detected: 82.7%'},
            {'timestamp': '2025-07-24 17:58:12', 'level': 'ERROR', 'message': 'Failed login attempt for user root from 192.168.1.100'},
            {'timestamp': '2025-07-24 17:45:33', 'level': 'INFO', 'message': 'Docker container webapp restarted'},
            {'timestamp': '2025-07-24 17:30:45', 'level': 'WARNING', 'message': 'Disk usage at 78% - monitoring required'}
        ],
        'anomalies': [
            {'type': 'high_memory_usage', 'severity': 'medium', 'description': 'Memory usage at 82.7%'},
            {'type': 'high_disk_usage', 'severity': 'high', 'description': 'Disk usage at 78%'},
            {'type': 'failed_logins', 'severity': 'medium', 'description': '12 failed login attempts for root'}
        ]
    }
    
    # Mock log_entries und anomalies
    log_entries = []
    anomalies = []
    
    console.print("\n[bold]Test 1: Erstelle System-Context[/bold]")
    try:
        from ssh_chat_system import create_system_context
        system_context = create_system_context(system_info, log_entries, anomalies, focus_network_security=False)
        console.print(f"[green]✅ System-Context erstellt (Länge: {len(system_context)} Zeichen)[/green]")
        
        # Zeige Ausschnitt des Contexts
        console.print(f"\n[dim]System-Context Ausschnitt (erste 500 Zeichen):[/dim]")
        console.print(f"[dim]{system_context[:500]}...[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Fehler beim Erstellen des System-Context: {e}[/red]")
        return
    
    console.print("\n[bold]Test 2: Erstelle verbesserten Report-Prompt[/bold]")
    try:
        report_prompt = create_system_report_prompt(system_context)
        console.print(f"[green]✅ Report-Prompt erstellt (Länge: {len(report_prompt)} Zeichen)[/green]")
        
        # Zeige Ausschnitt des Prompts
        console.print(f"\n[dim]Report-Prompt Ausschnitt (erste 300 Zeichen):[/dim]")
        console.print(f"[dim]{report_prompt[:300]}...[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Fehler beim Erstellen des Report-Prompts: {e}[/red]")
        return
    
    console.print("\n[bold]Test 3: Generiere Report mit verbessertem Prompt[/bold]")
    try:
        # Verwende komplexes Modell für Berichterstellung
        model = select_best_model(complex_analysis=True, for_menu=False)
        console.print(f"[dim]🔄 Verwende Modell: {model} für Report-Generierung[/dim]")
        
        # Generiere Bericht
        console.print(f"[dim]🤔 Generiere verbesserten Systembericht...[/dim]")
        report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
        
        if report_content:
            console.print(f"[green]✅ Verbesserter Report generiert (Länge: {len(report_content)} Zeichen)[/green]")
            
            # Zeige den Report
            console.print(f"\n[bold green]📄 GENERIERTER REPORT:[/bold green]")
            console.print("="*80)
            console.print(report_content)
            console.print("="*80)
            
            # Prüfe ob der Report spezifische Daten enthält
            specific_data_found = []
            if 'app02.profiflitzer.de' in report_content:
                specific_data_found.append("Hostname")
            if 'Debian GNU/Linux 10' in report_content:
                specific_data_found.append("Distribution")
            if '78%' in report_content:
                specific_data_found.append("Speicherplatz-Auslastung")
            if '82.7%' in report_content:
                specific_data_found.append("Memory-Auslastung")
            if '45.2%' in report_content:
                specific_data_found.append("CPU-Auslastung")
            if '5 containers running' in report_content:
                specific_data_found.append("Docker-Container")
            if '47' in report_content and 'updates' in report_content.lower():
                specific_data_found.append("Verfügbare Updates")
            
            console.print(f"\n[bold]Test 4: Prüfe spezifische Daten im Report[/bold]")
            if specific_data_found:
                console.print(f"[green]✅ Spezifische Daten gefunden: {', '.join(specific_data_found)}[/green]")
            else:
                console.print(f"[red]❌ Keine spezifischen Daten im Report gefunden[/red]")
            
            # Prüfe ob allgemeines "Gelaber" vorhanden ist
            generic_phrases = [
                "Überprüfung von Ressourcenverbrauch durch",
                "Analyse unregelmäßiger Log-Einträge",
                "Überprüfung und Installation von aktiven Updates",
                "Was ist zu tun?",
                "Warum ist es wichtig?",
                "Wie wird es umgesetzt?"
            ]
            
            generic_found = []
            for phrase in generic_phrases:
                if phrase in report_content:
                    generic_found.append(phrase)
            
            if generic_found:
                console.print(f"[yellow]⚠️ Allgemeine Phrasen gefunden: {len(generic_found)}[/yellow]")
                for phrase in generic_found[:3]:  # Zeige nur erste 3
                    console.print(f"[dim]  - {phrase}...[/dim]")
            else:
                console.print(f"[green]✅ Keine allgemeinen Phrasen gefunden[/green]")
            
            # Speichere Test-Report
            console.print(f"\n[bold]Test 5: Speichere Test-Report[/bold]")
            try:
                filename = save_system_report(report_content, system_info)
                console.print(f"[green]✅ Test-Report gespeichert: {filename}[/green]")
                
                # Lösche Test-Datei
                os.remove(filename)
                console.print(f"[dim]🗑️ Test-Datei gelöscht[/dim]")
                
            except Exception as e:
                console.print(f"[red]❌ Fehler beim Speichern: {e}[/red]")
            
        else:
            console.print(f"[red]❌ Keine Antwort von Ollama erhalten[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Fehler bei Report-Generierung: {e}[/red]")
        import traceback
        console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
    
    console.print(f"\n[bold green]✅ Verbesserter Report-Test abgeschlossen![/bold green]")

if __name__ == "__main__":
    test_improved_report() 