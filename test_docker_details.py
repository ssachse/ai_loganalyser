#!/usr/bin/env python3
"""
Test für erweiterte Docker-Container-Details
Zeigt spezifisch die laufenden Container, deren Details und Probleme
"""

import sys
import os
sys.path.append('.')

from ssh_chat_system import create_system_context, create_system_report_prompt, query_ollama, select_best_model
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def test_docker_details():
    """Testet die erweiterten Docker-Container-Details"""
    
    console.print("[bold blue]🐳 Teste erweiterte Docker-Container-Details...[/bold blue]")
    
    # Mock system_info mit detaillierten Docker-Daten
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
        'cpu_usage_percent': '0.0%',
        'memory_usage_percent': '11.4%',
        'load_average_1min': '0.53',
        'package_manager': 'apt',
        'installed_packages_count': '2847',
        'available_updates': '166',
        'current_users': '1 (root)',
        'user_login_stats': 'root: 1 login, letzte Anmeldung am 4. Juli um 14:33',
        'failed_logins_by_user': 'root: 0 failed attempts',
        
        # Detaillierte Docker-Informationen
        'docker_detected': True,
        'docker_version': '20.10.17',
        'docker_info': '''Docker Engine - Community
 Version: 20.10.17
 API version: 1.41
 Go version: go1.17.11
 Git commit: 100c701
 Built: Mon Jun 6 23:05:12 2022
 OS/Arch: linux/amd64
 Context: default
 Experimental: false''',
        
        'running_containers': '''NAMES               IMAGE                    STATUS              PORTS
my-prf               nginx:1.21-alpine        Up 3 weeks          0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
database             mysql:8.0                Up 2 weeks          0.0.0.0:3306->3306/tcp
redis-cache          redis:7-alpine           Up 1 week           0.0.0.0:6379->6379/tcp''',
        
        'all_containers': '''NAMES               IMAGE                    STATUS                     CREATED
my-prf               nginx:1.21-alpine        Up 3 weeks              2024-07-01 10:30:00
database             mysql:8.0                Up 2 weeks              2024-07-08 15:45:00
redis-cache          redis:7-alpine           Up 1 week               2024-07-15 09:20:00
old-backup           backup:1.0               Exited (1) 2 days ago   2024-07-20 03:00:00
test-container       test:latest              Exited (0) 1 week ago   2024-07-14 12:00:00''',
        
        'docker_images': '''REPOSITORY          TAG                 SIZE                CREATED
nginx               1.21-alpine        133MB               2024-06-01 08:00:00
mysql               8.0                545MB               2024-06-15 10:30:00
redis               7-alpine           32MB                2024-07-01 14:20:00
backup              1.0                89MB                2024-06-20 16:45:00
test                latest             67MB                2024-07-10 11:15:00''',
        
        'docker_volumes': '''DRIVER              VOLUME NAME
local               my-prf_data
local               database_data
local               redis_data
local               backup_volume''',
        
        'docker_networks': '''NETWORK ID          NAME                DRIVER              SCOPE
abc123def456        bridge              bridge              local
def456ghi789        my-prf_network      bridge              local
ghi789jkl012        database_network    bridge              local''',
        
        'system_usage': '''Docker system usage:
Images: 1.61GB
Containers: 0.1GB
Volumes: 0.5GB
Build cache: 0B''',
        
        # DETAILLIERTE CONTAINER-ANALYSE
        'container_details': {
            'my-prf': {
                'name': 'my-prf',
                'health_status': 'healthy',
                'restart_policy': 'unless-stopped',
                'started_at': '2024-07-01T10:30:00Z',
                'logs': '''2025-07-24 19:05:23 - [info] 1#1: *1 client closed connection while SSL handshaking
2025-07-24 19:04:12 - [info] 1#1: *2 GET / HTTP/1.1 200 612
2025-07-24 19:03:45 - [warn] 1#1: *3 client sent invalid method while reading client request line
2025-07-24 19:02:33 - [error] 1#1: *4 upstream timed out (110: Connection timed out)
2025-07-24 19:01:15 - [info] 1#1: *5 GET /api/health HTTP/1.1 200 45
2025-07-24 19:00:42 - [warn] 1#1: *6 client sent invalid method while reading client request line
2025-07-24 18:59:30 - [info] 1#1: *7 GET /favicon.ico HTTP/1.1 404 153
2025-07-24 18:58:15 - [error] 1#1: *8 upstream timed out (110: Connection timed out)
2025-07-24 18:57:00 - [info] 1#1: *9 GET / HTTP/1.1 200 612''',
                'errors': [
                    '2025-07-24 19:02:33 - [error] 1#1: *4 upstream timed out (110: Connection timed out)',
                    '2025-07-24 18:58:15 - [error] 1#1: *8 upstream timed out (110: Connection timed out)'
                ],
                'warnings': [
                    '2025-07-24 19:03:45 - [warn] 1#1: *3 client sent invalid method while reading client request line',
                    '2025-07-24 19:00:42 - [warn] 1#1: *6 client sent invalid method while reading client request line'
                ]
            },
            'database': {
                'name': 'database',
                'health_status': 'unhealthy',
                'restart_policy': 'always',
                'started_at': '2024-07-08T15:45:00Z',
                'health_logs': '''2025-07-24 19:05:00 - Health check failed: Connection refused
2025-07-24 19:04:30 - Health check failed: Connection refused
2025-07-24 19:04:00 - Health check failed: Connection refused
2025-07-24 19:03:30 - Health check failed: Connection refused
2025-07-24 19:03:00 - Health check failed: Connection refused''',
                'logs': '''2025-07-24 19:05:00 - [ERROR] MySQL server has gone away
2025-07-24 19:04:30 - [ERROR] Connection timeout
2025-07-24 19:04:00 - [ERROR] MySQL server has gone away
2025-07-24 19:03:30 - [ERROR] Connection timeout
2025-07-24 19:03:00 - [ERROR] MySQL server has gone away
2025-07-24 19:02:30 - [WARN] High memory usage detected
2025-07-24 19:02:00 - [INFO] Server startup complete
2025-07-24 19:01:30 - [INFO] InnoDB: Database was not shutdown normally
2025-07-24 19:01:00 - [INFO] Starting MySQL server''',
                'errors': [
                    '2025-07-24 19:05:00 - [ERROR] MySQL server has gone away',
                    '2025-07-24 19:04:30 - [ERROR] Connection timeout',
                    '2025-07-24 19:04:00 - [ERROR] MySQL server has gone away',
                    '2025-07-24 19:03:30 - [ERROR] Connection timeout',
                    '2025-07-24 19:03:00 - [ERROR] MySQL server has gone away'
                ],
                'warnings': [
                    '2025-07-24 19:02:30 - [WARN] High memory usage detected'
                ]
            },
            'redis-cache': {
                'name': 'redis-cache',
                'health_status': 'healthy',
                'restart_policy': 'unless-stopped',
                'started_at': '2024-07-15T09:20:00Z',
                'logs': '''2025-07-24 19:05:15 - [INFO] Redis is running
2025-07-24 19:04:45 - [INFO] Memory usage: 45.2MB
2025-07-24 19:04:15 - [INFO] Connected clients: 12
2025-07-24 19:03:45 - [INFO] Redis is running
2025-07-24 19:03:15 - [INFO] Memory usage: 44.8MB
2025-07-24 19:02:45 - [INFO] Connected clients: 11
2025-07-24 19:02:15 - [INFO] Redis is running
2025-07-24 19:01:45 - [INFO] Memory usage: 44.5MB
2025-07-24 19:01:15 - [INFO] Connected clients: 10''',
                'errors': [],
                'warnings': []
            }
        },
        
        'container_stats': {
            'my-prf': '''NAME                CPU %               MEM USAGE / LIMIT     MEM %               NET I/O             BLOCK I/O
my-prf               0.5%                45.2MB / 512MB        8.8%                1.2MB / 856KB        2.1MB / 1.8MB''',
            'database': '''NAME                CPU %               MEM USAGE / LIMIT     MEM %               NET I/O             BLOCK I/O
database             85.2%               1.2GB / 2GB          60.0%               45.6MB / 23.4MB      156.7MB / 89.2MB''',
            'redis-cache': '''NAME                CPU %               MEM USAGE / LIMIT     MEM %               NET I/O             BLOCK I/O
redis-cache          2.1%                32.1MB / 256MB       12.5%               8.9MB / 6.7MB        12.3MB / 4.5MB'''
        },
        
        # Docker-Probleme
        'problems': [
            'Container database: Health-Check fehlgeschlagen',
            'Container database: Hohe CPU-Nutzung (85.2%)',
            'Gestoppter Container mit Fehler: old-backup (Exit-Code: 1)',
            'Docker-Daemon-Fehler:\n2025-07-24 19:00:00 docker[1234]: error: failed to start container database\n2025-07-24 18:55:00 docker[1234]: error: container database health check failed'
        ],
        'problems_count': 4
    }
    
    # Mock log_entries und anomalies
    log_entries = []
    anomalies = []
    
    console.print("\n[bold]Test 1: Analysiere erweiterte Docker-Daten[/bold]")
    
    # Zeige Docker-spezifische Daten
    table = Table(title="Erweiterte Docker-System-Daten")
    table.add_column("Kategorie", style="cyan")
    table.add_column("Schlüssel", style="green")
    table.add_column("Wert", style="yellow")
    table.add_column("Typ", style="magenta")
    
    docker_keys = {
        'Docker-Basis': ['docker_detected', 'docker_version', 'docker_info'],
        'Container': ['running_containers', 'all_containers'],
        'Images': ['docker_images'],
        'Volumes': ['docker_volumes'],
        'Networks': ['docker_networks'],
        'System': ['system_usage'],
        'Details': ['container_details', 'container_stats'],
        'Probleme': ['problems', 'problems_count']
    }
    
    for category, keys in docker_keys.items():
        for key in keys:
            if key in system_info:
                value = system_info[key]
                if isinstance(value, dict):
                    value_str = f"Dict mit {len(value)} Einträgen"
                elif isinstance(value, list):
                    value_str = f"Liste mit {len(value)} Einträgen"
                elif isinstance(value, str) and len(value) > 200:
                    value_str = value[:200] + "..."
                else:
                    value_str = str(value)
                
                table.add_row(category, key, value_str, type(value).__name__)
    
    console.print(table)
    
    console.print(f"\n[bold]Test 2: Erstelle System-Context mit erweiterten Docker-Details[/bold]")
    
    # Erstelle System-Context
    system_context = create_system_context(system_info, log_entries, anomalies)
    
    # Zeige Docker-spezifische Teile des Contexts
    docker_sections = []
    lines = system_context.split('\n')
    in_docker_section = False
    current_section = []
    
    for line in lines:
        if '=== DOCKER' in line:
            if current_section:
                docker_sections.append('\n'.join(current_section))
            current_section = [line]
            in_docker_section = True
        elif in_docker_section and line.startswith('===') and 'DOCKER' not in line:
            docker_sections.append('\n'.join(current_section))
            current_section = []
            in_docker_section = False
        elif in_docker_section:
            current_section.append(line)
    
    if current_section:
        docker_sections.append('\n'.join(current_section))
    
    console.print(f"\n[bold green]Docker-Bereiche im System-Context:[/bold green]")
    for i, section in enumerate(docker_sections, 1):
        console.print(f"\n[bold cyan]Bereich {i}:[/bold cyan]")
        console.print(Panel(section, title=f"Docker-Bereich {i}", border_style="blue"))
    
    console.print(f"\n[bold]Test 3: Erstelle Report-Prompt mit Docker-Details[/bold]")
    
    # Erstelle Report-Prompt
    report_prompt = create_system_report_prompt(system_context)
    
    # Zeige Docker-spezifische Teile des Prompts
    if 'Docker' in report_prompt:
        docker_prompt_parts = []
        lines = report_prompt.split('\n')
        in_docker_section = False
        current_section = []
        
        for line in lines:
            if 'Docker' in line and 'Details' in line:
                if current_section:
                    docker_prompt_parts.append('\n'.join(current_section))
                current_section = [line]
                in_docker_section = True
            elif in_docker_section and line.startswith('##') and 'Docker' not in line:
                docker_prompt_parts.append('\n'.join(current_section))
                current_section = []
                in_docker_section = False
            elif in_docker_section:
                current_section.append(line)
        
        if current_section:
            docker_prompt_parts.append('\n'.join(current_section))
        
        console.print(f"\n[bold green]Docker-Bereiche im Report-Prompt:[/bold green]")
        for i, section in enumerate(docker_prompt_parts, 1):
            console.print(f"\n[bold cyan]Bereich {i}:[/bold cyan]")
            console.print(Panel(section, title=f"Docker-Prompt-Bereich {i}", border_style="green"))
    
    console.print(f"\n[bold]Test 4: Analysiere Container-Probleme[/bold]")
    
    # Analysiere Container-Probleme
    problems = system_info.get('problems', [])
    console.print(f"\n[bold red]Gefundene Docker-Probleme ({len(problems)}):[/bold red]")
    
    for i, problem in enumerate(problems, 1):
        console.print(f"[red]{i}. {problem}[/red]")
    
    # Analysiere Container-Details
    container_details = system_info.get('container_details', {})
    console.print(f"\n[bold yellow]Container-Details-Analyse:[/bold yellow]")
    
    for container_name, details in container_details.items():
        health_status = details.get('health_status', 'unknown')
        error_count = len(details.get('errors', []))
        warning_count = len(details.get('warnings', []))
        
        status_color = "green" if health_status == 'healthy' else "red"
        console.print(f"[{status_color}]Container {container_name}:[/{status_color}]")
        console.print(f"  Health: {health_status}")
        console.print(f"  Fehler: {error_count}")
        console.print(f"  Warnungen: {warning_count}")
        
        if error_count > 0:
            console.print(f"  [red]Letzte Fehler:[/red]")
            for error in details['errors'][-3:]:
                console.print(f"    [dim]{error}[/dim]")
    
    console.print(f"\n[bold green]✅ Test der erweiterten Docker-Container-Details abgeschlossen![/bold green]")
    console.print(f"[dim]Die neuen Features sammeln detaillierte Informationen über:[/dim]")
    console.print(f"[dim]• Container Health-Status und -Logs[/dim]")
    console.print(f"[dim]• Container-Statistiken (CPU, Memory, Netzwerk)[/dim]")
    console.print(f"[dim]• Log-Fehler und Warnungen[/dim]")
    console.print(f"[dim]• Restart-Policies und Uptime[/dim]")
    console.print(f"[dim]• Erweiterte Problem-Erkennung[/dim]")

if __name__ == "__main__":
    test_docker_details() 