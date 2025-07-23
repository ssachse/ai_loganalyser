#!/usr/bin/env python3
"""
SSH-basierter Log-Sammler mit interaktivem Ollama-Chat
Verwendet System-SSH für bessere Kompatibilität
"""

import os
import sys
import json
import tempfile
import tarfile
import shutil
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import subprocess
import argparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

# Importiere den bestehenden Log-Analyzer
from log_analyzer import LogAnalyzer, LogEntry, LogLevel, Anomaly
from config import Config
from i18n import _, i18n

console = Console()

class SSHLogCollector:
    """SSH-basierter Log-Sammler mit System-SSH"""
    
    def __init__(self, host: str, username: str, password: str = None, key_file: str = None, port: int = 22, 
                 ollama_port: int = 11434, use_port_forwarding: bool = True):
        self.host = host
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.ollama_port = ollama_port
        self.use_port_forwarding = use_port_forwarding
        
        # SSH-Verbindungsstring
        self.ssh_connection_string = f"{username}@{host}"
        
        # Temporäre Dateien
        self.temp_dir = None
        self.collected_files = []
        
        # Fehler-Tracking für intelligente Gruppierung
        self.error_patterns = {
            'permission_denied': [],
            'file_not_found': [],
            'kubectl_errors': [],
            'command_not_found': [],
            'other_errors': []
        }
    
    def connect(self) -> bool:
        """Testet die SSH-Verbindung"""
        try:
            console.print(f"[blue]{_('ssh_connecting')} {self.ssh_connection_string}...[/blue]")
            
            # Teste SSH-Verbindung
            test_cmd = ['ssh', '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes', 
                       self.ssh_connection_string, 'echo "SSH connection successful"']
            
            if self.key_file:
                test_cmd.extend(['-i', self.key_file])
            if self.port != 22:
                test_cmd.extend(['-p', str(self.port)])
            
            result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                console.print(f"[green]✅ {_('ssh_success')} {self.host}[/green]")
                return True
            else:
                console.print(f"[red]❌ {_('ssh_failed')}: {result.stderr.strip()}[/red]")
                return False
                
        except subprocess.TimeoutExpired:
            console.print(f"[red]❌ {_('ssh_timeout')}[/red]")
            return False
        except Exception as e:
            console.print(f"[red]❌ {_('ssh_error')}: {e}[/red]")
            return False
    
    def execute_remote_command(self, command: str) -> Optional[str]:
        """Führt einen Befehl auf dem Remote-System aus"""
        try:
            ssh_cmd = ['ssh', '-o', 'ConnectTimeout=10', self.ssh_connection_string]
            
            if self.key_file:
                ssh_cmd.extend(['-i', self.key_file])
            if self.port != 22:
                ssh_cmd.extend(['-p', str(self.port)])
            
            ssh_cmd.append(command)
            
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                # Analysiere Fehler für intelligente Gruppierung
                error_msg = result.stderr.strip() if result.stderr else ""
                self._analyze_error(command, result.returncode, error_msg)
                
                # Nur bei wichtigen Befehlen Warnung ausgeben
                if any(keyword in command.lower() for keyword in ['which', 'test', 'grep -v', 'wc -l']):
                    # Diese Befehle können normal fehlschlagen (z.B. Datei nicht gefunden)
                    return None
                else:
                    # Keine individuelle Warnung mehr - wird später gruppiert ausgegeben
                    return None
            
        except subprocess.TimeoutExpired:
            self.error_patterns['other_errors'].append({
                'command': command[:50] + '...' if len(command) > 50 else command,
                'error': 'Timeout',
                'type': 'timeout'
            })
            return None
        except Exception as e:
            # Nur bei wichtigen Befehlen Fehler tracken
            if any(keyword in command.lower() for keyword in ['which', 'test', 'grep -v', 'wc -l']):
                return None
            else:
                self.error_patterns['other_errors'].append({
                    'command': command[:50] + '...' if len(command) > 50 else command,
                    'error': str(e)[:100],
                    'type': 'exception'
                })
            return None
    
    def _analyze_error(self, command: str, exit_code: int, error_msg: str):
        """Analysiert Fehler und kategorisiert sie für intelligente Gruppierung"""
        command_short = command[:50] + '...' if len(command) > 50 else command
        
        # Permission denied Fehler
        if 'permission denied' in error_msg.lower() or 'cannot open' in error_msg.lower():
            self.error_patterns['permission_denied'].append({
                'command': command_short,
                'error': error_msg[:100],
                'full_command': command
            })
        
        # File not found Fehler
        elif 'no such file' in error_msg.lower() or 'file or directory' in error_msg.lower():
            self.error_patterns['file_not_found'].append({
                'command': command_short,
                'error': error_msg[:100],
                'full_command': command
            })
        
        # kubectl spezifische Fehler
        elif 'kubectl' in command.lower():
            self.error_patterns['kubectl_errors'].append({
                'command': command_short,
                'error': error_msg[:100],
                'full_command': command
            })
        
        # Command not found Fehler
        elif 'command not found' in error_msg.lower() or 'no such command' in error_msg.lower():
            self.error_patterns['command_not_found'].append({
                'command': command_short,
                'error': error_msg[:100],
                'full_command': command
            })
        
        # Andere Fehler
        else:
            self.error_patterns['other_errors'].append({
                'command': command_short,
                'error': error_msg[:100],
                'full_command': command
            })
    
    def print_error_summary(self):
        """Gibt eine zusammenfassende Übersicht aller Fehler aus"""
        total_errors = sum(len(errors) for errors in self.error_patterns.values())
        
        if total_errors == 0:
            return
        
        console.print(f"\n[bold yellow]⚠️  {_('error_summary')} ({total_errors} Fehler):[/bold yellow]")
        
        # Permission denied Fehler
        if self.error_patterns['permission_denied']:
            console.print(f"\n[red]🔒 {_('error_permission_denied')} ({len(self.error_patterns['permission_denied'])} Fehler):[/red]")
            console.print("   Weitere Analyse aufgrund fehlender Rechte nicht möglich.")
            console.print("   Betroffene Bereiche:")
            for error in self.error_patterns['permission_denied']:
                if 'du -sh' in error['full_command']:
                    console.print("   • Speicherplatz-Analyse")
                    break
            for error in self.error_patterns['permission_denied']:
                if 'tail' in error['full_command'] and 'log' in error['full_command']:
                    console.print("   • Log-Datei-Zugriff")
                    break
        
        # File not found Fehler
        if self.error_patterns['file_not_found']:
            console.print(f"\n[red]📁 Fehlende Dateien/Verzeichnisse ({len(self.error_patterns['file_not_found'])} Fehler):[/red]")
            console.print("   Weitere Analyse aufgrund unbekannter Struktur nicht möglich.")
            console.print("   Betroffene Bereiche:")
            for error in self.error_patterns['file_not_found']:
                if 'du -sh' in error['full_command']:
                    console.print("   • Speicherplatz-Analyse")
                    break
        
        # kubectl Fehler
        if self.error_patterns['kubectl_errors']:
            console.print(f"\n[red]☸️  Kubernetes-Befehle ({len(self.error_patterns['kubectl_errors'])} Fehler):[/red]")
            console.print("   Einige Kubernetes-Befehle fehlgeschlagen.")
            console.print("   Mögliche Ursachen: Fehlende Berechtigungen, Cluster nicht erreichbar")
        
        # Command not found Fehler
        if self.error_patterns['command_not_found']:
            console.print(f"\n[red]🔧 Fehlende Befehle ({len(self.error_patterns['command_not_found'])} Fehler):[/red]")
            console.print("   Einige System-Befehle nicht verfügbar.")
        
        # Andere Fehler
        if self.error_patterns['other_errors']:
            console.print(f"\n[red]❓ Andere Fehler ({len(self.error_patterns['other_errors'])} Fehler):[/red]")
            for error in self.error_patterns['other_errors'][:3]:  # Zeige nur die ersten 3
                console.print(f"   • {error['command']}: {error['error']}")
            if len(self.error_patterns['other_errors']) > 3:
                console.print(f"   • ... und {len(self.error_patterns['other_errors']) - 3} weitere")
        
        console.print("\n[dim]💡 Tipp: Verwenden Sie einen Benutzer mit erweiterten Rechten für vollständige Analyse.[/dim]")
    
    def get_system_info(self, quick_mode: bool = False) -> Dict[str, Any]:
        """Sammelt umfassende System-Informationen vom Zielsystem"""
        console.print("[blue]🔍 Analysiere System-Charakteristik...[/blue]")
        
        if quick_mode:
            console.print("[yellow]⚡ Quick-Modus aktiviert - Überspringe zeitaufwändige Analysen[/yellow]")
        
        system_info = {
            'hostname': self.host,
            'os_type': 'linux',
            'collection_time': datetime.now().isoformat(),
            'ssh_connection': self.ssh_connection_string,
            'port_forwarding': self.use_port_forwarding,
            'quick_mode': quick_mode
        }
        
        # 1. Basis-System-Informationen
        console.print("[dim]📋 Sammle Basis-System-Informationen...[/dim]")
        basic_commands = {
            'hostname': 'hostname',
            'os_version': 'cat /etc/os-release',
            'kernel_version': 'uname -r',
            'architecture': 'uname -m',
            'cpu_info': 'lscpu | grep "Model name" | head -1',
            'cpu_cores': 'nproc',
            'memory_total': 'free -h | grep Mem | awk "{print $2}"',
            'uptime': 'uptime',
            'load_average': 'cat /proc/loadavg',
            'users_logged_in': 'who | wc -l',
            'running_processes': 'ps aux | wc -l',
            'timezone': 'timedatectl | grep "Time zone" | awk "{print $3}"'
        }
        
        for key, command in basic_commands.items():
            result = self.execute_remote_command(command)
            if result:
                system_info[key] = result.strip()
        
        # 2. Distribution und Paket-Management
        console.print("[dim]📦 Analysiere Distribution und Paket-Management...[/dim]")
        distro_info = self._analyze_distribution()
        system_info.update(distro_info)
        
        # 3. Speicherplatz-Analyse
        console.print("[dim]💾 Analysiere Speicherplatz...[/dim]")
        storage_info = self._analyze_storage(quick_mode=quick_mode)
        system_info.update(storage_info)
        
        # 4. Service-Analyse
        console.print("[dim]🔧 Analysiere laufende Services...[/dim]")
        service_info = self._analyze_services(quick_mode=quick_mode)
        system_info.update(service_info)
        
        # 5. Sicherheits- und Anmeldungs-Analyse
        console.print("[dim]🔐 Analysiere Sicherheit und Anmeldungen...[/dim]")
        security_info = self._analyze_security()
        system_info.update(security_info)
        
        # 6. Performance-Analyse
        console.print("[dim]⚡ Analysiere System-Performance...[/dim]")
        performance_info = self._analyze_performance()
        system_info.update(performance_info)
        
        # 7. Kubernetes-Analyse (falls verfügbar)
        k8s_info = self._analyze_kubernetes()
        system_info.update(k8s_info)
        
        return system_info
    
    def _analyze_security(self) -> Dict[str, Any]:
        """Analysiert Sicherheits-Status und Anmeldungen"""
        security_info = {}
        
        # Detaillierte Anmeldungs-Analyse
        console.print("[dim]🔐 Analysiere Anmeldungen...[/dim]")
        
        # Letzte Anmeldungen (erweiterte Analyse)
        last_logins = self.execute_remote_command('last | head -20')
        if last_logins:
            security_info['recent_logins'] = last_logins
        
        # Aktuell eingeloggte Benutzer
        current_users = self.execute_remote_command('who')
        if current_users:
            security_info['current_users'] = current_users
        
        # Anmeldungs-Statistiken
        login_stats = self.execute_remote_command('last | grep -v "reboot\|wtmp" | wc -l')
        if login_stats:
            security_info['total_logins'] = login_stats
        
        # Anmeldungen nach Benutzer (letzte 7 Tage)
        user_logins = self.execute_remote_command('last -7 | grep -v "reboot\|wtmp" | awk "{print $1}" | sort | uniq -c | sort -nr')
        if user_logins:
            security_info['user_login_stats'] = user_logins
        
        # Letzte Anmeldungen nach Datum
        recent_by_date = self.execute_remote_command('last | grep -v "reboot\|wtmp" | head -10 | awk "{print $4, $5, $6, $7}" | sort | uniq -c')
        if recent_by_date:
            security_info['logins_by_date'] = recent_by_date
        
        # Fehlgeschlagene Anmeldungen
        failed_logins = self.execute_remote_command('grep "Failed password" /var/log/auth.log | tail -20 2>/dev/null')
        if failed_logins:
            security_info['failed_logins'] = failed_logins
        
        # Fehlgeschlagene Anmeldungen nach Benutzer
        failed_by_user = self.execute_remote_command('grep "Failed password" /var/log/auth.log | tail -50 | awk "{print $11}" | sort | uniq -c | sort -nr 2>/dev/null')
        if failed_by_user:
            security_info['failed_logins_by_user'] = failed_by_user
        
        return security_info
    
    def _analyze_distribution(self) -> Dict[str, Any]:
        """Analysiert die Linux-Distribution und Paket-Management"""
        distro_info = {}
        
        # OS-Release Informationen
        os_release = self.execute_remote_command('cat /etc/os-release')
        if os_release:
            lines = os_release.split('\n')
            for line in lines:
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"')
                    if key in ['NAME', 'VERSION', 'VERSION_ID', 'PRETTY_NAME', 'ID', 'ID_LIKE']:
                        distro_info[f'distro_{key.lower()}'] = value
        
        # Paket-Manager erkennen
        package_managers = {
            'apt': 'dpkg -l | wc -l',
            'yum': 'rpm -qa | wc -l',
            'dnf': 'dnf list installed | wc -l',
            'pacman': 'pacman -Q | wc -l',
            'zypper': 'zypper packages --installed | wc -l'
        }
        
        for pkg_mgr, cmd in package_managers.items():
            result = self.execute_remote_command(cmd)
            if result and result.strip().isdigit():
                distro_info['package_manager'] = pkg_mgr
                distro_info['installed_packages_count'] = int(result.strip())
                break
        
        # Letzte Updates
        update_commands = {
            'apt': 'apt list --upgradable 2>/dev/null | wc -l',
            'yum': 'yum check-update 2>/dev/null | wc -l',
            'dnf': 'dnf check-update 2>/dev/null | wc -l',
            'pacman': 'pacman -Qu | wc -l',
            'zypper': 'zypper list-updates | wc -l'
        }
        
        if 'package_manager' in distro_info:
            pkg_mgr = distro_info['package_manager']
            if pkg_mgr in update_commands:
                result = self.execute_remote_command(update_commands[pkg_mgr])
                if result and result.strip().isdigit():
                    distro_info['available_updates'] = int(result.strip())
        
        return distro_info
    
    def _analyze_storage(self, quick_mode: bool = False) -> Dict[str, Any]:
        """Analysiert Speicherplatz und Dateisystem"""
        storage_info = {}
        
        # Disk-Usage
        disk_usage = self.execute_remote_command('df -h')
        if disk_usage:
            storage_info['disk_usage'] = disk_usage
        
        # Wichtige Verzeichnisse
        important_dirs = ['/home', '/var', '/tmp', '/var/log', '/var/lib/docker', '/var/cache/apt']
        
        for directory in important_dirs:
            try:
                usage = self.execute_remote_command(f"du -sh {directory} 2>/dev/null")
                if usage:
                    key = f"{directory.replace('/', '_').replace('var_', '')}_usage"
                    storage_info[key] = usage.split()[0]
            except:
                pass  # Verzeichnis existiert möglicherweise nicht
        
        # Größte Verzeichnisse (nur wenn nicht Quick-Modus)
        if not quick_mode:
            largest_dirs = self.execute_remote_command('du -h / 2>/dev/null | sort -hr | head -10')
            if largest_dirs:
                storage_info['largest_directories'] = largest_dirs
        
        # Größte Dateien (nur wenn nicht Quick-Modus)
        if not quick_mode:
            console.print("[dim]📄 Suche größte Dateien...[/dim]")
            
            # Suche in wichtigen Verzeichnissen
            important_search_dirs = ['/var/log', '/home', '/tmp', '/var/cache']
            largest_files_by_dir = {}
            
            for search_dir in important_search_dirs:
                try:
                    # Prüfe ob Verzeichnis existiert
                    if self.execute_remote_command(f'test -d "{search_dir}"'):
                        files = self.execute_remote_command(f'find "{search_dir}" -type f -exec ls -lh {{}} + 2>/dev/null | sort -k5 -hr | head -5')
                        if files:
                            largest_files_by_dir[search_dir] = files
                except:
                    pass  # Verzeichnis existiert nicht
            
            if largest_files_by_dir:
                storage_info['largest_files_by_directory'] = largest_files_by_dir
            
            # Allgemeine größte Dateien (begrenzt auf wichtige Pfade)
            largest_files = self.execute_remote_command('find /var /home /tmp -type f -size +100M -exec ls -lh {} + 2>/dev/null | sort -k5 -hr | head -10')
            if largest_files:
                storage_info['largest_files'] = largest_files
        else:
            console.print("[dim]⏩ Überspringe detaillierte Datei-Analyse (Quick-Modus)[/dim]")
        
        return storage_info
    
    def _analyze_services(self, quick_mode: bool = False) -> Dict[str, Any]:
        """Analysiert laufende Services und Prozesse"""
        services_info = {}
        
        # Wichtige Services prüfen
        important_services = ['sshd', 'docker', 'containerd', 'cron', 'rsyslog', 'systemd']
        
        if quick_mode:
            # Im Quick-Modus nur die wichtigsten Services prüfen
            important_services = ['sshd', 'docker', 'cron']
        
        running_services = {}
        for service in important_services:
            try:
                # Prüfe ob Service läuft
                status = self.execute_remote_command(f'systemctl is-active {service} 2>/dev/null')
                if status:
                    running_services[service] = status.strip()
            except:
                pass  # Service existiert möglicherweise nicht
        
        if running_services:
            services_info['running_services'] = running_services
        
        # Top-Prozesse (nur wenn nicht Quick-Modus)
        if not quick_mode:
            top_processes = self.execute_remote_command('ps aux --sort=-%cpu | head -10')
            if top_processes:
                services_info['top_processes_cpu'] = top_processes
            
            top_memory = self.execute_remote_command('ps aux --sort=-%mem | head -10')
            if top_memory:
                services_info['top_processes_memory'] = top_memory
        
        return services_info
    
    def _analyze_performance(self) -> Dict[str, Any]:
        """Analysiert System-Performance"""
        performance_info = {}
        
        try:
            # CPU-Auslastung
            cpu_usage = self.execute_remote_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1")
            if cpu_usage:
                performance_info['cpu_usage_percent'] = cpu_usage
            
            # Memory-Auslastung
            memory_usage = self.execute_remote_command("free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100.0}'")
            if memory_usage:
                performance_info['memory_usage_percent'] = memory_usage
            
            # Load Average
            load_avg = self.execute_remote_command('cat /proc/loadavg')
            if load_avg:
                parts = load_avg.split()
                if len(parts) >= 3:
                    performance_info['load_average_1min'] = parts[0]
                    performance_info['load_average_5min'] = parts[1]
                    performance_info['load_average_15min'] = parts[2]
        except Exception as e:
            console.print(f"[yellow]⚠️  Fehler bei Performance-Analyse: {str(e)[:100]}[/yellow]")
        
        return performance_info
    
    def _analyze_kubernetes(self) -> Dict[str, Any]:
        """Analysiert Kubernetes-Cluster, falls verfügbar"""
        k8s_info = {}
        
        # Prüfe ob kubectl verfügbar ist
        kubectl_check = self.execute_remote_command('which kubectl')
        if not kubectl_check:
            return k8s_info
        
        console.print("[dim]☸️  Analysiere Kubernetes-Cluster...[/dim]")
        
        try:
            # Cluster-Informationen
            cluster_info = self.execute_remote_command('kubectl cluster-info 2>/dev/null')
            if cluster_info:
                k8s_info['cluster_info'] = cluster_info
            
            # Kubernetes-Version (korrigierter Befehl)
            version = self.execute_remote_command('kubectl version 2>/dev/null')
            if version:
                k8s_info['k8s_version'] = version
            
            # Nodes (korrigierter Befehl)
            nodes = self.execute_remote_command('kubectl get nodes 2>/dev/null')
            if nodes:
                k8s_info['nodes'] = nodes
            
            # Node-Status (vereinfachter Befehl)
            node_status = self.execute_remote_command('kubectl get nodes -o wide 2>/dev/null')
            if node_status:
                k8s_info['node_status'] = node_status
            
            # Namespaces
            namespaces = self.execute_remote_command('kubectl get namespaces 2>/dev/null')
            if namespaces:
                k8s_info['namespaces'] = namespaces
            
            # Pods (alle Namespaces)
            pods = self.execute_remote_command('kubectl get pods --all-namespaces 2>/dev/null')
            if pods:
                k8s_info['pods'] = pods
            
            # Services
            services = self.execute_remote_command('kubectl get services --all-namespaces 2>/dev/null')
            if services:
                k8s_info['services'] = services
            
            # Deployments
            deployments = self.execute_remote_command('kubectl get deployments --all-namespaces 2>/dev/null')
            if deployments:
                k8s_info['deployments'] = deployments
            
            # Probleme identifizieren
            problems = []
            
            # Prüfe auf nicht-ready Nodes
            not_ready_nodes = self.execute_remote_command('kubectl get nodes | grep -v "Ready" 2>/dev/null')
            if not_ready_nodes:
                problems.append(f"Nicht-ready Nodes:\n{not_ready_nodes}")
            
            # Prüfe auf nicht-running Pods (vereinfachter Befehl)
            not_running_pods = self.execute_remote_command('kubectl get pods --all-namespaces | grep -v "Running\|Completed" 2>/dev/null')
            if not_running_pods:
                problems.append(f"Nicht-running Pods:\n{not_running_pods}")
            
            # Prüfe auf Pod-Restarts (vereinfachter Befehl)
            restarted_pods = self.execute_remote_command('kubectl get pods --all-namespaces | grep -v "RESTARTS" | awk "$4 > 0 {print}" 2>/dev/null')
            if restarted_pods:
                problems.append(f"Pods mit Restarts:\n{restarted_pods}")
            
            # Prüfe auf Events (letzte 50)
            events = self.execute_remote_command('kubectl get events --all-namespaces | tail -50 2>/dev/null')
            if events:
                k8s_info['recent_events'] = events
                
                # Prüfe auf kritische Events
                critical_events = self.execute_remote_command('kubectl get events --all-namespaces | grep -i "error\|failed\|crash\|oom" | tail -20 2>/dev/null')
                if critical_events:
                    problems.append(f"Kritische Events:\n{critical_events}")
            
            # Prüfe auf Ressourcen-Auslastung
            resource_usage = self.execute_remote_command('kubectl top nodes 2>/dev/null')
            if resource_usage:
                k8s_info['node_resource_usage'] = resource_usage
            
            pod_resource_usage = self.execute_remote_command('kubectl top pods --all-namespaces 2>/dev/null')
            if pod_resource_usage:
                k8s_info['pod_resource_usage'] = pod_resource_usage
            
            # Prüfe auf Storage-Probleme
            pv_status = self.execute_remote_command('kubectl get pv 2>/dev/null')
            if pv_status:
                k8s_info['persistent_volumes'] = pv_status
                
                failed_pv = self.execute_remote_command('kubectl get pv | grep -v "Bound\|Available" 2>/dev/null')
                if failed_pv:
                    problems.append(f"Problematische Persistent Volumes:\n{failed_pv}")
            
            # Prüfe auf Network-Policies
            network_policies = self.execute_remote_command('kubectl get networkpolicies --all-namespaces 2>/dev/null')
            if network_policies:
                k8s_info['network_policies'] = network_policies
            
            # Prüfe auf Ingress
            ingress = self.execute_remote_command('kubectl get ingress --all-namespaces 2>/dev/null')
            if ingress:
                k8s_info['ingress'] = ingress
            
            # Prüfe auf ConfigMaps und Secrets
            configmaps = self.execute_remote_command('kubectl get configmaps --all-namespaces | wc -l 2>/dev/null')
            if configmaps:
                k8s_info['configmaps_count'] = configmaps
            
            secrets = self.execute_remote_command('kubectl get secrets --all-namespaces | wc -l 2>/dev/null')
            if secrets:
                k8s_info['secrets_count'] = secrets
            
            # Speichere identifizierte Probleme
            if problems:
                k8s_info['problems'] = problems
                k8s_info['problems_count'] = len(problems)
            
            # Cluster-Gesundheit
            health_check = self.execute_remote_command('kubectl get componentstatuses 2>/dev/null')
            if health_check:
                k8s_info['component_status'] = health_check
                
                unhealthy_components = self.execute_remote_command('kubectl get componentstatuses | grep -v "Healthy" 2>/dev/null')
                if unhealthy_components:
                    problems.append(f"Unhealthy Components:\n{unhealthy_components}")
            
            # Prüfe auf k9s
            k9s_check = self.execute_remote_command('which k9s')
            if k9s_check:
                k8s_info['k9s_available'] = True
            
            if k8s_info:
                k8s_info['kubernetes_detected'] = True
                console.print("[green]✅ Kubernetes-Cluster gefunden und analysiert[/green]")
            else:
                console.print("[yellow]⚠️  kubectl verfügbar, aber kein Cluster erreichbar[/yellow]")
                
        except Exception as e:
            console.print(f"[yellow]⚠️  Fehler bei Kubernetes-Analyse: {str(e)[:100]}[/yellow]")
        
        return k8s_info
    
    def collect_logs(self, hours_back: int = 24) -> str:
        """Sammelt Logs vom Zielsystem"""
        console.print(f"[blue]Sammle Logs der letzten {hours_back} Stunden...[/blue]")
        
        # Erstelle temporäres Verzeichnis
        self.temp_dir = tempfile.mkdtemp(prefix=f"linux_logs_{self.host}_")
        console.print(f"[dim]Temporäres Verzeichnis: {self.temp_dir}[/dim]")
        
        # Linux Log-Quellen
        log_sources = [
            ('/var/log/syslog', 'system'),
            ('/var/log/messages', 'system'),
            ('/var/log/kern.log', 'kernel'),
            ('/var/log/auth.log', 'security'),
            ('/var/log/secure', 'security'),
        ]
        
        # Sammle Logs mit Fortschrittsanzeige
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Sammle Logs...", total=len(log_sources))
            
            for log_path, source in log_sources:
                progress.update(task, description=f"Sammle {source} Logs...")
                
                try:
                    self._collect_log_file(log_path, source, hours_back)
                except Exception as e:
                    console.print(f"[yellow]Warnung: Konnte {log_path} nicht sammeln: {e}[/yellow]")
                
                progress.advance(task)
        
        # Sammle auch journalctl-Logs
        self._collect_journalctl_logs(hours_back)
        
        # Sammle Prozess-Informationen
        self._collect_process_info()
        
        # Sammle System-Status
        self._collect_system_status()
        
        console.print(f"[green]✓ Logs gesammelt in: {self.temp_dir}[/green]")
        return self.temp_dir
    
    def _collect_log_file(self, log_path: str, source: str, hours_back: int):
        """Sammelt eine einzelne Log-Datei"""
        try:
            # Prüfe ob Datei existiert
            check_cmd = f'test -f "{log_path}" && echo "exists"'
            if not self.execute_remote_command(check_cmd):
                return
            
            # Sammle Log-Einträge
            command = f'tail -n 1000 "{log_path}"'
            content = self.execute_remote_command(command)
            
            if content:
                # Speichere in lokale Datei
                local_file = os.path.join(self.temp_dir, f"{source}_{os.path.basename(log_path)}")
                with open(local_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                self.collected_files.append((local_file, source))
                
        except Exception as e:
            console.print(f"[yellow]Warnung: Fehler beim Sammeln von {log_path}: {e}[/yellow]")
    
    def _collect_journalctl_logs(self, hours_back: int):
        """Sammelt systemd journalctl-Logs"""
        try:
            console.print("[blue]Sammle systemd journalctl-Logs...[/blue]")
            
            # Sammle verschiedene Journal-Logs
            journal_commands = [
                f'journalctl --since "{hours_back} hours ago" --no-pager -o short-precise',
                f'journalctl --since "{hours_back} hours ago" --no-pager -o short-precise -p err',
            ]
            
            for i, command in enumerate(journal_commands):
                try:
                    content = self.execute_remote_command(command)
                    
                    if content:
                        local_file = os.path.join(self.temp_dir, f"journalctl_{i}.log")
                        with open(local_file, 'w', encoding='utf-8') as f:
                            f.write(content)
                        
                        self.collected_files.append((local_file, "systemd"))
                        
                except Exception as e:
                    console.print(f"[yellow]Warnung: Fehler beim Sammeln von journalctl {i}: {e}[/yellow]")
                    
        except Exception as e:
            console.print(f"[yellow]Warnung: Fehler beim Sammeln von journalctl-Logs: {e}[/yellow]")
    
    def _collect_process_info(self):
        """Sammelt Prozess-Informationen"""
        try:
            console.print("[blue]Sammle Prozess-Informationen...[/blue]")
            
            commands = {
                'processes': 'ps aux --sort=-%cpu | head -20',
                'memory_usage': 'ps aux --sort=-%mem | head -20',
            }
            
            for name, command in commands.items():
                try:
                    content = self.execute_remote_command(command)
                    
                    if content:
                        local_file = os.path.join(self.temp_dir, f"process_{name}.txt")
                        with open(local_file, 'w', encoding='utf-8') as f:
                            f.write(content)
                        
                        self.collected_files.append((local_file, "processes"))
                        
                except Exception as e:
                    console.print(f"[yellow]Warnung: Fehler beim Sammeln von {name}: {e}[/yellow]")
                    
        except Exception as e:
            console.print(f"[yellow]Warnung: Fehler beim Sammeln von Prozess-Informationen: {e}[/yellow]")
    
    def _collect_system_status(self):
        """Sammelt System-Status-Informationen"""
        try:
            console.print("[blue]Sammle System-Status...[/blue]")
            
            commands = {
                'system_status': 'systemctl --failed',
                'service_status': 'systemctl list-units --type=service --state=running',
                'disk_usage': 'df -h',
                'memory_usage': 'free -h',
                'load_average': 'uptime',
            }
            
            for name, command in commands.items():
                try:
                    content = self.execute_remote_command(command)
                    
                    if content:
                        local_file = os.path.join(self.temp_dir, f"system_{name}.txt")
                        with open(local_file, 'w', encoding='utf-8') as f:
                            f.write(content)
                        
                        self.collected_files.append((local_file, "system"))
                        
                except Exception as e:
                    console.print(f"[yellow]Warnung: Fehler beim Sammeln von {name}: {e}[/yellow]")
                    
        except Exception as e:
            console.print(f"[yellow]Warnung: Fehler beim Sammeln von System-Status: {e}[/yellow]")
    
    def create_archive(self) -> str:
        """Erstellt ein komprimiertes Archiv der gesammelten Logs"""
        if not self.temp_dir or not os.path.exists(self.temp_dir):
            return None
        
        archive_path = f"{self.temp_dir}.tar.gz"
        
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(self.temp_dir, arcname=os.path.basename(self.temp_dir))
        
        console.print(f"[green]✓ Archiv erstellt: {archive_path}[/green]")
        return archive_path
    
    def cleanup(self):
        """Räumt temporäre Dateien auf"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            console.print("[dim]Temporäre Dateien aufgeräumt[/dim]")
        
        # Lösche auch das Archiv, falls es existiert
        archive_path = f"{self.temp_dir}.tar.gz" if self.temp_dir else None
        if archive_path and os.path.exists(archive_path):
            os.remove(archive_path)
            console.print("[dim]Archiv gelöscht[/dim]")


def start_interactive_chat(system_info: Dict[str, Any], log_entries: List[LogEntry], anomalies: List[Anomaly]):
    """Startet interaktiven Chat mit Ollama"""
    
    # Erstelle System-Kontext
    system_context = create_system_context(system_info, log_entries, anomalies)
    
    # Chat-Historie
    chat_history = []
    
    # Cache für häufige Antworten
    response_cache = {}
    
    # Kürzelwörter für häufige Fragen mit Modell-Komplexität
    shortcuts = {
        'services': {
            'question': _('shortcut_services'),
            'complex': False,
            'cache_key': 'services_status'
        },
        'storage': {
            'question': _('shortcut_storage'),
            'complex': False,
            'cache_key': 'storage_status'
        },
        'security': {
            'question': _('shortcut_security'),
            'complex': True,
            'cache_key': 'security_analysis'
        },
        'processes': {
            'question': _('shortcut_processes'),
            'complex': False,
            'cache_key': 'top_processes'
        },
        'performance': {
            'question': _('shortcut_performance'),
            'complex': False,
            'cache_key': 'performance_status'
        },
        'users': {
            'question': _('shortcut_users'),
            'complex': False,
            'cache_key': 'active_users'
        },
        'updates': {
            'question': _('shortcut_updates'),
            'complex': False,
            'cache_key': 'system_updates'
        },
        'logs': {
            'question': _('shortcut_logs'),
            'complex': True,
            'cache_key': 'log_analysis'
        },
        'k8s': {
            'question': _('shortcut_k8s'),
            'complex': False,
            'cache_key': 'k8s_status'
        },
        'k8s-problems': {
            'question': _('shortcut_k8s_problems'),
            'complex': True,
            'cache_key': 'k8s_problems'
        },
        'k8s-pods': {
            'question': _('shortcut_k8s_pods'),
            'complex': False,
            'cache_key': 'k8s_pods'
        },
        'k8s-nodes': {
            'question': _('shortcut_k8s_nodes'),
            'complex': False,
            'cache_key': 'k8s_nodes'
        },
        'k8s-resources': {
            'question': _('shortcut_k8s_resources'),
            'complex': False,
            'cache_key': 'k8s_resources'
        },
        'help': {
            'question': _('shortcut_help'),
            'complex': False,
            'cache_key': None
        },
        'm': {
            'question': _('shortcut_help'),
            'complex': False,
            'cache_key': None
        }
    }
    
    console.print(f"\n[bold blue]💬 {_('chat_title')}[/bold blue]")
    console.print("="*60)
    console.print(_('chat_prompt'))
    console.print(f"\n[bold cyan]{_('chat_shortcuts')}[/bold cyan]")
    console.print(f"  • 'services' - {_('shortcut_services')}")
    console.print(f"  • 'storage' - {_('shortcut_storage')}")
    console.print(f"  • 'security' - {_('shortcut_security')}")
    console.print(f"  • 'processes' - {_('shortcut_processes')}")
    console.print(f"  • 'performance' - {_('shortcut_performance')}")
    console.print(f"  • 'users' - {_('shortcut_users')}")
    console.print(f"  • 'updates' - {_('shortcut_updates')}")
    console.print(f"  • 'logs' - {_('shortcut_logs')}")
    
    # Kubernetes-Kürzel nur anzeigen, wenn Kubernetes verfügbar ist
    if 'kubernetes_detected' in system_info and system_info['kubernetes_detected']:
        console.print(f"  • 'k8s' - {_('shortcut_k8s')}")
        console.print(f"  • 'k8s-problems' - {_('shortcut_k8s_problems')}")
        console.print(f"  • 'k8s-pods' - {_('shortcut_k8s_pods')}")
        console.print(f"  • 'k8s-nodes' - {_('shortcut_k8s_nodes')}")
        console.print(f"  • 'k8s-resources' - {_('shortcut_k8s_resources')}")
    
    console.print(f"  • 'help' oder 'm' - {_('shortcut_help')}")
    console.print(f"  • 'exit', 'quit', 'q', 'bye', 'beenden' {_('chat_exit_commands')}")
    console.print("="*60)
    console.print(f"\n[dim]💡 {_('chat_tip')}: ['q' to quit, 'm' -> Menü][/dim]")
    
    # Automatische System-Analyse beim Start
    console.print(f"\n[dim]🤖 {_('analysis_running')}[/dim]")
    initial_analysis_prompt = create_chat_prompt(
        system_context, 
        "Analysiere das System und gib eine kurze Zusammenfassung der wichtigsten Punkte, Probleme und Empfehlungen.",
        []
    )
    initial_analysis = query_ollama(initial_analysis_prompt, complex_analysis=True)
    
    if initial_analysis:
        console.print(f"\n[bold green]🤖 {_('analysis_summary')}[/bold green]")
        console.print(initial_analysis)
    
    # Chat-Loop
    while True:
        try:
            user_input = console.input(f"\n[bold cyan]{_('chat_you')}:[/bold cyan] ").strip()
            
            # Prüfe auf Exit-Befehle
            if user_input.lower() in ['exit', 'quit', 'q', 'bye', 'beenden', 'tschüss', 'ciao']:
                console.print(f"\n[green]👋 {_('chat_goodbye')}[/green]")
                break
            
            # Prüfe auf Kürzelwörter
            shortcut_used = False
            if user_input.lower() in shortcuts:
                shortcut_info = shortcuts[user_input.lower()]
                user_input = shortcut_info['question']
                complex_analysis = shortcut_info['complex']
                cache_key = shortcut_info['cache_key']
                shortcut_used = True
                
                console.print(f"[dim]Verwende: {user_input}[/dim]")
                
                # Prüfe Cache für Kürzelwörter
                if cache_key and cache_key in response_cache:
                    console.print(f"[dim]📋 {_('chat_using_cached')} '{user_input}'[/dim]")
                    console.print(f"\n[bold green]🤖 {_('chat_ollama')}:[/bold green]")
                    console.print(response_cache[cache_key])
                    
                    # Füge zur Chat-Historie hinzu
                    chat_history.append({"role": "user", "content": user_input})
                    chat_history.append({"role": "assistant", "content": response_cache[cache_key]})
                    continue
            
            # Hilfe anzeigen
            if user_input.lower() in ['help', 'm']:
                console.print(f"\n[bold cyan]{_('menu_available_shortcuts')}[/bold cyan]")
                for shortcut, info in shortcuts.items():
                    if shortcut not in ['help', 'm']:
                        console.print(f"  • '{shortcut}' - {info['question']}")
                continue
            
            if not user_input:
                continue
            
            # Erstelle Chat-Prompt
            prompt = create_chat_prompt(system_context, user_input, chat_history)
            
            # Bestimme Modell-Komplexität basierend auf Frage oder Kürzelwort
            if not shortcut_used:
                complex_analysis = any(keyword in user_input.lower() for keyword in [
                    'problem', 'issue', 'error', 'failure', 'crash', 'anomaly', 'security',
                    'performance', 'bottleneck', 'optimization', 'recommendation', 'analysis',
                    'investigate', 'debug', 'troubleshoot', 'diagnose'
                ])
            
            # Zeige Modell-Auswahl
            model = select_best_model(complex_analysis)
            if shortcut_used:
                model_type = _('chat_using_fast_model') if not complex_analysis else _('chat_using_complex_model')
                console.print(f"[dim]⚡ {model_type}: {model}[/dim]")
            else:
                console.print(f"[dim]🤖 {_('chat_using_model')} {model}[/dim]")
            
            # Sende an Ollama
            console.print(f"[dim]🤔 {_('chat_thinking')}[/dim]")
            response = query_ollama(prompt, model=model, complex_analysis=complex_analysis)
            
            if response:
                console.print(f"\n[bold green]🤖 {_('chat_ollama')}:[/bold green]")
                console.print(response)
                
                # Cache die Antwort für Kürzelwörter
                if shortcut_used and cache_key:
                    response_cache[cache_key] = response
                    console.print(f"[dim]📋 {_('chat_cached')} '{user_input}'[/dim]")
                
                # Füge zur Chat-Historie hinzu
                chat_history.append({"role": "user", "content": user_input})
                chat_history.append({"role": "assistant", "content": response})
                
                # Begrenze Historie auf letzte 10 Nachrichten
                if len(chat_history) > 10:
                    chat_history = chat_history[-10:]
            else:
                console.print(f"[red]❌ {_('chat_no_response')}[/red]")
                
        except KeyboardInterrupt:
            console.print(f"\n[green]👋 {_('chat_goodbye')}[/green]")
            break
        except Exception as e:
            console.print(f"[red]❌ Fehler im Chat: {e}[/red]")


def create_system_context(system_info: Dict[str, Any], log_entries: List[LogEntry], anomalies: List[Anomaly]) -> str:
    """Erstellt einen strukturierten System-Kontext für Ollama"""
    context_parts = []
    
    # System-Basis-Informationen
    context_parts.append("=== SYSTEM-INFORMATIONEN ===")
    context_parts.append(f"Hostname: {system_info.get('hostname', 'Unbekannt')}")
    context_parts.append(f"Distribution: {system_info.get('distro_pretty_name', system_info.get('distro_name', 'Unbekannt'))}")
    context_parts.append(f"Kernel: {system_info.get('kernel_version', 'Unbekannt')}")
    context_parts.append(f"Architektur: {system_info.get('architecture', 'Unbekannt')}")
    context_parts.append(f"CPU: {system_info.get('cpu_info', 'Unbekannt')}")
    context_parts.append(f"CPU-Kerne: {system_info.get('cpu_cores', 'Unbekannt')}")
    context_parts.append(f"RAM: {system_info.get('memory_total', 'Unbekannt')}")
    context_parts.append(f"Uptime: {system_info.get('uptime', 'Unbekannt')}")
    context_parts.append(f"Zeitzone: {system_info.get('timezone', 'Unbekannt')}")
    
    # Speicherplatz
    if 'root_usage_percent' in system_info:
        context_parts.append(f"Speicherplatz Root: {system_info.get('root_total', 'N/A')} gesamt, {system_info.get('root_used', 'N/A')} verwendet, {system_info.get('root_available', 'N/A')} verfügbar ({system_info.get('root_usage_percent', 'N/A')} Auslastung)")
    
    # Speicherplatz-Details
    if 'largest_directories' in system_info:
        context_parts.append("\n=== SPEICHERPLATZ-VERWENDUNG ===")
        dir_mapping = {
            'home_usage': '/home',
            'var_usage': '/var',
            'tmp_usage': '/tmp',
            'log_usage': '/var/log',
            'docker_usage': '/var/lib/docker',
            'apt_usage': '/var/cache/apt'
        }
        for key, path in dir_mapping.items():
            if key in system_info and system_info[key]:
                context_parts.append(f"{path}: {system_info[key]}")
    
    # Größte Dateien
    if 'largest_files' in system_info:
        context_parts.append("\n=== GRÖSSTE DATEIEN ===")
        if system_info['largest_files']:
            lines = system_info['largest_files'].split('\n')[:10]
            for line in lines:
                if line.strip():
                    context_parts.append(line.strip())
    
    # Größte Dateien nach Verzeichnissen
    if 'largest_files_by_directory' in system_info:
        context_parts.append("\n=== GRÖSSTE DATEIEN NACH VERZEICHNISSEN ===")
        for directory, files in system_info['largest_files_by_directory'].items():
            if files:
                context_parts.append(f"\n{directory}:")
                lines = files.split('\n')[:5]
                for line in lines:
                    if line.strip():
                        context_parts.append(f"  {line.strip()}")
    
    # Services
    if 'important_services_status' in system_info:
        context_parts.append("\n=== AKTIVE SERVICES ===")
        services = system_info['important_services_status']
        for service, status in services.items():
            context_parts.append(f"{service}: {status}")
    
    # Anmeldungen
    if 'current_users' in system_info or 'user_login_stats' in system_info:
        context_parts.append("\n=== ANMELDUNGS-STATISTIKEN ===")
        if 'current_users' in system_info and system_info['current_users']:
            context_parts.append(f"Aktuell eingeloggt: {system_info['current_users']}")
        if 'user_login_stats' in system_info and system_info['user_login_stats']:
            context_parts.append("Anmeldungen der letzten 7 Tage:")
            context_parts.append(system_info['user_login_stats'])
        if 'failed_logins_by_user' in system_info and system_info['failed_logins_by_user']:
            context_parts.append("Fehlgeschlagene Anmeldungen:")
            context_parts.append(system_info['failed_logins_by_user'])
    
    # Performance
    if 'cpu_usage_percent' in system_info or 'memory_usage_percent' in system_info:
        context_parts.append("\n=== PERFORMANCE ===")
        if 'cpu_usage_percent' in system_info:
            context_parts.append(f"CPU-Auslastung: {system_info['cpu_usage_percent']}%")
        if 'memory_usage_percent' in system_info:
            context_parts.append(f"Memory-Auslastung: {system_info['memory_usage_percent']}%")
        if 'load_average_1min' in system_info:
            context_parts.append(f"Load Average (1min): {system_info['load_average_1min']}")
    
    # Paket-Management
    if 'package_manager' in system_info:
        context_parts.append(f"\nPaket-Manager: {system_info['package_manager']}")
        context_parts.append(f"Installierte Pakete: {system_info.get('installed_packages_count', 'Unbekannt')}")
        context_parts.append(f"Verfügbare Updates: {system_info.get('available_updates', 'Unbekannt')}")
    
    # Kubernetes-Cluster
    if 'kubernetes_detected' in system_info and system_info['kubernetes_detected']:
        context_parts.append("\n=== KUBERNETES-CLUSTER ===")
        
        if 'cluster_info' in system_info:
            context_parts.append("Cluster-Info:")
            context_parts.append(system_info['cluster_info'])
        
        if 'k8s_version' in system_info:
            context_parts.append(f"Version: {system_info['k8s_version']}")
        
        if 'node_status' in system_info:
            context_parts.append("Node-Status:")
            context_parts.append(system_info['node_status'])
        
        if 'namespaces' in system_info:
            context_parts.append("Namespaces:")
            context_parts.append(system_info['namespaces'])
        
        if 'pods' in system_info:
            context_parts.append("Pods (alle Namespaces):")
            context_parts.append(system_info['pods'])
        
        if 'services' in system_info:
            context_parts.append("Services:")
            context_parts.append(system_info['services'])
        
        if 'deployments' in system_info:
            context_parts.append("Deployments:")
            context_parts.append(system_info['deployments'])
        
        if 'node_resource_usage' in system_info:
            context_parts.append("Node-Ressourcen:")
            context_parts.append(system_info['node_resource_usage'])
        
        if 'pod_resource_usage' in system_info:
            context_parts.append("Pod-Ressourcen:")
            context_parts.append(system_info['pod_resource_usage'])
        
        # Kubernetes-Probleme
        if 'problems_count' in system_info and system_info['problems_count'] > 0:
            context_parts.append(f"\nKUBERNETES-PROBLEME ({system_info['problems_count']} gefunden):")
            for i, problem in enumerate(system_info['problems'], 1):
                context_parts.append(f"Problem {i}: {problem}")
        
        if 'recent_events' in system_info:
            context_parts.append("Kürzliche Events:")
            context_parts.append(system_info['recent_events'])
    
    # Log-Statistiken
    if log_entries:
        context_parts.append(f"\n=== LOG-ANALYSE ===")
        context_parts.append(f"Analysierte Log-Einträge: {len(log_entries)}")
        
        # Log-Level-Verteilung
        level_counts = {}
        source_counts = {}
        for entry in log_entries:
            level_counts[entry.level.value] = level_counts.get(entry.level.value, 0) + 1
            source_counts[entry.source] = source_counts.get(entry.source, 0) + 1
        
        context_parts.append("Log-Level-Verteilung:")
        for level, count in level_counts.items():
            context_parts.append(f"  {level}: {count}")
        
        context_parts.append("Log-Quellen:")
        for source, count in source_counts.items():
            context_parts.append(f"  {source}: {count}")
    
    # Anomalien
    if anomalies:
        context_parts.append(f"\n=== GEFUNDENE ANOMALIEN ===")
        context_parts.append(f"Anzahl Anomalien: {len(anomalies)}")
        for i, anomaly in enumerate(anomalies[:5], 1):  # Zeige nur die ersten 5
            context_parts.append(f"Anomalie {i}: {anomaly.description} (Schwere: {anomaly.severity})")
    
    return "\n".join(context_parts)


def create_chat_prompt(system_context: str, user_question: str, chat_history: List[Dict]) -> str:
    """Erstellt eine strukturierte Anfrage für Ollama"""
    prompt_parts = []
    
    # System-Rolle für präzise System-Analyse
    prompt_parts.append("Du bist ein erfahrener System-Administrator und IT-Sicherheitsexperte.")
    prompt_parts.append("Deine Aufgabe ist es, Linux-Systeme zu analysieren und potenzielle Probleme zu identifizieren.")
    prompt_parts.append("WICHTIGE REGELN:")
    prompt_parts.append("- Antworte kurz, präzise und prägnant")
    prompt_parts.append("- Identifiziere automatisch Engpässe, Sicherheitslücken und Unregelmäßigkeiten")
    prompt_parts.append("- Warnung bei kritischen Problemen (hohe CPU/Last, wenig Speicher, Sicherheitsprobleme)")
    prompt_parts.append("- Gib konkrete Handlungsempfehlungen")
    prompt_parts.append("- Verwende die bereitgestellten System-Daten als Grundlage")
    
    # System-Kontext
    prompt_parts.append("\n=== SYSTEM-INFORMATIONEN ===")
    prompt_parts.append(system_context)
    
    # Chat-Historie (letzte 2 Einträge für Kontext)
    if chat_history:
        prompt_parts.append("\n=== CHAT-VERLAUF ===")
        for entry in chat_history[-2:]:
            prompt_parts.append(f"Benutzer: {entry['user']}")
            prompt_parts.append(f"Du: {entry['assistant']}")
    
    prompt_parts.append(f"\nBenutzer-Frage: {user_question}")
    prompt_parts.append("\nAntworte strukturiert:")
    prompt_parts.append("1. Kurze Analyse der Frage")
    prompt_parts.append("2. Identifizierte Probleme/Engpässe (falls vorhanden)")
    prompt_parts.append("3. Konkrete Empfehlungen")
    
    return "\n".join(prompt_parts)


def get_available_models() -> List[Dict[str, Any]]:
    """Hole verfügbare Ollama-Modelle und deren Details."""
    import requests
    
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=10)
        if response.status_code == 200:
            models = response.json().get('models', [])
            # Hole Details für jedes Modell
            detailed_models = []
            for model in models:
                try:
                    details_response = requests.post("http://localhost:11434/api/show", 
                                                   json={"name": model['name']}, timeout=5)
                    if details_response.status_code == 200:
                        details = details_response.json()
                        detailed_models.append({
                            'name': model['name'],
                            'size': details.get('size', 0),
                            'modified_at': details.get('modified_at', ''),
                            'parameters': details.get('parameter_size', ''),
                            'format': details.get('format', ''),
                            'family': details.get('family', '')
                        })
                except:
                    detailed_models.append({
                        'name': model['name'],
                        'size': 0,
                        'modified_at': '',
                        'parameters': '',
                        'format': '',
                        'family': ''
                    })
            return detailed_models
    except:
        pass
    return []


def select_best_model(complex_analysis: bool = False) -> str:
    """Wähle das beste verfügbare Modell für System-Analyse aus."""
    models = get_available_models()
    
    if not models:
        console.print("[yellow]⚠️  Keine Ollama-Modelle gefunden, verwende Standard[/yellow]")
        return "llama3.2:3b"
    
    if complex_analysis:
        # Für komplexe Analysen: Große Modelle bevorzugen
        preferred_models = [
            "llama3.2:70b", "llama3.2:8b", "llama3.1:70b", "llama3.1:8b",
            "llama2:70b", "llama2:13b", "codellama:70b", "codellama:13b",
            "mistral:7b", "mixtral:8x7b", "qwen2:72b", "qwen2:7b"
        ]
        model_type = "komplexe Analyse"
    else:
        # Für einfache Analysen: Kleine, schnelle Modelle bevorzugen
        preferred_models = [
            "llama3.2:3b", "llama3.1:3b", "llama2:7b", "codellama:7b",
            "mistral:7b", "qwen2:7b", "llama3.2:8b", "llama3.1:8b"
        ]
        model_type = "schnelle Analyse"
    
    # Suche nach bevorzugten Modellen
    for preferred in preferred_models:
        for model in models:
            if preferred in model['name']:
                console.print(f"[green]✅ Verwende Modell für {model_type}: {model['name']}[/green]")
                return model['name']
    
    # Fallback: Wähle das größte verfügbare Modell
    largest_model = max(models, key=lambda x: x.get('size', 0))
    console.print(f"[yellow]⚠️  Verwende größtes verfügbares Modell: {largest_model['name']}[/yellow]")
    
    # Warnung bei kleinen Modellen für komplexe Analysen
    if complex_analysis and largest_model.get('size', 0) < 3 * 1024 * 1024 * 1024:  # < 3GB
        console.print("[yellow]⚠️  Kleines Modell für komplexe Analyse. Empfehle größeres Modell (7B+)[/yellow]")
        console.print("[dim]Empfohlene Modelle: llama3.2:8b, llama3.2:70b, codellama:13b[/dim]")
    
    return largest_model['name']


def query_ollama(prompt: str, model: str = None, complex_analysis: bool = False) -> Optional[str]:
    """Sendet eine Anfrage an Ollama und gibt die Antwort zurück"""
    try:
        import requests
        
        if not model:
            model = select_best_model(complex_analysis=complex_analysis)
        
        url = "http://localhost:11434/api/generate"
        
        # Anpassung der Parameter je nach Komplexität
        if complex_analysis:
            options = {
                "temperature": 0.2,  # Sehr niedrige Temperatur für präzise komplexe Analysen
                "top_p": 0.9,
                "top_k": 40,
                "max_tokens": 2000
            }
            timeout = 90  # Längere Timeout für komplexe Analysen
        else:
            options = {
                "temperature": 0.4,  # Höhere Temperatur für schnellere Antworten
                "top_p": 0.9,
                "top_k": 30,
                "max_tokens": 1000
            }
            timeout = 45  # Kürzere Timeout für einfache Analysen
        
        data = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": options
        }
        
        response = requests.post(url, json=data, timeout=timeout)
        
        if response.status_code == 200:
            result = response.json()
            return result.get('response', '').strip()
        else:
            console.print(f"[red]Ollama-Fehler: {response.status_code}[/red]")
            return None
            
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Verbindungsfehler zu Ollama: {e}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Fehler bei Ollama-Anfrage: {e}[/red]")
        return None


def main():
    """Hauptfunktion für SSH-Log-Sammlung und -Analyse mit Chat"""
    parser = argparse.ArgumentParser(description='SSH-basierter Linux-Log-Analyzer mit Chat')
    parser.add_argument('target', help='Ziel-Server (user@host oder host)')
    parser.add_argument('--username', help='SSH-Benutzername (falls nicht in target angegeben)')
    parser.add_argument('--password', help='SSH-Passwort (wird abgefragt wenn nicht angegeben)')
    parser.add_argument('--key-file', help='Pfad zur SSH-Key-Datei')
    parser.add_argument('--port', type=int, default=22, help='SSH-Port (Standard: 22)')
    parser.add_argument('--ollama-port', type=int, default=11434, help='Ollama-Port (Standard: 11434)')
    parser.add_argument('--no-port-forwarding', action='store_true', help='Deaktiviere Port-Forwarding')
    parser.add_argument('--hours', type=int, default=24, help='Anzahl Stunden zurück (Standard: 24)')
    parser.add_argument('--keep-files', action='store_true', help='Temporäre Dateien behalten')
    parser.add_argument('--output', help='Ausgabe-Datei für Ergebnisse')
    parser.add_argument('--quick', action='store_true', help='Schnelle Analyse ohne detaillierte Datei-Suche')
    parser.add_argument('--no-logs', action='store_true', help='Überspringe Log-Sammlung (nur System-Info)')
    
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
    
    console.print("[bold blue]SSH-basierter Linux-Log-Analyzer mit Chat[/bold blue]")
    console.print("="*60)
    
    # Erstelle SSH-Collector
    collector = SSHLogCollector(
        host=host,
        username=username,
        password=args.password,
        key_file=args.key_file,
        port=args.port,
        ollama_port=args.ollama_port,
        use_port_forwarding=not args.no_port_forwarding
    )
    
    try:
        # Verbinde mit Zielsystem
        if not collector.connect():
            console.print("[red]❌ Konnte nicht mit Zielsystem verbinden[/red]")
            return 1
        
        # Sammle System-Informationen
        system_info = collector.get_system_info(quick_mode=args.quick)
        
        # Zeige Fehler-Zusammenfassung
        collector.print_error_summary()
        
        # Zeige System-Übersicht
        console.print("\n[bold blue]📊 System-Übersicht[/bold blue]")
        console.print("="*60)
        
        # Basis-Informationen
        basic_table = Table(title="System-Basis-Informationen", show_header=True, header_style="bold magenta")
        basic_table.add_column("Eigenschaft", style="cyan", width=20)
        basic_table.add_column("Wert", style="green", width=40)
        
        basic_info = [
            ("Hostname", system_info.get('hostname', 'Unbekannt')),
            ("Distribution", system_info.get('distro_pretty_name', system_info.get('distro_name', 'Unbekannt'))),
            ("Kernel", system_info.get('kernel_version', 'Unbekannt')),
            ("Architektur", system_info.get('architecture', 'Unbekannt')),
            ("CPU", system_info.get('cpu_info', 'Unbekannt')),
            ("CPU-Kerne", system_info.get('cpu_cores', 'Unbekannt')),
            ("RAM", system_info.get('memory_total', 'Unbekannt')),
            ("Uptime", system_info.get('uptime', 'Unbekannt')),
            ("Zeitzone", system_info.get('timezone', 'Unbekannt')),
            ("Paket-Manager", system_info.get('package_manager', 'Unbekannt')),
            ("Installierte Pakete", str(system_info.get('installed_packages_count', 'Unbekannt'))),
            ("Verfügbare Updates", str(system_info.get('available_updates', 'Unbekannt')))
        ]
        
        for label, value in basic_info:
            if value and value != 'Unbekannt':
                basic_table.add_row(label, str(value))
        
        console.print(basic_table)
        
        # Speicherplatz-Informationen
        if 'root_usage_percent' in system_info:
            storage_table = Table(title="Speicherplatz-Status", show_header=True, header_style="bold magenta")
            storage_table.add_column("Partition", style="cyan", width=15)
            storage_table.add_column("Gesamt", style="green", width=10)
            storage_table.add_column("Verwendet", style="yellow", width=10)
            storage_table.add_column("Verfügbar", style="green", width=10)
            storage_table.add_column("Auslastung", style="red", width=10)
            
            usage_percent = system_info.get('root_usage_percent', '0%').replace('%', '')
            usage_color = "red" if int(usage_percent) > 80 else "yellow" if int(usage_percent) > 60 else "green"
            
            storage_table.add_row(
                "/ (Root)",
                system_info.get('root_total', 'N/A'),
                system_info.get('root_used', 'N/A'),
                system_info.get('root_available', 'N/A'),
                f"[{usage_color}]{system_info.get('root_usage_percent', 'N/A')}[/{usage_color}]"
            )
            
            console.print(storage_table)
        
        # Service-Status
        if 'important_services_status' in system_info:
            service_table = Table(title="Wichtige Services", show_header=True, header_style="bold magenta")
            service_table.add_column("Service", style="cyan", width=15)
            service_table.add_column("Status", style="green", width=10)
            
            services = system_info['important_services_status']
            for service, status in services.items():
                status_color = "green" if status == "active" else "red" if status == "failed" else "yellow"
                service_table.add_row(service, f"[{status_color}]{status}[/{status_color}]")
            
            console.print(service_table)
        
        # Performance-Status
        if 'cpu_usage_percent' in system_info or 'memory_usage_percent' in system_info:
            perf_table = Table(title="Performance-Status", show_header=True, header_style="bold magenta")
            perf_table.add_column("Metrik", style="cyan", width=20)
            perf_table.add_column("Wert", style="green", width=15)
            
            if 'cpu_usage_percent' in system_info:
                cpu_usage = float(system_info['cpu_usage_percent'])
                cpu_color = "red" if cpu_usage > 80 else "yellow" if cpu_usage > 60 else "green"
                perf_table.add_row("CPU-Auslastung", f"[{cpu_color}]{cpu_usage:.1f}%[/{cpu_color}]")
            
            if 'memory_usage_percent' in system_info:
                mem_usage = float(system_info['memory_usage_percent'])
                mem_color = "red" if mem_usage > 80 else "yellow" if mem_usage > 60 else "green"
                perf_table.add_row("Memory-Auslastung", f"[{mem_color}]{mem_usage:.1f}%[/{mem_color}]")
            
            if 'load_average_1min' in system_info:
                load_1min = float(system_info['load_average_1min'])
                load_color = "red" if load_1min > 5 else "yellow" if load_1min > 2 else "green"
                perf_table.add_row("Load Average (1min)", f"[{load_color}]{load_1min:.2f}[/{load_color}]")
            
            console.print(perf_table)
        
        # Kubernetes-Status (falls verfügbar)
        if 'kubernetes_detected' in system_info and system_info['kubernetes_detected']:
            console.print("\n[bold blue]☸️ Kubernetes-Cluster[/bold blue]")
            console.print("="*60)
            
            # Cluster-Info
            if 'cluster_info' in system_info:
                console.print("[bold cyan]Cluster-Informationen:[/bold cyan]")
                console.print(system_info['cluster_info'])
            
            # Version
            if 'k8s_version' in system_info:
                console.print(f"\n[bold cyan]Kubernetes-Version:[/bold cyan] {system_info['k8s_version']}")
            
            # Node-Status
            if 'node_status' in system_info:
                console.print("\n[bold cyan]Node-Status:[/bold cyan]")
                console.print(system_info['node_status'])
            
            # Probleme
            if 'problems_count' in system_info and system_info['problems_count'] > 0:
                console.print(f"\n[bold red]⚠️  {system_info['problems_count']} Probleme gefunden:[/bold red]")
                for i, problem in enumerate(system_info['problems'], 1):
                    console.print(f"\n[red]Problem {i}:[/red]")
                    console.print(problem)
            else:
                console.print("\n[green]✅ Keine Kubernetes-Probleme gefunden[/green]")
            
            # Ressourcen-Auslastung
            if 'node_resource_usage' in system_info:
                console.print("\n[bold cyan]Node-Ressourcen:[/bold cyan]")
                console.print(system_info['node_resource_usage'])
            
            if 'pod_resource_usage' in system_info:
                console.print("\n[bold cyan]Pod-Ressourcen:[/bold cyan]")
                console.print(system_info['pod_resource_usage'])
        
        # Speicherplatz-Details
        if 'largest_directories' in system_info:
            console.print("\n[bold blue]📁 Speicherplatz-Verwendung[/bold blue]")
            console.print("="*60)
            
            # Wichtige Verzeichnisse
            if any(key in system_info for key in ['home_usage', 'var_usage', 'tmp_usage', 'log_usage', 'docker_usage', 'apt_usage']):
                storage_table = Table(title="Wichtige Verzeichnisse", show_header=True, header_style="bold magenta")
                storage_table.add_column("Verzeichnis", style="cyan", width=15)
                storage_table.add_column("Größe", style="green", width=15)
                
                dir_mapping = {
                    'home_usage': '/home',
                    'var_usage': '/var',
                    'tmp_usage': '/tmp',
                    'log_usage': '/var/log',
                    'docker_usage': '/var/lib/docker',
                    'apt_usage': '/var/cache/apt'
                }
                
                for key, path in dir_mapping.items():
                    if key in system_info and system_info[key]:
                        storage_table.add_row(path, system_info[key])
                
                console.print(storage_table)
        
        # Größte Dateien
        if 'largest_files' in system_info:
            console.print("\n[bold blue]📄 Größte Dateien im System[/bold blue]")
            console.print("="*60)
            
            # Zeige die Top 10 größten Dateien
            if system_info['largest_files']:
                console.print("[bold cyan]Top 10 größte Dateien:[/bold cyan]")
                lines = system_info['largest_files'].split('\n')[:10]
                for line in lines:
                    if line.strip():
                        console.print(f"[dim]{line}[/dim]")
        
        # Größte Dateien nach Verzeichnissen
        if 'largest_files_by_directory' in system_info:
            console.print("\n[bold blue]📂 Größte Dateien nach Verzeichnissen[/bold blue]")
            console.print("="*60)
            
            for directory, files in system_info['largest_files_by_directory'].items():
                if files:
                    console.print(f"\n[bold cyan]{directory}:[/bold cyan]")
                    lines = files.split('\n')[:5]  # Zeige nur Top 5 pro Verzeichnis
                    for line in lines:
                        if line.strip():
                            console.print(f"[dim]{line}[/dim]")
        
        # Anmeldungs-Übersicht
        if 'user_login_stats' in system_info or 'current_users' in system_info:
            console.print("\n[bold blue]🔐 Anmeldungs-Übersicht[/bold blue]")
            console.print("="*60)
            
            # Aktuell eingeloggte Benutzer
            if 'current_users' in system_info and system_info['current_users']:
                console.print("[bold cyan]Aktuell eingeloggte Benutzer:[/bold cyan]")
                console.print(system_info['current_users'])
            
            # Anmeldungs-Statistiken
            if 'user_login_stats' in system_info and system_info['user_login_stats']:
                console.print("\n[bold cyan]Anmeldungen der letzten 7 Tage:[/bold cyan]")
                console.print(system_info['user_login_stats'])
            
            # Fehlgeschlagene Anmeldungen
            if 'failed_logins_by_user' in system_info and system_info['failed_logins_by_user']:
                console.print("\n[bold red]Fehlgeschlagene Anmeldungen:[/bold red]")
                console.print(system_info['failed_logins_by_user'])
        
        # Sammle Logs (nur wenn nicht --no-logs)
        if args.no_logs:
            console.print("[yellow]⏩ Überspringe Log-Sammlung (--no-logs)[/yellow]")
            log_directory = None
            analyzer = LogAnalyzer()
            analyzer.log_entries = []
            analyzer.anomalies = []
        else:
            log_directory = collector.collect_logs(hours_back=args.hours)
            
            if not log_directory or not os.path.exists(log_directory):
                console.print("[red]❌ Keine Logs gesammelt[/red]")
                return 1
            
            # Erstelle Linux-Log-Analyzer
            analyzer = LogAnalyzer()
        
                # Überprüfe Ollama-Verbindung
        if not analyzer._check_ollama_connection():
            console.print("[red]❌ Ollama ist nicht erreichbar. Bitte starten Sie Ollama.[/red]")
            return 1
        
        console.print("[green]✅ Ollama-Verbindung erfolgreich[/green]")
        
        # Analysiere Linux-Logs (nur wenn Logs vorhanden)
        log_files = []  # Initialisiere als leere Liste
        if log_directory and os.path.exists(log_directory):
            console.print("[blue]Analysiere Linux-Logs...[/blue]")
            
            # Sammle alle Log-Dateien
            for root, dirs, files in os.walk(log_directory):
                for file in files:
                    if file.endswith(('.log', '.txt')):
                        log_files.append(os.path.join(root, file))
            
            console.print(f"[blue]Gefunden: {len(log_files)} Log-Dateien[/blue]")
            
            # Analysiere jede Log-Datei
            if log_files:  # Nur ausführen wenn Logs vorhanden
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    
                    task = progress.add_task("Analysiere Logs...", total=len(log_files))
                    
                    for log_file in log_files:
                        progress.update(task, description=f"Analysiere {os.path.basename(log_file)}...")
                        
                        try:
                            # Einfache Log-Analyse
                            source = os.path.basename(log_file).split('_')[0] if '_' in os.path.basename(log_file) else 'unknown'
                            
                            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                                for line_num, line in enumerate(f, 1):
                                    if line.strip():
                                        # Einfache Log-Einträge erstellen
                                        entry = LogEntry(
                                            timestamp=datetime.now(),
                                            level=LogLevel.INFO,
                                            source=source,
                                            message=line.strip()[:200],
                                            raw_line=line.strip(),
                                            priority_score=1.0
                                        )
                                        analyzer.log_entries.append(entry)
                                        
                                        # Begrenze die Anzahl der Einträge
                                        if len(analyzer.log_entries) >= 1000:
                                            break
                            
                                if len(analyzer.log_entries) >= 1000:
                                    break
                                    
                        except Exception as e:
                            console.print(f"[yellow]Warnung: Fehler bei Analyse von {log_file}: {e}[/yellow]")
                        
                        progress.advance(task)
                
                console.print(f"[green]✓ {len(analyzer.log_entries)} Log-Einträge analysiert[/green]")
            else:
                console.print("[yellow]Keine Log-Dateien gefunden.[/yellow]")
        else:
            console.print("[yellow]Keine Logs gesammelt - überspringe Log-Analyse.[/yellow]")
        
        if not analyzer.log_entries:
            console.print("[yellow]Keine Log-Einträge gefunden.[/yellow]")
            # Trotzdem Chat ermöglichen
            if Confirm.ask("\n[bold blue]Möchten Sie sich mit Ollama über das System unterhalten?"):
                start_interactive_chat(system_info, analyzer.log_entries, analyzer.anomalies)
            return 0
        
        # Analysiere mit Ollama (nur wenn Logs vorhanden)
        if log_files:
            analyzer.analyze_with_ollama()
            
            # Zeige Ergebnisse
            analyzer.display_results()
        
        # Erstelle Archiv (nur wenn Logs vorhanden)
        archive_path = None
        if log_directory and os.path.exists(log_directory):
            archive_path = collector.create_archive()
        
        # Speichere Ergebnisse
        if args.output:
            results = {
                'system_info': system_info,
                'log_entries_count': len(analyzer.log_entries),
                'anomalies_count': len(analyzer.anomalies),
                'collection_time': datetime.now().isoformat(),
                'archive_path': archive_path,
                'ssh_connection': system_info.get('ssh_connection'),
                'port_forwarding': system_info.get('port_forwarding', False)
            }
            
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            console.print(f"[green]✓ Ergebnisse gespeichert in: {args.output}[/green]")
        
        console.print(f"\n[bold green]Analyse abgeschlossen![/bold green]")
        if log_directory:
            console.print(f"📁 Logs gesammelt in: {log_directory}")
        if archive_path:
            console.print(f"📦 Archiv erstellt: {archive_path}")
        
        # Interaktiver Ollama-Chat
        if Confirm.ask("\n[bold blue]Möchten Sie sich mit Ollama über das System unterhalten?"):
            start_interactive_chat(system_info, analyzer.log_entries, analyzer.anomalies)
        
        return 0
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Analyse abgebrochen.[/yellow]")
        return 1
    except Exception as e:
        console.print(f"[red]Fehler bei der Analyse: {e}[/red]")
        return 1
    finally:
        # Cleanup
        if not args.keep_files:
            collector.cleanup()


if __name__ == "__main__":
    sys.exit(main()) 