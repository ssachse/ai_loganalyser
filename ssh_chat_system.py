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
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TaskID
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
import threading
import time

# Importiere den bestehenden Log-Analyzer
from log_analyzer import LogAnalyzer, LogEntry, LogLevel, Anomaly
from config import Config
from i18n import i18n

# Initialisiere dynamische Übersetzungen für unbekannte Locales
i18n.initialize_dynamic_translation()

console = Console()

class ProgressTracker:
    """Fortschrittsanzeige für lange Operationen"""
    
    def __init__(self, description: str, total_steps: int = 100):
        self.description = description
        self.total_steps = total_steps
        self.current_step = 0
        self.start_time = time.time()
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        )
        self.task_id = None
    
    def __enter__(self):
        self.progress.start()
        self.task_id = self.progress.add_task(self.description, total=self.total_steps)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.progress.stop()
    
    def update(self, step: int = 1, description: str = None):
        """Aktualisiert den Fortschritt"""
        self.current_step += step
        if self.task_id is not None:
            self.progress.update(self.task_id, completed=self.current_step)
            if description:
                self.progress.update(self.task_id, description=description)
    
    def set_description(self, description: str):
        """Setzt eine neue Beschreibung"""
        if self.task_id is not None:
            self.progress.update(self.task_id, description=description)

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
    
    def execute_remote_command(self, command: str, force_sudo: bool = False) -> Optional[str]:
        """Führt einen Befehl auf dem Remote-System aus mit intelligenter Sudo-Unterstützung"""
        
        # Sichere Liste von Befehlen, die mit Sudo ausgeführt werden dürfen (nur lesend!)
        SUDO_SAFE_COMMANDS = {
            'cat', 'head', 'tail', 'less', 'more', 'grep', 'find', 'ls', 'stat', 'file',
            'du', 'df', 'free', 'top', 'htop', 'ps', 'netstat', 'ss', 'lsof', 'iostat',
            'vmstat', 'sar', 'uptime', 'w', 'who', 'last', 'journalctl', 'systemctl',
            'service', 'chkconfig', 'systemd-analyze', 'pvesh', 'kubectl', 'docker',
            'podman', 'crictl', 'nvidia-smi', 'lspci', 'lsusb', 'dmidecode', 'smartctl',
            'hdparm', 'fdisk', 'blkid', 'mount', 'umount', 'lsof', 'fuser', 'lsof',
            'netstat', 'ss', 'ip', 'route', 'arp', 'ping', 'traceroute', 'dig', 'nslookup',
            'host', 'whois', 'curl', 'wget', 'telnet', 'nc', 'nmap', 'tcpdump', 'wireshark',
            'tcpflow', 'ngrep', 'iftop', 'iotop', 'nethogs', 'bandwhich', 'bmon', 'nload',
            'iftop', 'iptraf', 'vnstat', 'bwm-ng', 'speedtest-cli', 'speedtest', 'fast',
            'openssl', 'certbot', 'letsencrypt', 'acme.sh', 'certbot-auto', 'certbot-renew',
            'certbot-certonly', 'certbot-install', 'certbot-plugin', 'certbot-standalone',
            'certbot-webroot', 'certbot-manual', 'certbot-apache', 'certbot-nginx',
            'certbot-postfix', 'certbot-dovecot', 'certbot-proftpd', 'certbot-pure-ftpd',
            'certbot-vsftpd', 'certbot-lighttpd', 'certbot-haproxy', 'certbot-traefik',
            'certbot-caddy', 'certbot-httpd', 'certbot-httpd-ssl', 'certbot-httpd-ssl-conf',
            'certbot-httpd-ssl-conf-ssl', 'certbot-httpd-ssl-conf-ssl-conf',
            'certbot-httpd-ssl-conf-ssl-conf-ssl', 'certbot-httpd-ssl-conf-ssl-conf-ssl-conf'
        }
        
        # Gefährliche Befehle, die niemals mit Sudo ausgeführt werden dürfen
        DANGEROUS_COMMANDS = {
            'rm', 'rmdir', 'del', 'delete', 'remove', 'unlink', 'shred', 'wipe',
            'mkfs', 'fdisk', 'parted', 'gdisk', 'sgdisk', 'cfdisk', 'sfdisk',
            'dd', 'cp', 'mv', 'rename', 'chmod', 'chown', 'chgrp', 'setfacl',
            'useradd', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod',
            'passwd', 'chpasswd', 'newusers', 'vipw', 'vigr', 'visudo',
            'systemctl', 'service', 'initctl', 'telinit', 'shutdown', 'reboot',
            'halt', 'poweroff', 'suspend', 'hibernate', 'hybrid-sleep',
            'iptables', 'ip6tables', 'ebtables', 'arptables', 'nft',
            'ufw', 'firewalld', 'shorewall', 'fail2ban', 'rkhunter', 'chkrootkit',
            'clamscan', 'freshclam', 'sophos', 'mcafee', 'trend', 'kaspersky',
            'norton', 'avg', 'avast', 'bitdefender', 'eset', 'f-secure',
            'panda', 'comodo', 'webroot', 'malwarebytes', 'superantispyware',
            'spybot', 'ad-aware', 'spywareblaster', 'spywareterminator',
            'spywarenuker', 'spywarequarantine', 'spywarecleaner', 'spywarekiller',
            'spywareblocker', 'spywareguard', 'spywareprotector', 'spywaredefender',
            'spywarefighter', 'spywarehunter', 'spywarefinder', 'spywarelocator',
            'spywaretracker', 'spywaremonitor', 'spywarewatcher', 'spywareobserver',
            'spywareinspector', 'spywareanalyzer', 'spywareexaminer', 'spywareinvestigator',
            'spywareresearcher', 'spywareexplorer', 'spywarediscoverer', 'spywaredetector',
            'spywareidentifier', 'spywarerecognizer', 'spywareclassifier', 'spywarecategorizer',
            'spywareorganizer', 'spywarearranger', 'spywarecoordinator', 'spywaremanager',
            'spywarecontroller', 'spywaredirector', 'spywareadministrator', 'spywareoperator',
            'spywarehandler', 'spywareprocessor', 'spywareexecutor', 'spywareperformer',
            'spywareimplementer', 'spywareenforcer', 'spywareenactor', 'spywarecarrier',
            'spywareconductor', 'spywarefacilitator', 'spywaremediator', 'spywareintermediary',
            'spywarebroker', 'spywareagent', 'spywarerepresentative', 'spywaredelegate',
            'spywareproxy', 'spywarestandin', 'spywaredeputy', 'spywaresubstitute',
            'spywarealternate', 'spywarebackup', 'spywarereserve', 'spywareauxiliary',
            'spywareassistant', 'spywarehelper', 'spywareaid', 'spywaresupport',
            'spywarebackup', 'spywarereserve', 'spywareauxiliary', 'spywareassistant',
            'spywarehelper', 'spywareaid', 'spywaresupport', 'spywarebackup',
            'spywarereserve', 'spywareauxiliary', 'spywareassistant', 'spywarehelper',
            'spywareaid', 'spywaresupport', 'spywarebackup', 'spywarereserve',
            'spywareauxiliary', 'spywareassistant', 'spywarehelper', 'spywareaid',
            'spywaresupport', 'spywarebackup', 'spywarereserve', 'spywareauxiliary',
            'spywareassistant', 'spywarehelper', 'spywareaid', 'spywaresupport'
        }
        
        def is_safe_for_sudo(cmd: str) -> bool:
            """Prüft ob ein Befehl sicher mit Sudo ausgeführt werden kann"""
            cmd_parts = cmd.strip().split()
            if not cmd_parts:
                return False
            
            base_command = cmd_parts[0].lower()
            
            # Gefährliche Befehle niemals mit Sudo
            if base_command in DANGEROUS_COMMANDS:
                return False
            
            # Sichere Befehle dürfen mit Sudo
            if base_command in SUDO_SAFE_COMMANDS:
                return True
            
            # Spezielle Prüfungen für komplexe Befehle
            cmd_lower = cmd.lower()
            
            # Nur lesende Operationen erlauben
            if any(dangerous in cmd_lower for dangerous in ['rm ', 'del ', 'delete ', 'remove ', 'unlink ']):
                return False
            
            # Systemctl nur für Status-Abfragen
            if 'systemctl' in cmd_lower and not any(safe in cmd_lower for safe in ['status', 'is-active', 'is-enabled', 'list-units', 'list-unit-files']):
                return False
            
            # Docker nur für lesende Befehle
            if 'docker' in cmd_lower and any(dangerous in cmd_lower for dangerous in ['rm ', 'rmi ', 'prune ', 'kill ', 'stop ']):
                return False
            
            # Kubernetes nur für lesende Befehle
            if 'kubectl' in cmd_lower and any(dangerous in cmd_lower for dangerous in ['delete ', 'scale ', 'patch ', 'apply ', 'create ']):
                return False
            
            return False  # Im Zweifelsfall sicher sein
        
        def execute_with_ssh(cmd: str) -> tuple[Optional[str], int, str]:
            """Führt einen Befehl über SSH aus und gibt Ergebnis, Exit-Code und Fehlermeldung zurück"""
            try:
                ssh_cmd = ['ssh', '-o', 'ConnectTimeout=10', self.ssh_connection_string]
                
                if self.key_file:
                    ssh_cmd.extend(['-i', self.key_file])
                if self.port != 22:
                    ssh_cmd.extend(['-p', str(self.port)])
                
                ssh_cmd.append(cmd)
                
                result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
                return result.stdout.strip(), result.returncode, result.stderr.strip()
                
            except subprocess.TimeoutExpired:
                return None, -1, "Timeout"
            except Exception as e:
                return None, -1, str(e)
        
        # Erste Ausführung ohne Sudo
        if not force_sudo:
            output, exit_code, error_msg = execute_with_ssh(command)
            
            if exit_code == 0:
                return output
            
            # Bei Permission-Denied prüfen ob Sudo verfügbar und sicher
            if ('permission denied' in error_msg.lower() or 'cannot open' in error_msg.lower()) and is_safe_for_sudo(command):
                # Prüfe ob Sudo verfügbar ist
                sudo_check, sudo_exit, _ = execute_with_ssh('which sudo')
                if sudo_exit == 0:
                    # Prüfe ob Sudo ohne Passwort funktioniert
                    sudo_test, sudo_test_exit, _ = execute_with_ssh('sudo -n true')
                    if sudo_test_exit == 0:
                        # Führe Befehl mit Sudo aus
                        sudo_output, sudo_exit_code, sudo_error = execute_with_ssh(f'sudo {command}')
                        if sudo_exit_code == 0:
                            return sudo_output
                        else:
                            # Sudo hat auch nicht funktioniert, analysiere Fehler
                            self._analyze_error(f'sudo {command}', sudo_exit_code, sudo_error)
                            return None
                    else:
                        # Sudo benötigt Passwort - nicht automatisch verwenden
                        self._analyze_error(command, exit_code, error_msg)
                        return None
                else:
                    # Sudo nicht verfügbar
                    self._analyze_error(command, exit_code, error_msg)
                    return None
            else:
                # Kein Permission-Denied oder unsicherer Befehl
                self._analyze_error(command, exit_code, error_msg)
                return None
        
        # Direkte Sudo-Ausführung (nur wenn explizit angefordert und sicher)
        elif force_sudo and is_safe_for_sudo(command):
            sudo_output, sudo_exit_code, sudo_error = execute_with_ssh(f'sudo {command}')
            if sudo_exit_code == 0:
                return sudo_output
            else:
                self._analyze_error(f'sudo {command}', sudo_exit_code, sudo_error)
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
            console.print("   [green]💡 Automatische Sudo-Prüfung aktiviert - sichere Befehle werden automatisch mit erhöhten Rechten ausgeführt.[/green]")
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
        
        # 4.5. CVE-Sicherheitsanalyse (falls gewünscht)
        # Diese wird später in main() aufgerufen, wenn --with-cve Flag gesetzt ist
        
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
        
        # 8. Proxmox-Analyse (falls verfügbar)
        proxmox_info = self._analyze_proxmox()
        system_info.update(proxmox_info)
        
        # 9. Docker-Analyse (falls verfügbar)
        docker_info = self._analyze_docker()
        system_info.update(docker_info)
        
        # 10. Mailserver-Analyse (falls verfügbar)
        mailserver_info = self._analyze_mailservers()
        system_info.update(mailserver_info)
        
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
    
    def _analyze_cve_vulnerabilities(self, system_info: Dict[str, Any], cve_database: str = 'hybrid', 
                                   enable_cache: bool = True, offline_only: bool = False) -> Dict[str, Any]:
        """Analysiert CVE-Sicherheitslücken für installierte Services"""
        cve_info = {}
        
        console.print("[dim]🔍 Analysiere CVE-Sicherheitslücken...[/dim]")
        
        try:
            # Sammle installierte Pakete und deren Versionen
            installed_packages = {}
            
            # Debian/Ubuntu Pakete
            if system_info.get('distribution', '').lower() in ['debian', 'ubuntu']:
                packages_output = self.execute_remote_command('dpkg -l | grep "^ii" | head -100')
                if packages_output:
                    for line in packages_output.strip().split('\n'):
                        if line.startswith('ii'):
                            parts = line.split()
                            if len(parts) >= 3:
                                package_name = parts[1]
                                version = parts[2]
                                installed_packages[package_name] = version
            
            # RHEL/CentOS Pakete
            elif system_info.get('distribution', '').lower() in ['red hat', 'centos', 'fedora']:
                packages_output = self.execute_remote_command('rpm -qa --queryformat="%{NAME} %{VERSION}-%{RELEASE}\n" | head -100')
                if packages_output:
                    for line in packages_output.strip().split('\n'):
                        if ' ' in line:
                            package_name, version = line.split(' ', 1)
                            installed_packages[package_name] = version
            
            # Fallback: Versuche direkte Service-Versions-Erkennung
            if not installed_packages:
                console.print("[dim]⚠️ Paket-Erkennung fehlgeschlagen - verwende direkte Service-Erkennung[/dim]")
                
                # Docker-Version direkt prüfen
                docker_version = self.execute_remote_command('docker --version 2>/dev/null')
                if docker_version:
                    import re
                    version_match = re.search(r'Docker version (\d+\.\d+\.\d+)', docker_version)
                    if version_match:
                        installed_packages['docker'] = version_match.group(1)
                
                # SSH-Version direkt prüfen
                ssh_version = self.execute_remote_command('sshd -V 2>&1 | head -1')
                if ssh_version and 'OpenSSH' in ssh_version:
                    import re
                    version_match = re.search(r'OpenSSH_(\d+\.\d+)', ssh_version)
                    if version_match:
                        installed_packages['sshd'] = version_match.group(1)
                
                # Kubernetes-Version direkt prüfen
                k8s_version = self.execute_remote_command('kubectl version --client --short 2>/dev/null')
                if k8s_version:
                    import re
                    version_match = re.search(r'v(\d+\.\d+\.\d+)', k8s_version)
                    if version_match:
                        installed_packages['kubernetes'] = version_match.group(1)
            
            # Wichtige Services für CVE-Check
            important_services = [
                'openssh-server', 'apache2', 'nginx', 'mysql-server', 'postgresql',
                'docker', 'containerd', 'kubernetes', 'kubectl', 'kubelet',
                'proxmox', 'mailcow', 'postfix', 'dovecot', 'exim4'
            ]
            
            # Sammle Service-Versionen aus installierten Paketen
            service_versions = {}
            for service in important_services:
                if service in installed_packages:
                    service_versions[service] = installed_packages[service]
            
            # Sammle zusätzliche Service-Versionen aus laufenden Services
            running_services = system_info.get('running_services', {})
            
            # Füge Docker-Version hinzu, falls verfügbar
            if 'docker' in system_info and system_info['docker']['detected']:
                docker_info = system_info['docker']
                if 'version' in docker_info:
                    service_versions['docker'] = docker_info['version']
                    running_services['docker'] = f"Docker {docker_info['version']}"
            
            # Füge SSH-Version hinzu
            ssh_version = self.execute_remote_command("sshd -V 2>&1 | head -1")
            if ssh_version and 'OpenSSH' in ssh_version:
                import re
                version_match = re.search(r'OpenSSH_(\d+\.\d+)', ssh_version)
                if version_match:
                    service_versions['sshd'] = version_match.group(1)
                    running_services['sshd'] = f"OpenSSH {version_match.group(1)}"
            
            # Füge Kubernetes-Version hinzu, falls verfügbar
            if 'kubernetes' in system_info and system_info['kubernetes']['detected']:
                k8s_info = system_info['kubernetes']
                if 'version' in k8s_info:
                    service_versions['kubernetes'] = k8s_info['version']
                    running_services['kubernetes'] = f"Kubernetes {k8s_info['version']}"
            
            # Füge weitere wichtige Services hinzu
            additional_services = {
                'containerd': 'containerd',
                'rsyslog': 'rsyslog',
                'cron': 'cron',
                'systemd': 'systemd'
            }
            
            for service_name, package_name in additional_services.items():
                if package_name in installed_packages:
                    service_versions[service_name] = installed_packages[package_name]
                    running_services[service_name] = f"{service_name} {installed_packages[package_name]}"
            
            # Debug-Ausgabe für Service-Versions-Erkennung
            console.print(f"[dim]🔍 Gefundene Service-Versionen: {len(service_versions)}[/dim]")
            for service, version in service_versions.items():
                console.print(f"[dim]  • {service}: {version}[/dim]")
            
            # CVE-Analyse basierend auf gewählter Datenbank
            if cve_database == 'nvd' or cve_database == 'hybrid' or cve_database == 'hybrid-european':
                # Verwende echte CVE-Datenbanken
                cve_info.update(self._perform_nvd_cve_analysis(service_versions, enable_cache, offline_only))
            
            if cve_database == 'ollama' or cve_database == 'hybrid' or cve_database == 'hybrid-european':
                # Verwende Ollama für zusätzliche Analyse
                cve_info.update(self._perform_ollama_cve_analysis(service_versions, running_services, system_info))
            
            if cve_database == 'european' or cve_database == 'hybrid-european':
                # Verwende europäische CVE-Datenbanken
                cve_info.update(self._perform_european_cve_analysis(service_versions, enable_cache, offline_only))
            
            # Speichere Basis-Informationen
            cve_info['service_versions'] = service_versions
            cve_info['running_services'] = running_services
            cve_info['installed_packages_count'] = len(installed_packages)
            cve_info['cve_database_used'] = cve_database
            
        except Exception as e:
            console.print(f"[yellow]⚠️  Fehler bei CVE-Analyse: {str(e)[:100]}[/yellow]")
            cve_info['error'] = str(e)
        
        return cve_info
    
    def _perform_nvd_cve_analysis(self, service_versions: Dict[str, str], enable_cache: bool, offline_only: bool) -> Dict[str, Any]:
        """Führt CVE-Analyse mit NIST NVD durch"""
        try:
            # Importiere CVE-Datenbank-Checker
            from cve_database_checker import CVEAnalyzer, create_cve_report_content
            
            # Erstelle CVE-Analyzer
            analyzer = CVEAnalyzer(enable_cache=enable_cache)
            
            # Führe Analyse durch
            nvd_results = analyzer.analyze_services(service_versions)
            
            # Erstelle formatierten Report
            nvd_report = create_cve_report_content(nvd_results)
            
            return {
                'nvd_analysis': nvd_results,
                'nvd_report': nvd_report,
                'database_results': nvd_results.get('database_results', {}),
                'database_summary': nvd_results.get('summary', {})
            }
            
        except ImportError:
            console.print("[yellow]⚠️ CVE-Datenbank-Modul nicht verfügbar - verwende nur Ollama[/yellow]")
            return {}
        except Exception as e:
            console.print(f"[yellow]⚠️ Fehler bei NVD-Analyse: {str(e)[:100]}[/yellow]")
            return {}
    
    def _perform_european_cve_analysis(self, service_versions: Dict[str, str], enable_cache: bool, offline_only: bool) -> Dict[str, Any]:
        """Führt CVE-Analyse mit europäischen Datenbanken durch"""
        try:
            # Importiere europäischen CVE-Datenbank-Checker
            from european_cve_checker import EuropeanCVEAnalyzer, create_european_cve_report_content
            
            # Erstelle europäischen CVE-Analyzer
            analyzer = EuropeanCVEAnalyzer()
            
            # Führe europäische Analyse durch
            european_results = analyzer.analyze_european_cves(service_versions)
            
            # Erstelle formatierten europäischen Report
            european_report = create_european_cve_report_content(european_results)
            
            return {
                'european_analysis': european_results,
                'european_report': european_report,
                'european_results': european_results.get('results', {}),
                'european_summary': european_results.get('summary', {})
            }
            
        except ImportError:
            console.print("[yellow]⚠️ Europäisches CVE-Modul nicht verfügbar[/yellow]")
            return {}
        except Exception as e:
            console.print(f"[yellow]⚠️ Fehler bei europäischer CVE-Analyse: {str(e)[:100]}[/yellow]")
            return {}
    
    def _perform_ollama_cve_analysis(self, service_versions: Dict[str, str], running_services: Dict[str, str], system_info: Dict[str, Any]) -> Dict[str, Any]:
        """Führt CVE-Analyse mit Ollama durch"""
        try:
            # Erstelle CVE-Analyse-Prompt für Ollama
            cve_prompt = self._create_cve_analysis_prompt(service_versions, running_services, system_info)
            
            # Führe CVE-Analyse mit Ollama durch
            if cve_prompt:
                cve_analysis = self._perform_cve_analysis_with_ollama(cve_prompt)
                if cve_analysis:
                    return {
                        'ollama_analysis': cve_analysis,
                        'ollama_prompt': cve_prompt
                    }
            
            return {}
            
        except Exception as e:
            console.print(f"[yellow]⚠️ Fehler bei Ollama-Analyse: {str(e)[:100]}[/yellow]")
            return {}
    
    def _create_cve_analysis_prompt(self, service_versions: Dict[str, str], running_services: Dict[str, str], system_info: Dict[str, Any]) -> str:
        """Erstellt einen Prompt für die CVE-Analyse mit Ollama"""
        
        prompt = f"""Du bist ein IT-Sicherheitsexperte und CVE-Spezialist. Analysiere die folgenden installierten Services und deren Versionen auf bekannte Sicherheitslücken (CVEs).

SYSTEM-INFORMATIONEN:
- Distribution: {system_info.get('distribution', 'Unbekannt')}
- Kernel: {system_info.get('kernel', 'Unbekannt')}
- Architektur: {system_info.get('architecture', 'Unbekannt')}

INSTALLIERTE SERVICE-VERSIONEN:
"""
        
        for service, version in service_versions.items():
            prompt += f"- {service}: {version}\n"
        
        prompt += f"""
LAUFENDE SERVICES:
"""
        
        for service, status in running_services.items():
            prompt += f"- {service}: {status}\n"
        
        prompt += """
AUFGABE:
1. Identifiziere bekannte CVEs für die installierten Services
2. Bewerte die Schwere der Sicherheitslücken (Critical, High, Medium, Low)
3. Prüfe ob Updates verfügbar sind
4. Gib konkrete Handlungsempfehlungen

ANTWORTE IM FOLGENDEN FORMAT:

## CVE-SICHERHEITSANALYSE

### KRITISCHE SICHERHEITSLÜCKEN (Critical)
- [Service] [CVE-ID]: [Beschreibung] - [Empfehlung]

### HOHE SICHERHEITSLÜCKEN (High)
- [Service] [CVE-ID]: [Beschreibung] - [Empfehlung]

### MITTLERE SICHERHEITSLÜCKEN (Medium)
- [Service] [CVE-ID]: [Beschreibung] - [Empfehlung]

### NIEDRIGE SICHERHEITSLÜCKEN (Low)
- [Service] [CVE-ID]: [Beschreibung] - [Empfehlung]

### UPDATE-EMPFEHLUNGEN
- [Service]: [Aktuelle Version] → [Empfohlene Version]

### SICHERHEITSZUSAMMENFASSUNG
- Anzahl kritische CVEs: [X]
- Anzahl hohe CVEs: [X]
- Anzahl mittlere CVEs: [X]
- Anzahl niedrige CVEs: [X]
- Gesamtrisiko: [Critical/High/Medium/Low]

### SOFORTIGE MASSNAHMEN
1. [Konkrete Maßnahme 1]
2. [Konkrete Maßnahme 2]
3. [Konkrete Maßnahme 3]

Verwende nur aktuelle und verifizierte CVE-Informationen. Wenn keine spezifischen CVEs bekannt sind, gib das an."""
        
        return prompt
    
    def _perform_cve_analysis_with_ollama(self, cve_prompt: str) -> Optional[str]:
        """Führt die CVE-Analyse mit Ollama durch"""
        
        try:
            # Importiere die query_ollama Funktion
            from ssh_chat_system import query_ollama, select_best_model
            
            # Wähle bestes Modell für CVE-Analyse
            model = select_best_model(complex_analysis=True, for_menu=False)
            
            # Führe CVE-Analyse durch
            cve_analysis = query_ollama(cve_prompt, model=model, complex_analysis=True)
            
            return cve_analysis
            
        except Exception as e:
            console.print(f"[yellow]⚠️  Fehler bei Ollama CVE-Analyse: {str(e)[:100]}[/yellow]")
            return None
    
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
    
    def _analyze_proxmox(self) -> Dict[str, Any]:
        """Analysiert Proxmox VE, falls verfügbar"""
        proxmox_info = {}
        
        # Prüfe ob Proxmox verfügbar ist
        proxmox_check = self.execute_remote_command('which pvesh')
        if not proxmox_check:
            return proxmox_info
        
        # Verwende Fortschrittsanzeige für Proxmox-Analyse
        with ProgressTracker("🖥️  Analysiere Proxmox VE", total_steps=15) as progress:
            try:
                # Proxmox-Version
                progress.update(1, "📋 Prüfe Proxmox-Version...")
                version = self.execute_remote_command('pveversion -v')
                if version:
                    proxmox_info['proxmox_version'] = version
                
                # Cluster-Status
                progress.update(1, "🔗 Prüfe Cluster-Status...")
                cluster_status = self.execute_remote_command('pvesh get /cluster/status')
                if cluster_status:
                    proxmox_info['cluster_status'] = cluster_status
                
                # Nodes
                progress.update(1, "🖥️  Lade Node-Liste...")
                nodes = self.execute_remote_command('pvesh get /nodes')
                if nodes:
                    proxmox_info['nodes'] = nodes
                
                # Node-Details (erste 3 Nodes)
                node_details = {}
                for i in range(3):  # Prüfe erste 3 Nodes
                    progress.update(1, f"📊 Analysiere Node {i+1}/3...")
                    node_name = self.execute_remote_command(f'pvesh get /nodes | grep -o "node[0-9]*" | head -{i+1} | tail -1')
                    if node_name:
                        node_name = node_name.strip()
                        # Node-Status
                        status = self.execute_remote_command(f'pvesh get /nodes/{node_name}/status')
                        if status:
                            node_details[f'{node_name}_status'] = status
                        
                        # VMs auf diesem Node
                        vms = self.execute_remote_command(f'pvesh get /nodes/{node_name}/qemu')
                        if vms:
                            node_details[f'{node_name}_vms'] = vms
                        
                        # Container auf diesem Node
                        containers = self.execute_remote_command(f'pvesh get /nodes/{node_name}/lxc')
                        if containers:
                            node_details[f'{node_name}_containers'] = containers
                
                if node_details:
                    proxmox_info['node_details'] = node_details
                
                # Storage-Informationen
                progress.update(1, "💾 Prüfe Storage-Status...")
                storage = self.execute_remote_command('pvesh get /storage')
                if storage:
                    proxmox_info['storage'] = storage
                
                # Netzwerk-Informationen
                progress.update(1, "🌐 Prüfe Netzwerk-Konfiguration...")
                network = self.execute_remote_command('pvesh get /cluster/config')
                if network:
                    proxmox_info['network_config'] = network
                
                # Probleme identifizieren
                progress.update(1, "🔍 Suche nach Problemen...")
                problems = []
                
                # Prüfe auf nicht-online Nodes
                offline_nodes = self.execute_remote_command('pvesh get /nodes | grep -v "online"')
                if offline_nodes:
                    problems.append(f"Offline Nodes:\n{offline_nodes}")
                
                # Prüfe auf gestoppte VMs
                stopped_vms = self.execute_remote_command('pvesh get /nodes --output-format=json | jq -r ".[] | .node" | head -3 | while read node; do pvesh get /nodes/$node/qemu --output-format=json | jq -r ".[] | select(.status != \"running\") | .name" 2>/dev/null; done')
                if stopped_vms:
                    problems.append(f"Gestoppte VMs:\n{stopped_vms}")
                
                # Prüfe auf gestoppte Container
                stopped_containers = self.execute_remote_command('pvesh get /nodes --output-format=json | jq -r ".[] | .node" | head -3 | while read node; do pvesh get /nodes/$node/lxc --output-format=json | jq -r ".[] | select(.status != \"running\") | .name" 2>/dev/null; done')
                if stopped_containers:
                    problems.append(f"Gestoppte Container:\n{stopped_containers}")
                
                # Prüfe auf Storage-Probleme
                storage_problems = self.execute_remote_command('pvesh get /storage | grep -i "error\|failed\|unavailable"')
                if storage_problems:
                    problems.append(f"Storage-Probleme:\n{storage_problems}")
                
                # Prüfe auf Backup-Status
                progress.update(1, "💾 Prüfe Backup-Status...")
                backup_status = self.execute_remote_command('pvesh get /nodes --output-format=json | jq -r ".[] | .node" | head -3 | while read node; do pvesh get /nodes/$node/tasks --output-format=json | jq -r ".[] | select(.type == \"vzdump\") | select(.status != \"OK\") | .id" 2>/dev/null; done')
                if backup_status:
                    problems.append(f"Backup-Probleme:\n{backup_status}")
                
                # Prüfe auf Ressourcen-Auslastung
                progress.update(1, "📊 Analysiere Ressourcen-Auslastung...")
                resource_usage = self.execute_remote_command('pvesh get /nodes --output-format=json | jq -r ".[] | .node" | head -3 | while read node; do echo "=== $node ==="; pvesh get /nodes/$node/status --output-format=json | jq -r ".cpuinfo | .cpus, .model" 2>/dev/null; pvesh get /nodes/$node/status --output-format=json | jq -r ".memory | .total, .used, .free" 2>/dev/null; done')
                if resource_usage:
                    proxmox_info['resource_usage'] = resource_usage
                
                # Prüfe auf HA-Status (falls verfügbar)
                progress.update(1, "🔄 Prüfe HA-Status...")
                ha_status = self.execute_remote_command('pvesh get /cluster/ha/status')
                if ha_status:
                    proxmox_info['ha_status'] = ha_status
                    
                    # Prüfe auf HA-Probleme
                    ha_problems = self.execute_remote_command('pvesh get /cluster/ha/status | grep -i "error\|failed\|stopped"')
                    if ha_problems:
                        problems.append(f"HA-Probleme:\n{ha_problems}")
                
                # Prüfe auf ZFS-Status (falls verwendet)
                progress.update(1, "💾 Prüfe ZFS-Status...")
                zfs_status = self.execute_remote_command('zpool status')
                if zfs_status:
                    proxmox_info['zfs_status'] = zfs_status
                    
                    # Prüfe auf ZFS-Probleme
                    zfs_problems = self.execute_remote_command('zpool status | grep -i "degraded\|faulted\|offline"')
                    if zfs_problems:
                        problems.append(f"ZFS-Probleme:\n{zfs_problems}")
                
                # Prüfe auf Ceph-Status (falls verwendet)
                progress.update(1, "🔄 Prüfe Ceph-Status...")
                ceph_status = self.execute_remote_command('ceph status')
                if ceph_status:
                    proxmox_info['ceph_status'] = ceph_status
                    
                    # Prüfe auf Ceph-Probleme
                    ceph_problems = self.execute_remote_command('ceph status | grep -i "health\|error\|warning"')
                    if ceph_problems:
                        problems.append(f"Ceph-Probleme:\n{ceph_problems}")
                
                # Speichere identifizierte Probleme
                if problems:
                    proxmox_info['problems'] = problems
                    proxmox_info['problems_count'] = len(problems)
                
                # Prüfe auf Proxmox-Tools
                progress.update(1, "🔧 Prüfe Proxmox-Tools...")
                tools_check = {}
                tools = ['qm', 'pct', 'pvesm', 'pveceph']
                for tool in tools:
                    tool_path = self.execute_remote_command(f'which {tool}')
                    if tool_path:
                        tools_check[tool] = True
                
                if tools_check:
                    proxmox_info['available_tools'] = tools_check
                
                if proxmox_info:
                    proxmox_info['proxmox_detected'] = True
                    console.print("[green]✅ Proxmox VE gefunden und analysiert[/green]")
                else:
                    console.print("[yellow]⚠️  pvesh verfügbar, aber keine Proxmox-Daten erreichbar[/yellow]")
                    
            except Exception as e:
                console.print(f"[yellow]⚠️  Fehler bei Proxmox-Analyse: {str(e)[:100]}[/yellow]")
        
        return proxmox_info

    def _analyze_docker(self) -> Dict[str, Any]:
        """Analysiert Docker, falls verfügbar"""
        docker_info = {}
        
        # Prüfe ob Docker verfügbar ist
        docker_check = self.execute_remote_command('which docker')
        if not docker_check:
            return docker_info
        
        console.print("[dim]🐳 Analysiere Docker...[/dim]")
        
        try:
            # Docker-Version
            version = self.execute_remote_command('docker --version')
            if version:
                docker_info['docker_version'] = version
            
            # Docker-Info
            info = self.execute_remote_command('docker info')
            if info:
                docker_info['docker_info'] = info
            
            # Laufende Container
            running_containers = self.execute_remote_command('docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"')
            if running_containers:
                docker_info['running_containers'] = running_containers
            
            # Alle Container (auch gestoppte)
            all_containers = self.execute_remote_command('docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.CreatedAt}}"')
            if all_containers:
                docker_info['all_containers'] = all_containers
            
            # Docker-Images
            images = self.execute_remote_command('docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"')
            if images:
                docker_info['images'] = images
            
            # Docker-Volumes
            volumes = self.execute_remote_command('docker volume ls --format "table {{.Name}}\t{{.Driver}}"')
            if volumes:
                docker_info['volumes'] = volumes
            
            # Docker-Netzwerke
            networks = self.execute_remote_command('docker network ls --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"')
            if networks:
                docker_info['networks'] = networks
            
            # Docker-System-Info
            system_info = self.execute_remote_command('docker system df')
            if system_info:
                docker_info['system_usage'] = system_info
            
            # DETAILLIERTE CONTAINER-ANALYSE
            console.print("[dim]🔍 Analysiere Container-Details...[/dim]")
            
            # Hole alle laufenden Container-Namen
            running_container_names = self.execute_remote_command('docker ps --format "{{.Names}}"')
            if running_container_names and running_container_names.strip():
                container_names = [name.strip() for name in running_container_names.split('\n') if name.strip()]
                
                container_details = {}
                container_stats = {}
                container_problems = []
                
                for container_name in container_names:
                    console.print(f"[dim]📊 Analysiere Container: {container_name}[/dim]")
                    
                    # Container-Inspect (detaillierte Informationen)
                    inspect_cmd = f'docker inspect {container_name}'
                    inspect_result = self.execute_remote_command(inspect_cmd)
                    if inspect_result:
                        container_details[container_name] = {
                            'inspect': inspect_result,
                            'name': container_name
                        }
                    
                    # Container-Logs (letzte 50 Zeilen)
                    logs_cmd = f'docker logs --tail 50 {container_name} 2>&1'
                    logs_result = self.execute_remote_command(logs_cmd)
                    if logs_result:
                        container_details[container_name]['logs'] = logs_result
                        
                        # Analysiere Logs auf Fehler
                        error_lines = []
                        warning_lines = []
                        for line in logs_result.split('\n'):
                            line_lower = line.lower()
                            if any(error_word in line_lower for error_word in ['error', 'fatal', 'failed', 'exception', 'panic']):
                                error_lines.append(line.strip())
                            elif any(warning_word in line_lower for warning_word in ['warn', 'warning', 'deprecated']):
                                warning_lines.append(line.strip())
                        
                        if error_lines:
                            container_details[container_name]['errors'] = error_lines[-10:]  # Letzte 10 Fehler
                        if warning_lines:
                            container_details[container_name]['warnings'] = warning_lines[-10:]  # Letzte 10 Warnungen
                    
                    # Container-Statistiken
                    stats_cmd = f'docker stats {container_name} --no-stream --format "table {{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}"'
                    stats_result = self.execute_remote_command(stats_cmd)
                    if stats_result:
                        container_stats[container_name] = stats_result
                    
                    # Container-Health-Check
                    health_cmd = f'docker inspect {container_name} --format "{{{{.State.Health.Status}}}}"'
                    health_result = self.execute_remote_command(health_cmd)
                    if health_result and health_result.strip():
                        container_details[container_name]['health_status'] = health_result.strip()
                        
                        # Wenn Health-Check fehlschlägt, hole Details
                        if 'unhealthy' in health_result.lower():
                            health_logs_cmd = f'docker inspect {container_name} --format "{{{{range .State.Health.Log}}}}{{.Output}}{{end}}"'
                            health_logs = self.execute_remote_command(health_logs_cmd)
                            if health_logs:
                                container_details[container_name]['health_logs'] = health_logs
                                container_problems.append(f"Container {container_name}: Health-Check fehlgeschlagen")
                    
                    # Container-Restart-Policy
                    restart_cmd = f'docker inspect {container_name} --format "{{{{.HostConfig.RestartPolicy.Name}}}}"'
                    restart_result = self.execute_remote_command(restart_cmd)
                    if restart_result:
                        container_details[container_name]['restart_policy'] = restart_result.strip()
                    
                    # Container-Uptime
                    uptime_cmd = f'docker inspect {container_name} --format "{{{{.State.StartedAt}}}}"'
                    uptime_result = self.execute_remote_command(uptime_cmd)
                    if uptime_result:
                        container_details[container_name]['started_at'] = uptime_result.strip()
                    
                    # Container-Exit-Code (falls gestoppt)
                    exit_code_cmd = f'docker inspect {container_name} --format "{{{{.State.ExitCode}}}}"'
                    exit_code_result = self.execute_remote_command(exit_code_cmd)
                    if exit_code_result and exit_code_result.strip() != '0':
                        container_details[container_name]['exit_code'] = exit_code_result.strip()
                        if exit_code_result.strip() != '0':
                            container_problems.append(f"Container {container_name}: Exit-Code {exit_code_result.strip()}")
                
                # Speichere Container-Details
                if container_details:
                    docker_info['container_details'] = container_details
                if container_stats:
                    docker_info['container_stats'] = container_stats
            
            # ERWEITERTE PROBLEM-ERKENNUNG
            problems = []
            
            # Prüfe auf gestoppte Container
            stopped_containers = self.execute_remote_command('docker ps -a --filter "status=exited" --format "{{.Names}}\t{{.Status}}\t{{.ExitCode}}"')
            if stopped_containers and stopped_containers.strip():
                stopped_lines = stopped_containers.strip().split('\n')
                for line in stopped_lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            name, status, exit_code = parts[0], parts[1], parts[2]
                            if exit_code != '0':
                                problems.append(f"Gestoppter Container mit Fehler: {name} (Exit-Code: {exit_code})")
                            else:
                                problems.append(f"Gestoppter Container: {name} ({status})")
            
            # Prüfe auf Container mit hoher CPU/Memory-Nutzung
            high_usage_containers = self.execute_remote_command('docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemPerc}}" | tail -n +2')
            if high_usage_containers:
                for line in high_usage_containers.strip().split('\n'):
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            name, cpu_perc, mem_perc = parts[0], parts[1], parts[2]
                            try:
                                cpu_val = float(cpu_perc.replace('%', ''))
                                mem_val = float(mem_perc.replace('%', ''))
                                if cpu_val > 80:
                                    problems.append(f"Container {name}: Hohe CPU-Nutzung ({cpu_perc})")
                                if mem_val > 80:
                                    problems.append(f"Container {name}: Hohe Memory-Nutzung ({mem_perc})")
                            except:
                                pass
            
            # Prüfe auf ungenutzte Images
            dangling_images = self.execute_remote_command('docker images -f "dangling=true" --format "{{.Repository}}:{{.Tag}}"')
            if dangling_images and dangling_images.strip():
                problems.append(f"Ungenutzte Images:\n{dangling_images}")
            
            # Prüfe auf ungenutzte Volumes
            unused_volumes = self.execute_remote_command('docker volume ls -q -f dangling=true')
            if unused_volumes and unused_volumes.strip():
                problems.append(f"Ungenutzte Volumes:\n{unused_volumes}")
            
            # Prüfe auf Docker-Daemon-Status
            daemon_status = self.execute_remote_command('systemctl is-active docker')
            if daemon_status and 'inactive' in daemon_status:
                problems.append("Docker-Daemon ist inaktiv")
            
            # Prüfe auf Docker-Daemon-Logs für Fehler
            daemon_logs = self.execute_remote_command('journalctl -u docker --since "1 hour ago" --no-pager | grep -i "error\|fatal\|failed" | tail -10')
            if daemon_logs and daemon_logs.strip():
                problems.append(f"Docker-Daemon-Fehler:\n{daemon_logs}")
            
            # Füge Container-spezifische Probleme hinzu
            problems.extend(container_problems)
            
            # Speichere identifizierte Probleme
            if problems:
                docker_info['problems'] = problems
                docker_info['problems_count'] = len(problems)
            
            if docker_info:
                docker_info['docker_detected'] = True
                console.print("[green]✅ Docker gefunden und detailliert analysiert[/green]")
            else:
                console.print("[yellow]⚠️  Docker verfügbar, aber keine Daten erreichbar[/yellow]")
                
        except Exception as e:
            console.print(f"[yellow]⚠️  Fehler bei Docker-Analyse: {str(e)[:100]}[/yellow]")
        
        return docker_info

    def _analyze_mailservers(self) -> Dict[str, Any]:
        """Analysiert Mailserver (Mailcow, Postfix), falls verfügbar"""
        mailserver_info = {}
        
        console.print("[dim]📧 Analysiere Mailserver...[/dim]")
        
        try:
            # Prüfe auf Mailcow
            mailcow_info = self._analyze_mailcow()
            if mailcow_info:
                mailserver_info['mailcow'] = mailcow_info
                mailserver_info['mailcow_detected'] = True
            
            # Prüfe auf Postfix
            postfix_info = self._analyze_postfix()
            if postfix_info:
                mailserver_info['postfix'] = postfix_info
                mailserver_info['postfix_detected'] = True
            
            # Prüfe auf andere Mailserver
            other_mailservers = self._analyze_other_mailservers()
            if other_mailservers:
                mailserver_info['other_mailservers'] = other_mailservers
            
            if mailserver_info:
                mailserver_info['mailserver_detected'] = True
                console.print("[green]✅ Mailserver gefunden und analysiert[/green]")
            else:
                console.print("[yellow]⚠️  Keine Mailserver erkannt[/yellow]")
                
        except Exception as e:
            console.print(f"[yellow]⚠️  Fehler bei Mailserver-Analyse: {str(e)[:100]}[/yellow]")
        
        return mailserver_info

    def _analyze_mailcow(self) -> Dict[str, Any]:
        """Analysiert Mailcow, falls verfügbar"""
        mailcow_info = {}
        
        # Prüfe auf Mailcow-Installation
        mailcow_check = self.execute_remote_command('ls -la /opt/mailcow-dockerized/')
        if not mailcow_check:
            return mailcow_info
        
        console.print("[dim]📧 Analysiere Mailcow...[/dim]")
        
        try:
            # Mailcow-Konfiguration
            config = self.execute_remote_command('cat /opt/mailcow-dockerized/mailcow.conf 2>/dev/null')
            if config:
                mailcow_info['config'] = config
            
            # Mailcow-Status
            status = self.execute_remote_command('cd /opt/mailcow-dockerized && docker-compose ps')
            if status:
                mailcow_info['status'] = status
            
            # Mailcow-Logs (letzte 50 Zeilen)
            logs = self.execute_remote_command('cd /opt/mailcow-dockerized && docker-compose logs --tail=50')
            if logs:
                mailcow_info['recent_logs'] = logs
            
            # Mailcow-Container
            containers = self.execute_remote_command('cd /opt/mailcow-dockerized && docker-compose ps --format "table {{.Name}}\t{{.State}}\t{{.Ports}}"')
            if containers:
                mailcow_info['containers'] = containers
            
            # Mailcow-Version
            version = self.execute_remote_command('cd /opt/mailcow-dockerized && git describe --tags --abbrev=0 2>/dev/null')
            if version:
                mailcow_info['version'] = version
            
            # Probleme identifizieren
            problems = []
            
            # Prüfe auf gestoppte Container
            stopped_containers = self.execute_remote_command('cd /opt/mailcow-dockerized && docker-compose ps | grep -v "Up"')
            if stopped_containers and 'Up' not in stopped_containers:
                problems.append(f"Gestoppte Mailcow-Container:\n{stopped_containers}")
            
            # Prüfe auf Fehler in Logs
            error_logs = self.execute_remote_command('cd /opt/mailcow-dockerized && docker-compose logs --tail=100 | grep -i "error\|failed\|exception"')
            if error_logs:
                problems.append(f"Fehler in Mailcow-Logs:\n{error_logs}")
            
            # Prüfe auf Speicherplatz
            disk_usage = self.execute_remote_command('df -h /opt/mailcow-dockerized/')
            if disk_usage:
                mailcow_info['disk_usage'] = disk_usage
            
            # Speichere identifizierte Probleme
            if problems:
                mailcow_info['problems'] = problems
                mailcow_info['problems_count'] = len(problems)
            
            if mailcow_info:
                mailcow_info['mailcow_detected'] = True
                console.print("[green]✅ Mailcow gefunden und analysiert[/green]")
                
        except Exception as e:
            console.print(f"[yellow]⚠️  Fehler bei Mailcow-Analyse: {str(e)[:100]}[/yellow]")
        
        return mailcow_info

    def _analyze_postfix(self) -> Dict[str, Any]:
        """Analysiert Postfix, falls verfügbar"""
        postfix_info = {}
        
        # Prüfe ob Postfix verfügbar ist
        postfix_check = self.execute_remote_command('which postfix')
        if not postfix_check:
            return postfix_info
        
        console.print("[dim]📧 Analysiere Postfix...[/dim]")
        
        try:
            # Postfix-Version
            version = self.execute_remote_command('postconf -d | grep mail_version')
            if version:
                postfix_info['version'] = version
            
            # Postfix-Status
            status = self.execute_remote_command('systemctl status postfix')
            if status:
                postfix_info['status'] = status
            
            # Postfix-Konfiguration
            config = self.execute_remote_command('postconf -n')
            if config:
                postfix_info['config'] = config
            
            # Postfix-Queue-Status
            queue_status = self.execute_remote_command('mailq')
            if queue_status:
                postfix_info['queue_status'] = queue_status
            
            # Postfix-Logs (letzte 50 Zeilen)
            logs = self.execute_remote_command('tail -50 /var/log/mail.log 2>/dev/null || tail -50 /var/log/maillog 2>/dev/null')
            if logs:
                postfix_info['recent_logs'] = logs
            
            # Postfix-Statistiken
            stats = self.execute_remote_command('postconf -d | grep -E "(mynetworks|mydomain|myhostname)"')
            if stats:
                postfix_info['network_config'] = stats
            
            # Probleme identifizieren
            problems = []
            
            # Prüfe auf Postfix-Service-Status
            service_status = self.execute_remote_command('systemctl is-active postfix')
            if service_status and 'inactive' in service_status:
                problems.append("Postfix-Service ist inaktiv")
            
            # Prüfe auf Queue-Probleme
            queue_count = self.execute_remote_command('mailq | grep -c "^[A-F0-9]"')
            if queue_count and int(queue_count.strip()) > 10:
                problems.append(f"Viele E-Mails in Queue: {queue_count.strip()}")
            
            # Prüfe auf Fehler in Logs
            error_logs = self.execute_remote_command('tail -100 /var/log/mail.log 2>/dev/null | grep -i "error\|failed\|reject" | tail -10')
            if error_logs:
                problems.append(f"Fehler in Postfix-Logs:\n{error_logs}")
            
            # Prüfe auf Spam/Blacklist-Probleme
            spam_logs = self.execute_remote_command('tail -100 /var/log/mail.log 2>/dev/null | grep -i "spam\|blacklist\|blocked" | tail -10')
            if spam_logs:
                problems.append(f"Spam/Blacklist-Probleme:\n{spam_logs}")
            
            # Speichere identifizierte Probleme
            if problems:
                postfix_info['problems'] = problems
                postfix_info['problems_count'] = len(problems)
            
            if postfix_info:
                postfix_info['postfix_detected'] = True
                console.print("[green]✅ Postfix gefunden und analysiert[/green]")
                
        except Exception as e:
            console.print(f"[yellow]⚠️  Fehler bei Postfix-Analyse: {str(e)[:100]}[/yellow]")
        
        return postfix_info

    def _analyze_other_mailservers(self) -> Dict[str, Any]:
        """Analysiert andere Mailserver (Dovecot, Exim, etc.)"""
        other_info = {}
        
        # Prüfe auf Dovecot
        dovecot_check = self.execute_remote_command('which dovecot')
        if dovecot_check:
            dovecot_status = self.execute_remote_command('systemctl status dovecot')
            if dovecot_status:
                other_info['dovecot'] = dovecot_status
        
        # Prüfe auf Exim
        exim_check = self.execute_remote_command('which exim')
        if exim_check:
            exim_status = self.execute_remote_command('systemctl status exim')
            if exim_status:
                other_info['exim'] = exim_status
        
        # Prüfe auf Sendmail
        sendmail_check = self.execute_remote_command('which sendmail')
        if sendmail_check:
            sendmail_status = self.execute_remote_command('systemctl status sendmail')
            if sendmail_status:
                other_info['sendmail'] = sendmail_status
        
        return other_info

    def refresh_proxmox_data(self, target: str = "all") -> Dict[str, Any]:
        """Aktualisiert gezielt Proxmox-Daten per Chat-Befehl"""
        proxmox_info = {}
        
        # Prüfe ob Proxmox verfügbar ist
        proxmox_check = self.execute_remote_command('which pvesh')
        if not proxmox_check:
            return {"error": "Proxmox nicht verfügbar"}
        
        # Berechne Gesamtschritte basierend auf Target
        total_steps = 0
        if target in ["all", "vms", "containers"]:
            total_steps += 10  # Nodes + VMs + Container
        if target in ["all", "storage"]:
            total_steps += 2
        if target in ["all", "cluster"]:
            total_steps += 3
        if target in ["all", "ha"]:
            total_steps += 2
        if target in ["all", "tasks"]:
            total_steps += 4
        if target in ["all", "backups"]:
            total_steps += 4
        
        # Verwende Fortschrittsanzeige
        with ProgressTracker(f"🔄 Aktualisiere Proxmox-Daten: {target}", total_steps=total_steps) as progress:
            try:
                if target in ["all", "vms", "containers"]:
                    # Hole alle Nodes
                    progress.update(1, "📋 Lade Node-Liste...")
                    nodes_json = self.execute_remote_command('pvesh get /nodes --output-format=json')
                    if nodes_json:
                        import json
                        try:
                            nodes_data = json.loads(nodes_json)
                            for node in nodes_data[:3]:  # Erste 3 Nodes
                                node_name = node.get('node', '')
                                if node_name:
                                    progress.update(1, f"📊 Analysiere {node_name}...")
                                    
                                    # VMs
                                    if target in ["all", "vms"]:
                                        vms_data = self.execute_remote_command(f'pvesh get /nodes/{node_name}/qemu --output-format=json')
                                        if vms_data:
                                            proxmox_info[f'{node_name}_vms'] = vms_data
                                    
                                    # Container
                                    if target in ["all", "containers"]:
                                        containers_data = self.execute_remote_command(f'pvesh get /nodes/{node_name}/lxc --output-format=json')
                                        if containers_data:
                                            proxmox_info[f'{node_name}_containers'] = containers_data
                                            
                                            # Detaillierte Container-Informationen
                                            try:
                                                containers_list = json.loads(containers_data)
                                                detailed_containers = {}
                                                for container in containers_list:
                                                    container_id = container.get('vmid', '')
                                                    if container_id:
                                                        # Container-Details
                                                        container_details = self.execute_remote_command(f'pvesh get /nodes/{node_name}/lxc/{container_id}/status/current --output-format=json')
                                                        if container_details:
                                                            detailed_containers[f'container_{container_id}'] = container_details
                                                        
                                                        # Container-Konfiguration
                                                        container_config = self.execute_remote_command(f'pvesh get /nodes/{node_name}/lxc/{container_id}/config --output-format=json')
                                                        if container_config:
                                                            detailed_containers[f'config_{container_id}'] = container_config
                                                        
                                                        # Container-Ressourcen
                                                        container_rrd = self.execute_remote_command(f'pvesh get /nodes/{node_name}/lxc/{container_id}/rrddata --output-format=json')
                                                        if container_rrd:
                                                            detailed_containers[f'rrd_{container_id}'] = container_rrd
                                                
                                                if detailed_containers:
                                                    proxmox_info[f'{node_name}_detailed_containers'] = detailed_containers
                                            except json.JSONDecodeError:
                                                pass
                                    
                                    # Node-Status
                                    if target == "all":
                                        status_data = self.execute_remote_command(f'pvesh get /nodes/{node_name}/status --output-format=json')
                                        if status_data:
                                            proxmox_info[f'{node_name}_status'] = status_data
                        except json.JSONDecodeError:
                            console.print("[yellow]⚠️  Fehler beim Parsen der Node-Daten[/yellow]")
                
                if target in ["all", "storage"]:
                    progress.update(1, "💾 Prüfe Storage-Status...")
                    storage_data = self.execute_remote_command('pvesh get /storage --output-format=json')
                    if storage_data:
                        proxmox_info['storage'] = storage_data
                
                if target in ["all", "cluster"]:
                    progress.update(1, "🔗 Prüfe Cluster-Status...")
                    cluster_data = self.execute_remote_command('pvesh get /cluster/status --output-format=json')
                    if cluster_data:
                        proxmox_info['cluster_status'] = cluster_data
                    
                    progress.update(1, "⚙️  Prüfe Cluster-Konfiguration...")
                    cluster_config = self.execute_remote_command('pvesh get /cluster/config --output-format=json')
                    if cluster_config:
                        proxmox_info['cluster_config'] = cluster_config
                
                if target in ["all", "ha"]:
                    progress.update(1, "🔄 Prüfe HA-Status...")
                    ha_data = self.execute_remote_command('pvesh get /cluster/ha/status')
                    if ha_data:
                        proxmox_info['ha_status'] = ha_data
                
                if target in ["all", "tasks"]:
                    # Aktuelle Tasks
                    progress.update(1, "📋 Prüfe aktuelle Tasks...")
                    nodes_json = self.execute_remote_command('pvesh get /nodes --output-format=json')
                    if nodes_json:
                        try:
                            nodes_data = json.loads(nodes_json)
                            for node in nodes_data[:2]:  # Erste 2 Nodes
                                node_name = node.get('node', '')
                                if node_name:
                                    tasks_data = self.execute_remote_command(f'pvesh get /nodes/{node_name}/tasks --output-format=json --limit 10')
                                    if tasks_data:
                                        proxmox_info[f'{node_name}_tasks'] = tasks_data
                        except json.JSONDecodeError:
                            pass
                
                if target in ["all", "backups"]:
                    # Backup-Status
                    progress.update(1, "💾 Prüfe Backup-Status...")
                    nodes_json = self.execute_remote_command('pvesh get /nodes --output-format=json')
                    if nodes_json:
                        try:
                            nodes_data = json.loads(nodes_json)
                            for node in nodes_data[:2]:  # Erste 2 Nodes
                                node_name = node.get('node', '')
                                if node_name:
                                    # Backup-Jobs
                                    backup_jobs = self.execute_remote_command(f'pvesh get /nodes/{node_name}/vzdump --output-format=json')
                                    if backup_jobs:
                                        proxmox_info[f'{node_name}_backup_jobs'] = backup_jobs
                        except json.JSONDecodeError:
                            pass
                
                console.print(f"[green]✅ Proxmox-Daten aktualisiert: {target}[/green]")
                
            except Exception as e:
                console.print(f"[red]❌ Fehler beim Aktualisieren der Proxmox-Daten: {str(e)[:100]}[/red]")
                proxmox_info["error"] = str(e)
        
        return proxmox_info
    
    def get_detailed_proxmox_containers(self) -> Dict[str, Any]:
        """Holt detaillierte Informationen über alle Proxmox-Container"""
        container_info = {
            'running_containers': [],
            'stopped_containers': [],
            'total_containers': 0,
            'nodes_with_containers': [],
            'container_summary': {}
        }
        
        # Prüfe ob Proxmox verfügbar ist
        proxmox_check = self.execute_remote_command('which pvesh')
        if not proxmox_check:
            return {"error": "Proxmox nicht verfügbar"}
        
        # Verwende Fortschrittsanzeige
        with ProgressTracker("📊 Analysiere Proxmox-Container", total_steps=20) as progress:
            try:
                # Hole alle Nodes
                progress.update(1, "📋 Lade Node-Liste...")
                nodes_json = self.execute_remote_command('pvesh get /nodes --output-format=json')
                if not nodes_json:
                    return {"error": "Keine Nodes gefunden"}
                
                import json
                nodes_data = json.loads(nodes_json)
                
                for i, node in enumerate(nodes_data):
                    node_name = node.get('node', '')
                    if not node_name:
                        continue
                    
                    progress.update(1, f"📊 Analysiere Node {i+1}/{len(nodes_data)}: {node_name}...")
                    
                    # Hole Container für diesen Node
                    containers_json = self.execute_remote_command(f'pvesh get /nodes/{node_name}/lxc --output-format=json')
                    if not containers_json:
                        continue
                    
                    try:
                        containers_data = json.loads(containers_json)
                        if not containers_data:
                            continue
                        
                        node_containers = {
                            'node': node_name,
                            'running': 0,
                            'stopped': 0,
                            'containers': []
                        }
                        
                        for container in containers_data:
                            container_id = container.get('vmid', '')
                            container_name = container.get('name', f'Container-{container_id}')
                            container_status = container.get('status', 'unknown')
                            container_template = container.get('template', False)
                            
                            # Überspringe Templates
                            if container_template:
                                continue
                            
                            container_details = {
                                'id': container_id,
                                'name': container_name,
                                'status': container_status,
                                'node': node_name
                            }
                            
                            # Hole zusätzliche Details
                            try:
                                # CPU und Memory
                                status_details = self.execute_remote_command(f'pvesh get /nodes/{node_name}/lxc/{container_id}/status/current --output-format=json')
                                if status_details:
                                    status_data = json.loads(status_details)
                                    container_details['cpu'] = status_data.get('cpu', 0)
                                    container_details['memory'] = status_data.get('memory', {})
                                    container_details['uptime'] = status_data.get('uptime', 0)
                                    container_details['disk'] = status_data.get('disk', {})
                                
                                # Netzwerk-Informationen
                                network_info = self.execute_remote_command(f'pvesh get /nodes/{node_name}/lxc/{container_id}/status/current --output-format=json | jq -r ".netin, .netout" 2>/dev/null')
                                if network_info:
                                    container_details['network'] = network_info
                                
                            except (json.JSONDecodeError, Exception):
                                pass
                            
                            # Kategorisiere Container
                            if container_status == 'running':
                                container_info['running_containers'].append(container_details)
                                node_containers['running'] += 1
                            else:
                                container_info['stopped_containers'].append(container_details)
                                node_containers['stopped'] += 1
                            
                            node_containers['containers'].append(container_details)
                            container_info['total_containers'] += 1
                        
                        if node_containers['containers']:
                            container_info['nodes_with_containers'].append(node_containers)
                            container_info['container_summary'][node_name] = {
                                'total': len(node_containers['containers']),
                                'running': node_containers['running'],
                                'stopped': node_containers['stopped']
                            }
                    
                    except json.JSONDecodeError:
                        continue
                
                # Erstelle Zusammenfassung
                container_info['summary'] = {
                    'total_containers': container_info['total_containers'],
                    'running_containers': len(container_info['running_containers']),
                    'stopped_containers': len(container_info['stopped_containers']),
                    'nodes_with_containers': len(container_info['nodes_with_containers'])
                }
                
            except Exception as e:
                container_info["error"] = str(e)
        
        return container_info
    
    def analyze_listening_services(self) -> Dict[str, Any]:
        """Analysiert alle lauschenden Services und deren Netzwerk-Konfiguration (INTERNE Analyse)"""
        services_info = {
            'analysis_type': 'internal',
            'listening_ports': [],
            'service_mapping': {},
            'external_interfaces': [],
            'firewall_status': {},
            'security_analysis': {}
        }
        
        console.print("[dim]🔍 Analysiere lauschende Services...[/dim]")
        
        try:
            # Sammle alle lauschenden Ports mit ss (modern) oder netstat (Fallback)
            # Verwende -p für Prozess-Informationen
            listening_ports = self.execute_remote_command('ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null')
            if listening_ports:
                services_info['listening_ports'] = listening_ports
                
                # Parse Ports und identifiziere Services
                port_services = {}
                lines = listening_ports.split('\n')
                
                for line in lines:
                    # Bereinige die Zeile von überschüssigen Leerzeichen
                    line = ' '.join(line.split())
                    
                    if 'LISTEN' in line and 'tcp' in line:
                        # Suche nach der Local Address:Port
                        import re
                        # Verbesserte Regex für verschiedene Adressformate
                        address_port_match = re.search(r'(\S+):(\d+)\s+\S+:\*', line)
                        if not address_port_match:
                            # Fallback für andere Formate
                            address_port_match = re.search(r'(\S+):(\d+)\s+0\.0\.0\.0:\*', line)
                        if address_port_match:
                            address = address_port_match.group(1)
                            port_str = address_port_match.group(2)
                            
                            try:
                                port_num = int(port_str)
                                
                                # Identifiziere Service basierend auf Port
                                service_name = self._identify_service_by_port(port_num)
                                
                                # Extrahiere Prozess-Informationen falls verfügbar
                                process_info = ""
                                if 'users:' in line:
                                    process_start = line.find('users:')
                                    process_info = line[process_start:].split('ino:')[0].strip()
                                
                                port_services[port_num] = {
                                    'address': address,
                                    'external': address in ['0.0.0.0', '::', '*'],
                                    'service': service_name,
                                    'status': 'LISTEN',
                                    'details': process_info
                                }
                            except ValueError:
                                continue
                
                services_info['service_mapping'] = port_services
            
            # Identifiziere alle IP-Adressen aus ip a
            all_ip_addresses = []
            ip_a_output = self.execute_remote_command('ip a 2>/dev/null')
            if ip_a_output:
                import re
                # Extrahiere alle IPv4-Adressen
                ipv4_pattern = r'inet\s+(\d+\.\d+\.\d+\.\d+)'
                ipv4_addresses = re.findall(ipv4_pattern, ip_a_output)
                
                # Extrahiere alle IPv6-Adressen (globale und link-local)
                ipv6_pattern = r'inet6\s+([0-9a-fA-F:]+)'
                ipv6_addresses = re.findall(ipv6_pattern, ip_a_output)
                
                # Filtere loopback und link-local Adressen
                for ip in ipv4_addresses:
                    if not ip.startswith('127.') and not ip.startswith('169.254.'):
                        all_ip_addresses.append(ip)
                
                for ip in ipv6_addresses:
                    if not ip.startswith('fe80:') and not ip.startswith('::1'):
                        all_ip_addresses.append(ip)
                
                services_info['all_ip_addresses'] = all_ip_addresses
            
            # Fallback: Identifiziere externe Interfaces über Route
            if not all_ip_addresses:
                external_interfaces = self.execute_remote_command('ip route get 8.8.8.8 2>/dev/null | grep -o "src [0-9.]*" | cut -d" " -f2')
                if external_interfaces:
                    services_info['external_interfaces'] = external_interfaces.strip().split('\n')
            
            # Prüfe Firewall-Status
            firewall_status = {}
            
            # iptables Status
            iptables_status = self.execute_remote_command('iptables -L -n 2>/dev/null | head -20')
            if iptables_status:
                firewall_status['iptables'] = iptables_status
            
            # ufw Status
            ufw_status = self.execute_remote_command('ufw status 2>/dev/null')
            if ufw_status:
                firewall_status['ufw'] = ufw_status
            
            # firewalld Status
            firewalld_status = self.execute_remote_command('firewall-cmd --list-all 2>/dev/null')
            if firewalld_status:
                firewall_status['firewalld'] = firewalld_status
            
            services_info['firewall_status'] = firewall_status
            
            # Service-spezifische Informationen
            service_details = {}
            
            # SSH-Konfiguration
            ssh_config = self.execute_remote_command('grep -E "^(Port|ListenAddress|PermitRootLogin|PasswordAuthentication)" /etc/ssh/sshd_config 2>/dev/null')
            if ssh_config:
                service_details['ssh'] = ssh_config
            
            # Web-Server-Konfiguration
            apache_status = self.execute_remote_command('systemctl status apache2 2>/dev/null || systemctl status httpd 2>/dev/null')
            if apache_status:
                service_details['apache'] = apache_status
            
            nginx_status = self.execute_remote_command('systemctl status nginx 2>/dev/null')
            if nginx_status:
                service_details['nginx'] = nginx_status
            
            # Datenbank-Services
            mysql_status = self.execute_remote_command('systemctl status mysql 2>/dev/null || systemctl status mysqld 2>/dev/null')
            if mysql_status:
                service_details['mysql'] = mysql_status
            
            postgres_status = self.execute_remote_command('systemctl status postgresql 2>/dev/null')
            if postgres_status:
                service_details['postgresql'] = postgres_status
            
            services_info['service_details'] = service_details
            
            # Sicherheitsanalyse
            security_issues = []
            
            # Prüfe auf Standard-Ports
            standard_ports = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 5432: 'PostgreSQL'}
            for port, service in standard_ports.items():
                if port in port_services:
                    if port_services[port]['external']:
                        security_issues.append(f"Service {service} (Port {port}) ist extern erreichbar")
            
            # Prüfe auf ungewöhnliche Ports
            unusual_ports = [port for port in port_services.keys() if port not in standard_ports and port < 1024]
            if unusual_ports:
                security_issues.append(f"Ungewöhnliche privilegierte Ports gefunden: {unusual_ports}")
            
            services_info['security_analysis']['issues'] = security_issues
            
            console.print(f"[green]✅ Service-Analyse abgeschlossen: {len(port_services)} Services gefunden[/green]")
            
        except Exception as e:
            services_info['error'] = str(e)
            console.print(f"[red]❌ Fehler bei Service-Analyse: {e}[/red]")
        
        return services_info
    
    def _identify_service_by_port(self, port: int) -> str:
        """Identifiziert Service basierend auf Port-Nummer"""
        service_mapping = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 9000: 'Web-Alt', 27017: 'MongoDB', 11211: 'Memcached',
            111: 'RPC', 123: 'NTP', 161: 'SNMP', 389: 'LDAP', 636: 'LDAPS',
            3128: 'Proxy', 8006: 'Proxmox-Web', 5999: 'VNC', 61000: 'VNC-Alt',
            85: 'Proxmox-Daemon', 5405: 'Corosync', 323: 'Chrony'
        }
        return service_mapping.get(port, f'Unknown-{port}')
    
    def _classify_ip_address(self, ip: str) -> Dict[str, Any]:
        """Klassifiziert IP-Adressen nach RFC-Standards"""
        import ipaddress
        
        try:
            # Parse IP-Adresse
            ip_obj = ipaddress.ip_address(ip)
            
            # IPv4-Klassifikation
            if ip_obj.version == 4:
                # RFC 1918 Private Addresses
                if ip_obj.is_private:
                    return {
                        'type': 'private',
                        'rfc': 'RFC 1918',
                        'description': 'Private Netzwerk-Adresse',
                        'risk_level': 'low',
                        'explanation': 'Interne Adresse - kein externes Sicherheitsrisiko'
                    }
                
                # RFC 6890 Special Purpose Addresses
                elif ip_obj.is_loopback:
                    return {
                        'type': 'loopback',
                        'rfc': 'RFC 6890',
                        'description': 'Loopback-Adresse',
                        'risk_level': 'none',
                        'explanation': 'Lokale Loopback-Adresse - kein Netzwerkrisiko'
                    }
                elif ip_obj.is_link_local:
                    return {
                        'type': 'link_local',
                        'rfc': 'RFC 6890',
                        'description': 'Link-Local-Adresse',
                        'risk_level': 'none',
                        'explanation': 'Automatische Link-Local-Adresse - kein externes Risiko'
                    }
                elif ip_obj.is_multicast:
                    return {
                        'type': 'multicast',
                        'rfc': 'RFC 5771',
                        'description': 'Multicast-Adresse',
                        'risk_level': 'low',
                        'explanation': 'Multicast-Adresse - begrenztes Risiko'
                    }
                elif ip_obj.is_reserved:
                    return {
                        'type': 'reserved',
                        'rfc': 'RFC 6890',
                        'description': 'Reservierte Adresse',
                        'risk_level': 'none',
                        'explanation': 'Reservierte Adresse - kein Risiko'
                    }
                else:
                    return {
                        'type': 'public',
                        'rfc': 'RFC 1918',
                        'description': 'Öffentliche IP-Adresse',
                        'risk_level': 'medium',
                        'explanation': 'Öffentliche Adresse - extern erreichbar'
                    }
            
            # IPv6-Klassifikation
            else:
                # RFC 4193 Unique Local Addresses
                if ip_obj.is_private:
                    return {
                        'type': 'private',
                        'rfc': 'RFC 4193',
                        'description': 'Unique Local IPv6-Adresse',
                        'risk_level': 'low',
                        'explanation': 'Interne IPv6-Adresse - kein externes Sicherheitsrisiko'
                    }
                elif ip_obj.is_loopback:
                    return {
                        'type': 'loopback',
                        'rfc': 'RFC 6890',
                        'description': 'IPv6 Loopback-Adresse',
                        'risk_level': 'none',
                        'explanation': 'Lokale IPv6 Loopback-Adresse - kein Netzwerkrisiko'
                    }
                elif ip_obj.is_link_local:
                    return {
                        'type': 'link_local',
                        'rfc': 'RFC 6890',
                        'description': 'IPv6 Link-Local-Adresse',
                        'risk_level': 'none',
                        'explanation': 'Automatische IPv6 Link-Local-Adresse - kein externes Risiko'
                    }
                elif ip_obj.is_multicast:
                    return {
                        'type': 'multicast',
                        'rfc': 'RFC 5771',
                        'description': 'IPv6 Multicast-Adresse',
                        'risk_level': 'low',
                        'explanation': 'IPv6 Multicast-Adresse - begrenztes Risiko'
                    }
                elif ip_obj.is_reserved:
                    return {
                        'type': 'reserved',
                        'rfc': 'RFC 6890',
                        'description': 'Reservierte IPv6-Adresse',
                        'risk_level': 'none',
                        'explanation': 'Reservierte IPv6-Adresse - kein Risiko'
                    }
                else:
                    return {
                        'type': 'public',
                        'rfc': 'RFC 4193',
                        'description': 'Öffentliche IPv6-Adresse',
                        'risk_level': 'medium',
                        'explanation': 'Öffentliche IPv6-Adresse - extern erreichbar'
                    }
        
        except ValueError:
            return {
                'type': 'invalid',
                'rfc': 'N/A',
                'description': 'Ungültige IP-Adresse',
                'risk_level': 'unknown',
                'explanation': 'Konnte IP-Adresse nicht parsen'
            }
    
    def test_external_accessibility(self, target_hosts: List, ports: List[int], include_dns: bool = False) -> Dict[str, Any]:
        """Testet externe Erreichbarkeit von allen IP-Adressen (EXTERNE Analyse)"""
        accessibility_results = {
            'analysis_type': 'external',
            'reachable_ports': [],
            'service_versions': {},
            'security_headers': {},
            'vulnerability_indicators': [],
            'reachable_hosts': {},  # Welche Hosts sind erreichbar
            'host_port_mapping': {},  # Welche Ports auf welchen Hosts
            'dns_results': {}  # DNS-basierte Tests
        }
        
        console.print(f"[dim]🔍 Teste externe Erreichbarkeit von {len(target_hosts)} IP-Adressen...[/dim]")
        
        try:
            # DNS-basierte Tests (optional)
            if include_dns:
                console.print("[dim]🔍 Führe DNS-basierte Tests durch...[/dim]")
                dns_results = self._perform_dns_tests(target_hosts, ports)
                accessibility_results['dns_results'] = dns_results
            
            # Teste jede IP-Adresse einzeln
            for target_host in target_hosts:
                # Extrahiere IP-Adresse falls es ein Dictionary ist
                if isinstance(target_host, dict):
                    host_ip = target_host.get('ip', str(target_host))
                else:
                    host_ip = str(target_host)
                
                console.print(f"[dim]  Teste {host_ip}...[/dim]")
                accessibility_results['reachable_hosts'][host_ip] = []
                accessibility_results['host_port_mapping'][host_ip] = {}
                
                # Schneller Port-Scan mit nmap (falls verfügbar)
                nmap_available = self.execute_remote_command('which nmap')
                if nmap_available:
                    # Erstelle Port-Liste für nmap
                    port_list = ','.join(map(str, ports))
                    nmap_scan = self.execute_remote_command(f'nmap -sS -p {port_list} {target_host} 2>/dev/null')
                    if nmap_scan:
                        if target_host not in accessibility_results:
                            accessibility_results[target_host] = {}
                        accessibility_results[target_host]['nmap_scan'] = nmap_scan
                        
                        # Parse nmap-Ergebnisse
                        for line in nmap_scan.split('\n'):
                            if 'open' in line and 'tcp' in line:
                                # Extrahiere Port und Service
                                parts = line.split()
                                if len(parts) >= 3:
                                    port_info = parts[0]
                                    if '/' in port_info:
                                        port = port_info.split('/')[0]
                                        try:
                                            port_num = int(port)
                                            if port_num not in accessibility_results['reachable_ports']:
                                                accessibility_results['reachable_ports'].append(port_num)
                                            accessibility_results['reachable_hosts'][target_host].append(port_num)
                                            accessibility_results['host_port_mapping'][target_host][port_num] = 'open'
                                            
                                            # Service-Version falls verfügbar
                                            if len(parts) > 3:
                                                service_info = ' '.join(parts[3:])
                                                accessibility_results['service_versions'][port_num] = service_info
                                        except ValueError:
                                            continue
            
            # Fallback: Einzelne Port-Tests mit telnet/netcat für jede IP
            for target_host in target_hosts:
                for port in ports:
                    # Teste mit netcat (falls verfügbar)
                    nc_test = self.execute_remote_command(f'timeout 5 bash -c "</dev/tcp/{target_host}/{port}" 2>/dev/null && echo "open" || echo "closed"')
                    if nc_test and 'open' in nc_test:
                        if port not in accessibility_results['reachable_ports']:
                            accessibility_results['reachable_ports'].append(port)
                        if port not in accessibility_results['reachable_hosts'][target_host]:
                            accessibility_results['reachable_hosts'][target_host].append(port)
                        accessibility_results['host_port_mapping'][target_host][port] = 'open'
                        
                        # Banner-Grabbing für bekannte Services
                        if port == 22:  # SSH
                            ssh_banner = self.execute_remote_command(f'timeout 5 bash -c "echo | nc {target_host} {port}" 2>/dev/null')
                            if ssh_banner:
                                accessibility_results['service_versions'][port] = ssh_banner.strip()
                        
                        elif port == 80:  # HTTP
                            http_headers = self.execute_remote_command(f'timeout 5 bash -c "curl -I http://{target_host}:{port} 2>/dev/null"')
                            if http_headers:
                                accessibility_results['security_headers'][port] = http_headers
                        
                        elif port == 443:  # HTTPS
                            https_headers = self.execute_remote_command(f'timeout 5 bash -c "curl -I https://{target_host}:{port} 2>/dev/null"')
                            if https_headers:
                                accessibility_results['security_headers'][port] = https_headers
            
            # Erweiterte Vulnerability-Analyse
            accessibility_results['vulnerability_analysis'] = {}
            
            # Prüfe jeden erreichbaren Service auf Vulnerabilities
            for port in accessibility_results['reachable_ports']:
                service_version = accessibility_results['service_versions'].get(port, '')
                service_name = self._identify_service_by_port(port)
                
                # Extrahiere Version aus Service-String
                version = None
                if service_version:
                    import re
                    version_match = re.search(r'(\d+\.\d+\.?\d*)', service_version)
                    if version_match:
                        version = version_match.group(1)
                
                # Führe Vulnerability-Check durch
                if service_name and version:
                    console.print(f"[dim]🔍 Prüfe {service_name} {version} auf Vulnerabilities...[/dim]")
                    vuln_info = self._check_vulnerability_databases(service_name, version, port)
                    accessibility_results['vulnerability_analysis'][port] = vuln_info
                    
                    # Füge kritische Vulnerabilities zu Indikatoren hinzu
                    if vuln_info['critical_cves']:
                        accessibility_results['vulnerability_indicators'].append(f"Kritische CVE in {service_name} {version}: {len(vuln_info['critical_cves'])} gefunden")
                    
                    if vuln_info['high_cves']:
                        accessibility_results['vulnerability_indicators'].append(f"Hohe CVE in {service_name} {version}: {len(vuln_info['high_cves'])} gefunden")
            
            # Security-Headers für Web-Services prüfen
            accessibility_results['security_headers_analysis'] = {}
            for target_host in target_hosts:
                for port in [80, 443, 8080, 8443]:
                    if port in accessibility_results['reachable_ports']:
                        console.print(f"[dim]🔍 Prüfe Security-Headers für {target_host}:{port}...[/dim]")
                        headers_info = self._check_security_headers(target_host, port)
                        accessibility_results['security_headers_analysis'][f"{target_host}:{port}"] = headers_info
                        
                        # Füge Security-Header-Probleme zu Indikatoren hinzu
                        if headers_info['security_score'] < 50:
                            accessibility_results['vulnerability_indicators'].append(f"Schwache Security-Headers auf {target_host}:{port} (Score: {headers_info['security_score']})")
            
            # Legacy-Sicherheits-Indikatoren (für Kompatibilität)
            if 22 in accessibility_results['reachable_ports']:
                ssh_version = accessibility_results['service_versions'].get(22, '')
                if 'OpenSSH' in ssh_version:
                    # Prüfe auf alte SSH-Versionen
                    if any(old_ver in ssh_version for old_ver in ['4.', '5.', '6.']):
                        accessibility_results['vulnerability_indicators'].append('Alte SSH-Version erkannt')
            
            if 80 in accessibility_results['reachable_ports']:
                http_headers = accessibility_results['security_headers'].get(80, '')
                if 'Server:' in http_headers:
                    if any(old_server in http_headers for old_server in ['Apache/2.2', 'Apache/2.0']):
                        accessibility_results['vulnerability_indicators'].append('Alte Apache-Version erkannt')
            
            # Zeige Zusammenfassung der erreichbaren Hosts
            reachable_hosts_count = sum(1 for host, ports in accessibility_results['reachable_hosts'].items() if ports)
            console.print(f"[green]✅ Externe Erreichbarkeit getestet: {len(accessibility_results['reachable_ports'])} Ports auf {reachable_hosts_count} Hosts erreichbar[/green]")
            
            # Zeige detaillierte Host-Informationen
            for host, ports in accessibility_results['reachable_hosts'].items():
                if ports:
                    console.print(f"[dim]  {host}: {', '.join(map(str, ports))}[/dim]")
            
        except Exception as e:
            accessibility_results['error'] = str(e)
            console.print(f"[red]❌ Fehler bei externer Erreichbarkeit: {e}[/red]")
        
        return accessibility_results
    
    def _perform_dns_tests(self, target_hosts: List, ports: List[int]) -> Dict[str, Any]:
        """Führt DNS-basierte Tests durch"""
        dns_results = {
            'hostname_resolution': {},
            'reverse_dns': {},
            'service_discovery': {},
            'dns_zone_transfer': {}
        }
        
        try:
            for target_host in target_hosts:
                # Extrahiere IP-Adresse falls es ein Dictionary ist
                if isinstance(target_host, dict):
                    host_ip = target_host.get('ip', str(target_host))
                else:
                    host_ip = str(target_host)
                
                dns_results['hostname_resolution'][host_ip] = {}
                dns_results['reverse_dns'][host_ip] = {}
                
                # Reverse DNS Lookup
                reverse_dns = self.execute_remote_command(f'host {host_ip} 2>/dev/null || nslookup {host_ip} 2>/dev/null')
                if reverse_dns:
                    dns_results['reverse_dns'][host_ip] = reverse_dns.strip()
                
                # Forward DNS Lookup (falls Hostname verfügbar)
                if reverse_dns and 'domain name' in reverse_dns.lower():
                    # Extrahiere Hostname aus Reverse DNS
                    import re
                    hostname_match = re.search(r'domain name pointer (.+)', reverse_dns, re.IGNORECASE)
                    if hostname_match:
                        hostname = hostname_match.group(1).rstrip('.')
                        dns_results['hostname_resolution'][host_ip] = hostname
                        
                        # Teste Hostname-basierte Services
                        for port in ports:
                            if port in [80, 443, 8080, 8443]:  # Web-Services
                                web_test = self.execute_remote_command(f'timeout 5 bash -c "</dev/tcp/{hostname}/{port}" 2>/dev/null && echo "open" || echo "closed"')
                                if web_test and 'open' in web_test:
                                    if hostname not in dns_results['service_discovery']:
                                        dns_results['service_discovery'][hostname] = []
                                    dns_results['service_discovery'][hostname].append(port)
                
                # DNS Zone Transfer Test (falls verfügbar)
                if reverse_dns and 'domain name' in reverse_dns.lower():
                    domain_match = re.search(r'domain name pointer .+\.(.+)', reverse_dns, re.IGNORECASE)
                    if domain_match:
                        domain = domain_match.group(1)
                        zone_transfer = self.execute_remote_command(f'dig AXFR {domain} @{host_ip} 2>/dev/null')
                        if zone_transfer and 'transfer failed' not in zone_transfer.lower():
                            dns_results['dns_zone_transfer'][domain] = zone_transfer.strip()
        
        except Exception as e:
            dns_results['error'] = str(e)
        
        return dns_results
    
    def _check_vulnerability_databases(self, service_name: str, version: str = None, port: int = None) -> Dict[str, Any]:
        """Prüft verschiedene Vulnerability-Datenbanken für bekannte Schwachstellen"""
        vulnerability_info = {
            'service': service_name,
            'version': version,
            'port': port,
            'cve_count': 0,
            'critical_cves': [],
            'high_cves': [],
            'medium_cves': [],
            'low_cves': [],
            'last_checked': None,
            'sources': []
        }
        
        try:
            import requests
            import json
            from datetime import datetime
            
            # NVD (National Vulnerability Database) API
            if version:
                nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {
                    'keywordSearch': f"{service_name} {version}",
                    'resultsPerPage': 20
                }
                
                try:
                    response = requests.get(nvd_url, params=params, timeout=10)
                    if response.status_code == 200:
                        nvd_data = response.json()
                        if 'vulnerabilities' in nvd_data:
                            for vuln in nvd_data['vulnerabilities']:
                                cve = vuln.get('cve', {})
                                cve_id = cve.get('id', 'Unknown')
                                metrics = cve.get('metrics', {})
                                
                                # CVSS Score ermitteln
                                cvss_score = 0
                                if 'cvssMetricV31' in metrics:
                                    cvss_score = float(metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 0))
                                elif 'cvssMetricV30' in metrics:
                                    cvss_score = float(metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 0))
                                elif 'cvssMetricV2' in metrics:
                                    cvss_score = float(metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 0))
                                
                                # CVE nach Schweregrad kategorisieren
                                if cvss_score >= 9.0:
                                    vulnerability_info['critical_cves'].append({
                                        'id': cve_id,
                                        'score': cvss_score,
                                        'description': cve.get('descriptions', [{}])[0].get('value', 'No description')
                                    })
                                elif cvss_score >= 7.0:
                                    vulnerability_info['high_cves'].append({
                                        'id': cve_id,
                                        'score': cvss_score,
                                        'description': cve.get('descriptions', [{}])[0].get('value', 'No description')
                                    })
                                elif cvss_score >= 4.0:
                                    vulnerability_info['medium_cves'].append({
                                        'id': cve_id,
                                        'score': cvss_score,
                                        'description': cve.get('descriptions', [{}])[0].get('value', 'No description')
                                    })
                                else:
                                    vulnerability_info['low_cves'].append({
                                        'id': cve_id,
                                        'score': cvss_score,
                                        'description': cve.get('descriptions', [{}])[0].get('value', 'No description')
                                    })
                                
                                vulnerability_info['cve_count'] += 1
                        
                        vulnerability_info['sources'].append('NVD')
                except Exception as e:
                    console.print(f"[dim]⚠️  NVD API Fehler: {e}[/dim]")
            
            # CVE-Search.org API (falls verfügbar)
            try:
                cve_search_url = f"https://cve.circl.lu/api/search/{service_name}"
                response = requests.get(cve_search_url, timeout=10)
                if response.status_code == 200:
                    cve_data = response.json()
                    if isinstance(cve_data, list):
                        for cve in cve_data[:10]:  # Limitiere auf 10 Ergebnisse
                            cve_id = cve.get('id', 'Unknown')
                            cvss_score = float(cve.get('cvss', 0))
                            
                            if cvss_score >= 9.0:
                                vulnerability_info['critical_cves'].append({
                                    'id': cve_id,
                                    'score': cvss_score,
                                    'description': cve.get('summary', 'No description')
                                })
                            elif cvss_score >= 7.0:
                                vulnerability_info['high_cves'].append({
                                    'id': cve_id,
                                    'score': cvss_score,
                                    'description': cve.get('summary', 'No description')
                                })
                            elif cvss_score >= 4.0:
                                vulnerability_info['medium_cves'].append({
                                    'id': cve_id,
                                    'score': cvss_score,
                                    'description': cve.get('summary', 'No description')
                                })
                            else:
                                vulnerability_info['low_cves'].append({
                                    'id': cve_id,
                                    'score': cvss_score,
                                    'description': cve.get('summary', 'No description')
                                })
                            
                            vulnerability_info['cve_count'] += 1
                        
                        vulnerability_info['sources'].append('CVE-Search')
            except Exception as e:
                console.print(f"[dim]⚠️  CVE-Search API Fehler: {e}[/dim]")
            
            # Service-spezifische Checks
            if service_name.lower() in ['ssh', 'openssh']:
                vulnerability_info.update(self._check_ssh_vulnerabilities(version))
            elif service_name.lower() in ['apache', 'httpd']:
                vulnerability_info.update(self._check_apache_vulnerabilities(version))
            elif service_name.lower() in ['nginx']:
                vulnerability_info.update(self._check_nginx_vulnerabilities(version))
            elif service_name.lower() in ['mysql', 'mariadb']:
                vulnerability_info.update(self._check_mysql_vulnerabilities(version))
            elif service_name.lower() in ['postgresql', 'postgres']:
                vulnerability_info.update(self._check_postgresql_vulnerabilities(version))
            
            vulnerability_info['last_checked'] = datetime.now().isoformat()
            
        except Exception as e:
            vulnerability_info['error'] = str(e)
            console.print(f"[dim]⚠️  Vulnerability-Check Fehler: {e}[/dim]")
        
        return vulnerability_info
    
    def _check_ssh_vulnerabilities(self, version: str = None) -> Dict[str, Any]:
        """Spezielle SSH-Vulnerability-Checks"""
        ssh_vulns = {
            'ssh_specific': [],
            'recommendations': []
        }
        
        try:
            if version:
                # Prüfe auf bekannte SSH-Vulnerabilities
                known_vulnerable_versions = [
                    '4.', '5.', '6.', '7.0', '7.1', '7.2', '7.3', '7.4', '7.5', '7.6', '7.7'
                ]
                
                for vuln_ver in known_vulnerable_versions:
                    if version.startswith(vuln_ver):
                        ssh_vulns['ssh_specific'].append(f"Alte SSH-Version {version} - Update empfohlen")
                        ssh_vulns['recommendations'].append("SSH auf neueste Version aktualisieren")
                        break
                
                # Prüfe auf spezifische CVE-Patterns
                if '7.2' in version:
                    ssh_vulns['ssh_specific'].append("CVE-2016-6210: Timing attack vulnerability")
                elif '7.1' in version:
                    ssh_vulns['ssh_specific'].append("CVE-2016-1908: Memory leak vulnerability")
            
            # Allgemeine SSH-Empfehlungen
            ssh_vulns['recommendations'].extend([
                "Key-basierte Authentifizierung verwenden",
                "PasswordAuthentication deaktivieren",
                "Root-Login deaktivieren",
                "Fail2ban für Brute-Force-Schutz konfigurieren"
            ])
            
        except Exception as e:
            ssh_vulns['error'] = str(e)
        
        return ssh_vulns
    
    def _check_apache_vulnerabilities(self, version: str = None) -> Dict[str, Any]:
        """Spezielle Apache-Vulnerability-Checks"""
        apache_vulns = {
            'apache_specific': [],
            'recommendations': []
        }
        
        try:
            if version:
                # Prüfe auf bekannte Apache-Vulnerabilities
                known_vulnerable_versions = [
                    '2.2.', '2.0.', '1.3.'
                ]
                
                for vuln_ver in known_vulnerable_versions:
                    if version.startswith(vuln_ver):
                        apache_vulns['apache_specific'].append(f"Alte Apache-Version {version} - Update empfohlen")
                        apache_vulns['recommendations'].append("Apache auf neueste Version aktualisieren")
                        break
            
            # Allgemeine Apache-Empfehlungen
            apache_vulns['recommendations'].extend([
                "ServerTokens Prod konfigurieren",
                "ServerSignature Off setzen",
                "ModSecurity WAF aktivieren",
                "HTTPS erzwingen",
                "Sicherheits-Header setzen"
            ])
            
        except Exception as e:
            apache_vulns['error'] = str(e)
        
        return apache_vulns
    
    def _check_nginx_vulnerabilities(self, version: str = None) -> Dict[str, Any]:
        """Spezielle Nginx-Vulnerability-Checks"""
        nginx_vulns = {
            'nginx_specific': [],
            'recommendations': []
        }
        
        try:
            if version:
                # Prüfe auf bekannte Nginx-Vulnerabilities
                known_vulnerable_versions = [
                    '1.0.', '1.1.', '1.2.', '1.3.', '1.4.', '1.5.', '1.6.'
                ]
                
                for vuln_ver in known_vulnerable_versions:
                    if version.startswith(vuln_ver):
                        nginx_vulns['nginx_specific'].append(f"Alte Nginx-Version {version} - Update empfohlen")
                        nginx_vulns['recommendations'].append("Nginx auf neueste Version aktualisieren")
                        break
            
            # Allgemeine Nginx-Empfehlungen
            nginx_vulns['recommendations'].extend([
                "server_tokens off konfigurieren",
                "HTTPS erzwingen",
                "Sicherheits-Header setzen",
                "Rate-Limiting aktivieren",
                "ModSecurity WAF aktivieren"
            ])
            
        except Exception as e:
            nginx_vulns['error'] = str(e)
        
        return nginx_vulns
    
    def _check_mysql_vulnerabilities(self, version: str = None) -> Dict[str, Any]:
        """Spezielle MySQL-Vulnerability-Checks"""
        mysql_vulns = {
            'mysql_specific': [],
            'recommendations': []
        }
        
        try:
            if version:
                # Prüfe auf bekannte MySQL-Vulnerabilities
                known_vulnerable_versions = [
                    '5.0.', '5.1.', '5.5.', '5.6.'
                ]
                
                for vuln_ver in known_vulnerable_versions:
                    if version.startswith(vuln_ver):
                        mysql_vulns['mysql_specific'].append(f"Alte MySQL-Version {version} - Update empfohlen")
                        mysql_vulns['recommendations'].append("MySQL auf neueste Version aktualisieren")
                        break
            
            # Allgemeine MySQL-Empfehlungen
            mysql_vulns['recommendations'].extend([
                "Root-Passwort ändern",
                "Anonyme Benutzer entfernen",
                "Test-Datenbank entfernen",
                "Remote-Zugriff einschränken",
                "SSL/TLS für Verbindungen aktivieren"
            ])
            
        except Exception as e:
            mysql_vulns['error'] = str(e)
        
        return mysql_vulns
    
    def _check_postgresql_vulnerabilities(self, version: str = None) -> Dict[str, Any]:
        """Spezielle PostgreSQL-Vulnerability-Checks"""
        postgres_vulns = {
            'postgres_specific': [],
            'recommendations': []
        }
        
        try:
            if version:
                # Prüfe auf bekannte PostgreSQL-Vulnerabilities
                known_vulnerable_versions = [
                    '8.', '9.0.', '9.1.', '9.2.', '9.3.', '9.4.', '9.5.'
                ]
                
                for vuln_ver in known_vulnerable_versions:
                    if version.startswith(vuln_ver):
                        postgres_vulns['postgres_specific'].append(f"Alte PostgreSQL-Version {version} - Update empfohlen")
                        postgres_vulns['recommendations'].append("PostgreSQL auf neueste Version aktualisieren")
                        break
            
            # Allgemeine PostgreSQL-Empfehlungen
            postgres_vulns['recommendations'].extend([
                "Postgres-Benutzer-Passwort ändern",
                "pg_hba.conf für Zugriffskontrolle konfigurieren",
                "SSL für Verbindungen aktivieren",
                "Logging aktivieren",
                "Regelmäßige Backups konfigurieren"
            ])
            
        except Exception as e:
            postgres_vulns['error'] = str(e)
        
        return postgres_vulns
    
    def _check_security_headers(self, target_host: str, port: int = 80) -> Dict[str, Any]:
        """Prüft Security-Headers von Web-Services"""
        headers_info = {
            'target': f"{target_host}:{port}",
            'headers': {},
            'security_score': 0,
            'missing_headers': [],
            'recommendations': []
        }
        
        try:
            import requests
            
            # Teste HTTP und HTTPS
            protocols = ['http', 'https']
            if port == 443:
                protocols = ['https']
            elif port == 80:
                protocols = ['http']
            
            for protocol in protocols:
                try:
                    url = f"{protocol}://{target_host}:{port}"
                    response = requests.get(url, timeout=10, allow_redirects=False)
                    
                    # Sammle alle Security-Headers
                    security_headers = {
                        'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                        'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                        'X-Frame-Options': response.headers.get('X-Frame-Options'),
                        'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                        'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                        'Referrer-Policy': response.headers.get('Referrer-Policy'),
                        'Permissions-Policy': response.headers.get('Permissions-Policy'),
                        'Server': response.headers.get('Server'),
                        'X-Powered-By': response.headers.get('X-Powered-By')
                    }
                    
                    headers_info['headers'] = security_headers
                    
                    # Bewerte Security-Headers
                    score = 0
                    missing = []
                    
                    if security_headers['Strict-Transport-Security']:
                        score += 20
                    else:
                        missing.append('Strict-Transport-Security')
                    
                    if security_headers['X-Content-Type-Options'] == 'nosniff':
                        score += 15
                    else:
                        missing.append('X-Content-Type-Options')
                    
                    if security_headers['X-Frame-Options']:
                        score += 15
                    else:
                        missing.append('X-Frame-Options')
                    
                    if security_headers['X-XSS-Protection']:
                        score += 10
                    else:
                        missing.append('X-XSS-Protection')
                    
                    if security_headers['Content-Security-Policy']:
                        score += 20
                    else:
                        missing.append('Content-Security-Policy')
                    
                    if not security_headers['Server']:
                        score += 10
                    else:
                        missing.append('Server-Header verstecken')
                    
                    if not security_headers['X-Powered-By']:
                        score += 10
                    else:
                        missing.append('X-Powered-By-Header verstecken')
                    
                    headers_info['security_score'] = score
                    headers_info['missing_headers'] = missing
                    
                    # Empfehlungen basierend auf fehlenden Headers
                    if 'Strict-Transport-Security' in missing:
                        headers_info['recommendations'].append("HSTS-Header hinzufügen: max-age=31536000; includeSubDomains")
                    
                    if 'X-Content-Type-Options' in missing:
                        headers_info['recommendations'].append("X-Content-Type-Options: nosniff hinzufügen")
                    
                    if 'X-Frame-Options' in missing:
                        headers_info['recommendations'].append("X-Frame-Options: DENY oder SAMEORIGIN hinzufügen")
                    
                    if 'Content-Security-Policy' in missing:
                        headers_info['recommendations'].append("Content-Security-Policy-Header konfigurieren")
                    
                    if 'Server-Header verstecken' in missing:
                        headers_info['recommendations'].append("Server-Header in Web-Server-Konfiguration verstecken")
                    
                    break  # Verwende das erste erfolgreiche Protokoll
                    
                except Exception as e:
                    continue
            
        except Exception as e:
            headers_info['error'] = str(e)
        
        return headers_info
    
    def assess_network_security(self, internal_services: Dict, external_tests: Dict) -> Dict[str, Any]:
        """Bewertet die Netzwerk-Sicherheit basierend auf allen Tests"""
        security_assessment = {
            'analysis_summary': {
                'internal_analysis': {
                    'total_services': 0,
                    'external_interfaces': 0,
                    'firewall_status': 'unknown'
                },
                'external_analysis': {
                    'reachable_services': 0,
                    'dns_tests': False,
                    'vulnerability_indicators': 0
                }
            },
            'risk_level': 'low',  # low, medium, high, critical
            'exposed_services': [],
            'recommendations': [],
            'compliance_issues': []
        }
        
        console.print("[dim]🔍 Bewerte Netzwerk-Sicherheit...[/dim]")
        
        try:
            # Analysiere interne Services
            internal_ports = set()
            external_ports = set()
            
            # Sammle interne Analyse-Daten
            if 'service_mapping' in internal_services:
                security_assessment['analysis_summary']['internal_analysis']['total_services'] = len(internal_services['service_mapping'])
                for port, info in internal_services['service_mapping'].items():
                    internal_ports.add(port)
                    if info.get('external', False):
                        external_ports.add(port)
                        security_assessment['analysis_summary']['internal_analysis']['external_interfaces'] += 1
            
            # Sammle externe Analyse-Daten
            if 'reachable_ports' in external_tests:
                security_assessment['analysis_summary']['external_analysis']['reachable_services'] = len(external_tests['reachable_ports'])
            if 'dns_results' in external_tests:
                security_assessment['analysis_summary']['external_analysis']['dns_tests'] = True
            if 'vulnerability_indicators' in external_tests:
                security_assessment['analysis_summary']['external_analysis']['vulnerability_indicators'] = len(external_tests['vulnerability_indicators'])
            
            if 'service_mapping' in internal_services:
                for port, info in internal_services['service_mapping'].items():
                    internal_ports.add(port)
                    if info.get('external', False):
                        external_ports.add(port)
            
            # Analysiere externe Tests
            reachable_ports_raw = external_tests.get('reachable_ports', [])
            # Konvertiere zu Set, falls es Dictionaries sind
            reachable_ports = set()
            for port in reachable_ports_raw:
                if isinstance(port, dict):
                    reachable_ports.add(port.get('port', port))
                else:
                    reachable_ports.add(port)
            reachable_hosts = external_tests.get('reachable_hosts', {})
            
            # Identifiziere exponierte Services
            exposed_services = external_ports.intersection(reachable_ports)
            security_assessment['exposed_services'] = list(exposed_services)
            
            # Host-spezifische Expositionsanalyse mit IP-Klassifikation
            host_exposure = {}
            host_classification = {}
            public_hosts_only = {}
            
            for host, ports in reachable_hosts.items():
                if ports:
                    # Klassifiziere IP-Adresse
                    ip_class = self._classify_ip_address(host)
                    host_classification[host] = ip_class
                    
                    # Sammle alle exponierten Ports
                    exposed_ports = list(set(ports).intersection(external_ports))
                    host_exposure[host] = exposed_ports
                    
                    # Nur öffentliche IPs für externe Sicherheitsbewertung
                    if ip_class['type'] == 'public':
                        public_hosts_only[host] = exposed_ports
            
            security_assessment['host_exposure'] = host_exposure
            security_assessment['host_classification'] = host_classification
            security_assessment['public_host_exposure'] = public_hosts_only
            
            # Risiko-Bewertung (nur für öffentliche IPs)
            risk_score = 0
            
            # Berücksichtige nur öffentliche IPs für externe Sicherheitsbewertung
            public_exposed_services = set()
            for host, ports in public_hosts_only.items():
                public_exposed_services.update(ports)
            
            # Kritische Services (nur auf öffentlichen IPs)
            critical_services = {22, 23, 3389}  # SSH, Telnet, RDP
            if public_exposed_services.intersection(critical_services):
                risk_score += 3
            
            # Datenbank-Services (nur auf öffentlichen IPs)
            database_services = {3306, 5432, 1433, 1521}  # MySQL, PostgreSQL, MSSQL, Oracle
            if public_exposed_services.intersection(database_services):
                risk_score += 2
            
            # Web-Services (nur auf öffentlichen IPs)
            web_services = {80, 443, 8080, 8443}
            if public_exposed_services.intersection(web_services):
                risk_score += 1
            
            # Erweiterte Vulnerability-Bewertung
            vulnerability_count = len(external_tests.get('vulnerability_indicators', []))
            risk_score += vulnerability_count
            
            # Berücksichtige detaillierte Vulnerability-Analyse
            vulnerability_analysis = external_tests.get('vulnerability_analysis', {})
            total_critical_cves = 0
            total_high_cves = 0
            total_medium_cves = 0
            
            for port, vuln_info in vulnerability_analysis.items():
                total_critical_cves += len(vuln_info.get('critical_cves', []))
                total_high_cves += len(vuln_info.get('high_cves', []))
                total_medium_cves += len(vuln_info.get('medium_cves', []))
            
            # Gewichtete Risiko-Bewertung basierend auf CVE-Schweregrad
            risk_score += total_critical_cves * 5  # Kritische CVEs haben hohes Gewicht
            risk_score += total_high_cves * 3      # Hohe CVEs haben mittleres Gewicht
            risk_score += total_medium_cves * 1    # Mittlere CVEs haben niedriges Gewicht
            
            # Security-Headers-Bewertung
            security_headers_analysis = external_tests.get('security_headers_analysis', {})
            weak_headers_count = 0
            for target, headers_info in security_headers_analysis.items():
                if headers_info.get('security_score', 100) < 50:
                    weak_headers_count += 1
            
            risk_score += weak_headers_count * 2  # Schwache Security-Headers erhöhen Risiko
            
            # Risiko-Level bestimmen
            if risk_score >= 5:
                security_assessment['risk_level'] = 'critical'
            elif risk_score >= 3:
                security_assessment['risk_level'] = 'high'
            elif risk_score >= 1:
                security_assessment['risk_level'] = 'medium'
            else:
                security_assessment['risk_level'] = 'low'
            
            # Empfehlungen generieren (nur für öffentliche IPs)
            recommendations = []
            
            # Zähle private vs. öffentliche IPs
            private_hosts = sum(1 for host, class_info in host_classification.items() 
                              if class_info['type'] == 'private')
            public_hosts = sum(1 for host, class_info in host_classification.items() 
                             if class_info['type'] == 'public')
            
            if public_hosts > 0:
                if 22 in public_exposed_services:
                    recommendations.append("SSH ist auf öffentlichen IPs erreichbar - Prüfe Key-basierte Authentifizierung")
                
                if public_exposed_services.intersection(database_services):
                    recommendations.append("Datenbank-Services sind auf öffentlichen IPs erreichbar - Firewall-Regeln prüfen")
                
                if public_exposed_services.intersection(web_services):
                    recommendations.append("Web-Services sind auf öffentlichen IPs erreichbar - HTTPS erzwingen")
                
                            # Vulnerability-basierte Empfehlungen
            if total_critical_cves > 0:
                recommendations.append(f"🚨 {total_critical_cves} kritische CVEs gefunden - SOFORTIGE Updates erforderlich")
            
            if total_high_cves > 0:
                recommendations.append(f"⚠️  {total_high_cves} hohe CVEs gefunden - Prioritäre Updates empfohlen")
            
            if total_medium_cves > 0:
                recommendations.append(f"🔶 {total_medium_cves} mittlere CVEs gefunden - Updates planen")
            
            if weak_headers_count > 0:
                recommendations.append(f"🔒 {weak_headers_count} Services mit schwachen Security-Headers - Konfiguration prüfen")
            
            if vulnerability_count > 0:
                recommendations.append(f"📊 {vulnerability_count} Sicherheitsprobleme auf öffentlichen IPs gefunden - Detaillierte Analyse verfügbar")
            else:
                recommendations.append("Keine öffentlichen IPs erreichbar - System ist intern isoliert")
            
            if private_hosts > 0:
                recommendations.append(f"{private_hosts} private IP-Adressen gefunden - Normales internes Netzwerk")
            
            if not internal_services.get('firewall_status'):
                recommendations.append("Keine Firewall-Konfiguration gefunden - Firewall aktivieren")
            
            security_assessment['recommendations'] = recommendations
            
            # Compliance-Probleme (nur für öffentliche IPs)
            compliance_issues = []
            
            if 23 in public_exposed_services:  # Telnet
                compliance_issues.append("Telnet ist auf öffentlichen IPs aktiv - Nicht konform mit Sicherheitsstandards")
            
            if public_exposed_services.intersection(database_services):
                compliance_issues.append("Datenbank-Services auf öffentlichen IPs erreichbar - Datenschutz-Risiko")
            
            security_assessment['compliance_issues'] = compliance_issues
            
            console.print(f"[green]✅ Sicherheitsbewertung abgeschlossen: Risiko-Level {security_assessment['risk_level'].upper()}[/green]")
            
        except Exception as e:
            security_assessment['error'] = str(e)
            console.print(f"[red]❌ Fehler bei Sicherheitsbewertung: {e}[/red]")
        
        return security_assessment
    
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
    
    def test_sudo_availability(self) -> Dict[str, Any]:
        """Testet die Sudo-Verfügbarkeit und Berechtigungen"""
        sudo_info = {
            'available': False,
            'passwordless': False,
            'safe_commands': [],
            'tested_commands': []
        }
        
        # Prüfe ob Sudo verfügbar ist
        sudo_check = self.execute_remote_command('which sudo')
        if sudo_check:
            sudo_info['available'] = True
            
            # Prüfe ob Sudo ohne Passwort funktioniert
            sudo_test = self.execute_remote_command('sudo -n true')
            if sudo_test is not None:  # Kein Fehler bedeutet Erfolg
                sudo_info['passwordless'] = True
                
                # Teste einige sichere Befehle
                test_commands = [
                    'sudo ls /var/log',
                    'sudo cat /etc/hostname',
                    'sudo df -h',
                    'sudo ps aux | head -5'
                ]
                
                for cmd in test_commands:
                    result = self.execute_remote_command(cmd)
                    if result:
                        sudo_info['safe_commands'].append(cmd)
                    sudo_info['tested_commands'].append(cmd)
        
        return sudo_info


def start_interactive_chat(system_info: Dict[str, Any], log_entries: List[LogEntry], anomalies: List[Anomaly], args=None):
    # Debug-Modus aktivieren
    if args and hasattr(args, 'debug') and args.debug:
        console.debug_mode = True
    """Startet interaktiven Chat mit Ollama"""
    
    # Übersetzungen werden direkt im Chat verwendet - keine Abhängigkeit von i18n
    
    system_context = create_system_context(system_info, log_entries, anomalies)
    chat_history = []
    response_cache = {}
    initial_analysis_result = {'done': False, 'result': None}
    
    # Cache und Historie bereinigen (entferne alte, möglicherweise falsche Antworten)
    response_cache.clear()
    chat_history.clear()

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
        'proxmox': {
            'question': 'Wie ist der Status des Proxmox-Clusters?',
            'complex': False,
            'cache_key': 'proxmox_status'
        },
        'proxmox-problems': {
            'question': 'Welche Probleme gibt es im Proxmox-Cluster?',
            'complex': True,
            'cache_key': 'proxmox-problems'
        },
        'proxmox-vms': {
            'question': 'Welche VMs laufen auf Proxmox?',
            'complex': False,
            'cache_key': 'proxmox-vms'
        },
        'proxmox-containers': {
            'question': 'Welche Container laufen auf Proxmox?',
            'complex': False,
            'cache_key': 'proxmox-containers'
        },
        'proxmox-storage': {
            'question': 'Wie ist der Speicherplatz-Status im Proxmox-Cluster?',
            'complex': False,
            'cache_key': 'proxmox-storage'
        },
        'docker': {
            'question': 'Wie ist der Docker-Status und welche Container laufen?',
            'complex': False,
            'cache_key': 'docker_status'
        },
        'docker-problems': {
            'question': 'Welche Docker-Probleme gibt es?',
            'complex': True,
            'cache_key': 'docker_problems'
        },
        'docker-containers': {
            'question': 'Welche Docker-Container laufen?',
            'complex': False,
            'cache_key': 'docker_containers'
        },
        'docker-images': {
            'question': 'Welche Docker-Images sind installiert?',
            'complex': False,
            'cache_key': 'docker_images'
        },
        'mailcow': {
            'question': 'Wie ist der Mailcow-Status?',
            'complex': False,
            'cache_key': 'mailcow_status'
        },
        'mailcow-problems': {
            'question': 'Welche Mailcow-Probleme gibt es?',
            'complex': True,
            'cache_key': 'mailcow_problems'
        },
        'postfix': {
            'question': 'Wie ist der Postfix-Status?',
            'complex': False,
            'cache_key': 'postfix_status'
        },
        'postfix-problems': {
            'question': 'Welche Postfix-Probleme gibt es?',
            'complex': True,
            'cache_key': 'postfix_problems'
        },
        'mailservers': {
            'question': 'Welche Mailserver sind installiert und aktiv?',
            'complex': False,
            'cache_key': 'mailservers_status'
        },
        'report': {
            'question': 'Erstelle einen detaillierten Systembericht mit Handlungsanweisungen',
            'complex': True,
            'cache_key': 'system_report'
        },
        'network-security': {
            'question': 'Führe eine vollständige Netzwerk-Sicherheitsanalyse durch. Fokussiere dich ausschließlich auf Netzwerk-spezifische Themen wie lauschende Services, externe Erreichbarkeit, Firewall-Konfiguration, exponierte Ports und Netzwerk-Sicherheitsrisiken. Ignoriere andere Systemprobleme wie offline Nodes oder nicht-Netzwerk-bezogene Fehler.',
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
        },
        # 'help' und 'm' werden direkt behandelt, nicht als Shortcuts
    }
    
    # Verwende Übersetzungen oder Fallback
    def get_text(key):
        # Verwende die i18n-Übersetzungsfunktion
        from i18n import _, i18n
        # Erzwinge deutsche Sprache
        i18n.set_language('de')
        return _(key)
    
    console.print(f"\n[bold blue]💬 {get_text('chat_title')}[/bold blue]")
    console.print("="*60)
    console.print(get_text('chat_prompt'))
    # Verwende intelligentes Menü mit numerischen Kürzeln
    intelligent_menu = create_intelligent_menu(shortcuts)
    console.print(intelligent_menu)
    
    # Navigation
    console.print(f"\n[bold cyan]Navigation:[/bold cyan]")
    console.print(f"  • 'help' oder 'm' - {get_text('shortcut_help')}")
    console.print(f"  • 'exit', 'quit', 'q', 'bye', 'beenden' {get_text('chat_exit_commands')}")
    console.print("="*60)
    console.print(f"\n[dim]💡 {get_text('chat_tip')} ['q' to quit, 'm' -> Menü][/dim]")

    # Zeige Modell-Info nur im Debug-Modus
    if args and hasattr(args, 'debug') and args.debug:
        available_models = get_available_models()
        if available_models:
            # Prüfe auf qwen:0.5b für Menü
            menu_model = None
            for model in available_models:
                if "qwen" in model['name'].lower() and "0.5b" in model['name']:
                    menu_model = model
                    break
            
            if menu_model:
                console.print(f"[green]⚡ Ultraschnelles Menü-Modell verfügbar: {menu_model['name']}[/green]")
            
            # Zeige schnellstes Modell für normale Analysen
            sorted_models = sorted(available_models, key=lambda x: x.get('size', float('inf')))
            fastest_model = sorted_models[0]
            console.print(f"[green]✅ Schnellstes Modell für Analysen: {fastest_model['name']}[/green]")
        else:
            console.print("[yellow]⚠️  Keine Ollama-Modelle gefunden[/yellow]")
            console.print("[blue]💡 Empfohlene Installation: ollama pull llama3.2:3b[/blue]")

    # Hinweis, dass die Analyse im Hintergrund läuft
    console.print(f"\n[dim]🤖 {get_text('analysis_running')} ({get_text('chat_tip')} {get_text('chat_you')} ...)[/dim]")

    def run_initial_analysis():
        # Vereinfachter Prompt für Initialanalyse
        simple_prompt = f"""Du bist ein deutscher System-Administrator. Analysiere diese System-Daten und gib eine kurze Zusammenfassung in 2-3 Sätzen.

SPRACHE: Du MUSST auf Deutsch antworten, niemals auf Englisch.

System-Daten:
{system_context}

Zusammenfassung:"""
        
        # Nutze das schnellste verfügbare Modell für die Initialanalyse
        result = query_ollama(simple_prompt, model=select_best_model(complex_analysis=False, for_menu=False), complex_analysis=False)
        initial_analysis_result['result'] = result
        initial_analysis_result['done'] = True

    # Starte die Initialanalyse im Hintergrund
    analysis_thread = threading.Thread(target=run_initial_analysis, daemon=True)
    analysis_thread.start()

    # Chat-Loop
    while True:
        try:
            # Zeige das Initialanalyse-Ergebnis, sobald es fertig ist
            if initial_analysis_result['done'] and initial_analysis_result['result']:
                console.print(f"\n[bold green]🤖 {get_text('analysis_summary')}[/bold green]")
                console.print(initial_analysis_result['result'])
                initial_analysis_result['done'] = False  # Nur einmal anzeigen

            user_input = console.input(f"\n[bold cyan]{get_text('chat_you')}[/bold cyan] ").strip()

            # Prüfe auf Exit-Befehle
            if user_input.lower() in ['exit', 'quit', 'q', 'bye', 'beenden', 'tschüss', 'ciao']:
                console.print(f"\n[green]👋 {get_text('chat_goodbye')}[/green]")
                break

            # Prüfe auf leere Eingabe
            if not user_input:
                console.print(f"[dim]💡 Tipp: Verwenden Sie 'menu' für verfügbare Kürzelwörter oder stellen Sie eine Frage.[/dim]")
                continue

            # Intelligentes Menü anzeigen (VOR der Interpolation!)
            if user_input.lower() in ['help', 'm', 'menu']:
                console.print(f"[dim]🔍 Debug: Menü-Anfrage erkannt: '{user_input.lower()}'[/dim]")
                intelligent_menu = create_intelligent_menu(shortcuts)
                console.print(intelligent_menu)
                continue
            
            # Context Cache Status anzeigen
            if user_input.lower() in ['cache', 'c', 'status']:
                console.print(f"[dim]🔍 Debug: Cache-Status-Anfrage erkannt: '{user_input.lower()}'[/dim]")
                print_context_cache_status()
                continue
            
            # Context Cache löschen
            if user_input.lower() in ['clear', 'clear-cache']:
                console.print(f"[dim]🔍 Debug: Cache-Lösch-Anfrage erkannt: '{user_input.lower()}'[/dim]")
                clear_context_cache()
                continue

            # Proxmox-spezifische Befehle
            if 'proxmox_detected' in system_info and system_info['proxmox_detected']:
                # Proxmox-Refresh-Befehle
                if user_input.lower().startswith('proxmox-refresh') or user_input.lower().startswith('refresh-proxmox'):
                    target = "all"
                    if 'vms' in user_input.lower():
                        target = "vms"
                    elif 'containers' in user_input.lower() or 'lxc' in user_input.lower():
                        target = "containers"
                    elif 'storage' in user_input.lower():
                        target = "storage"
                    elif 'cluster' in user_input.lower():
                        target = "cluster"
                    elif 'ha' in user_input.lower():
                        target = "ha"
                    elif 'tasks' in user_input.lower():
                        target = "tasks"
                    elif 'backups' in user_input.lower():
                        target = "backups"
                    
                    console.print(f"[dim]🔄 Proxmox-Refresh erkannt: {target}[/dim]")
                    
                    # Erstelle eine temporäre SSH-Verbindung für den Refresh
                    # Verwende die aktuelle SSHLogCollector-Klasse, die die refresh_proxmox_data Methode hat
                    temp_collector = SSHLogCollector(
                        host=system_info.get('hostname', 'localhost'),
                        username=system_info.get('current_user', 'root'),
                        key_file=getattr(args, 'key_file', None) if args else None
                    )
                    
                    # Führe Refresh durch
                    refresh_data = temp_collector.refresh_proxmox_data(target)
                    
                    if refresh_data and not refresh_data.get("error"):
                        # Aktualisiere system_info mit neuen Proxmox-Daten
                        if 'proxmox' not in system_info:
                            system_info['proxmox'] = {}
                        
                        # Merge neue Daten
                        for key, value in refresh_data.items():
                            system_info['proxmox'][key] = value
                        
                        # Aktualisiere Systemkontext
                        system_context = create_system_context(system_info, log_entries, anomalies)
                        
                        console.print(f"[green]✅ Proxmox-Daten aktualisiert: {target}[/green]")
                        
                        # Zeige Zusammenfassung der aktualisierten Daten
                        if target == "vms" or target == "all":
                            vm_count = 0
                            for key in refresh_data.keys():
                                if key.endswith('_vms'):
                                    try:
                                        import json
                                        vms_data = json.loads(refresh_data[key])
                                        vm_count += len(vms_data)
                                    except:
                                        pass
                            if vm_count > 0:
                                console.print(f"[dim]📊 {vm_count} VMs gefunden[/dim]")
                        
                        if target == "containers" or target == "all":
                            container_count = 0
                            running_count = 0
                            stopped_count = 0
                            for key in refresh_data.keys():
                                if key.endswith('_containers'):
                                    try:
                                        import json
                                        containers_data = json.loads(refresh_data[key])
                                        container_count += len(containers_data)
                                        
                                        # Zähle laufende und gestoppte Container
                                        for container in containers_data:
                                            if container.get('template', False):
                                                continue  # Überspringe Templates
                                            if container.get('status') == 'running':
                                                running_count += 1
                                            else:
                                                stopped_count += 1
                                    except:
                                        pass
                            if container_count > 0:
                                console.print(f"[dim]📊 {container_count} Container gefunden ({running_count} laufend, {stopped_count} gestoppt)[/dim]")
                                
                                # Zeige detaillierte Container-Informationen für spezifische Container-Abfragen
                                if target == "containers":
                                    console.print(f"[dim]🔍 Detaillierte Container-Informationen gesammelt[/dim]")
                        
                        # Cache leeren für Proxmox-bezogene Fragen
                        clear_context_cache('proxmox')
                        
                    else:
                        error_msg = refresh_data.get("error", "Unbekannter Fehler") if refresh_data else "Keine Daten erhalten"
                        console.print(f"[red]❌ Fehler beim Proxmox-Refresh: {error_msg}[/red]")
                    
                    continue
                
                # Proxmox-Status-Befehle
                elif user_input.lower() in ['proxmox-status', 'proxmox-status']:
                    console.print(f"[dim]📊 Zeige Proxmox-Status...[/dim]")
                    
                    # Erstelle eine temporäre SSH-Verbindung
                    temp_collector = SSHLogCollector(
                        host=system_info.get('ssh_host', system_info.get('hostname', 'localhost')),
                        username=system_info.get('ssh_user', system_info.get('current_user', 'root')),
                        key_file=getattr(args, 'key_file', None) if args else None
                    )
                    
                    # Verbinde zur temporären SSH-Verbindung
                    if not temp_collector.connect():
                        console.print(f"[red]❌ Fehler bei SSH-Verbindung für Proxmox-Status[/red]")
                        continue
                    
                    # Hole aktuellen Status
                    status_data = temp_collector.refresh_proxmox_data("cluster")
                    
                    if status_data and not status_data.get("error"):
                        console.print(f"[green]✅ Proxmox-Cluster-Status:[/green]")
                        if 'cluster_status' in status_data:
                            try:
                                import json
                                cluster_info = json.loads(status_data['cluster_status'])
                                for node in cluster_info:
                                    node_name = node.get('node', 'Unbekannt')
                                    node_status = node.get('status', 'Unbekannt')
                                    console.print(f"  • {node_name}: {node_status}")
                            except:
                                console.print(f"[dim]{status_data['cluster_status']}[/dim]")
                    else:
                        console.print(f"[red]❌ Fehler beim Abrufen des Proxmox-Status[/red]")
                    
                    continue

            # Prüfe auf Kürzelwörter (robustere Erkennung)
            shortcut_used = False
            original_input = user_input.lower().strip()
            user_input_lower = user_input.lower().strip()
            complex_analysis = False  # Initialisiere complex_analysis
            cache_key = None  # Initialisiere cache_key
            interpolated_shortcut = None  # Initialisiere interpolated_shortcut
            
            # Erweiterte Kürzelwörter-Erkennung
            if user_input_lower in shortcuts:
                shortcut_info = shortcuts[user_input_lower]
                user_input = shortcut_info['question']
                complex_analysis = shortcut_info['complex']
                cache_key = shortcut_info['cache_key']
                shortcut_used = True
                interpolated_shortcut = user_input_lower  # Setze interpolated_shortcut für direkte Shortcuts

                console.print(f"[dim]Verwende Kürzelwort: {user_input}[/dim]")
            else:
                # Intelligente Abfrage-Interpolation mit Mini-Modell
                interpolated_shortcut = interpolate_user_input_to_shortcut(user_input_lower, shortcuts)
                if interpolated_shortcut:
                    try:
                        shortcut_info = shortcuts[interpolated_shortcut]
                        user_input = shortcut_info['question']
                        complex_analysis = shortcut_info['complex']
                        cache_key = shortcut_info['cache_key']
                        shortcut_used = True

                        console.print(f"[dim]Verwende interpoliertes Kürzelwort: {user_input} (aus '{original_input}')[/dim]")
                        
                        # Debug-Ausgabe für Modell-Auswahl
                        console.print(f"[dim]🔍 Shortcut: {interpolated_shortcut}, Complex: {complex_analysis}[/dim]")
                        console.print(f"[dim]🔍 Verfügbare Shortcuts: {list(shortcuts.keys())}[/dim]")
                        console.print(f"[dim]🔍 Cache Key: {cache_key}[/dim]")
                        console.print(f"[dim]🔍 Shortcut Info: {shortcut_info}[/dim]")
                        
                    except KeyError as e:
                        console.print(f"[red]❌ Fehler: Shortcut '{interpolated_shortcut}' nicht gefunden. Verfügbare: {list(shortcuts.keys())}[/red]")
                        console.print(f"[dim]🔍 Debug: interpolated_shortcut='{interpolated_shortcut}', user_input='{user_input_lower}'[/dim]")
                        continue
                
                # Spezielle Behandlung für Proxmox-Container
                if interpolated_shortcut and interpolated_shortcut == 'proxmox-containers':
                    console.print(f"[dim]🔄 Sammle detaillierte Proxmox-Container-Informationen...[/dim]")
                    
                    # Verwende die refresh_proxmox_data Methode mit "containers" Target
                    # Erstelle eine temporäre SSH-Verbindung
                    temp_collector = SSHLogCollector(
                        host=system_info.get('ssh_host', system_info.get('hostname', 'localhost')),
                        username=system_info.get('ssh_user', system_info.get('current_user', 'root')),
                        key_file=getattr(args, 'key_file', None) if args else None
                    )
                    
                    # Verbinde zur temporären SSH-Verbindung
                    if not temp_collector.connect():
                        console.print(f"[red]❌ Fehler bei SSH-Verbindung für Proxmox-Analyse[/red]")
                        continue
                    
                    # Hole detaillierte Container-Informationen über refresh_proxmox_data
                    detailed_containers = temp_collector.refresh_proxmox_data("containers")
                    
                    if detailed_containers and not detailed_containers.get("error"):
                        # Aktualisiere system_info mit Container-Daten
                        if 'proxmox' not in system_info:
                            system_info['proxmox'] = {}
                        
                        # Merge Container-Daten in system_info
                        for key, value in detailed_containers.items():
                            system_info['proxmox'][key] = value
                        
                        # Aktualisiere Systemkontext
                        system_context = create_system_context(system_info, log_entries, anomalies)
                        
                        console.print(f"[green]✅ Container-Informationen gesammelt[/green]")
                        
                        # Zeige Zusammenfassung basierend auf den gesammelten Daten
                        container_count = 0
                        running_count = 0
                        stopped_count = 0
                        
                        for key in detailed_containers.keys():
                            if key.endswith('_containers'):
                                try:
                                    import json
                                    containers_data = json.loads(detailed_containers[key])
                                    container_count += len(containers_data)
                                    
                                    for container in containers_data:
                                        if container.get('template', False):
                                            continue
                                        if container.get('status') == 'running':
                                            running_count += 1
                                        else:
                                            stopped_count += 1
                                except:
                                    pass
                        
                        if container_count > 0:
                            console.print(f"[dim]📊 {container_count} Container gefunden ({running_count} laufend, {stopped_count} gestoppt)[/dim]")
                        
                        # Cache leeren für Container-bezogene Fragen
                        clear_context_cache('proxmox')
                        
                        # Führe normale Chat-Analyse mit aktualisiertem Kontext durch
                        continue
                        
                    else:
                        error_msg = detailed_containers.get("error", "Unbekannter Fehler") if detailed_containers else "Keine Daten erhalten"
                        console.print(f"[red]❌ Fehler beim Sammeln der Container-Informationen: {error_msg}[/red]")
                        continue
                
                # Spezielle Behandlung für Netzwerk-Sicherheitsanalyse
                if interpolated_shortcut and interpolated_shortcut == 'network-security':
                    console.print(f"[dim]🔄 Führe vollständige Netzwerk-Sicherheitsanalyse durch...[/dim]")
                    
                    # Erstelle eine temporäre SSH-Verbindung
                    # Verwende die ursprünglichen Verbindungsdaten
                    temp_collector = SSHLogCollector(
                        host=system_info.get('ssh_host', system_info.get('hostname', 'localhost')),
                        username=system_info.get('ssh_user', system_info.get('current_user', 'root')),
                        key_file=getattr(args, 'key_file', None) if args else None
                    )
                    
                    # Verbinde zur temporären SSH-Verbindung
                    if not temp_collector.connect():
                        console.print(f"[red]❌ Fehler bei SSH-Verbindung für Netzwerk-Analyse[/red]")
                        continue
                    
                    # 1. Interne Service-Analyse
                    internal_services = temp_collector.analyze_listening_services()
                    
                    # 2. Externe Erreichbarkeit testen
                    all_ip_addresses = internal_services.get('all_ip_addresses', [])
                    if all_ip_addresses:
                        internal_ports = list(internal_services.get('service_mapping', {}).keys())
                        
                        if internal_ports:
                            external_tests = temp_collector.test_external_accessibility(all_ip_addresses, internal_ports)
                            
                            # 3. Sicherheitsbewertung
                            security_assessment = temp_collector.assess_network_security(internal_services, external_tests)
                            
                            # Aktualisiere system_info
                            if 'network_security' not in system_info:
                                system_info['network_security'] = {}
                            
                            system_info['network_security'].update({
                                'internal_services': internal_services,
                                'external_tests': external_tests,
                                'security_assessment': security_assessment
                            })
                            
                            # Aktualisiere Systemkontext mit Netzwerk-Fokus
                            system_context = create_system_context(system_info, log_entries, anomalies, focus_network_security=True)
                            
                            console.print(f"[green]✅ Netzwerk-Sicherheitsanalyse abgeschlossen[/green]")
                            
                            # Zeige Zusammenfassung
                            risk_level = security_assessment.get('risk_level', 'unknown')
                            exposed_count = len(security_assessment.get('exposed_services', []))
                            issues_count = len(security_assessment.get('recommendations', []))
                            
                            console.print(f"[dim]📊 Risiko-Level: {risk_level.upper()}, {exposed_count} exponierte Services, {issues_count} Empfehlungen[/dim]")
                            
                            # Cache leeren für Sicherheits-bezogene Fragen
                            clear_context_cache('security')
                            
                            # Führe normale Chat-Analyse mit aktualisiertem Kontext durch
                            continue
                        else:
                            console.print(f"[yellow]⚠️ Keine lauschenden Ports gefunden[/yellow]")
                            continue
                    else:
                        console.print(f"[yellow]⚠️ Keine externe IP-Adresse gefunden[/yellow]")
                        continue
                
                # Spezielle Behandlung für exponierte Services
                elif interpolated_shortcut and interpolated_shortcut == 'exposed-services':
                    console.print(f"[dim]🔄 Identifiziere exponierte Services...[/dim]")
                    
                    temp_collector = SSHLogCollector(
                        host=system_info.get('ssh_host', system_info.get('hostname', 'localhost')),
                        username=system_info.get('ssh_user', system_info.get('current_user', 'root')),
                        key_file=getattr(args, 'key_file', None) if args else None
                    )
                    
                    # Verbinde zur temporären SSH-Verbindung
                    if not temp_collector.connect():
                        console.print(f"[red]❌ Fehler bei SSH-Verbindung für Service-Analyse[/red]")
                        continue
                    
                    internal_services = temp_collector.analyze_listening_services()
                    all_ip_addresses = internal_services.get('all_ip_addresses', [])
                    
                    if all_ip_addresses and internal_services.get('service_mapping'):
                        internal_ports = list(internal_services.get('service_mapping', {}).keys())
                        
                        external_tests = temp_collector.test_external_accessibility(all_ip_addresses, internal_ports)
                        
                        # Aktualisiere system_info
                        if 'network_security' not in system_info:
                            system_info['network_security'] = {}
                        
                        system_info['network_security'].update({
                            'internal_services': internal_services,
                            'external_tests': external_tests
                        })
                        
                        system_context = create_system_context(system_info, log_entries, anomalies, focus_network_security=True)
                        
                        exposed_count = len(external_tests.get('reachable_ports', []))
                        console.print(f"[green]✅ Exponierte Services identifiziert: {exposed_count} Services erreichbar[/green]")
                        
                        clear_context_cache('security')
                        
                        # Führe normale Chat-Analyse mit aktualisiertem Kontext durch
                        continue
                
                # Spezielle Behandlung für Systembericht
                if original_input == 'report' or (interpolated_shortcut and interpolated_shortcut == 'report'):
                    console.print(f"[dim]🔄 Generiere detaillierten Systembericht...[/dim]")
                    
                    # Erstelle spezialisierten Prompt für Bericht
                    report_prompt = create_system_report_prompt(system_context)
                    
                    # Verwende komplexes Modell für Berichterstellung
                    model = select_best_model(complex_analysis=True, for_menu=False)
                    console.print(f"[dim]🔄 Wechsle zu komplexem Modell für detaillierte Berichterstellung...[/dim]")
                    
                    # Generiere Bericht
                    console.print(f"[dim]🤔 Denke nach...[/dim]")
                    report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
                    
                    if report_content:
                        # Speichere Bericht
                        console.print(f"[dim]💾 Speichere Bericht...[/dim]")
                        try:
                            filename = save_system_report(report_content, system_info)
                            console.print(f"\n[bold green]✅ Bericht erfolgreich gespeichert![/bold green]")
                            console.print(f"[green]📄 Datei: {filename}[/green]")
                            
                            # Zeige Bericht in Chat
                            console.print(f"\n[bold green]🤖 Ollama::[/bold green]")
                            console.print(report_content)
                            
                            # Cache die Antwort
                            if cache_key:
                                response_cache[cache_key] = report_content
                            
                            # Füge zur Chat-Historie hinzu
                            chat_history.append({"role": "user", "content": user_input})
                            chat_history.append({"role": "assistant", "content": report_content})
                            continue
                            
                        except Exception as e:
                            console.print(f"[red]❌ Fehler beim Speichern des Berichts: {e}[/red]")
                            continue
                    else:
                        console.print(f"[red]❌ Keine Antwort von Ollama erhalten[/red]")
                        continue
                
                # Prüfe Context Cache für Shortcuts
                if shortcut_used and interpolated_shortcut and interpolated_shortcut is not None:
                    # Bestimme Topic und Subtopic aus dem Shortcut
                    if interpolated_shortcut.startswith('proxmox-'):
                        topic = 'proxmox'
                        subtopic = interpolated_shortcut.replace('proxmox-', '')
                    elif interpolated_shortcut.startswith('k8s-'):
                        topic = 'kubernetes'
                        subtopic = interpolated_shortcut.replace('k8s-', '')
                    elif interpolated_shortcut in ['proxmox', 'k8s']:
                        topic = interpolated_shortcut
                        subtopic = 'status'
                    else:
                        topic = 'system'
                        subtopic = interpolated_shortcut
                    
                    # Prüfe Context Cache
                    cached_data = get_contextual_response(topic, subtopic)
                    if cached_data and cached_data.get('answer'):
                        cached_response = cached_data['answer']
                        if len(cached_response) > 50 and not cached_response.startswith('Benutzer:'):
                            console.print(f"[dim]📋 Context Cache: {topic}.{subtopic} für '{original_input}'[/dim]")
                            console.print(f"\n[bold green]🤖 {get_text('chat_ollama')}:[/bold green]")
                            console.print(cached_response)

                            # Füge zur Chat-Historie hinzu
                            chat_history.append({"role": "user", "content": user_input})
                            chat_history.append({"role": "assistant", "content": cached_response})
                            continue

            # Optimiere Kontextfenster für längere Konversationen
            optimized_history = optimize_context_window(chat_history)
            
            # Hole relevanten Kontext für die Frage
            context_for_question = get_context_for_question(user_input)
            
            # Erstelle erweiterten Chat-Prompt mit Kontext
            if context_for_question:
                enhanced_system_context = f"{system_context}\n\n{context_for_question}"
                prompt = create_chat_prompt(enhanced_system_context, user_input, optimized_history)
            else:
                prompt = create_chat_prompt(system_context, user_input, optimized_history)
            


            # Modell-Auswahl basierend auf Eingabe-Typ
            if shortcut_used:
                # Für die eigentliche Analyse nach Shortcut: besseres Modell
                if 'shortcut_info' in locals() and shortcut_info and shortcut_info.get('complex'):
                    model = select_best_model(complex_analysis=True, for_menu=False)
                    console.print(f"[dim]🔄 Wechsle zu komplexem Modell für detaillierte Analyse...[/dim]")
                else:
                    model = select_best_model(complex_analysis=False, for_menu=False)
                    console.print(f"[dim]🔄 Wechsle zu Standard-Modell für Analyse...[/dim]")
            else:
                # Bestimme Modell-Komplexität für freie Fragen
                complex_analysis = any(keyword in user_input.lower() for keyword in [
                    'problem', 'issue', 'error', 'failure', 'crash', 'anomaly', 'security',
                    'performance', 'bottleneck', 'optimization', 'recommendation', 'analysis',
                    'investigate', 'debug', 'troubleshoot', 'diagnose', 'lxc', 'container', 'proxmox'
                ])
                model = select_best_model(complex_analysis)

            # Zeige Modell-Info für Debugging
            if args and hasattr(args, 'debug') and args.debug:
                model_type = "Komplexes Modell" if complex_analysis else "Standard-Modell"
                console.print(f"[dim]🤖 Verwende {model_type}: {model}[/dim]")

            # Sende an Ollama
            console.print(f"[dim]🤔 {get_text('chat_thinking')}[/dim]")
            response = query_ollama(prompt, model=model, complex_analysis=complex_analysis)

            if response:
                console.print(f"\n[bold green]🤖 {get_text('chat_ollama')}:[/bold green]")
                console.print(response)

                # Cache die Antwort im Context Cache (nur echte Antworten)
                if shortcut_used and interpolated_shortcut and interpolated_shortcut is not None and response:
                    # Prüfe, ob es eine echte Antwort ist, nicht nur ein Prompt
                    if len(response) > 50 and not response.startswith('Benutzer:') and not response.startswith('Du:'):
                        # Bestimme Topic und Subtopic aus dem Shortcut
                        if interpolated_shortcut.startswith('proxmox-'):
                            topic = 'proxmox'
                            subtopic = interpolated_shortcut.replace('proxmox-', '')
                        elif interpolated_shortcut.startswith('k8s-'):
                            topic = 'kubernetes'
                            subtopic = interpolated_shortcut.replace('k8s-', '')
                        elif interpolated_shortcut in ['proxmox', 'k8s']:
                            topic = interpolated_shortcut
                            subtopic = 'status'
                        else:
                            topic = 'system'
                            subtopic = interpolated_shortcut
                        
                        # Cache im Context Cache
                        cache_contextual_response(topic, subtopic, user_input, response, system_context)
                        console.print(f"[dim]📋 Context Cache: {topic}.{subtopic} gecacht[/dim]")
                    else:
                        console.print(f"[dim]⚠️ Antwort zu kurz oder unvollständig - nicht gecacht[/dim]")

                # Füge zur Chat-Historie hinzu
                chat_history.append({"role": "user", "content": user_input})
                chat_history.append({"role": "assistant", "content": response})

                # Aktualisiere Konversations-Cache
                update_conversation_cache(chat_history)

                # Begrenze Historie auf letzte 10 Nachrichten
                if len(chat_history) > 10:
                    chat_history = chat_history[-10:]
            else:
                console.print(f"[red]❌ {get_text('chat_no_response')}[/red]")

            # Zeige das Initialanalyse-Ergebnis nur einmal nach der ersten Antwort
            if initial_analysis_result['done'] and initial_analysis_result['result'] and len(chat_history) == 2:
                console.print(f"\n[bold green]🤖 {get_text('analysis_summary')}[/bold green]")
                console.print(initial_analysis_result['result'])
                initial_analysis_result['done'] = False

        except KeyboardInterrupt:
            console.print(f"\n[green]👋 {get_text('chat_goodbye')}[/green]")
            break
        except Exception as e:
            console.print(f"[red]❌ Fehler im Chat: {e}[/red]")
            console.print(f"[dim]🔍 Debug: Exception Type: {type(e).__name__}[/dim]")
            console.print(f"[dim]🔍 Debug: Exception Args: {e.args}[/dim]")
            console.print(f"[dim]💡 Tipp: Verwenden Sie 'm' für verfügbare Kürzelwörter oder stellen Sie eine freie Frage.[/dim]")
            # Zeige verfügbare Shortcuts bei Fehlern
            if 'shortcut' in str(e).lower() or 'proxmox' in str(e).lower():
                console.print(f"[dim]Verfügbare Shortcuts: {list(shortcuts.keys())}[/dim]")
                # Sichere Prüfung der interpolated_shortcut Variable
                try:
                    debug_interpolated = interpolated_shortcut if 'interpolated_shortcut' in locals() else 'N/A'
                except UnboundLocalError:
                    debug_interpolated = 'N/A (UnboundLocalError)'
                console.print(f"[dim]🔍 Debug: Shortcut Error Details - interpolated_shortcut: {debug_interpolated}[/dim]")
            continue


def create_system_context(system_info: Dict[str, Any], log_entries: List[LogEntry], anomalies: List[Anomaly], focus_network_security: bool = False) -> str:
    """Erstellt einen strukturierten System-Kontext für Ollama"""
    context_parts = []
    
    # System-Basis-Informationen
    context_parts.append("=== SYSTEM-INFORMATIONEN ===")
    context_parts.append(f"Hostname: {system_info.get('hostname', 'Unbekannt')}")
    context_parts.append(f"Distribution: {system_info.get('distro_pretty_name', system_info.get('distro_name', 'Unbekannt'))}")
    context_parts.append(f"Kernel: {system_info.get('kernel_version', 'Unbekannt')}")
    context_parts.append(f"Architektur: {system_info.get('architecture', 'Unbekannt')}")
    
    # Bei Netzwerk-Sicherheitsanalyse nur relevante Basis-Informationen
    if not focus_network_security:
        context_parts.append(f"CPU: {system_info.get('cpu_info', 'Unbekannt')}")
        context_parts.append(f"CPU-Kerne: {system_info.get('cpu_cores', 'Unbekannt')}")
        context_parts.append(f"RAM: {system_info.get('memory_total', 'Unbekannt')}")
        context_parts.append(f"Uptime: {system_info.get('uptime', 'Unbekannt')}")
        context_parts.append(f"Zeitzone: {system_info.get('timezone', 'Unbekannt')}")
    
    # Speicherplatz (nur bei nicht-Netzwerk-Analysen)
    if not focus_network_security:
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
                if isinstance(system_info['largest_files'], list):
                    for file_info in system_info['largest_files'][:10]:
                        context_parts.append(file_info)
                else:
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
                    if isinstance(files, list):
                        for file_info in files[:5]:
                            context_parts.append(f"  {file_info}")
                    else:
                        lines = files.split('\n')[:5]
                        for line in lines:
                            if line.strip():
                                context_parts.append(f"  {line.strip()}")
    
    # Services (nur bei nicht-Netzwerk-Analysen)
    if not focus_network_security:
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
        
        # Docker-Informationen
        if 'docker_detected' in system_info and system_info['docker_detected']:
            context_parts.append("\n=== DOCKER-SYSTEM ===")
            
            if 'docker_version' in system_info:
                context_parts.append(f"Version: {system_info['docker_version']}")
            
            if 'docker_info' in system_info:
                context_parts.append("Docker-Info:")
                context_parts.append(system_info['docker_info'])
            
            if 'running_containers' in system_info:
                context_parts.append("Laufende Container:")
                context_parts.append(system_info['running_containers'])
            
            if 'all_containers' in system_info:
                context_parts.append("Alle Container:")
                context_parts.append(system_info['all_containers'])
            
            if 'docker_containers' in system_info:
                context_parts.append("Docker-Container Details:")
                context_parts.append(system_info['docker_containers'])
            
            if 'docker_images' in system_info:
                context_parts.append("Docker-Images:")
                context_parts.append(system_info['docker_images'])
            
            if 'docker_volumes' in system_info:
                context_parts.append("Docker-Volumes:")
                context_parts.append(system_info['docker_volumes'])
            
            if 'docker_networks' in system_info:
                context_parts.append("Docker-Netzwerke:")
                context_parts.append(system_info['docker_networks'])
            
            if 'system_usage' in system_info:
                context_parts.append("Docker-System-Nutzung:")
                context_parts.append(system_info['system_usage'])
            
            # DETAILLIERTE CONTAINER-ANALYSE
            if 'container_details' in system_info:
                context_parts.append("\n=== DETAILLIERTE CONTAINER-ANALYSE ===")
                
                container_details = system_info['container_details']
                for container_name, details in container_details.items():
                    context_parts.append(f"\n--- Container: {container_name} ---")
                    
                    # Health-Status
                    if 'health_status' in details:
                        health_status = details['health_status']
                        context_parts.append(f"Health-Status: {health_status}")
                        
                        if 'unhealthy' in health_status.lower() and 'health_logs' in details:
                            context_parts.append("Health-Check-Fehler:")
                            context_parts.append(details['health_logs'])
                    
                    # Restart-Policy
                    if 'restart_policy' in details:
                        context_parts.append(f"Restart-Policy: {details['restart_policy']}")
                    
                    # Uptime
                    if 'started_at' in details:
                        context_parts.append(f"Gestartet: {details['started_at']}")
                    
                    # Exit-Code (falls vorhanden)
                    if 'exit_code' in details:
                        context_parts.append(f"Exit-Code: {details['exit_code']}")
                    
                    # Log-Fehler und Warnungen
                    if 'errors' in details and details['errors']:
                        context_parts.append("Letzte Fehler in Logs:")
                        for error in details['errors'][-5:]:  # Letzte 5 Fehler
                            context_parts.append(f"  ERROR: {error}")
                    
                    if 'warnings' in details and details['warnings']:
                        context_parts.append("Letzte Warnungen in Logs:")
                        for warning in details['warnings'][-5:]:  # Letzte 5 Warnungen
                            context_parts.append(f"  WARN: {warning}")
            
            # Container-Statistiken
            if 'container_stats' in system_info:
                context_parts.append("\n=== CONTAINER-STATISTIKEN ===")
                container_stats = system_info['container_stats']
                for container_name, stats in container_stats.items():
                    context_parts.append(f"\n{container_name}:")
                    context_parts.append(stats)
            
            # Docker-Probleme
            if 'problems_count' in system_info and system_info['problems_count'] > 0:
                context_parts.append(f"\n=== DOCKER-PROBLEME ({system_info['problems_count']} gefunden) ===")
                for i, problem in enumerate(system_info['problems'], 1):
                    context_parts.append(f"Problem {i}: {problem}")
        
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
    
    # Proxmox-Cluster
    if 'proxmox_detected' in system_info and system_info['proxmox_detected']:
        context_parts.append("\n=== PROXMOX-CLUSTER ===")
        
        if 'proxmox_version' in system_info:
            context_parts.append(f"Version: {system_info['proxmox_version']}")
        
        if 'cluster_status' in system_info:
            context_parts.append("Cluster-Status:")
            context_parts.append(system_info['cluster_status'])
        
        if 'cluster_config' in system_info:
            context_parts.append("Cluster-Konfiguration:")
            context_parts.append(system_info['cluster_config'])
        
        if 'nodes' in system_info:
            context_parts.append("Nodes:")
            context_parts.append(system_info['nodes'])
        
        # Strukturierte Node-Details mit VMs und Containern
        if 'node_details' in system_info:
            context_parts.append("Node-Details:")
            for key, value in system_info['node_details'].items():
                context_parts.append(f"{key}: {value}")
        
        # Neue strukturierte Proxmox-Daten (aus Refresh)
        if 'proxmox' in system_info:
            proxmox_data = system_info['proxmox']
            
            # VMs nach Nodes
            vm_nodes = [key for key in proxmox_data.keys() if key.endswith('_vms')]
            if vm_nodes:
                context_parts.append("\n=== PROXMOX-VMs ===")
                for node_key in vm_nodes:
                    node_name = node_key.replace('_vms', '')
                    try:
                        import json
                        vms_data = json.loads(proxmox_data[node_key])
                        context_parts.append(f"\n{node_name}:")
                        for vm in vms_data:
                            vm_id = vm.get('vmid', 'N/A')
                            vm_name = vm.get('name', 'N/A')
                            vm_status = vm.get('status', 'N/A')
                            vm_cpu = vm.get('cpu', 'N/A')
                            vm_memory = vm.get('mem', 'N/A')
                            context_parts.append(f"  VM {vm_id}: {vm_name} ({vm_status}) - CPU: {vm_cpu}%, RAM: {vm_memory}MB")
                    except:
                        context_parts.append(f"{node_name}: {proxmox_data[node_key]}")
            
            # Container nach Nodes
            container_nodes = [key for key in proxmox_data.keys() if key.endswith('_containers')]
            if container_nodes:
                context_parts.append("\n=== PROXMOX-CONTAINER ===")
                for node_key in container_nodes:
                    node_name = node_key.replace('_containers', '')
                    try:
                        import json
                        containers_data = json.loads(proxmox_data[node_key])
                        context_parts.append(f"\n{node_name}:")
                        
                        # Kategorisiere Container nach Status
                        running_containers = []
                        stopped_containers = []
                        
                        for container in containers_data:
                            ct_id = container.get('vmid', 'N/A')
                            ct_name = container.get('name', 'N/A')
                            ct_status = container.get('status', 'N/A')
                            ct_cpu = container.get('cpu', 'N/A')
                            ct_memory = container.get('mem', 'N/A')
                            ct_template = container.get('template', False)
                            
                            # Überspringe Templates
                            if ct_template:
                                continue
                            
                            container_info = f"  CT {ct_id}: {ct_name} ({ct_status}) - CPU: {ct_cpu}%, RAM: {ct_memory}MB"
                            
                            # Hole detaillierte Informationen falls verfügbar
                            detailed_key = f'{node_name}_detailed_containers'
                            if detailed_key in proxmox_data:
                                try:
                                    detailed_containers = proxmox_data[detailed_key]
                                    container_detail_key = f'container_{ct_id}'
                                    if container_detail_key in detailed_containers:
                                        container_detail = json.loads(detailed_containers[container_detail_key])
                                        uptime = container_detail.get('uptime', 0)
                                        if uptime > 0:
                                            uptime_hours = uptime // 3600
                                            uptime_minutes = (uptime % 3600) // 60
                                            container_info += f" - Uptime: {uptime_hours}h {uptime_minutes}m"
                                        
                                        # Memory-Details
                                        memory_info = container_detail.get('memory', {})
                                        if memory_info:
                                            used_memory = memory_info.get('used', 0)
                                            total_memory = memory_info.get('total', 0)
                                            if total_memory > 0:
                                                memory_percent = (used_memory / total_memory) * 100
                                                container_info += f" - Memory: {used_memory}MB/{total_memory}MB ({memory_percent:.1f}%)"
                                except:
                                    pass
                            
                            if ct_status == 'running':
                                running_containers.append(container_info)
                            else:
                                stopped_containers.append(container_info)
                        
                        # Zeige laufende Container zuerst
                        if running_containers:
                            context_parts.append("  Laufende Container:")
                            for container in running_containers:
                                context_parts.append(container)
                        
                        # Zeige gestoppte Container
                        if stopped_containers:
                            context_parts.append("  Gestoppte Container:")
                            for container in stopped_containers:
                                context_parts.append(container)
                        
                        # Zusammenfassung
                        total_containers = len(running_containers) + len(stopped_containers)
                        context_parts.append(f"  Zusammenfassung: {total_containers} Container ({len(running_containers)} laufend, {len(stopped_containers)} gestoppt)")
                        
                    except:
                        context_parts.append(f"{node_name}: {proxmox_data[node_key]}")
            
            # Detaillierte Container-Informationen (aus get_detailed_proxmox_containers)
            if 'detailed_containers' in proxmox_data:
                detailed_containers = proxmox_data['detailed_containers']
                if not detailed_containers.get("error"):
                    context_parts.append("\n=== DETAILLIERTE PROXMOX-CONTAINER-INFO ===")
                    
                    summary = detailed_containers.get('summary', {})
                    total = summary.get('total_containers', 0)
                    running = summary.get('running_containers', 0)
                    stopped = summary.get('stopped_containers', 0)
                    nodes = summary.get('nodes_with_containers', 0)
                    
                    context_parts.append(f"Gesamtübersicht: {total} Container auf {nodes} Nodes ({running} laufend, {stopped} gestoppt)")
                    
                    # Laufende Container
                    running_containers = detailed_containers.get('running_containers', [])
                    if running_containers:
                        context_parts.append("\nLaufende Container:")
                        for container in running_containers:
                            ct_id = container.get('id', 'N/A')
                            ct_name = container.get('name', 'N/A')
                            ct_node = container.get('node', 'N/A')
                            ct_cpu = container.get('cpu', 0)
                            ct_memory = container.get('memory', {})
                            ct_uptime = container.get('uptime', 0)
                            
                            # Memory-Details
                            memory_str = "N/A"
                            if ct_memory:
                                used_memory = ct_memory.get('used', 0)
                                total_memory = ct_memory.get('total', 0)
                                if total_memory > 0:
                                    memory_percent = (used_memory / total_memory) * 100
                                    memory_str = f"{used_memory}MB/{total_memory}MB ({memory_percent:.1f}%)"
                            
                            # Uptime-Formatierung
                            uptime_str = "N/A"
                            if ct_uptime > 0:
                                uptime_hours = ct_uptime // 3600
                                uptime_minutes = (ct_uptime % 3600) // 60
                                uptime_str = f"{uptime_hours}h {uptime_minutes}m"
                            
                            context_parts.append(f"  CT {ct_id} ({ct_node}): {ct_name} - CPU: {ct_cpu}%, Memory: {memory_str}, Uptime: {uptime_str}")
                    
                    # Gestoppte Container
                    stopped_containers = detailed_containers.get('stopped_containers', [])
                    if stopped_containers:
                        context_parts.append("\nGestoppte Container:")
                        for container in stopped_containers:
                            ct_id = container.get('id', 'N/A')
                            ct_name = container.get('name', 'N/A')
                            ct_node = container.get('node', 'N/A')
                            context_parts.append(f"  CT {ct_id} ({ct_node}): {ct_name}")
                    
                    # Node-Zusammenfassung
                    nodes_with_containers = detailed_containers.get('nodes_with_containers', [])
                    if nodes_with_containers:
                        context_parts.append("\nContainer pro Node:")
                        for node_info in nodes_with_containers:
                            node_name = node_info.get('node', 'N/A')
                            total = node_info.get('total', 0)
                            running = node_info.get('running', 0)
                            stopped = node_info.get('stopped', 0)
                            context_parts.append(f"  {node_name}: {total} Container ({running} laufend, {stopped} gestoppt)")
            
            # Node-Status
            status_nodes = [key for key in proxmox_data.keys() if key.endswith('_status')]
            if status_nodes:
                context_parts.append("\n=== PROXMOX-NODE-STATUS ===")
                for node_key in status_nodes:
                    node_name = node_key.replace('_status', '')
                    context_parts.append(f"{node_name}: {proxmox_data[node_key]}")
            
            # Tasks
            task_nodes = [key for key in proxmox_data.keys() if key.endswith('_tasks')]
            if task_nodes:
                context_parts.append("\n=== PROXMOX-TASKS ===")
                for node_key in task_nodes:
                    node_name = node_key.replace('_tasks', '')
                    context_parts.append(f"{node_name}: {proxmox_data[node_key]}")
            
            # Backup-Jobs
            backup_nodes = [key for key in proxmox_data.keys() if key.endswith('_backup_jobs')]
            if backup_nodes:
                context_parts.append("\n=== PROXMOX-BACKUP-JOBS ===")
                for node_key in backup_nodes:
                    node_name = node_key.replace('_backup_jobs', '')
                    context_parts.append(f"{node_name}: {proxmox_data[node_key]}")
        
        if 'storage' in system_info:
            context_parts.append("\nStorage:")
            context_parts.append(system_info['storage'])
        
        if 'network_config' in system_info:
            context_parts.append("Netzwerk-Konfiguration:")
            context_parts.append(system_info['network_config'])
        
        if 'resource_usage' in system_info:
            context_parts.append("Ressourcen-Auslastung:")
            context_parts.append(system_info['resource_usage'])
        
        if 'ha_status' in system_info:
            context_parts.append("HA-Status:")
            context_parts.append(system_info['ha_status'])
        
        if 'zfs_status' in system_info:
            context_parts.append("ZFS-Status:")
            context_parts.append(system_info['zfs_status'])
        
        if 'ceph_status' in system_info:
            context_parts.append("Ceph-Status:")
            context_parts.append(system_info['ceph_status'])
        
        # Proxmox-Probleme
        if 'problems_count' in system_info and system_info['problems_count'] > 0:
            context_parts.append(f"\nPROXMOX-PROBLEME ({system_info['problems_count']} gefunden):")
            for i, problem in enumerate(system_info['problems'], 1):
                context_parts.append(f"Problem {i}: {problem}")
        
        if 'recent_events' in system_info:
            context_parts.append("Kürzliche Events:")
            context_parts.append(system_info['recent_events'])
    
    # Netzwerk-Sicherheitsanalyse (nur bei Netzwerk-Fokus oder wenn explizit gefragt)
    if 'network_security' in system_info and focus_network_security:
        network_data = system_info['network_security']
        context_parts.append("\n=== NETZWERK-SICHERHEITSANALYSE ===")
        
        # Interne Services
        if 'internal_services' in network_data:
            internal_services = network_data['internal_services']
            
            if 'service_mapping' in internal_services:
                context_parts.append("Lauschende Services:")
                for port, info in internal_services['service_mapping'].items():
                    address = info.get('address', 'N/A')
                    external = "extern" if info.get('external', False) else "intern"
                    context_parts.append(f"  Port {port}: {address} ({external})")
            
            if 'all_ip_addresses' in internal_services:
                context_parts.append(f"Alle IP-Adressen: {', '.join(internal_services['all_ip_addresses'])}")
            
            if 'firewall_status' in internal_services:
                firewall_status = internal_services['firewall_status']
                if firewall_status:
                    context_parts.append("Firewall-Status:")
                    for fw_type, status in firewall_status.items():
                        context_parts.append(f"  {fw_type}: Aktiv")
                else:
                    context_parts.append("Firewall-Status: Keine Firewall konfiguriert")
        
        # Externe Tests
        if 'external_tests' in network_data:
            external_tests = network_data['external_tests']
            
            if 'reachable_ports' in external_tests:
                reachable_ports = external_tests['reachable_ports']
                if reachable_ports:
                    context_parts.append(f"Extern erreichbare Ports: {', '.join(map(str, reachable_ports))}")
                else:
                    context_parts.append("Extern erreichbare Ports: Keine")
            
            # Detaillierte Host-Informationen
            if 'reachable_hosts' in external_tests:
                reachable_hosts = external_tests['reachable_hosts']
                if reachable_hosts:
                    context_parts.append("Erreichbare Hosts und Ports:")
                    for host, ports in reachable_hosts.items():
                        if ports:
                            context_parts.append(f"  {host}: {', '.join(map(str, ports))}")
                else:
                    context_parts.append("Erreichbare Hosts: Keine")
            
            if 'service_versions' in external_tests:
                service_versions = external_tests['service_versions']
                if service_versions:
                    context_parts.append("Service-Versionen:")
                    for port, version in service_versions.items():
                        context_parts.append(f"  Port {port}: {version}")
            
            # Erweiterte Vulnerability-Analyse
            if 'vulnerability_analysis' in external_tests:
                vuln_analysis = external_tests['vulnerability_analysis']
                if vuln_analysis:
                    context_parts.append("Vulnerability-Analyse:")
                    for port, vuln_info in vuln_analysis.items():
                        service_name = vuln_info.get('service', f'Service-{port}')
                        version = vuln_info.get('version', 'Unbekannt')
                        context_parts.append(f"  {service_name} {version} (Port {port}):")
                        
                        if vuln_info.get('critical_cves'):
                            context_parts.append(f"    🚨 Kritische CVEs: {len(vuln_info['critical_cves'])}")
                            for cve in vuln_info['critical_cves'][:3]:  # Zeige nur die ersten 3
                                context_parts.append(f"      • {cve['id']} (Score: {cve['score']})")
                        
                        if vuln_info.get('high_cves'):
                            context_parts.append(f"    ⚠️  Hohe CVEs: {len(vuln_info['high_cves'])}")
                            for cve in vuln_info['high_cves'][:3]:  # Zeige nur die ersten 3
                                context_parts.append(f"      • {cve['id']} (Score: {cve['score']})")
                        
                        if vuln_info.get('medium_cves'):
                            context_parts.append(f"    🔶 Mittlere CVEs: {len(vuln_info['medium_cves'])}")
                        
                        if vuln_info.get('low_cves'):
                            context_parts.append(f"    🔵 Niedrige CVEs: {len(vuln_info['low_cves'])}")
                        
                        # Service-spezifische Empfehlungen
                        if vuln_info.get('recommendations'):
                            context_parts.append(f"    💡 Empfehlungen:")
                            for rec in vuln_info['recommendations'][:3]:  # Zeige nur die ersten 3
                                context_parts.append(f"      • {rec}")
            
            # Security-Headers-Analyse
            if 'security_headers_analysis' in external_tests:
                headers_analysis = external_tests['security_headers_analysis']
                if headers_analysis:
                    context_parts.append("Security-Headers-Analyse:")
                    for target, headers_info in headers_analysis.items():
                        score = headers_info.get('security_score', 0)
                        score_emoji = "🟢" if score >= 80 else "🟡" if score >= 50 else "🔴"
                        context_parts.append(f"  {score_emoji} {target}: Score {score}/100")
                        
                        if headers_info.get('missing_headers'):
                            context_parts.append(f"    Fehlende Headers: {', '.join(headers_info['missing_headers'][:3])}")
                        
                        if headers_info.get('recommendations'):
                            context_parts.append(f"    💡 Empfehlungen:")
                            for rec in headers_info['recommendations'][:2]:  # Zeige nur die ersten 2
                                context_parts.append(f"      • {rec}")
            
            # Legacy Vulnerability-Indikatoren
            if 'vulnerability_indicators' in external_tests:
                vuln_indicators = external_tests['vulnerability_indicators']
                if vuln_indicators:
                    context_parts.append("Sicherheitsprobleme:")
                    for indicator in vuln_indicators:
                        context_parts.append(f"  • {indicator}")
        
        # Sicherheitsbewertung
        if 'security_assessment' in network_data:
            assessment = network_data['security_assessment']
            
            if 'risk_level' in assessment:
                context_parts.append(f"Sicherheitsrisiko: {assessment['risk_level'].upper()}")
            
            if 'exposed_services' in assessment:
                exposed_services = assessment['exposed_services']
                if exposed_services:
                    context_parts.append(f"Exponierte Services: {', '.join(map(str, exposed_services))}")
            
            if 'host_exposure' in assessment:
                host_exposure = assessment['host_exposure']
                host_classification = assessment.get('host_classification', {})
                if host_exposure:
                    context_parts.append("Host-spezifische Exposition:")
                    for host, ports in host_exposure.items():
                        if ports:
                            # IP-Klassifikation anzeigen
                            ip_class = host_classification.get(host, {})
                            ip_type = ip_class.get('type', 'unknown')
                            ip_rfc = ip_class.get('rfc', 'N/A')
                            ip_explanation = ip_class.get('explanation', '')
                            
                            if ip_type == 'private':
                                context_parts.append(f"  **{host}:** {', '.join(map(str, ports))} ({ip_rfc} - {ip_explanation})")
                            elif ip_type == 'public':
                                context_parts.append(f"  **{host}:** {', '.join(map(str, ports))} ({ip_rfc} - {ip_explanation})")
                            else:
                                context_parts.append(f"  **{host}:** {', '.join(map(str, ports))} ({ip_type})")
                    
                    # Zusammenfassung der IP-Typen
                    private_count = sum(1 for host, class_info in host_classification.items() 
                                      if class_info.get('type') == 'private')
                    public_count = sum(1 for host, class_info in host_classification.items() 
                                     if class_info.get('type') == 'public')
                    
                    if private_count > 0:
                        context_parts.append(f"  📍 {private_count} private IP-Adressen (RFC 1918/4193) - Normales internes Netzwerk")
                    if public_count > 0:
                        context_parts.append(f"  🌐 {public_count} öffentliche IP-Adressen - Extern erreichbar")
            
            if 'recommendations' in assessment:
                recommendations = assessment['recommendations']
                if recommendations:
                    context_parts.append("Sicherheitsempfehlungen:")
                    for rec in recommendations:
                        # Markiere wichtige Empfehlungen
                        if 'öffentlichen IPs' in rec:
                            context_parts.append(f"  ⚠️  {rec}")
                        elif 'private IP-Adressen' in rec:
                            context_parts.append(f"  ℹ️  {rec}")
                        elif 'intern isoliert' in rec:
                            context_parts.append(f"  ✅ {rec}")
                        else:
                            context_parts.append(f"  • {rec}")
            
            if 'compliance_issues' in assessment:
                compliance_issues = assessment['compliance_issues']
                if compliance_issues:
                    context_parts.append("Compliance-Probleme:")
                    for issue in compliance_issues:
                        context_parts.append(f"  • {issue}")
    
    # Docker-Container
    if 'docker_detected' in system_info and system_info['docker_detected']:
        context_parts.append("\n=== DOCKER ===")
        
        if 'docker_version' in system_info:
            context_parts.append(f"Version: {system_info['docker_version']}")
        
        if 'running_containers' in system_info:
            context_parts.append("Laufende Container:")
            context_parts.append(system_info['running_containers'])
        
        if 'all_containers' in system_info:
            context_parts.append("Alle Container:")
            context_parts.append(system_info['all_containers'])
        
        if 'images' in system_info:
            context_parts.append("Docker-Images:")
            context_parts.append(system_info['images'])
        
        if 'system_usage' in system_info:
            context_parts.append("Docker-System-Nutzung:")
            context_parts.append(system_info['system_usage'])
        
        # DETAILLIERTE CONTAINER-ANALYSE
        if 'container_details' in system_info:
            context_parts.append("\n=== DETAILLIERTE CONTAINER-ANALYSE ===")
            
            container_details = system_info['container_details']
            for container_name, details in container_details.items():
                context_parts.append(f"\n--- Container: {container_name} ---")
                
                # Health-Status
                if 'health_status' in details:
                    health_status = details['health_status']
                    context_parts.append(f"Health-Status: {health_status}")
                    
                    if 'unhealthy' in health_status.lower() and 'health_logs' in details:
                        context_parts.append("Health-Check-Fehler:")
                        context_parts.append(details['health_logs'])
                
                # Restart-Policy
                if 'restart_policy' in details:
                    context_parts.append(f"Restart-Policy: {details['restart_policy']}")
                
                # Uptime
                if 'started_at' in details:
                    context_parts.append(f"Gestartet: {details['started_at']}")
                
                # Exit-Code (falls vorhanden)
                if 'exit_code' in details:
                    context_parts.append(f"Exit-Code: {details['exit_code']}")
                
                # Log-Fehler und Warnungen
                if 'errors' in details and details['errors']:
                    context_parts.append("Letzte Fehler in Logs:")
                    for error in details['errors'][-5:]:  # Letzte 5 Fehler
                        context_parts.append(f"  ERROR: {error}")
                
                if 'warnings' in details and details['warnings']:
                    context_parts.append("Letzte Warnungen in Logs:")
                    for warning in details['warnings'][-5:]:  # Letzte 5 Warnungen
                        context_parts.append(f"  WARN: {warning}")
        
        # Container-Statistiken
        if 'container_stats' in system_info:
            context_parts.append("\n=== CONTAINER-STATISTIKEN ===")
            container_stats = system_info['container_stats']
            for container_name, stats in container_stats.items():
                context_parts.append(f"\n{container_name}:")
                context_parts.append(stats)
        
        # Docker-Probleme
        if 'problems_count' in system_info and system_info['problems_count'] > 0:
            context_parts.append(f"\nDOCKER-PROBLEME ({system_info['problems_count']} gefunden):")
            for i, problem in enumerate(system_info['problems'], 1):
                context_parts.append(f"Problem {i}: {problem}")
    
    # Mailserver
    if 'mailserver_detected' in system_info and system_info['mailserver_detected']:
        context_parts.append("\n=== MAILSERVER ===")
        
        # Mailcow
        if 'mailcow_detected' in system_info and system_info['mailcow_detected']:
            context_parts.append("Mailcow:")
            if 'mailcow' in system_info:
                mailcow_data = system_info['mailcow']
                if 'version' in mailcow_data:
                    context_parts.append(f"  Version: {mailcow_data['version']}")
                if 'status' in mailcow_data:
                    context_parts.append(f"  Status: {mailcow_data['status']}")
                if 'containers' in mailcow_data:
                    context_parts.append(f"  Container: {mailcow_data['containers']}")
                if 'problems_count' in mailcow_data and mailcow_data['problems_count'] > 0:
                    context_parts.append(f"  Probleme: {mailcow_data['problems_count']} gefunden")
        
        # Postfix
        if 'postfix_detected' in system_info and system_info['postfix_detected']:
            context_parts.append("Postfix:")
            if 'postfix' in system_info:
                postfix_data = system_info['postfix']
                if 'version' in postfix_data:
                    context_parts.append(f"  Version: {postfix_data['version']}")
                if 'status' in postfix_data:
                    context_parts.append(f"  Status: {postfix_data['status']}")
                if 'queue_status' in postfix_data:
                    context_parts.append(f"  Queue: {postfix_data['queue_status']}")
                if 'problems_count' in postfix_data and postfix_data['problems_count'] > 0:
                    context_parts.append(f"  Probleme: {postfix_data['problems_count']} gefunden")
        
        # Andere Mailserver
        if 'other_mailservers' in system_info:
            context_parts.append("Andere Mailserver:")
            for server, status in system_info['other_mailservers'].items():
                context_parts.append(f"  {server}: {status}")
    
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
    
    # CVE-Sicherheitsanalyse
    if 'cve_analysis' in system_info and system_info['cve_analysis']:
        context_parts.append(f"\n=== CVE-SICHERHEITSANALYSE ===")
        cve_data = system_info['cve_analysis']
        
        # NVD-Datenbank-Ergebnisse
        if 'database_summary' in cve_data:
            summary = cve_data['database_summary']
            context_parts.append("NVD-Datenbank-Analyse:")
            context_parts.append(f"  Services analysiert: {summary.get('total_services', 0)}")
            context_parts.append(f"  CVEs gefunden: {summary.get('total_cves', 0)}")
            context_parts.append(f"  Kritische CVEs: {summary.get('critical_cves', 0)}")
            context_parts.append(f"  Hohe CVEs: {summary.get('high_cves', 0)}")
            context_parts.append(f"  Mittlere CVEs: {summary.get('medium_cves', 0)}")
            context_parts.append(f"  Niedrige CVEs: {summary.get('low_cves', 0)}")
            context_parts.append(f"  Gesamtrisiko: {summary.get('overall_risk', 'Unknown')}")
        
        # NVD-Report
        if 'nvd_report' in cve_data:
            context_parts.append("\nNVD-Report:")
            context_parts.append(cve_data['nvd_report'])
        
        # Europäische CVE-Analyse
        if 'european_summary' in cve_data:
            european_summary = cve_data['european_summary']
            context_parts.append("\n🇪🇺 Europäische CVE-Analyse:")
            context_parts.append(f"  EU-Datenbanken geprüft: {european_summary.get('databases_checked', 0)}")
            context_parts.append(f"  Europäische CVEs gefunden: {european_summary.get('total_cves', 0)}")
            context_parts.append(f"  Kritische EU-CVEs: {european_summary.get('critical_count', 0)}")
            context_parts.append(f"  Hohe EU-CVEs: {european_summary.get('high_count', 0)}")
            context_parts.append(f"  Mittlere EU-CVEs: {european_summary.get('medium_count', 0)}")
            context_parts.append(f"  Niedrige EU-CVEs: {european_summary.get('low_count', 0)}")
            
            # EU-Compliance Status
            compliance = european_summary.get('eu_compliance', {})
            context_parts.append(f"  GDPR-konform: {'Ja' if compliance.get('gdpr_compliant') else 'Nein'}")
            context_parts.append(f"  NIS-Richtlinie: {'Ja' if compliance.get('nis_directive') else 'Nein'}")
            context_parts.append(f"  Datenverarbeitung: {compliance.get('data_processing', 'N/A')}")
            context_parts.append(f"  Datenspeicherung: {compliance.get('data_storage', 'N/A')}")
        
        # Europäische CVE-Ergebnisse
        if 'european_results' in cve_data:
            context_parts.append("\n🇪🇺 Europäische CVE-Details:")
            european_results = cve_data['european_results']
            for service, db_results in european_results.items():
                if any(db_results.values()):
                    context_parts.append(f"  {service}:")
                    for db_id, cves in db_results.items():
                        if cves:
                            context_parts.append(f"    {db_id}: {len(cves)} CVEs")
                            for cve in cves[:3]:  # Zeige nur die ersten 3
                                context_parts.append(f"      • {cve.get('cve_id', 'N/A')}: {cve.get('title', 'N/A')}")
        
        # Europäischer CVE-Report
        if 'european_report' in cve_data:
            context_parts.append("\n🇪🇺 Europäischer CVE-Report:")
            context_parts.append(cve_data['european_report'])
        
        # Ollama-Analyse
        if 'ollama_analysis' in cve_data:
            context_parts.append("\nOllama-Analyse:")
            context_parts.append(cve_data['ollama_analysis'])
        
        # Service-Versionen
        if 'service_versions' in cve_data:
            context_parts.append("\nService-Versionen:")
            for service, version in cve_data['service_versions'].items():
                context_parts.append(f"  {service}: {version}")
        
        # Basis-Informationen
        if 'installed_packages_count' in cve_data:
            context_parts.append(f"\nAnalysierte Pakete: {cve_data['installed_packages_count']}")
        
        if 'cve_database_used' in cve_data:
            context_parts.append(f"Datenbank: {cve_data['cve_database_used']}")
    
    return "\n".join(context_parts)


def create_system_report_prompt(system_context: str) -> str:
    """Erstellt einen spezialisierten Prompt für die Systemberichterstellung"""
    prompt = f"""Du bist ein erfahrener System-Administrator und IT-Sicherheitsexperte. Deine Aufgabe ist es, eine detaillierte Systemanalyse zu erstellen, die auf den tatsächlich gesammelten Daten basiert.

WICHTIGE REGELN:
- Antworte IMMER auf Deutsch
- Analysiere NUR die bereitgestellten System-Daten
- Gib konkrete, spezifische Informationen über das tatsächliche System
- Verwende die echten Werte aus den System-Daten (CPU-Auslastung, Speicherplatz, etc.)
- Identifiziere echte Probleme basierend auf den Daten
- Wenn keine relevanten Daten vorhanden sind, sage das ehrlich
- KEINE allgemeinen Aussagen oder "Gelaber"
- Verwende ALLE verfügbaren Daten aus dem System-Context
- Der Bericht sollte so vollständig wie möglich sein
- INKLUDIERE ALLE DETAILLIERTEN INFORMATIONEN aus dem System-Context
- Bei Kubernetes: Verwende ALLE Node-Namen, Pod-Details, Ressourcen-Verbrauch und Probleme
- Bei Docker: Verwende ALLE Container-Details, Images, Volumes und Probleme

VERBOTEN: Verwende KEINE generischen Beispiele wie "10 Pods" oder "5 Services"!
ERFORDERLICH: Verwende die ECHTEN Daten aus dem System-Context!
- Echte Node-Namen: k3s-agent-arm-cow, k3s-control-plane-fsn1-xuk, etc.
- Echte Pod-Namen: argo-cd-argocd-application-controller-0, etc.
- Echte Ressourcen-Verbrauch: CPU(cores) und MEMORY(bytes) aus den Daten

SYSTEMBERICHT-STRUKTUR:

## System-Übersicht
- Hostname: [aus den Daten]
- Distribution: [aus den Daten]
- Kernel: [aus den Daten]
- CPU: [aus den Daten]
- RAM: [aus den Daten]
- Speicherplatz: [aus den Daten]
- Zeitzone: [aus den Daten]
- Uptime: [aus den Daten]

## Aktuelle System-Status
- CPU-Auslastung: [konkreter Wert aus den Daten]
- Memory-Auslastung: [konkreter Wert aus den Daten]
- Speicherplatz-Auslastung: [konkreter Wert aus den Daten]
- Load Average (1min/5min/15min): [aus den Daten]
- Aktuelle Benutzer: [aus den Daten]
- Uptime: [aus den Daten]
- Zeitzone: [aus den Daten]

## Erkannte Services und Module
- Docker: [Status und Details aus den Daten]
- Kubernetes: [Status aus den Daten]
- Proxmox: [Status aus den Daten]
- Mailserver: [Status aus den Daten]
- Wichtige Services: [Liste aus den Daten]
- Paket-Manager: [aus den Daten]
- Installierte Pakete: [aus den Daten]
- Verfügbare Updates: [aus den Daten]

## Speicherplatz-Details
- Root-Partition: [aus den Daten]
- Größte Verzeichnisse: [aus den Daten]
- Größte Dateien: [aus den Daten]
- Docker-Speicherplatz: [aus den Daten]
- Log-Speicherplatz: [aus den Daten]

## Kubernetes-Cluster (falls vorhanden)
- Cluster-Version: [aus den Daten]
- Nodes: [Anzahl und Status aus den Daten]
- Pods: [Anzahl und Details aus den Daten]
- Services: [aus den Daten]
- Probleme: [aus den Daten]
- Ressourcen-Auslastung: [aus den Daten]
- Node-Details: [aus den Daten]
- Pod-Ressourcen: [aus den Daten]
- Namespaces: [aus den Daten]
- Deployments: [aus den Daten]

WICHTIG: Wenn Kubernetes-Daten im System-Context vorhanden sind, verwende ALLE verfügbaren Informationen:
- Node-Status mit IPs und Rollen
- Pod-Ressourcen-Verbrauch (CPU/Memory)
- Cluster-Informationen
- Probleme und Warnungen
- Spezifische Node-Namen und deren Status

BEISPIEL für Kubernetes-Abschnitt:
**Kubernetes-Cluster:**
- **Version:** v1.30.14+k3s1
- **Nodes:** 9 Nodes (k3s-agent-arm-cow, k3s-agent-arm-iuw, k3s-control-plane-fsn1-xuk, etc.)
- **Pods:** 100+ Pods in verschiedenen Namespaces
- **Node-Ressourcen:** CPU-Auslastung 1-16%, Memory-Auslastung 16-81%
- **Pod-Ressourcen:** Detaillierte CPU/Memory-Verbrauch pro Pod
- **Probleme:** 1 Problem (ungenutzte Volumes)

WICHTIG: Verwende die ECHTEN Daten aus dem System-Context, nicht generische Beispiele!
- Wenn "Kubernetes-Version: Client Version: v1.30.0" im Context steht, verwende das!
- Wenn "Node-Status:" mit echten Node-Namen im Context steht, verwende das!
- Wenn "Pod-Ressourcen:" mit echten Pod-Namen im Context steht, verwende das!

VERBOTEN: Verwende KEINE generischen Beispiele wie "10 Pods" oder "5 Services"!
ERFORDERLICH: Verwende die ECHTEN Daten aus dem System-Context!
- Echte Node-Namen: k3s-agent-arm-cow, k3s-control-plane-fsn1-xuk, etc.
- Echte Pod-Namen: argo-cd-argocd-application-controller-0, etc.
- Echte Ressourcen-Verbrauch: CPU(cores) und MEMORY(bytes) aus den Daten

OBLIGATORISCH: Wenn Kubernetes-Daten im System-Context vorhanden sind, MUSS ein Kubernetes-Abschnitt im Report enthalten sein!

WICHTIG: Der Report MUSS folgende Abschnitte enthalten, wenn die entsprechenden Daten im System-Context vorhanden sind:
1. Kubernetes-Cluster (wenn Kubernetes-Daten vorhanden sind)
2. Docker-Container (wenn Docker-Daten vorhanden sind)
3. CVE-Sicherheitsanalyse (wenn CVE-Daten vorhanden sind)

JEDER dieser Abschnitte MUSS die ECHTEN Daten aus dem System-Context verwenden!

WICHTIG: Der Report MUSS folgende Abschnitte enthalten, wenn die entsprechenden Daten im System-Context vorhanden sind:
1. Kubernetes-Cluster (wenn Kubernetes-Daten vorhanden sind)
2. Docker-Container (wenn Docker-Daten vorhanden sind)
3. CVE-Sicherheitsanalyse (wenn CVE-Daten vorhanden sind)

JEDER dieser Abschnitte MUSS die ECHTEN Daten aus dem System-Context verwenden!

BEISPIEL für Kubernetes-Abschnitt:
**Kubernetes-Cluster:**
- **Version:** v1.30.14+k3s1
- **Nodes:** 9 Nodes (k3s-agent-arm-cow, k3s-agent-arm-iuw, k3s-control-plane-fsn1-xuk, etc.)
- **Pods:** 100+ Pods in verschiedenen Namespaces
- **Node-Ressourcen:** CPU-Auslastung 1-16%, Memory-Auslastung 16-81%
- **Pod-Ressourcen:** Detaillierte CPU/Memory-Verbrauch pro Pod
- **Probleme:** 1 Problem (ungenutzte Volumes)

WICHTIG: Verwende die ECHTEN Daten aus dem System-Context, nicht generische Beispiele!
- Wenn "Kubernetes-Version: Client Version: v1.30.0" im Context steht, verwende das!
- Wenn "Node-Status:" mit echten Node-Namen im Context steht, verwende das!
- Wenn "Pod-Ressourcen:" mit echten Pod-Namen im Context steht, verwende das!

VERBOTEN: Verwende KEINE generischen Beispiele wie "10 Pods" oder "5 Services"!
ERFORDERLICH: Verwende die ECHTEN Daten aus dem System-Context!
- Echte Node-Namen: k3s-agent-arm-cow, k3s-control-plane-fsn1-xuk, etc.
- Echte Pod-Namen: argo-cd-argocd-application-controller-0, etc.
- Echte Ressourcen-Verbrauch: CPU(cores) und MEMORY(bytes) aus den Daten

OBLIGATORISCH: Wenn Kubernetes-Daten im System-Context vorhanden sind, MUSS ein Kubernetes-Abschnitt im Report enthalten sein!

## Docker-Container (falls vorhanden)
- Version: [aus den Daten]
- Laufende Container: [Liste aus den Daten]
- Container-Status: [aus den Daten]
- Probleme: [aus den Daten]
- Ungenutzte Volumes: [aus den Daten]

## Netzwerk und Sicherheit
- SSH-Konfiguration: [aus den Daten]
- Firewall-Status: [aus den Daten]
- Offene Ports: [aus den Daten]
- Benutzer-Logins: [aus den Daten]

## CVE-Sicherheitsanalyse
- NVD-Datenbank-Analyse: [aus den Daten]
- Ollama-Analyse: [aus den Daten]
- Europäische CVE-Analyse: [aus den Daten]
- Gefundene CVEs: [aus den Daten]
- Update-Empfehlungen: [aus den Daten]

## Identifizierte Probleme
- Kritische Probleme: [aus den Daten]
- Hohe Probleme: [aus den Daten]
- Mittlere Probleme: [aus den Daten]
- Niedrige Probleme: [aus den Daten]

## Empfehlungen
- Sofortige Maßnahmen: [basierend auf den gefundenen Problemen]
- Mittelfristige Maßnahmen: [basierend auf den Daten]
- Langfristige Maßnahmen: [basierend auf den Daten]

## Sicherheitszusammenfassung
- Anzahl kritische CVEs: [aus den Daten]
- Anzahl hohe CVEs: [aus den Daten]
- Anzahl mittlere CVEs: [aus den Daten]
- Anzahl niedrige CVEs: [aus den Daten]
- Gesamtrisiko: [aus den Daten]
- SSH-Konfiguration: [aus den Daten]
- Lauschende Services: [aus den Daten]
- Offene Ports: [aus den Daten]
- Benutzer-Logins: [aus den Daten]
- Fehlgeschlagene Anmeldungen: [aus den Daten]

## Docker-Details (falls vorhanden)
- Version: [aus den Daten]
- Laufende Container: [aus den Daten]
- Docker-Images: [aus den Daten]
- Docker-Volumes: [aus den Daten]
- Docker-Netzwerke: [aus den Daten]
- System-Nutzung: [aus den Daten]

## Log-Einträge und Anomalien
- Kürzliche Log-Einträge: [aus den Daten]
- Erkannte Anomalien: [aus den Daten]
- Prozess-Informationen: [aus den Daten]
- System-Status: [aus den Daten]

## Identifizierte Probleme
Basierend auf den tatsächlichen Daten:
- [Problem 1 mit konkreten Werten]
- [Problem 2 mit konkreten Werten]
- [Problem 3 mit konkreten Werten]

## Empfehlungen
Konkrete, umsetzbare Empfehlungen basierend auf den echten Daten:
1. [Spezifische Empfehlung mit Begründung]
2. [Spezifische Empfehlung mit Begründung]
3. [Spezifische Empfehlung mit Begründung]

## Nächste Schritte
Priorisierte Liste der wichtigsten Maßnahmen:
1. [Konkrete Maßnahme]
2. [Konkrete Maßnahme]
3. [Konkrete Maßnahme]

WICHTIG: Verwende ALLE verfügbaren Informationen aus den System-Daten. Erfinde keine Daten oder allgemeine Aussagen. Der Bericht sollte so vollständig wie möglich sein und alle relevanten Informationen enthalten.

=== SYSTEM-INFORMATIONEN ===
{system_context}

Erstelle jetzt einen detaillierten, spezifischen Systembericht basierend auf ALLEN verfügbaren Daten:"""
    
    return prompt

def create_chat_prompt(system_context: str, user_question: str, chat_history: List[Dict]) -> str:
    """Erstellt eine strukturierte Anfrage für Ollama"""
    from i18n import i18n
    
    prompt_parts = []
    
    # Verwende aktuelle Sprache
    current_lang = i18n.get_language()
    
    # System-Rolle für präzise System-Analyse
    if current_lang == 'de':
        prompt_parts.append("Du bist ein erfahrener System-Administrator und IT-Sicherheitsexperte.")
        prompt_parts.append("Deine Aufgabe ist es, Linux-Systeme zu analysieren und potenzielle Probleme zu identifizieren.")
        prompt_parts.append("WICHTIGE REGELN:")
        prompt_parts.append("- Antworte kurz, präzise und prägnant")
        prompt_parts.append("- Verwende die bereitgestellten System-Daten als Grundlage")
        prompt_parts.append("- Antworte IMMER auf Deutsch")
        prompt_parts.append("- Analysiere die System-Daten und gib konkrete Antworten")
        prompt_parts.append("- Wenn keine relevanten Daten vorhanden sind, sage das ehrlich")
        prompt_parts.append("- WICHTIG: Antworte NUR auf Deutsch")
        prompt_parts.append("- Verwende deutsche Begriffe")
        prompt_parts.append("- Keine englischen Wörter verwenden")
        prompt_parts.append("- SPRACHE: Du bist ein deutscher System-Administrator, antworte IMMER auf Deutsch")
        prompt_parts.append("- BEISPIEL: 'Updates' → 'System-Updates', 'Services' → 'Dienste', 'Storage' → 'Speicherplatz'")
        
        # Spezifische Prompts je nach Fragetyp
        question_lower = user_question.lower()
        if any(keyword in question_lower for keyword in ['user', 'benutzer', 'users']):
            prompt_parts.append("- Analysiere die Benutzer-Informationen aus den System-Daten")
            prompt_parts.append("- Liste aktive Benutzer mit Details auf")
            prompt_parts.append("- Identifiziere Benutzer-Probleme oder Anomalien")
        elif any(keyword in question_lower for keyword in ['container', 'lxc', 'proxmox']):
            prompt_parts.append("- Analysiere die Proxmox Container-Informationen")
            prompt_parts.append("- Liste laufende Container mit Status auf")
            prompt_parts.append("- Identifiziere Container-Probleme")
        elif any(keyword in question_lower for keyword in ['vm', 'virtual machine', 'proxmox']):
            prompt_parts.append("- Analysiere die Proxmox VM-Informationen")
            prompt_parts.append("- Liste laufende VMs mit Status auf")
            prompt_parts.append("- Identifiziere VM-Probleme")
        elif any(keyword in question_lower for keyword in ['service', 'services']):
            prompt_parts.append("- Analysiere die Service-Informationen")
            prompt_parts.append("- Liste wichtige Services mit Status auf")
            prompt_parts.append("- Identifiziere Service-Probleme")
        elif any(keyword in question_lower for keyword in ['speicher', 'storage', 'disk']):
            prompt_parts.append("- Analysiere die Speicherplatz-Informationen")
            prompt_parts.append("- Identifiziere Speicherplatz-Probleme")
            prompt_parts.append("- Gib Speicherplatz-Empfehlungen")
        elif any(keyword in question_lower for keyword in ['sicherheit', 'security']):
            prompt_parts.append("- Analysiere die Sicherheits-Informationen")
            prompt_parts.append("- Identifiziere Sicherheitsprobleme")
            prompt_parts.append("- Gib Sicherheits-Empfehlungen")
        elif any(keyword in question_lower for keyword in ['docker', 'container']):
            prompt_parts.append("- FOKUSSIERE DICH AUSSCHLIESSLICH auf Docker-spezifische Themen")
            prompt_parts.append("- Analysiere nur Docker-Container, Images, Volumes und Netzwerke")
            prompt_parts.append("- IGNORIERE Proxmox-Container, VMs, Nodes und andere nicht-Docker-Systeme")
            prompt_parts.append("- Verwende nur Docker-bezogene System-Daten")
            prompt_parts.append("- Gib nur Docker-spezifische Empfehlungen und Befehle")
        elif any(keyword in question_lower for keyword in ['netzwerk', 'network', 'network-security']):
            prompt_parts.append("- FOKUSSIERE DICH AUSSCHLIESSLICH auf Netzwerk-spezifische Themen")
            prompt_parts.append("- Analysiere nur lauschende Services, externe Erreichbarkeit, Firewall-Konfiguration")
            prompt_parts.append("- Ignoriere andere Systemprobleme wie offline Nodes oder nicht-Netzwerk-bezogene Fehler")
            prompt_parts.append("- Konzentriere dich auf exponierte Ports und Netzwerk-Sicherheitsrisiken")
            prompt_parts.append("- Gib nur Netzwerk-spezifische Sicherheitsempfehlungen")
        else:
            # Bei allen anderen Fragen: Netzwerk-Sicherheitsdaten ignorieren
            prompt_parts.append("- IGNORIERE Netzwerk-Sicherheitsdaten und -Probleme in deiner Antwort")
            prompt_parts.append("- Konzentriere dich auf die spezifische Frage (Docker, Mailserver, etc.)")
            prompt_parts.append("- Verwende nur die relevanten System-Daten für die gestellte Frage")
            prompt_parts.append("- Identifiziere automatisch Engpässe, Sicherheitslücken und Unregelmäßigkeiten")
            prompt_parts.append("- Warnung bei kritischen Problemen (hohe CPU/Last, wenig Speicher, Sicherheitsprobleme)")
            prompt_parts.append("- Gib konkrete Handlungsempfehlungen")
        
        # System-Kontext
        prompt_parts.append("\n=== SYSTEM-INFORMATIONEN ===")
        prompt_parts.append(system_context)
        
        # Chat-Historie (letzte 2 Einträge für Kontext)
        if chat_history:
            prompt_parts.append("\n=== CHAT-VERLAUF ===")
            for entry in chat_history[-2:]:
                if entry['role'] == 'user':
                    prompt_parts.append(f"Benutzer: {entry['content']}")
                else:
                    prompt_parts.append(f"Du: {entry['content']}")
        
        prompt_parts.append(f"\nBenutzer-Frage: {user_question}")
        prompt_parts.append("\nAntworte direkt und präzise auf die Frage basierend auf den System-Daten:")
    else:
        # Englische Prompts
        prompt_parts.append("You are an experienced system administrator and IT security expert.")
        prompt_parts.append("Your task is to analyze Linux systems and identify potential problems.")
        prompt_parts.append("IMPORTANT RULES:")
        prompt_parts.append("- Answer briefly, precisely and concisely")
        prompt_parts.append("- Use the provided system data as a basis")
        prompt_parts.append("- Answer ALWAYS in English")
        prompt_parts.append("- Analyze the system data and give concrete answers")
        prompt_parts.append("- If no relevant data is available, say so honestly")
        
        # System context
        prompt_parts.append("\n=== SYSTEM INFORMATION ===")
        prompt_parts.append(system_context)
        
        # Chat history (last 2 entries for context)
        if chat_history:
            prompt_parts.append("\n=== CHAT HISTORY ===")
    
    return "\n".join(prompt_parts)

def detect_and_correct_nonsense(response: str, question: str, system_info: Dict[str, Any]) -> str:
    """Erkennt und korrigiert Unsinn in Chat-Antworten"""
    
    # Unsinn-Erkennung
    response_lower = response.lower()
    question_lower = question.lower()
    
    # Context-Mismatches erkennen
    context_mismatches = {
        "docker": ["netzwerk-sicherheitsanalyse", "ssh-service", "mailserver", "proxmox", "node", "vm", "offline-node"],
        "mailserver": ["netzwerk-sicherheitsanalyse", "ssh-service", "docker", "proxmox"],
        "netzwerk": ["docker", "mailserver", "container", "proxmox"],
        "services": ["netzwerk-sicherheitsanalyse", "docker", "mailserver", "proxmox"],
        "proxmox": ["docker", "mailserver", "netzwerk-sicherheitsanalyse"]
    }
    
    # Prüfe Context-Mismatches
    for context, forbidden_terms in context_mismatches.items():
        if context in question_lower:
            for term in forbidden_terms:
                if term in response_lower:
                    # Korrigiere basierend auf Context
                    if "docker" in question_lower:
                        return f"""
Docker-Status-Analyse:

Basierend auf den System-Daten:
- Docker ist {'verfügbar' if system_info.get('docker_detected', False) else 'nicht verfügbar'}

Docker-Befehle für die Analyse:
- `docker ps` - Laufende Container anzeigen
- `docker ps -a` - Alle Container (auch gestoppte) anzeigen
- `docker images` - Verfügbare Images anzeigen
- `docker system df` - Docker-Speicherplatz prüfen
- `docker volume ls` - Docker-Volumes anzeigen
- `docker network ls` - Docker-Netzwerke anzeigen

Für detaillierte Informationen führen Sie bitte 'docker ps -a' aus.
"""
                    elif "mailserver" in question_lower:
                        return f"""
Mailserver-Analyse:

Basierend auf den System-Daten:
- Mailserver sind {'verfügbar' if system_info.get('mailserver_detected', False) else 'nicht verfügbar'}
- Verwende 'systemctl status postfix' für Postfix-Status
- Verwende 'systemctl status dovecot' für Dovecot-Status
- Verwende 'netstat -tlnp | grep :25' für SMTP-Port

Für detaillierte Informationen prüfen Sie bitte die Mailserver-Logs.
"""
                    elif "netzwerk" in question_lower:
                        return f"""
Netzwerk-Sicherheitsanalyse:

Basierend auf den System-Daten:
- Führe 'netstat -tlnp' für lauschende Ports aus
- Führe 'ss -tuln' für Socket-Status aus
- Führe 'iptables -L' für Firewall-Regeln aus

Für eine vollständige Netzwerk-Sicherheitsanalyse verwenden Sie den 'netzwerk' Shortcut.
"""
    
    # Generische Unsinn-Indikatoren
    nonsense_patterns = [
        "es gibt einen problem",
        "sicherheitsrisiko low",
        "ssh-identification-string ungültig"
    ]
    
    for pattern in nonsense_patterns:
        if pattern in response_lower:
            return f"""
System-Analyse:

Basierend auf den System-Daten:
- Hostname: {system_info.get('hostname', 'unbekannt')}
- Distribution: {system_info.get('distro_pretty_name', 'unbekannt')}

Für spezifische Informationen verwenden Sie bitte die verfügbaren Shortcuts.
"""
    
    return response


def save_system_report(report_content: str, system_info: Dict[str, Any]) -> str:
    """Speichert den Systembericht als Markdown-Datei"""
    import os
    from datetime import datetime
    
    # Erstelle Berichtsverzeichnis
    reports_dir = "system_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    # Generiere Dateinamen mit Timestamp
    hostname = system_info.get('hostname', 'unknown')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{reports_dir}/system_report_{hostname}_{timestamp}.md"
    
    # Erstelle Bericht mit Header
    report_header = f"""# Systembericht: {hostname}

**Erstellt am:** {datetime.now().strftime("%d.%m.%Y um %H:%M Uhr")}
**System:** {hostname}
**Distribution:** {system_info.get('distro_pretty_name', system_info.get('distro_name', 'Unbekannt'))}
**Kernel:** {system_info.get('kernel_version', 'Unbekannt')}

---

"""
    
    # Füge Netzwerk-Sicherheitsanalyse hinzu, falls vorhanden
    network_section = ""
    if 'network_security' in system_info:
        network_data = system_info['network_security']
        network_section = "\n## 🔒 Netzwerk-Sicherheitsanalyse\n\n"
        
        # Interne Services
        if 'internal_services' in network_data:
            internal_services = network_data['internal_services']
            
            if 'service_mapping' in internal_services and internal_services['service_mapping']:
                network_section += "### Lauschende Services\n\n"
                network_section += "| Port | Service | Status | Details |\n"
                network_section += "|------|---------|--------|---------|\n"
                
                for port, info in internal_services['service_mapping'].items():
                    service_name = info.get('service', 'Unbekannt')
                    status = info.get('status', 'Unbekannt')
                    details = info.get('details', '')
                    address = info.get('address', 'N/A')
                    external = "extern" if info.get('external', False) else "intern"
                    
                    network_section += f"| {port} | {service_name} | {status} | {address} ({external}) |\n"
                
                network_section += "\n"
            
            if 'all_ip_addresses' in internal_services and internal_services['all_ip_addresses']:
                network_section += "### IP-Adressen\n\n"
                for ip_info in internal_services['all_ip_addresses']:
                    if isinstance(ip_info, dict):
                        network_section += f"- **{ip_info.get('ip', 'Unbekannt')}** auf Interface {ip_info.get('interface', 'Unbekannt')} ({ip_info.get('type', 'Unbekannt')})\n"
                    else:
                        network_section += f"- **{ip_info}**\n"
                network_section += "\n"
        
        # Externe Tests
        if 'external_tests' in network_data:
            external_tests = network_data['external_tests']
            
            if 'reachable_ports' in external_tests and external_tests['reachable_ports']:
                network_section += "### Extern erreichbare Ports\n\n"
                network_section += f"**{len(external_tests['reachable_ports'])} Ports sind von außen erreichbar:**\n\n"
                for port in external_tests['reachable_ports']:
                    network_section += f"- Port {port}\n"
                network_section += "\n"
            
            # Detaillierte Host-Informationen
            if 'reachable_hosts' in external_tests and external_tests['reachable_hosts']:
                network_section += "### Erreichbare Hosts und Ports\n\n"
                for host, ports in external_tests['reachable_hosts'].items():
                    if ports:
                        network_section += f"**{host}:** {', '.join(map(str, ports))}\n"
                network_section += "\n"
            
            if 'service_versions' in external_tests and external_tests['service_versions']:
                network_section += "### Service-Versionen\n\n"
                for port, version in external_tests['service_versions'].items():
                    network_section += f"- **Port {port}:** {version}\n"
                network_section += "\n"
            
            if 'vulnerability_indicators' in external_tests and external_tests['vulnerability_indicators']:
                network_section += "### Sicherheitsprobleme\n\n"
                for indicator in external_tests['vulnerability_indicators']:
                    network_section += f"- ⚠️ {indicator}\n"
                network_section += "\n"
        
        # Sicherheitsbewertung
        if 'security_assessment' in network_data:
            assessment = network_data['security_assessment']
            
            network_section += "### Sicherheitsbewertung\n\n"
            
            if 'risk_level' in assessment:
                risk_level = assessment['risk_level'].upper()
                risk_emoji = "🔴" if risk_level in ["HIGH", "KRITISCH"] else "🟡" if risk_level in ["MEDIUM", "MITTEL"] else "🟢"
                network_section += f"{risk_emoji} **Risiko-Level:** {risk_level}\n\n"
            
            if 'security_score' in assessment:
                score = assessment['security_score']
                network_section += f"**Sicherheits-Score:** {score}/100\n\n"
            
            if 'exposed_services' in assessment and assessment['exposed_services']:
                network_section += "### Exponierte Services\n\n"
                for service in assessment['exposed_services']:
                    network_section += f"- ⚠️ {service}\n"
                network_section += "\n"
            
            if 'host_exposure' in assessment and assessment['host_exposure']:
                network_section += "### Host-spezifische Exposition\n\n"
                for host, ports in assessment['host_exposure'].items():
                    if ports:
                        network_section += f"**{host}:** {', '.join(map(str, ports))}\n"
                network_section += "\n"
            
            if 'recommendations' in assessment and assessment['recommendations']:
                network_section += "### Sicherheitsempfehlungen\n\n"
                for rec in assessment['recommendations']:
                    network_section += f"- 💡 {rec}\n"
                network_section += "\n"
            
            if 'compliance_issues' in assessment and assessment['compliance_issues']:
                network_section += "### Compliance-Probleme\n\n"
                for issue in assessment['compliance_issues']:
                    network_section += f"- ❌ {issue}\n"
                network_section += "\n"
    
    # Speichere Bericht
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report_header)
            if network_section:
                f.write(network_section)
            f.write(report_content)
        return filename
    except Exception as e:
        raise Exception(f"Fehler beim Speichern des Berichts: {e}")


def get_shortcuts() -> Dict[str, Any]:
    """
    Gibt die zentralen Shortcuts-Definitionen zurück.
    Diese Funktion stellt sicher, dass alle Teile der Anwendung die gleichen Shortcuts verwenden.
    """
    # Verwende direkte Übersetzungen ohne i18n-Abhängigkeit
    shortcuts = {
        'services': {
            'question': 'Wie ist der Status der System-Services?',
            'complex': False,
            'cache_key': 'services_status'
        },
        'storage': {
            'question': 'Wie ist der Speicherplatz-Status?',
            'complex': False,
            'cache_key': 'storage_status'
        },
        'security': {
            'question': 'Wie ist der Sicherheitsstatus des Systems?',
            'complex': True,
            'cache_key': 'security_analysis'
        },
        'processes': {
            'question': 'Welche Prozesse laufen auf dem System?',
            'complex': False,
            'cache_key': 'top_processes'
        },
        'performance': {
            'question': 'Wie ist die System-Performance?',
            'complex': False,
            'cache_key': 'performance_status'
        },
        'users': {
            'question': 'Welche Benutzer sind aktiv?',
            'complex': False,
            'cache_key': 'active_users'
        },
        'updates': {
            'question': 'Gibt es verfügbare System-Updates?',
            'complex': False,
            'cache_key': 'system_updates'
        },
        'logs': {
            'question': 'Analysiere die System-Logs',
            'complex': True,
            'cache_key': 'log_analysis'
        },
        'k8s': {
            'question': 'Wie ist der Kubernetes-Cluster-Status?',
            'complex': False,
            'cache_key': 'k8s_status'
        },
        'k8s-problems': {
            'question': 'Welche Probleme gibt es im Kubernetes-Cluster?',
            'complex': True,
            'cache_key': 'k8s_problems'
        },
        'k8s-pods': {
            'question': 'Welche Kubernetes-Pods laufen?',
            'complex': False,
            'cache_key': 'k8s_pods'
        },
        'k8s-nodes': {
            'question': 'Wie ist der Status der Kubernetes-Nodes?',
            'complex': False,
            'cache_key': 'k8s_nodes'
        },
        'k8s-resources': {
            'question': 'Welche Kubernetes-Ressourcen sind verfügbar?',
            'complex': False,
            'cache_key': 'k8s_resources'
        },
        'proxmox': {
            'question': 'Wie ist der Status des Proxmox-Clusters?',
            'complex': False,
            'cache_key': 'proxmox_status'
        },
        'proxmox-problems': {
            'question': 'Welche Probleme gibt es im Proxmox-Cluster?',
            'complex': True,
            'cache_key': 'proxmox-problems'
        },
        'proxmox-vms': {
            'question': 'Welche VMs laufen auf Proxmox?',
            'complex': False,
            'cache_key': 'proxmox-vms'
        },
        'proxmox-containers': {
            'question': 'Welche Container laufen auf Proxmox?',
            'complex': False,
            'cache_key': 'proxmox-containers'
        },
        'proxmox-storage': {
            'question': 'Wie ist der Speicherplatz-Status im Proxmox-Cluster?',
            'complex': False,
            'cache_key': 'proxmox-storage'
        },
        'docker': {
            'question': 'Wie ist der Docker-Status und welche Container laufen?',
            'complex': False,
            'cache_key': 'docker_status'
        },
        'docker-problems': {
            'question': 'Welche Docker-Probleme gibt es?',
            'complex': True,
            'cache_key': 'docker_problems'
        },
        'docker-containers': {
            'question': 'Welche Docker-Container laufen?',
            'complex': False,
            'cache_key': 'docker_containers'
        },
        'docker-images': {
            'question': 'Welche Docker-Images sind verfügbar?',
            'complex': False,
            'cache_key': 'docker_images'
        },
        'mailservers': {
            'question': 'Wie ist der Status der Mailserver?',
            'complex': False,
            'cache_key': 'mailservers_status'
        },
        'mailcow': {
            'question': 'Wie ist der Status von Mailcow?',
            'complex': False,
            'cache_key': 'mailcow_status'
        },
        'mailcow-problems': {
            'question': 'Welche Probleme gibt es mit Mailcow?',
            'complex': True,
            'cache_key': 'mailcow_problems'
        },
        'postfix': {
            'question': 'Wie ist der Status von Postfix?',
            'complex': False,
            'cache_key': 'postfix_status'
        },
        'postfix-problems': {
            'question': 'Welche Probleme gibt es mit Postfix?',
            'complex': True,
            'cache_key': 'postfix_problems'
        },
        'network-security': {
            'question': 'Führe eine Netzwerk-Sicherheitsanalyse durch',
            'complex': True,
            'cache_key': 'network_security'
        },
        'exposed-services': {
            'question': 'Analysiere exponierte Services',
            'complex': False,
            'cache_key': 'exposed_services'
        },
        'port-scan': {
            'question': 'Führe einen Port-Scan durch',
            'complex': False,
            'cache_key': 'port_scan'
        },
        'service-test': {
            'question': 'Teste Service-Erreichbarkeit',
            'complex': False,
            'cache_key': 'service_test'
        },
        'report': {
            'question': 'Erstelle einen System-Report',
            'complex': True,
            'cache_key': 'system_report'
        },
        'cache': {
            'question': 'Analysiere Cache-Status',
            'complex': False,
            'cache_key': 'cache_status'
        },
        'clear': {
            'question': 'Bereinige Cache',
            'complex': False,
            'cache_key': 'clear_cache'
        },
    }
    
    return shortcuts
    
    # Verwende die zentrale Shortcuts-Definition
    shortcuts = get_shortcuts()
    
    return shortcuts

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


def select_best_model(complex_analysis: bool = False, for_menu: bool = False) -> str:
    """Wähle das beste verfügbare Modell für System-Analyse aus."""
    models = get_available_models()
    
    if not models:
        console.print("[yellow]⚠️  Keine Ollama-Modelle gefunden[/yellow]")
        console.print("[blue]💡 Empfohlene Installation: ollama pull llama3.2:3b[/blue]")
        return "llama2"  # Fallback auf Standard-Modell
    
    # Debug-Output für Modell-Auswahl (nur wenn Debug-Modus aktiv)
    if hasattr(console, 'debug_mode') and console.debug_mode:
        console.print(f"[dim]🔍 Modell-Auswahl: complex_analysis={complex_analysis}, for_menu={for_menu}[/dim]")
        console.print(f"[dim]📋 Verfügbare Modelle: {[m['name'] for m in models]}[/dim]")
    
    # Für Menü/Shortcuts: Verwende qwen:0.5b wenn verfügbar
    if for_menu:
        for model in models:
            if "qwen" in model['name'].lower() and "0.5b" in model['name']:
                return model['name']
        
        # Fallback: Verwende das kleinste verfügbare Modell für Menü
        sorted_models = sorted(models, key=lambda x: x.get('size', float('inf')))
        selected_model = sorted_models[0]
        return selected_model['name']
    
    # Modell-Auswahl basierend auf Namen (da Größen nicht korrekt abgerufen werden)
    if complex_analysis:
        # Für komplexe Analysen: Priorisiere größere Modelle
        priority_models = [
            "llama3.1:8b", "deepseek-r1:14b", "qwen3:14b", "openthinker:32b",  # Große Modelle
            "mistral:7b", "llama3.2:3b", "codellama:7b", "deepseek-coder:latest",  # Mittlere Modelle
            "qwen2.5-coder:1.5b-base", "phi4:latest", "gemma3n:latest"  # Kleinere Modelle
        ]
        
        for priority_model in priority_models:
            for model in models:
                if model['name'] == priority_model:
                    return model['name']
        
        # Fallback: Verwende das erste verfügbare Modell
        selected_model = models[0]['name']
        if hasattr(console, 'debug_mode') and console.debug_mode:
            console.print(f"[dim]🎯 Komplexe Analyse: Verwende {selected_model}[/dim]")
        return selected_model
    else:
        # Für einfache Analysen: Priorisiere Modelle mit mindestens 3B Parametern
        fast_models = [
            "llama3.2:3b", "mistral:7b", "gemma3n:latest",  # Mindestens 3B Parameter
            "qwen2.5-coder:1.5b-base", "phi4:latest", "qwen:0.5b"  # Kleinere Modelle als Fallback
        ]
        
        for fast_model in fast_models:
            for model in models:
                if model['name'] == fast_model:
                    if hasattr(console, 'debug_mode') and console.debug_mode:
                        console.print(f"[dim]🎯 Einfache Analyse: Verwende {model['name']}[/dim]")
                    return model['name']
        
        # Fallback: Verwende das erste verfügbare Modell
        selected_model = models[0]['name']
        if hasattr(console, 'debug_mode') and console.debug_mode:
            console.print(f"[dim]🎯 Fallback: Verwende {selected_model}[/dim]")
        return selected_model


# Cache für Interpolation
_interpolation_cache = {}

# Intelligentes kontext-basiertes Caching
_context_cache = {
    "system_analysis": {
        "topics": {},
        "relationships": {},
        "conversations": {},  # Neue: Konversations-Zusammenfassungen
        "last_updated": None
    }
}

def cache_contextual_response(topic: str, subtopic: str, question: str, answer: str, system_context: str = None):
    """
    Cached Antworten mit Kontext-Erhaltung und intelligenten Verknüpfungen.
    
    Args:
        topic: Hauptbereich (z.B. 'proxmox', 'kubernetes', 'system')
        subtopic: Unterbereich (z.B. 'vms', 'containers', 'storage')
        question: Gestellte Frage
        answer: Gegebene Antwort
        system_context: Optionaler System-Kontext für Beziehungen
    """
    import time
    
    if topic not in _context_cache["system_analysis"]["topics"]:
        _context_cache["system_analysis"]["topics"][topic] = {}
    
    if subtopic not in _context_cache["system_analysis"]["topics"][topic]:
        _context_cache["system_analysis"]["topics"][topic][subtopic] = {}
    
    # Cache die Antwort mit Metadaten
    _context_cache["system_analysis"]["topics"][topic][subtopic] = {
        "question": question,
        "answer": answer,
        "timestamp": time.time(),
        "system_context": system_context
    }
    
    # Aktualisiere Zeitstempel
    _context_cache["system_analysis"]["last_updated"] = time.time()
    
    # Debug-Ausgabe
    if hasattr(console, 'debug_mode') and console.debug_mode:
        console.print(f"[dim]🔍 Context Cache: {topic}.{subtopic} gecacht[/dim]")

def get_contextual_response(topic: str, subtopic: str) -> Optional[Dict]:
    """
    Holt gecachte Antwort mit Kontext.
    
    Args:
        topic: Hauptbereich
        subtopic: Unterbereich
    
    Returns:
        Dict mit 'answer', 'question', 'timestamp' oder None
    """
    if (topic in _context_cache["system_analysis"]["topics"] and 
        subtopic in _context_cache["system_analysis"]["topics"][topic]):
        return _context_cache["system_analysis"]["topics"][topic][subtopic]
    return None

def get_topic_summary(topic: str) -> Optional[str]:
    """
    Erstellt eine Zusammenfassung für einen ganzen Bereich.
    
    Args:
        topic: Hauptbereich (z.B. 'proxmox')
    
    Returns:
        Zusammenfassung oder None
    """
    if topic not in _context_cache["system_analysis"]["topics"]:
        return None
    
    subtopics = _context_cache["system_analysis"]["topics"][topic]
    if not subtopics:
        return None
    
    summary_parts = [f"📊 {topic.upper()} Bereich:"]
    for subtopic, data in subtopics.items():
        if data.get("answer"):
            # Kürze die Antwort für die Zusammenfassung
            short_answer = data["answer"][:100] + "..." if len(data["answer"]) > 100 else data["answer"]
            summary_parts.append(f"  • {subtopic}: {short_answer}")
    
    return "\n".join(summary_parts)

def get_related_context(topic: str, subtopic: str) -> List[str]:
    """
    Findet verwandte Kontexte für bessere Antworten.
    
    Args:
        topic: Hauptbereich
        subtopic: Unterbereich
    
    Returns:
        Liste verwandter Kontexte
    """
    related = []
    
    # Suche nach verwandten Themen im gleichen Bereich
    if topic in _context_cache["system_analysis"]["topics"]:
        for other_subtopic, data in _context_cache["system_analysis"]["topics"][topic].items():
            if other_subtopic != subtopic and data.get("answer"):
                related.append(f"{topic}.{other_subtopic}: {data['answer'][:50]}...")
    
    # Suche nach verwandten Bereichen
    for other_topic, topic_data in _context_cache["system_analysis"]["topics"].items():
        if other_topic != topic:
            for other_subtopic, data in topic_data.items():
                if data.get("answer"):
                    related.append(f"{other_topic}.{other_subtopic}: {data['answer'][:50]}...")
    
    return related[:3]  # Maximal 3 verwandte Kontexte

def clear_context_cache(topic: str = None):
    """
    Löscht Cache-Einträge.
    
    Args:
        topic: Optional - nur diesen Bereich löschen, sonst alles
    """
    if topic:
        if topic in _context_cache["system_analysis"]["topics"]:
            del _context_cache["system_analysis"]["topics"][topic]
            console.print(f"[dim]🗑️ Context Cache für '{topic}' gelöscht[/dim]")
    else:
        _context_cache["system_analysis"]["topics"].clear()
        _context_cache["system_analysis"]["relationships"].clear()
        console.print(f"[dim]🗑️ Gesamter Context Cache gelöscht[/dim]")

def print_context_cache_status():
    """Zeigt Status des Context Caches an."""
    topics = _context_cache["system_analysis"]["topics"]
    conversations = _context_cache["system_analysis"]["conversations"]
    
    if not topics and not conversations:
        console.print("[dim]📋 Context Cache: Leer[/dim]")
        return
    
    console.print(f"[dim]📋 Context Cache Status:[/dim]")
    
    # Zeige Topics
    if topics:
        console.print(f"[dim]📁 Topics:[/dim]")
        for topic, subtopics in topics.items():
            console.print(f"[dim]  • {topic}: {len(subtopics)} Unterbereiche[/dim]")
            for subtopic in subtopics.keys():
                console.print(f"[dim]    - {subtopic}[/dim]")
    
    # Zeige Konversationen
    if conversations:
        console.print(f"[dim]💬 Konversationen:[/dim]")
        for topic, convs in conversations.items():
            console.print(f"[dim]  • {topic}: {len(convs)} Zusammenfassungen[/dim]")
            for conv_id, conv_data in list(convs.items())[:3]:  # Zeige max. 3 pro Topic
                summary_preview = conv_data["summary"][:50] + "..." if len(conv_data["summary"]) > 50 else conv_data["summary"]
                console.print(f"[dim]    - {conv_id}: {summary_preview}[/dim]")

def summarize_conversation(chat_history: List[Dict], topic: str = None) -> str:
    """
    Erstellt eine intelligente Zusammenfassung einer Konversation.
    
    Args:
        chat_history: Liste der Chat-Nachrichten
        topic: Optional - spezifisches Thema für fokussierte Zusammenfassung
    
    Returns:
        Zusammenfassung der Konversation
    """
    if not chat_history or len(chat_history) < 4:  # Mindestens 2 Q&A-Paare
        return None
    
    # Erstelle Prompt für Zusammenfassung
    conversation_text = ""
    for msg in chat_history[-10:]:  # Letzte 10 Nachrichten
        role = "Benutzer" if msg["role"] == "user" else "Assistent"
        conversation_text += f"{role}: {msg['content']}\n"
    
    summary_prompt = f"""Du bist ein System-Administrator. Erstelle eine präzise Zusammenfassung dieser Konversation.

SPRACHE: Du MUSST auf Deutsch antworten, niemals auf Englisch.

Konversation:
{conversation_text}

{f"FOKUS: Konzentriere dich auf das Thema '{topic}'" if topic else ""}

Erstelle eine kurze, präzise Zusammenfassung (max. 3 Sätze) der wichtigsten Erkenntnisse und Antworten.
Zusammenfassung:"""
    
    try:
        # Verwende ein schnelles Modell für Zusammenfassungen
        model = select_best_model(complex_analysis=False, for_menu=False)
        summary = query_ollama(summary_prompt, model=model, complex_analysis=False)
        
        if summary and len(summary) > 20:
            return summary.strip()
        else:
            return None
    except Exception as e:
        return None

def cache_conversation_summary(topic: str, chat_history: List[Dict], summary: str = None):
    """
    Cached eine Konversations-Zusammenfassung.
    
    Args:
        topic: Hauptbereich der Konversation
        chat_history: Chat-Verlauf
        summary: Optional - vorgegebene Zusammenfassung
    """
    import time
    
    if not summary:
        summary = summarize_conversation(chat_history, topic)
    
    if not summary:
        return
    
    if topic not in _context_cache["system_analysis"]["conversations"]:
        _context_cache["system_analysis"]["conversations"][topic] = {}
    
    # Erstelle eindeutige ID für die Konversation
    conversation_id = f"conv_{int(time.time())}"
    
    _context_cache["system_analysis"]["conversations"][topic][conversation_id] = {
        "summary": summary,
        "message_count": len(chat_history),
        "timestamp": time.time(),
        "last_messages": chat_history[-4:] if len(chat_history) >= 4 else chat_history  # Letzte 4 Nachrichten
    }
    
    # Aktualisiere Zeitstempel
    _context_cache["system_analysis"]["last_updated"] = time.time()
    
    # Debug-Ausgabe
    if hasattr(console, 'debug_mode') and console.debug_mode:
        console.print(f"[dim]🔍 Conversation Cache: {topic}.{conversation_id} gecacht[/dim]")

def get_conversation_context(topic: str, max_age_hours: int = 24) -> List[str]:
    """
    Holt relevante Konversations-Kontexte für ein Thema.
    
    Args:
        topic: Hauptbereich
        max_age_hours: Maximales Alter der Konversationen in Stunden
    
    Returns:
        Liste relevanter Konversations-Zusammenfassungen
    """
    import time
    current_time = time.time()
    max_age_seconds = max_age_hours * 3600
    
    contexts = []
    
    if topic in _context_cache["system_analysis"]["conversations"]:
        for conv_id, conv_data in _context_cache["system_analysis"]["conversations"][topic].items():
            # Prüfe Alter der Konversation
            if current_time - conv_data["timestamp"] <= max_age_seconds:
                contexts.append(conv_data["summary"])
    
    return contexts[:3]  # Maximal 3 relevante Kontexte

def optimize_context_window(chat_history: List[Dict], max_messages: int = 20) -> List[Dict]:
    """
    Optimiert das Kontextfenster durch Zusammenfassung längerer Konversationen.
    
    Args:
        chat_history: Aktueller Chat-Verlauf
        max_messages: Maximale Anzahl Nachrichten vor Zusammenfassung
    
    Returns:
        Optimierter Chat-Verlauf
    """
    if len(chat_history) <= max_messages:
        return chat_history
    
    # Erstelle Zusammenfassung der älteren Nachrichten
    older_messages = chat_history[:-max_messages//2]  # Ältere Hälfte
    recent_messages = chat_history[-max_messages//2:]  # Neuere Hälfte
    
    # Bestimme Hauptthema aus den älteren Nachrichten
    topics = []
    for msg in older_messages:
        if msg["role"] == "user":
            content = msg["content"].lower()
            if any(keyword in content for keyword in ['proxmox', 'vm', 'container']):
                topics.append('proxmox')
            elif any(keyword in content for keyword in ['kubernetes', 'k8s', 'pod']):
                topics.append('kubernetes')
            elif any(keyword in content for keyword in ['service', 'storage', 'security']):
                topics.append('system')
    
    main_topic = max(set(topics), key=topics.count) if topics else 'system'
    
    # Erstelle Zusammenfassung
    summary = summarize_conversation(older_messages, main_topic)
    
    if summary:
        # Cache die Zusammenfassung
        cache_conversation_summary(main_topic, older_messages, summary)
        
        # Erstelle optimierten Verlauf
        optimized_history = [
            {"role": "system", "content": f"Zusammenfassung vorheriger Konversation ({main_topic}): {summary}"}
        ]
        optimized_history.extend(recent_messages)
        
        return optimized_history
    else:
        # Fallback: Behalte nur die neueren Nachrichten
        return recent_messages

def get_context_for_question(question: str, topic: str = None) -> str:
    """
    Sammelt relevanten Kontext für eine neue Frage.
    
    Args:
        question: Die neue Frage
        topic: Optional - spezifisches Thema
    
    Returns:
        Zusammengefasster Kontext für die Frage
    """
    contexts = []
    
    # Bestimme Topic aus der Frage, falls nicht gegeben
    if not topic:
        question_lower = question.lower()
        if any(keyword in question_lower for keyword in ['proxmox', 'vm', 'container']):
            topic = 'proxmox'
        elif any(keyword in question_lower for keyword in ['kubernetes', 'k8s', 'pod']):
            topic = 'kubernetes'
        else:
            topic = 'system'
    
    # Hole relevante Konversations-Kontexte
    conversation_contexts = get_conversation_context(topic)
    if conversation_contexts:
        contexts.extend(conversation_contexts)
    
    # Hole verwandte Antworten aus dem Topic Cache
    if topic in _context_cache["system_analysis"]["topics"]:
        for subtopic, data in _context_cache["system_analysis"]["topics"][topic].items():
            if data.get("answer"):
                contexts.append(f"{subtopic}: {data['answer'][:100]}...")
    
    # Erstelle zusammengefassten Kontext
    if contexts:
        context_text = f"Relevanter Kontext für {topic}:\n" + "\n".join(contexts[:3])
        return context_text
    
    return ""

def update_conversation_cache(chat_history: List[Dict], topic: str = None):
    """
    Aktualisiert den Konversations-Cache basierend auf dem aktuellen Chat-Verlauf.
    
    Args:
        chat_history: Aktueller Chat-Verlauf
        topic: Optional - spezifisches Thema
    """
    if len(chat_history) >= 6:  # Mindestens 3 Q&A-Paare
        # Bestimme Topic aus den letzten Nachrichten
        if not topic:
            recent_messages = chat_history[-6:]
            topics = []
            for msg in recent_messages:
                if msg["role"] == "user":
                    content = msg["content"].lower()
                    if any(keyword in content for keyword in ['proxmox', 'vm', 'container']):
                        topics.append('proxmox')
                    elif any(keyword in content for keyword in ['kubernetes', 'k8s', 'pod']):
                        topics.append('kubernetes')
                    elif any(keyword in content for keyword in ['service', 'storage', 'security']):
                        topics.append('system')
            
            topic = max(set(topics), key=topics.count) if topics else 'system'
        
        # Cache die Konversation
        cache_conversation_summary(topic, chat_history)

def create_intelligent_menu(shortcuts: Dict) -> str:
    """
    Erstellt ein intelligentes Menü mit Wortwolke-Anreicherung durch schnelles Modell.
    """
    # Verwende schnelles Modell für Wortwolke-Anreicherung
    model = select_best_model(complex_analysis=False, for_menu=True)
    
    # Erstelle Basis-Menü
    menu_parts = []
    menu_parts.append(f"\n[bold cyan]Verfügbare Kürzelwörter:[/bold cyan]")
    
    # Gruppiere Shortcuts nach Kategorien mit numerischen Kürzeln
    categories = {
        'system': [
            ('s1', 'services'),
            ('s2', 'storage'), 
            ('s3', 'security'),
            ('s4', 'processes'),
            ('s5', 'performance'),
            ('s6', 'users'),
            ('s7', 'updates'),
            ('s8', 'logs')
        ],
        'kubernetes': [
            ('k1', 'k8s'),
            ('k2', 'k8s-problems'),
            ('k3', 'k8s-pods'),
            ('k4', 'k8s-nodes'),
            ('k5', 'k8s-resources')
        ],
        'proxmox': [
            ('p1', 'proxmox'),
            ('p2', 'proxmox-problems'),
            ('p3', 'proxmox-vms'),
            ('p4', 'proxmox-containers'),
            ('p5', 'proxmox-storage')
        ],
        'docker': [
            ('d1', 'docker'),
            ('d2', 'docker-problems'),
            ('d3', 'docker-containers'),
            ('d4', 'docker-images')
        ],
        'mailservers': [
            ('m1', 'mailservers'),
            ('m2', 'mailcow'),
            ('m3', 'mailcow-problems'),
            ('m4', 'postfix'),
            ('m5', 'postfix-problems')
        ],
        'network-security': [
            ('n1', 'network-security'),
            ('n2', 'exposed-services'),
            ('n3', 'port-scan'),
            ('n4', 'service-test')
        ],
        'tools': [
            ('t1', 'report'),
            ('t2', 'cache'),
            ('t3', 'clear')
        ]
    }
    
    # Verwende Übersetzungen für Menü-Texte
    from i18n import _, i18n
    i18n.set_language('de')
    
    for category, shortcut_list in categories.items():
        if category == 'system':
            menu_parts.append(f"\n[bold green]System:[/bold green]")
        elif category == 'kubernetes':
            menu_parts.append(f"\n[bold blue]Kubernetes:[/bold blue]")
        elif category == 'proxmox':
            menu_parts.append(f"\n[bold magenta]Proxmox:[/bold magenta]")
        elif category == 'docker':
            menu_parts.append(f"\n[bold cyan]Docker:[/bold cyan]")
        elif category == 'mailservers':
            menu_parts.append(f"\n[bold yellow]Mailserver:[/bold yellow]")
        elif category == 'network-security':
            menu_parts.append(f"\n[bold red]Netzwerk-Sicherheit:[/bold red]")
        elif category == 'tools':
            menu_parts.append(f"\n[bold yellow]Berichte & Tools:[/bold yellow]")
        
        for code, shortcut in shortcut_list:
            if shortcut in shortcuts:
                # Verwende übersetzte Fragen aus den Shortcuts
                question = shortcuts[shortcut]['question']
                menu_parts.append(f"  • {code} / '{shortcut}' - {question}")
    
    menu_parts.append(f"\n[dim]💡 Tipp: Sie können auch freie Fragen stellen, z.B. 'Was sind LXC Container?'[/dim]")
    menu_parts.append(f"[dim]💡 Schnellzugriff: Verwenden Sie Kürzel wie 's1', 'k3', 'p4' etc.[/dim]")
    
    return "\n".join(menu_parts)

def interpolate_user_input_to_shortcut(user_input: str, shortcuts: Dict) -> Optional[str]:
    """
    Intelligente Interpolation mit zweistufiger Modell-Nutzung:
    1. Schnelles Modell für Intent-Erkennung
    2. Analysemodell für die eigentliche Antwort
    """
    # Prüfe Cache zuerst
    if user_input in _interpolation_cache:
        return _interpolation_cache[user_input]
    
    # Numerische Kürzel-Mapping
    numeric_mapping = {
        # System
        's1': 'services',
        's2': 'storage',
        's3': 'security',
        's4': 'processes',
        's5': 'performance',
        's6': 'users',
        's7': 'updates',
        's8': 'logs',
        # Kubernetes
        'k1': 'k8s',
        'k2': 'k8s-problems',
        'k3': 'k8s-pods',
        'k4': 'k8s-nodes',
        'k5': 'k8s-resources',
        # Proxmox
        'p1': 'proxmox',
        'p2': 'proxmox-problems',
        'p3': 'proxmox-vms',
        'p4': 'proxmox-containers',
        'p5': 'proxmox-storage',
        # Docker
        'd1': 'docker',
        'd2': 'docker-problems',
        'd3': 'docker-containers',
        'd4': 'docker-images',
        # Mailserver
        'm1': 'mailservers',
        'm2': 'mailcow',
        'm3': 'mailcow-problems',
        'm4': 'postfix',
        'm5': 'postfix-problems',
        # Netzwerk-Sicherheit
        'n1': 'network-security',
        'n2': 'exposed-services',
        'n3': 'port-scan',
        'n4': 'service-test',
        # Tools
        't1': 'report',
        't2': 'cache',
        't3': 'clear'
    }
    
    # Prüfe numerische Kürzel zuerst
    if user_input.lower() in numeric_mapping:
        shortcut = numeric_mapping[user_input.lower()]
        if shortcut in shortcuts:
            return shortcut
    
    # Einfache Keyword-basierte Zuordnung für häufige Fälle
    keyword_mapping = {
        'lxc': 'proxmox-containers',
        'container': 'proxmox-containers',
        'containers': 'proxmox-containers',
        'proxmox_containers': 'proxmox-containers',  # Fallback für Modell-Ausgabe
        'proxmox-containers': 'proxmox-containers',  # Fallback für Modell-Ausgabe
        'vm': 'proxmox-vms',
        'vms': 'proxmox-vms',
        'virtual machine': 'proxmox-vms',
        'virtual machines': 'proxmox-vms',
        'k8s': 'k8s',
        'kubernetes': 'k8s',
        'pods': 'k8s-pods',
        'nodes': 'k8s-nodes',
        'docker': 'docker',
        'docker container': 'docker-containers',
        'docker containers': 'docker-containers',
        'docker image': 'docker-images',
        'docker images': 'docker-images',
        'mailcow': 'mailcow',
        'postfix': 'postfix',
        'mail': 'mailservers',
        'email': 'mailservers',
        'e-mail': 'mailservers',
        'services': 'services',
        'service': 'services',
        'storage': 'storage',
        'disk': 'storage',
        'speicher': 'storage',
        'security': 'security',
        'sicherheit': 'security',
        'performance': 'performance',
        'leistung': 'performance',
        'users': 'users',
        'benutzer': 'users',
        'updates': 'updates',
        'logs': 'logs',
        'log': 'logs',
        'report': 'report',
        'bericht': 'report',
        # Netzwerk-Sicherheit
        'netzwerk': 'network-security',
        'network': 'network-security',
        'sicherheit': 'network-security',
        'security': 'network-security',
        'firewall': 'network-security',
        'ports': 'port-scan',
        'port': 'port-scan',
        'scan': 'port-scan',
        'nmap': 'port-scan',
        'exposed': 'exposed-services',
        'exponiert': 'exposed-services',
        'erreichbar': 'exposed-services',
        'reachable': 'exposed-services',
        'service-test': 'service-test',
        'service-tests': 'service-test',
        'test': 'service-test',
        'telnet': 'service-test',
        'netcat': 'service-test',
        'nc': 'service-test'
    }
    
    # Prüfe direkte Keyword-Zuordnung
    for keyword, shortcut in keyword_mapping.items():
        if keyword in user_input.lower():
            if shortcut in shortcuts:
                # Cache das Ergebnis
                _interpolation_cache[user_input] = shortcut
                return shortcut
            else:
                # Debug: Shortcut nicht gefunden
                if hasattr(console, 'debug_mode') and console.debug_mode:
                    console.print(f"[dim]🔍 Debug: Keyword '{keyword}' gefunden, aber Shortcut '{shortcut}' nicht in shortcuts: {list(shortcuts.keys())}[/dim]")
    
    # Prüfe exakte Übereinstimmung zuerst
    if user_input.lower() in shortcuts:
        _interpolation_cache[user_input] = user_input.lower()
        return user_input.lower()
    
    # Verwende schnelles Modell für Intent-Erkennung
    try:
        model = select_best_model(complex_analysis=False, for_menu=True)
        
        # Erstelle Prompt für Interpolation
        available_shortcuts = list(shortcuts.keys())
        interpolation_prompt = f"""Du bist ein intelligenter Assistent, der Benutzereingaben zu verfügbaren Kürzelwörtern zuordnet.

Verfügbare Kürzelwörter: {available_shortcuts}

Benutzereingabe: "{user_input}"

Antworte NUR mit dem passenden Kürzelwort oder "none" wenn keine Übereinstimmung.
Beispiele:
- "LXC" -> "proxmox-containers"
- "Container" -> "proxmox-containers" 
- "VMs" -> "proxmox-vms"
- "Kubernetes" -> "k8s"
- "Speicherplatz" -> "storage"
- "Was ist das Wetter?" -> "none"

Antwort:"""
        
        response = query_ollama(interpolation_prompt, model=model, complex_analysis=False)
        
        if response:
            # Bereinige Antwort
            response = response.strip().lower()
            # Ersetze Unterstriche durch Bindestriche für Proxmox-Shortcuts
            response = response.replace('_', '-')
            
            # Debug-Ausgabe
            console.print(f"[dim]🔍 Debug: Modell-Interpolation '{user_input}' -> '{response}'[/dim]")
            if hasattr(console, 'debug_mode') and console.debug_mode:
                console.print(f"[dim]🔍 Verfügbare Shortcuts: {list(shortcuts.keys())}[/dim]")
            
            if response in shortcuts:
                # Cache das Ergebnis
                _interpolation_cache[user_input] = response
                return response
            elif response == "none":
                # Cache das Ergebnis
                _interpolation_cache[user_input] = None
                return None
            else:
                # Versuche alternative Schreibweisen
                alternatives = [
                    response.replace('_', '-'),
                    response.replace('-', '_'),
                    response.replace('proxmox', 'proxmox'),
                    response.replace('containers', 'containers'),
                    response.replace('container', 'containers')
                ]
                
                for alt in alternatives:
                    if alt in shortcuts:
                        _interpolation_cache[user_input] = alt
                        return alt
                
                # Wenn nichts funktioniert, versuche direkte Zuordnung
                if 'container' in user_input.lower():
                    if 'proxmox-containers' in shortcuts:
                        _interpolation_cache[user_input] = 'proxmox-containers'
                        return 'proxmox-containers'
        
    except Exception as e:
        # Bei Fehlern: keine Interpolation
        pass
    
    # Cache das Ergebnis
    _interpolation_cache[user_input] = None
    return None

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
        
        # Debug-Ausgabe für Modell-Verwendung
        if hasattr(console, 'debug_mode') and console.debug_mode:
            console.print(f"[dim]🔧 Verwende Modell: {model} (complex_analysis={complex_analysis})[/dim]")
        
        response = requests.post(url, json=data, timeout=timeout)
        
        if response.status_code == 200:
            result = response.json()
            return result.get('response', '').strip()
        elif response.status_code == 404:
            console.print(f"[red]❌ Modell '{model}' nicht gefunden. Verfügbare Modelle prüfen...[/red]")
            # Versuche mit dem schnellsten verfügbaren Modell
            available_models = get_available_models()
            if available_models:
                # Sortiere nach Größe und wähle das schnellste
                sorted_models = sorted(available_models, key=lambda x: x.get('size', float('inf')))
                fallback_model = sorted_models[0]['name']
                console.print(f"[yellow]⚠️  Verwende schnellstes verfügbares Modell: {fallback_model}[/yellow]")
                data['model'] = fallback_model
                response = requests.post(url, json=data, timeout=timeout)
                if response.status_code == 200:
                    result = response.json()
                    return result.get('response', '').strip()
            
            # Wenn auch das nicht funktioniert
            console.print("[red]❌ Keine funktionierenden Modelle gefunden[/red]")
            return None
        else:
            console.print(f"[red]❌ Ollama-Fehler: {response.status_code}[/red]")
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
    parser.add_argument('--debug', action='store_true', help='Zeige Debug-Informationen (Modell-Auswahl, etc.)')
    parser.add_argument('--include-network-security', action='store_true', help='Führe Netzwerk-Sicherheitsanalyse automatisch am Anfang durch')
    parser.add_argument('--auto-report', action='store_true', help='Generiere automatisch einen Systembericht und beende das Programm')
    parser.add_argument('--report-and-chat', action='store_true', help='Generiere automatisch einen Systembericht und starte dann den interaktiven Chat')
    parser.add_argument('--with-cve', action='store_true', help='Führe CVE-Sicherheitsanalyse für installierte Services durch')
    parser.add_argument('--cve-database', choices=['ollama', 'nvd', 'hybrid', 'european', 'hybrid-european'], 
                       default='hybrid', help='CVE-Datenbank für Analyse (Standard: hybrid)')
    parser.add_argument('--cve-cache', action='store_true', 
                       help='Verwende lokalen CVE-Cache')
    parser.add_argument('--cve-offline', action='store_true', 
                       help='Nur lokale CVE-Daten verwenden')
    parser.add_argument('--eu-compliance', action='store_true',
                       help='Aktiviere EU-Compliance-Modus (GDPR, NIS-Richtlinie)')
    
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
        
        # Speichere SSH-Verbindungsdaten für spätere Verwendung
        system_info['ssh_host'] = host
        system_info['ssh_user'] = username
        system_info['ssh_port'] = args.port
        system_info['ssh_key_file'] = args.key_file
        
        # Führe CVE-Sicherheitsanalyse durch, falls gewünscht
        if args.with_cve:
            console.print("\n[bold blue]🔍 CVE-Sicherheitsanalyse[/bold blue]")
            console.print("="*60)
            
            try:
                # Bestimme CVE-Datenbank und Cache-Einstellungen
                cve_database = args.cve_database
                enable_cache = args.cve_cache or True  # Standardmäßig aktiviert
                offline_only = args.cve_offline
                
                console.print(f"[dim]Datenbank: {cve_database}, Cache: {'Aktiviert' if enable_cache else 'Deaktiviert'}, Offline: {'Ja' if offline_only else 'Nein'}[/dim]")
                
                cve_info = collector._analyze_cve_vulnerabilities(
                    system_info, 
                    cve_database=cve_database,
                    enable_cache=enable_cache,
                    offline_only=offline_only
                )
                
                if cve_info:
                    system_info['cve_analysis'] = cve_info
                    
                    # Zeige CVE-Zusammenfassung basierend auf verwendeter Datenbank
                    if cve_database in ['nvd', 'hybrid', 'hybrid-european'] and 'database_summary' in cve_info:
                        summary = cve_info['database_summary']
                        console.print(f"[green]✅ NVD CVE-Analyse abgeschlossen[/green]")
                        console.print(f"[dim]📊 {summary.get('total_services', 0)} Services analysiert[/dim]")
                        console.print(f"[dim]🔍 {summary.get('total_cves', 0)} CVEs gefunden[/dim]")
                        
                        if summary.get('critical_cves', 0) > 0:
                            console.print(f"[bold red]🚨 {summary['critical_cves']} kritische CVEs gefunden![/bold red]")
                        if summary.get('high_cves', 0) > 0:
                            console.print(f"[bold yellow]⚠️ {summary['high_cves']} hohe CVEs gefunden[/bold yellow]")
                        
                        console.print(f"[dim]📈 Gesamtrisiko: {summary.get('overall_risk', 'Unknown')}[/dim]")
                    
                    if cve_database in ['european', 'hybrid-european'] and 'european_summary' in cve_info:
                        european_summary = cve_info['european_summary']
                        console.print(f"[green]✅ Europäische CVE-Analyse abgeschlossen[/green]")
                        console.print(f"[dim]🇪🇺 {european_summary.get('databases_checked', 0)} EU-Datenbanken geprüft[/dim]")
                        console.print(f"[dim]🔍 {european_summary.get('total_cves', 0)} europäische CVEs gefunden[/dim]")
                        
                        if european_summary.get('critical_count', 0) > 0:
                            console.print(f"[bold red]🚨 {european_summary['critical_count']} kritische EU-CVEs gefunden![/bold red]")
                        if european_summary.get('high_count', 0) > 0:
                            console.print(f"[bold yellow]⚠️ {european_summary['high_count']} hohe EU-CVEs gefunden[/bold yellow]")
                        
                        # EU-Compliance Status
                        compliance = european_summary.get('eu_compliance', {})
                        console.print(f"[dim]🔒 GDPR-konform: {'Ja' if compliance.get('gdpr_compliant') else 'Nein'}[/dim]")
                        console.print(f"[dim]🏛️ NIS-Richtlinie: {'Ja' if compliance.get('nis_directive') else 'Nein'}[/dim]")
                    
                    if cve_database in ['ollama', 'hybrid', 'hybrid-european'] and 'ollama_analysis' in cve_info:
                        console.print(f"[green]✅ Ollama CVE-Analyse abgeschlossen[/green]")
                        console.print(f"[dim]📊 {cve_info.get('installed_packages_count', 0)} Pakete analysiert[/dim]")
                        console.print(f"[dim]🔧 {len(cve_info.get('service_versions', {}))} Services geprüft[/dim]")
                        
                        # Zeige erste Zeilen der Ollama-Analyse
                        ollama_analysis = cve_info['ollama_analysis']
                        lines = ollama_analysis.split('\n')[:10]
                        console.print(f"[dim]📝 Ollama-Analyse (erste Zeilen):[/dim]")
                        for line in lines:
                            if line.strip():
                                console.print(f"[dim]  {line.strip()}[/dim]")
                    
                    if not any(key in cve_info for key in ['database_summary', 'ollama_analysis']):
                        console.print(f"[yellow]⚠️ Keine CVE-Informationen gefunden[/yellow]")
                else:
                    console.print(f"[red]❌ Fehler bei CVE-Analyse[/red]")
                    
            except Exception as e:
                console.print(f"[red]❌ Fehler bei CVE-Analyse: {e}[/red]")
        
        # Führe Netzwerk-Sicherheitsanalyse durch, falls gewünscht
        if args.include_network_security:
            console.print("\n[bold blue]🔒 Netzwerk-Sicherheitsanalyse[/bold blue]")
            console.print("="*60)
            
            try:
                # 1. Interne Service-Analyse
                console.print("[dim]Analysiere lauschende Services...[/dim]")
                internal_services = collector.analyze_listening_services()
                
                # 2. Externe Erreichbarkeit testen
                all_ip_addresses = internal_services.get('all_ip_addresses', [])
                if all_ip_addresses:
                    internal_ports = list(internal_services.get('service_mapping', {}).keys())
                    
                    if internal_ports:
                        console.print(f"[dim]Teste externe Erreichbarkeit für {len(all_ip_addresses)} IP-Adressen und {len(internal_ports)} Ports...[/dim]")
                        external_tests = collector.test_external_accessibility(all_ip_addresses, internal_ports)
                        
                        # 3. Sicherheitsbewertung
                        console.print("[dim]Erstelle Sicherheitsbewertung...[/dim]")
                        security_assessment = collector.assess_network_security(internal_services, external_tests)
                        
                        # Aktualisiere system_info
                        if 'network_security' not in system_info:
                            system_info['network_security'] = {}
                        
                        system_info['network_security'].update({
                            'internal_services': internal_services,
                            'external_tests': external_tests,
                            'security_assessment': security_assessment
                        })
                        
                        # Zeige Zusammenfassung
                        risk_level = security_assessment.get('risk_level', 'unknown')
                        exposed_count = len(security_assessment.get('exposed_services', []))
                        issues_count = len(security_assessment.get('recommendations', []))
                        
                        console.print(f"[green]✅ Netzwerk-Sicherheitsanalyse abgeschlossen[/green]")
                        console.print(f"[dim]📊 Risiko-Level: {risk_level.upper()}, {exposed_count} exponierte Services, {issues_count} Empfehlungen[/dim]")
                        
                    else:
                        console.print(f"[yellow]⚠️ Keine lauschenden Ports gefunden[/yellow]")
                else:
                    console.print(f"[yellow]⚠️ Keine externe IP-Adresse gefunden[/yellow]")
                    
            except Exception as e:
                console.print(f"[red]❌ Fehler bei Netzwerk-Sicherheitsanalyse: {e}[/red]")
                console.print("[yellow]Analyse wird fortgesetzt ohne Netzwerk-Sicherheitsdaten[/yellow]")
        
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
        
        # Proxmox-Status (falls verfügbar)
        if 'proxmox_detected' in system_info and system_info['proxmox_detected']:
            console.print("\n[bold blue]🖥️ Proxmox VE[/bold blue]")
            console.print("="*60)
            
            # Version
            if 'proxmox_version' in system_info:
                console.print(f"\n[bold cyan]Proxmox-Version:[/bold cyan] {system_info['proxmox_version']}")
            
            # Cluster-Status
            if 'cluster_status' in system_info:
                console.print("\n[bold cyan]Cluster-Status:[/bold cyan]")
                console.print(system_info['cluster_status'])
            
            # Nodes
            if 'nodes' in system_info:
                console.print("\n[bold cyan]Nodes:[/bold cyan]")
                console.print(system_info['nodes'])
            
            # Probleme
            if 'problems_count' in system_info and system_info['problems_count'] > 0:
                console.print(f"\n[bold red]⚠️  {system_info['problems_count']} Probleme gefunden:[/bold red]")
                for i, problem in enumerate(system_info['problems'], 1):
                    console.print(f"\n[red]Problem {i}:[/red]")
                    console.print(problem)
            else:
                console.print("\n[green]✅ Keine Proxmox-Probleme gefunden[/green]")
            
            # Storage
            if 'storage' in system_info:
                console.print("\n[bold cyan]Storage:[/bold cyan]")
                console.print(system_info['storage'])
            
            # HA-Status
            if 'ha_status' in system_info:
                console.print("\n[bold cyan]HA-Status:[/bold cyan]")
                console.print(system_info['ha_status'])
            
            # ZFS-Status
            if 'zfs_status' in system_info:
                console.print("\n[bold cyan]ZFS-Status:[/bold cyan]")
                console.print(system_info['zfs_status'])
            
            # Ceph-Status
            if 'ceph_status' in system_info:
                console.print("\n[bold cyan]Ceph-Status:[/bold cyan]")
                console.print(system_info['ceph_status'])
        
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
        
        # Anmeldungen
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
        
        # Hilfsfunktion für Report-Generierung
        def generate_system_report():
            console.print("\n[bold blue]📄 Automatische Report-Generierung[/bold blue]")
            console.print("="*60)
            
            try:
                # Erstelle leere Log-Entries und Anomalies für den Report
                log_entries = []
                anomalies = []
                
                # Erstelle System-Context
                console.print("[dim]Erstelle System-Context...[/dim]")
                system_context = create_system_context(system_info, log_entries, anomalies)
                
                # Erstelle Report-Prompt
                console.print("[dim]Erstelle Report-Prompt...[/dim]")
                report_prompt = create_system_report_prompt(system_context)
                
                # Wähle bestes Modell für Report-Generierung
                console.print("[dim]Wähle Modell für Report-Generierung...[/dim]")
                model = select_best_model(complex_analysis=True, for_menu=False)
                console.print(f"[dim]Verwende Modell: {model}[/dim]")
                
                # Generiere Report
                console.print("[dim]Generiere Systembericht...[/dim]")
                report_content = query_ollama(report_prompt, model=model, complex_analysis=True)
                
                if report_content:
                    # Speichere Report
                    console.print("[dim]Speichere Report...[/dim]")
                    filename = save_system_report(report_content, system_info)
                    
                    if filename and os.path.exists(filename):
                        console.print(f"[green]✅ Systembericht erfolgreich generiert und gespeichert[/green]")
                        console.print(f"[green]📄 Datei: {filename}[/green]")
                        
                        # Prüfe ob Datei tatsächlich existiert
                        if os.path.exists(filename):
                            console.print(f"[green]✅ Datei existiert und ist lesbar[/green]")
                            
                            # Zeige Dateigröße
                            file_size = os.path.getsize(filename)
                            console.print(f"[dim]📊 Dateigröße: {file_size} Bytes[/dim]")
                            
                            # Zeige erste Zeilen des Reports
                            try:
                                with open(filename, 'r', encoding='utf-8') as f:
                                    first_lines = [f.readline().strip() for _ in range(5) if f.readline().strip()]
                                console.print(f"[dim]📝 Erste Zeilen:[/dim]")
                                for line in first_lines:
                                    console.print(f"[dim]  {line}[/dim]")
                            except Exception as e:
                                console.print(f"[yellow]⚠️ Konnte Datei nicht lesen: {e}[/yellow]")
                        else:
                            console.print(f"[red]❌ Datei wurde nicht erstellt: {filename}[/red]")
                    else:
                        console.print(f"[red]❌ Fehler beim Speichern des Reports[/red]")
                else:
                    console.print(f"[red]❌ Keine Antwort von Ollama erhalten[/red]")
                
                return True
                
            except Exception as e:
                console.print(f"[red]❌ Fehler bei Auto-Report-Generierung: {e}[/red]")
                import traceback
                console.print(f"[red]Traceback: {traceback.format_exc()}[/red]")
                return False
        
        # Auto-Report Generierung (nur Report, dann beenden)
        if args.auto_report:
            if generate_system_report():
                console.print(f"\n[bold green]Auto-Report abgeschlossen![/bold green]")
                return 0
            else:
                return 1
        
        # Report-and-Chat Generierung (Report + Chat)
        if args.report_and_chat:
            if generate_system_report():
                console.print(f"\n[bold green]Report generiert! Starte Chat...[/bold green]")
            else:
                console.print(f"[red]❌ Fehler bei Report-Generierung, aber Chat wird trotzdem gestartet[/red]")
        
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
            start_interactive_chat(system_info, analyzer.log_entries, analyzer.anomalies, args)
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
        start_interactive_chat(system_info, analyzer.log_entries, analyzer.anomalies, args)
        
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