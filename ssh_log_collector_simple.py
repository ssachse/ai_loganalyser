#!/usr/bin/env python3
"""
SSH-basierter Log-Sammler für Linux-Zielsysteme
Sammelt Logs von entfernten Linux-Systemen und analysiert sie lokal mit Ollama
Unterstützt SSH Port-Forwarding für Ollama-Verbindung
"""

import os
import sys
import json
import tempfile
import tarfile
import gzip
import shutil
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import paramiko
from pathlib import Path
import argparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
import subprocess
import threading
import queue
import time
import socket

# Importiere den bestehenden Log-Analyzer
from log_analyzer import LogAnalyzer, LogEntry, LogLevel, Anomaly
from config import Config

console = Console()

class SSHLogCollector:
    """SSH-basierter Log-Sammler für Linux-Systeme"""
    
    def __init__(self, host: str, username: str, password: str = None, key_file: str = None, port: int = 22, 
                 ollama_port: int = 11434, use_port_forwarding: bool = True):
        self.host = host
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.ollama_port = ollama_port
        self.use_port_forwarding = use_port_forwarding
        self.ssh_client = None
        self.sftp_client = None
        self.temp_dir = None
        self.collected_files = []
        self.port_forward_active = False
        
    def connect(self) -> bool:
        """Verbindet sich mit dem Zielsystem"""
        try:
            console.print(f"[blue]Verbinde mit {self.username}@{self.host}:{self.port}...[/blue]")
            
            # Überprüfe SSH-Agent wenn keine expliziten Credentials angegeben sind
            if not self.key_file and not self.password:
                try:
                    result = subprocess.run(['ssh-add', '-l'], capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout.strip():
                        console.print(f"[dim]SSH-Agent hat {len(result.stdout.strip().split())} Key(s) geladen[/dim]")
                    else:
                        console.print("[yellow]⚠️  SSH-Agent hat keine Keys geladen[/yellow]")
                except:
                    console.print("[dim]SSH-Agent nicht verfügbar[/dim]")
            
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Konfiguriere SSH-Agent-Unterstützung
            try:
                import paramiko.agent
                agent = paramiko.agent.Agent()
                if agent.get_keys():
                    console.print("[dim]SSH-Agent wird für Authentifizierung verwendet[/dim]")
            except Exception as e:
                console.print(f"[dim]SSH-Agent nicht verfügbar: {e}[/dim]")
                pass
            
            # Verbindungsoptionen
            connect_kwargs = {
                'hostname': self.host,
                'username': self.username,
                'port': self.port,
                'timeout': 30,
                'allow_agent': True,  # Erlaube SSH-Agent
                'look_for_keys': True  # Suche nach SSH-Keys
            }
            
            if self.key_file:
                connect_kwargs['key_filename'] = self.key_file
                console.print(f"[dim]Verwende SSH-Key: {self.key_file}[/dim]")
            elif self.password:
                connect_kwargs['password'] = self.password
                connect_kwargs['allow_agent'] = False
                connect_kwargs['look_for_keys'] = False
                console.print("[dim]Verwende Passwort-Authentifizierung[/dim]")
            else:
                # Versuche zuerst SSH-Keys, dann Passwort-Prompt
                console.print("[dim]Versuche SSH-Key-Authentifizierung (SSH-Agent + Standard-Keys)...[/dim]")
            
            self.ssh_client.connect(**connect_kwargs)
            self.sftp_client = self.ssh_client.open_sftp()
            
            # Teste Verbindung
            stdin, stdout, stderr = self.ssh_client.exec_command('echo "SSH connection successful"')
            if stdout.channel.recv_exit_status() == 0:
                console.print(f"[green]✅ Verbindung zu {self.host} erfolgreich[/green]")
                
                # Aktiviere Port-Forwarding für Ollama
                if self.use_port_forwarding:
                    self._setup_port_forwarding()
                
                return True
            else:
                console.print(f"[red]❌ Verbindung zu {self.host} fehlgeschlagen[/red]")
                return False
                
        except Exception as e:
            error_msg = str(e)
            if "Authentication failed" in error_msg:
                console.print(f"[red]❌ SSH-Authentifizierung fehlgeschlagen[/red]")
                console.print("[yellow]Versuche System-SSH als Fallback...[/yellow]")
                
                # Versuche System-SSH als Fallback
                if self.connect_with_system_ssh():
                    console.print("[green]✅ System-SSH-Verbindung erfolgreich[/green]")
                    console.print("[yellow]Hinweis: Einige erweiterte Features sind möglicherweise eingeschränkt[/yellow]")
                    return True
                else:
                    console.print("[yellow]Mögliche Lösungen:[/yellow]")
                    console.print("  • Überprüfen Sie Ihre SSH-Keys: ssh-add -l")
                    console.print("  • Testen Sie die Verbindung: ssh stefan@developer")
                    console.print("  • Verwenden Sie --key-file für spezifischen Key")
                    console.print("  • Verwenden Sie --password für Passwort-Authentifizierung")
            else:
                console.print(f"[red]❌ SSH-Verbindungsfehler: {e}[/red]")
            return False
    
    def connect_with_system_ssh(self) -> bool:
        """Verbindet sich mit dem Zielsystem über System-SSH als Fallback"""
        try:
            console.print("[blue]Versuche System-SSH als Fallback...[/blue]")
            
            # Teste SSH-Verbindung
            test_cmd = ['ssh', '-o', 'ConnectTimeout=10', f'{self.username}@{self.host}', 'echo "SSH connection successful"']
            result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                console.print(f"[green]✅ System-SSH-Verbindung zu {self.host} erfolgreich[/green]")
                return True
            else:
                console.print(f"[red]❌ System-SSH-Verbindung fehlgeschlagen: {result.stderr.strip()}[/red]")
                return False
                
        except subprocess.TimeoutExpired:
            console.print("[red]❌ SSH-Verbindung Timeout[/red]")
            return False
        except Exception as e:
            console.print(f"[red]❌ System-SSH-Fehler: {e}[/red]")
            return False
    
    def _setup_port_forwarding(self):
        """Richtet Port-Forwarding für Ollama ein"""
        try:
            console.print(f"[blue]Richte Port-Forwarding für Ollama ein (localhost:{self.ollama_port})...[/blue]")
            
            # Überprüfe ob Port bereits verfügbar ist
            if self._check_local_ollama():
                console.print(f"[green]✅ Ollama bereits verfügbar auf localhost:{self.ollama_port}[/green]")
                return True
            
            # Versuche Port-Forwarding über SSH
            transport = self.ssh_client.get_transport()
            transport.request_port_forward('', self.ollama_port, 'localhost', self.ollama_port)
            
            # Warte kurz und teste dann
            time.sleep(2)
            
            if self._check_local_ollama():
                console.print(f"[green]✅ Port-Forwarding erfolgreich eingerichtet[/green]")
                self.port_forward_active = True
                return True
            else:
                console.print(f"[yellow]⚠️  Port-Forwarding nicht verfügbar, verwende lokale Ollama-Instanz[/yellow]")
                return False
                
        except Exception as e:
            console.print(f"[yellow]⚠️  Port-Forwarding fehlgeschlagen: {e}[/yellow]")
            console.print(f"[dim]Verwende lokale Ollama-Instanz auf localhost:{self.ollama_port}[/dim]")
            return False
    
    def _check_local_ollama(self) -> bool:
        """Überprüft ob Ollama auf localhost verfügbar ist"""
        try:
            import requests
            response = requests.get(f"http://localhost:{self.ollama_port}/api/tags", timeout=3)
            return response.status_code == 200
        except:
            return False
    
    def disconnect(self):
        """Trennt die SSH-Verbindung"""
        if self.port_forward_active:
            try:
                transport = self.ssh_client.get_transport()
                transport.cancel_port_forward('', self.ollama_port)
                console.print(f"[dim]Port-Forwarding für Ollama beendet[/dim]")
            except:
                pass
        
        if self.sftp_client:
            self.sftp_client.close()
        if self.ssh_client:
            self.ssh_client.close()
        console.print("[yellow]SSH-Verbindung getrennt[/yellow]")
    
    def get_system_info(self) -> Dict[str, Any]:
        """Sammelt System-Informationen vom Zielsystem"""
        console.print("[blue]Sammle System-Informationen...[/blue]")
        
        system_info = {
            'hostname': self.host,
            'os_type': 'linux',
            'collection_time': datetime.now().isoformat(),
            'ssh_connection': f"{self.username}@{self.host}:{self.port}",
            'port_forwarding': self.port_forward_active
        }
        
        # Basis-System-Informationen
        commands = {
            'hostname': 'hostname',
            'os_version': 'cat /etc/os-release',
            'kernel_version': 'uname -r',
            'cpu_info': 'lscpu | grep "Model name" | head -1',
            'cpu_cores': 'nproc',
            'memory_total': 'free -h | grep Mem | awk "{print $2}"',
            'disk_usage': 'df -h / | tail -1 | awk "{print $5}"',
            'uptime': 'uptime',
            'load_average': 'cat /proc/loadavg',
            'users_logged_in': 'who | wc -l',
            'running_processes': 'ps aux | wc -l'
        }
        
        for key, command in commands.items():
            try:
                stdin, stdout, stderr = self.ssh_client.exec_command(command)
                result = stdout.read().decode('utf-8').strip()
                if result:
                    system_info[key] = result
            except Exception as e:
                console.print(f"[yellow]Warnung: Konnte {key} nicht abrufen: {e}[/yellow]")
        
        return system_info
    
    def collect_logs(self, hours_back: int = 24) -> str:
        """Sammelt Logs vom Zielsystem"""
        console.print(f"[blue]Sammle Logs der letzten {hours_back} Stunden...[/blue]")
        
        # Erstelle temporäres Verzeichnis
        self.temp_dir = tempfile.mkdtemp(prefix=f"linux_logs_{self.host}_")
        console.print(f"[dim]Temporäres Verzeichnis: {self.temp_dir}[/dim]")
        
        # Linux Log-Quellen
        log_sources = [
            # System-Logs
            ('/var/log/syslog', 'system'),
            ('/var/log/messages', 'system'),
            ('/var/log/kern.log', 'kernel'),
            ('/var/log/auth.log', 'security'),
            ('/var/log/secure', 'security'),
            
            # Service-Logs
            ('/var/log/dmesg', 'kernel'),
            ('/var/log/boot.log', 'boot'),
            ('/var/log/cron', 'cron'),
            ('/var/log/maillog', 'mail'),
            ('/var/log/mail.log', 'mail'),
            
            # Anwendungs-Logs
            ('/var/log/apache2/access.log', 'web'),
            ('/var/log/apache2/error.log', 'web'),
            ('/var/log/nginx/access.log', 'web'),
            ('/var/log/nginx/error.log', 'web'),
            ('/var/log/mysql/error.log', 'database'),
            ('/var/log/postgresql/postgresql-*.log', 'database'),
            
            # Systemd-Logs
            ('/var/log/journal', 'systemd'),
            
            # Weitere wichtige Logs
            ('/var/log/fail2ban.log', 'security'),
            ('/var/log/ufw.log', 'firewall'),
            ('/var/log/iptables.log', 'firewall'),
            ('/var/log/audit/audit.log', 'audit'),
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
        
        # Sammle Netzwerk-Informationen
        self._collect_network_info()
        
        # Sammle System-Status
        self._collect_system_status()
        
        console.print(f"[green]✓ Logs gesammelt in: {self.temp_dir}[/green]")
        return self.temp_dir
    
    def _collect_log_file(self, log_path: str, source: str, hours_back: int):
        """Sammelt eine einzelne Log-Datei"""
        try:
            # Prüfe ob Datei existiert
            stdin, stdout, stderr = self.ssh_client.exec_command(f'test -f "{log_path}" && echo "exists"')
            if not stdout.read().decode('utf-8').strip():
                return
            
            # Berechne Zeitstempel für Filterung
            cutoff_time = datetime.now() - timedelta(hours=hours_back)
            cutoff_timestamp = cutoff_time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Sammle Log-Einträge nach Zeitstempel
            if source in ['systemd', 'journal']:
                # Für journalctl verwende spezielle Behandlung
                return
            
            # Verwende tail und grep für effiziente Filterung
            command = f'tail -n 10000 "{log_path}" | grep -E "^[0-9]{{4}}-|^[A-Z][a-z]{{2}}\\s+[0-9]{{1,2}}" | tail -n 1000'
            
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            content = stdout.read().decode('utf-8', errors='ignore')
            
            if content.strip():
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
                f'journalctl --since "{hours_back} hours ago" --no-pager -o short-precise -p crit',
                f'journalctl --since "{hours_back} hours ago" --no-pager -o short-precise -p emerg',
                f'journalctl --since "{hours_back} hours ago" --no-pager -o short-precise -p alert',
            ]
            
            for i, command in enumerate(journal_commands):
                try:
                    stdin, stdout, stderr = self.ssh_client.exec_command(command)
                    content = stdout.read().decode('utf-8', errors='ignore')
                    
                    if content.strip():
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
                'open_files': 'lsof | head -50',
                'network_connections': 'netstat -tuln',
                'listening_ports': 'ss -tuln',
            }
            
            for name, command in commands.items():
                try:
                    stdin, stdout, stderr = self.ssh_client.exec_command(command)
                    content = stdout.read().decode('utf-8', errors='ignore')
                    
                    if content.strip():
                        local_file = os.path.join(self.temp_dir, f"process_{name}.txt")
                        with open(local_file, 'w', encoding='utf-8') as f:
                            f.write(content)
                        
                        self.collected_files.append((local_file, "processes"))
                        
                except Exception as e:
                    console.print(f"[yellow]Warnung: Fehler beim Sammeln von {name}: {e}[/yellow]")
                    
        except Exception as e:
            console.print(f"[yellow]Warnung: Fehler beim Sammeln von Prozess-Informationen: {e}[/yellow]")
    
    def _collect_network_info(self):
        """Sammelt Netzwerk-Informationen"""
        try:
            console.print("[blue]Sammle Netzwerk-Informationen...[/blue]")
            
            commands = {
                'interfaces': 'ip addr show',
                'routing': 'ip route show',
                'connections': 'ss -tuln',
                'dns': 'cat /etc/resolv.conf',
                'hosts': 'cat /etc/hosts',
                'firewall_status': 'iptables -L -n -v',
                'ufw_status': 'ufw status verbose',
            }
            
            for name, command in commands.items():
                try:
                    stdin, stdout, stderr = self.ssh_client.exec_command(command)
                    content = stdout.read().decode('utf-8', errors='ignore')
                    
                    if content.strip():
                        local_file = os.path.join(self.temp_dir, f"network_{name}.txt")
                        with open(local_file, 'w', encoding='utf-8') as f:
                            f.write(content)
                        
                        self.collected_files.append((local_file, "network"))
                        
                except Exception as e:
                    console.print(f"[yellow]Warnung: Fehler beim Sammeln von {name}: {e}[/yellow]")
                    
        except Exception as e:
            console.print(f"[yellow]Warnung: Fehler beim Sammeln von Netzwerk-Informationen: {e}[/yellow]")
    
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
                'last_reboot': 'last reboot',
                'kernel_messages': 'dmesg | tail -50',
                'installed_packages': 'dpkg -l | tail -50',  # Für Debian/Ubuntu
                'rpm_packages': 'rpm -qa | tail -50',  # Für RHEL/CentOS
            }
            
            for name, command in commands.items():
                try:
                    stdin, stdout, stderr = self.ssh_client.exec_command(command)
                    content = stdout.read().decode('utf-8', errors='ignore')
                    
                    if content.strip():
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


class LinuxLogAnalyzer(LogAnalyzer):
    """Erweiterter Log-Analyzer für Linux-Logs mit SSH Port-Forwarding-Unterstützung"""
    
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        super().__init__(ollama_url)
        self.linux_system_info = {}
        self.ssh_connection_info = {}
    
    def set_ssh_info(self, ssh_info: Dict[str, Any]):
        """Setzt SSH-Verbindungsinformationen"""
        self.ssh_connection_info = ssh_info
    
    def analyze_linux_logs(self, log_directory: str, system_info: Dict[str, Any]) -> None:
        """Analysiert Linux-Logs aus einem Verzeichnis"""
        self.linux_system_info = system_info
        
        console.print("[blue]Analysiere Linux-Logs...[/blue]")
        
        # Sammle alle Log-Dateien
        log_files = []
        for root, dirs, files in os.walk(log_directory):
            for file in files:
                if file.endswith(('.log', '.txt')):
                    log_files.append(os.path.join(root, file))
        
        console.print(f"[blue]Gefunden: {len(log_files)} Log-Dateien[/blue]")
        
        # Analysiere jede Log-Datei
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
                    self._analyze_linux_log_file(log_file)
                except Exception as e:
                    console.print(f"[yellow]Warnung: Fehler bei Analyse von {log_file}: {e}[/yellow]")
                
                progress.advance(task)
        
        console.print(f"[green]✓ {len(self.log_entries)} Log-Einträge analysiert[/green]")
    
    def _analyze_linux_log_file(self, log_file: str):
        """Analysiert eine einzelne Linux-Log-Datei"""
        source = self._determine_log_source(log_file)
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = self._parse_linux_log_line(line.strip(), source, log_file, line_num)
                    if entry:
                        self.log_entries.append(entry)
        except Exception as e:
            console.print(f"[yellow]Warnung: Konnte {log_file} nicht lesen: {e}[/yellow]")
    
    def _determine_log_source(self, log_file: str) -> str:
        """Bestimmt die Log-Quelle basierend auf dem Dateinamen"""
        filename = os.path.basename(log_file).lower()
        
        if 'auth' in filename or 'secure' in filename:
            return 'security'
        elif 'kernel' in filename or 'kern' in filename:
            return 'kernel'
        elif 'system' in filename or 'syslog' in filename:
            return 'system'
        elif 'web' in filename or 'apache' in filename or 'nginx' in filename:
            return 'web'
        elif 'database' in filename or 'mysql' in filename or 'postgresql' in filename:
            return 'database'
        elif 'mail' in filename:
            return 'mail'
        elif 'cron' in filename:
            return 'cron'
        elif 'journal' in filename or 'systemd' in filename:
            return 'systemd'
        elif 'network' in filename:
            return 'network'
        elif 'process' in filename:
            return 'processes'
        else:
            return 'unknown'
    
    def _parse_linux_log_line(self, line: str, source: str, filename: str, line_num: int) -> Optional[LogEntry]:
        import re
        """Parst eine Linux-Log-Zeile"""
        if not line.strip():
            return None
        
        # Verschiedene Linux-Log-Formate erkennen
        timestamp_patterns = [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # Standard syslog Format
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',  # ISO Format
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',  # ISO mit T
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\.\d+)',  # Mit Millisekunden
        ]
        
        timestamp = None
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    timestamp_str = match.group(1)
                    if 'T' in timestamp_str:  # ISO mit T
                        timestamp = datetime.fromisoformat(timestamp_str.replace('T', ' '))
                    elif len(timestamp_str.split()) == 3:  # Standard Format
                        timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                    else:  # ISO Format
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    break
                except ValueError:
                    continue
        
        if not timestamp:
            timestamp = datetime.now()
        
        # Log-Level erkennen
        level = LogLevel.INFO
        line_lower = line.lower()
        
        if any(word in line_lower for word in ['error', 'failed', 'failure', 'critical', 'emerg']):
            level = LogLevel.ERROR
        elif any(word in line_lower for word in ['warning', 'warn']):
            level = LogLevel.WARNING
        elif any(word in line_lower for word in ['panic', 'kernel panic', 'fatal', 'alert']):
            level = LogLevel.CRITICAL
        
        # Prioritäts-Score berechnen
        priority_score = self._calculate_linux_priority_score(line, level, source)
        
        return LogEntry(
            timestamp=timestamp,
            level=level,
            source=source,
            message=line.strip(),
            raw_line=line.strip(),
            priority_score=priority_score
        )
    
    def _calculate_linux_priority_score(self, line: str, level: LogLevel, source: str) -> float:
        """Berechnet Prioritäts-Score für Linux-Logs"""
        score = 0.0
        
        # Basis-Score basierend auf Log-Level
        level_scores = {
            LogLevel.INFO: 1.0,
            LogLevel.WARNING: 3.0,
            LogLevel.ERROR: 5.0,
            LogLevel.CRITICAL: 10.0
        }
        score += level_scores[level]
        
        # Linux-spezifische kritische Schlüsselwörter
        critical_keywords = [
            'kernel panic', 'panic', 'fatal', 'corruption', 'corrupted',
            'disk full', 'out of memory', 'oom', 'segmentation fault',
            'authentication failed', 'unauthorized access', 'malware',
            'virus', 'trojan', 'backdoor', 'rootkit', 'exploit',
            'buffer overflow', 'stack overflow', 'null pointer',
            'hardware error', 'cpu fault', 'memory fault',
            'emergency', 'alert', 'emerg', 'crit'
        ]
        
        warning_keywords = [
            'warning', 'failed', 'failure', 'timeout', 'connection refused',
            'permission denied', 'quota exceeded', 'high cpu usage',
            'high memory usage', 'disk space low', 'slow performance',
            'network timeout', 'dns resolution failed', 'ssl error',
            'certificate error', 'authentication timeout', 'denied'
        ]
        
        line_lower = line.lower()
        
        for keyword in critical_keywords:
            if keyword in line_lower:
                score += 5.0
        
        for keyword in warning_keywords:
            if keyword in line_lower:
                score += 2.0
        
        # Source-spezifische Gewichtung für Linux
        source_weights = {
            'security': 1.8,  # Höhere Gewichtung für Sicherheit
            'kernel': 1.5,
            'system': 1.2,
            'database': 1.3,
            'web': 1.1,
            'network': 1.2,
            'systemd': 1.0,
        }
        
        for source_key, weight in source_weights.items():
            if source_key in source:
                score *= weight
                break
        
        return min(score, 25.0)  # Maximaler Score für Linux
    
    def _create_linux_analysis_prompt(self, logs: List[LogEntry]) -> str:
        """Erstellt einen Linux-spezifischen Analyse-Prompt"""
        system_info = f"""
Linux-System-Informationen:
- Hostname: {self.linux_system_info.get('hostname', 'Unbekannt')}
- OS Version: {self.linux_system_info.get('os_version', 'Unbekannt')}
- Kernel Version: {self.linux_system_info.get('kernel_version', 'Unbekannt')}
- CPU Cores: {self.linux_system_info.get('cpu_cores', 'Unbekannt')}
- Memory: {self.linux_system_info.get('memory_total', 'Unbekannt')}
- Disk Usage: {self.linux_system_info.get('disk_usage', 'Unbekannt')}
- Uptime: {self.linux_system_info.get('uptime', 'Unbekannt')}
- SSH Connection: {self.ssh_connection_info.get('ssh_connection', 'Unbekannt')}
- Port Forwarding: {self.ssh_connection_info.get('port_forwarding', False)}
"""
        
        log_summary = "\n".join([
            f"[{entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {entry.level.value} ({entry.source}): {entry.message[:200]}..."
            for entry in logs[:30]  # Erste 30 für Prompt
        ])
        
        return f"""
Du bist ein erfahrener Linux-Systemadministrator mit umfassender Erfahrung in der Log-Analyse und Systemdiagnose.

Analysiere die folgenden Linux-Log-Einträge systematisch und identifiziere:

1. **Kritische Systemprobleme** (Kernel Panics, Hardware-Fehler, System-Crashes)
2. **Sicherheitsprobleme** (Authentifizierungsfehler, unbefugte Zugriffe, Malware-Indikatoren, SSH-Angriffe)
3. **Performance-Probleme** (hohe CPU/Memory-Nutzung, Timeouts, Ressourcen-Engpässe)
4. **Service-Probleme** (Failed Services, systemd-Fehler, Dependency-Probleme)
5. **Netzwerkprobleme** (Verbindungsfehler, DNS-Probleme, SSL/TLS-Fehler, Firewall-Issues)
6. **Dateisystem-Probleme** (Disk-Fehler, Permission-Probleme, Quota-Überschreitungen)
7. **Anwendungsfehler** (Web-Server-Fehler, Database-Probleme, Mail-Server-Issues)

{system_info}

Log-Einträge:
{log_summary}

Antworte ausschließlich im folgenden JSON-Format:
{{
    "anomalies": [
        {{
            "description": "Kurze, präzise Beschreibung des Problems",
            "severity": "CRITICAL|ERROR|WARNING|INFO",
            "affected_components": ["Liste der betroffenen Systemkomponenten"],
            "recommendations": [
                "Konkrete, umsetzbare Empfehlungen zur Problemlösung"
            ],
            "evidence": [
                "Relevante Log-Zeilen als Beweis für das Problem"
            ],
            "impact": "Beschreibung der Auswirkungen auf das System"
        }}
    ],
    "summary": "Kurze Zusammenfassung der wichtigsten Probleme und deren Priorität"
}}

Wichtige Hinweise für Linux-Systeme:
- Achte besonders auf systemd-Service-Fehler
- Überprüfe SSH-Sicherheitsprobleme
- Identifiziere Performance-Bottlenecks
- Erkenne Malware- und Angriffs-Indikatoren
- Gib Linux-spezifische Lösungsansätze
"""


def main():
    """Hauptfunktion für SSH-Log-Sammlung und -Analyse"""
    parser = argparse.ArgumentParser(description='SSH-basierter Linux-Log-Analyzer')
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
    
    console.print("[bold blue]SSH-basierter Linux-Log-Analyzer mit Port-Forwarding[/bold blue]")
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
        system_info = collector.get_system_info()
        
        # Sammle Logs
        log_directory = collector.collect_logs(hours_back=args.hours)
        
        if not log_directory or not os.path.exists(log_directory):
            console.print("[red]❌ Keine Logs gesammelt[/red]")
            return 1
        
        # Erstelle Linux-Log-Analyzer
        analyzer = LinuxLogAnalyzer()
        
        # Setze SSH-Informationen
        analyzer.set_ssh_info({
            'ssh_connection': system_info.get('ssh_connection'),
            'port_forwarding': system_info.get('port_forwarding', False)
        })
        
        # Überprüfe Ollama-Verbindung
        if not analyzer._check_ollama_connection():
            console.print("[red]❌ Ollama ist nicht erreichbar. Bitte starten Sie Ollama.[/red]")
            return 1
        
        console.print("[green]✅ Ollama-Verbindung erfolgreich[/green]")
        
        # Analysiere Linux-Logs
        analyzer.analyze_linux_logs(log_directory, system_info)
        
        if not analyzer.log_entries:
            console.print("[yellow]Keine Log-Einträge gefunden.[/yellow]")
            return 0
        
        # Analysiere mit Ollama
        analyzer.analyze_with_ollama()
        
        # Zeige Ergebnisse
        analyzer.display_results()
        
        # Erstelle Archiv
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


def start_interactive_chat(system_info: Dict[str, Any], log_entries: List[LogEntry], anomalies: List[Anomaly]):
    """Startet einen interaktiven Chat mit Ollama über das System"""
    console.print("\n[bold blue]🤖 Interaktiver Ollama-Chat gestartet[/bold blue]")
    console.print("="*60)
    console.print("[dim]Sie können jetzt Fragen über das analysierte System stellen.[/dim]")
    console.print("[dim]Beispiele:[/dim]")
    console.print("  • 'Welche Services laufen auf dem System?'")
    console.print("  • 'Wie ist der Speicherplatz?'")
    console.print("  • 'Gibt es Sicherheitsprobleme?'")
    console.print("  • 'Was sind die Top-Prozesse?'")
    console.print("  • 'exit' zum Beenden")
    console.print("="*60)
    
    # Erstelle System-Kontext für Ollama
    system_context = create_system_context(system_info, log_entries, anomalies)
    
    chat_history = []
    
    while True:
        try:
            # Benutzer-Eingabe
            user_input = Prompt.ask("\n[bold cyan]Sie[/bold cyan]")
            
            if user_input.lower() in ['exit', 'quit', 'q', 'beenden']:
                console.print("[yellow]Chat beendet.[/yellow]")
                break
            
            if not user_input.strip():
                continue
            
            # Erstelle vollständige Anfrage mit Kontext
            full_prompt = create_chat_prompt(system_context, user_input, chat_history)
            
            # Sende an Ollama
            console.print("[dim]Ollama denkt nach...[/dim]")
            response = query_ollama(full_prompt)
            
            if response:
                console.print(f"\n[bold green]Ollama[/bold green]: {response}")
                chat_history.append({"user": user_input, "assistant": response})
            else:
                console.print("[red]Fehler: Keine Antwort von Ollama erhalten.[/red]")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Chat beendet.[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Fehler im Chat: {e}[/red]")


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
    
    # Services
    if 'important_services_status' in system_info:
        context_parts.append("\n=== AKTIVE SERVICES ===")
        services = system_info['important_services_status']
        for service, status in services.items():
            context_parts.append(f"{service}: {status}")
    
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
    
    prompt_parts.append("Du bist ein erfahrener Linux-Systemadministrator und analysierst ein Linux-System.")
    prompt_parts.append("Hier sind die aktuellen System-Informationen:")
    prompt_parts.append(system_context)
    
    if chat_history:
        prompt_parts.append("\n=== CHAT-VERLAUF ===")
        for entry in chat_history[-3:]:  # Zeige nur die letzten 3 Einträge
            prompt_parts.append(f"Benutzer: {entry['user']}")
            prompt_parts.append(f"Du: {entry['assistant']}")
    
    prompt_parts.append(f"\nBenutzer-Frage: {user_question}")
    prompt_parts.append("\nAntworte hilfreich und präzise auf Deutsch. Verwende die verfügbaren System-Informationen für deine Antwort.")
    
    return "\n".join(prompt_parts)


def query_ollama(prompt: str) -> Optional[str]:
    """Sendet eine Anfrage an Ollama und gibt die Antwort zurück"""
    try:
        import requests
        
        url = "http://localhost:11434/api/generate"
        data = {
            "model": "llama3.2:3b",  # Standard-Modell, kann angepasst werden
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 1000
            }
        }
        
        response = requests.post(url, json=data, timeout=30)
        
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
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Analyse abgebrochen.[/yellow]")
        return 1
    except Exception as e:
        console.print(f"[red]Fehler bei der Analyse: {e}[/red]")
        return 1
    finally:
        # Cleanup
        collector.disconnect()
        if not args.keep_files:
            collector.cleanup()


if __name__ == "__main__":
    sys.exit(main()) 