#!/usr/bin/env python3
"""
macOS Logfile-Analysator mit Ollama-Integration
Analysiert System-Logs und priorisiert Auffälligkeiten
"""

import os
import sys
import json
import subprocess
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
import re
from dataclasses import dataclass
from enum import Enum

console = Console()

class LogLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

@dataclass
class LogEntry:
    timestamp: datetime
    level: LogLevel
    source: str
    message: str
    raw_line: str
    priority_score: float = 0.0

@dataclass
class Anomaly:
    description: str
    severity: LogLevel
    affected_components: List[str]
    recommendations: List[str]
    evidence: List[str]
    priority_score: float

class LogAnalyzer:
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.ollama_url = ollama_url
        self.log_entries: List[LogEntry] = []
        self.anomalies: List[Anomaly] = []
        self.system_info = self._get_system_info()
        
    def _get_system_info(self) -> Dict[str, Any]:
        """Sammelt System-Informationen"""
        try:
            return {
                "hostname": os.uname().nodename,
                "os_version": os.uname().release,
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "disk_usage": psutil.disk_usage('/').percent
            }
        except Exception as e:
            console.print(f"[red]Fehler beim Sammeln der System-Informationen: {e}[/red]")
            return {}
    
    def _check_ollama_connection(self) -> bool:
        """Überprüft die Verbindung zu Ollama"""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False
    
    def collect_logs(self, hours_back: int = 24) -> None:
        """Sammelt Logs aus verschiedenen macOS-Quellen"""
        console.print("[bold blue]Sammle System-Logs...[/bold blue]")
        
        log_sources = [
            ("/var/log/system.log", "system"),
            ("/var/log/install.log", "install"),
            ("/var/log/secure.log", "security"),
            ("/var/log/fsck_hfs.log", "filesystem"),
            ("/var/log/fsck_apfs.log", "filesystem"),
            ("/var/log/fsck_exfat.log", "filesystem"),
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Sammle Logs...", total=len(log_sources))
            
            for log_path, source in log_sources:
                progress.update(task, description=f"Lese {source} Logs...")
                self._read_log_file(log_path, source, hours_back)
                progress.advance(task)
        
        # Sammle auch LaunchDaemon und LaunchAgent Logs
        self._collect_launch_logs(hours_back)
        
        console.print(f"[green]✓ {len(self.log_entries)} Log-Einträge gesammelt[/green]")
    
    def _read_log_file(self, log_path: str, source: str, hours_back: int) -> None:
        """Liest eine einzelne Log-Datei"""
        if not os.path.exists(log_path):
            return
        
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    entry = self._parse_log_line(line, source)
                    if entry and entry.timestamp >= cutoff_time:
                        self.log_entries.append(entry)
        except Exception as e:
            console.print(f"[yellow]Warnung: Konnte {log_path} nicht lesen: {e}[/yellow]")
    
    def _collect_launch_logs(self, hours_back: int) -> None:
        """Sammelt LaunchDaemon und LaunchAgent Logs"""
        launch_dirs = [
            "/Library/LaunchDaemons",
            "/System/Library/LaunchDaemons",
            f"{os.path.expanduser('~')}/Library/LaunchAgents",
            "/Library/LaunchAgents"
        ]
        
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        for launch_dir in launch_dirs:
            if os.path.exists(launch_dir):
                for file in os.listdir(launch_dir):
                    if file.endswith('.plist'):
                        plist_path = os.path.join(launch_dir, file)
                        try:
                            # Verwende log show für Launch-Service Logs
                            result = subprocess.run(
                                ["log", "show", "--predicate", f"process == '{file}'", 
                                 "--start", cutoff_time.strftime("%%Y-%%m-%%d %%H:%%M:%%S")],
                                capture_output=True, text=True, timeout=30
                            )
                            if result.stdout:
                                for line in result.stdout.split('\n'):
                                    if line.strip():
                                        entry = self._parse_log_line(line, f"launch_{file}")
                                        if entry:
                                            self.log_entries.append(entry)
                        except Exception as e:
                            continue
    
    def _parse_log_line(self, line: str, source: str) -> Optional[LogEntry]:
        """Parst eine einzelne Log-Zeile"""
        if not line.strip():
            return None
        
        # Verschiedene Log-Formate erkennen
        timestamp_patterns = [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # Standard macOS Format
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',  # ISO Format
        ]
        
        timestamp = None
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    timestamp_str = match.group(1)
                    if len(timestamp_str.split()) == 3:  # Standard Format
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
        if any(word in line.lower() for word in ['error', 'failed', 'failure', 'critical']):
            level = LogLevel.ERROR
        elif any(word in line.lower() for word in ['warning', 'warn']):
            level = LogLevel.WARNING
        elif any(word in line.lower() for word in ['panic', 'kernel panic', 'fatal']):
            level = LogLevel.CRITICAL
        
        # Prioritäts-Score berechnen
        priority_score = self._calculate_priority_score(line, level, source)
        
        return LogEntry(
            timestamp=timestamp,
            level=level,
            source=source,
            message=line.strip(),
            raw_line=line.strip(),
            priority_score=priority_score
        )
    
    def _calculate_priority_score(self, line: str, level: LogLevel, source: str) -> float:
        """Berechnet einen Prioritäts-Score für einen Log-Eintrag"""
        score = 0.0
        
        # Basis-Score basierend auf Log-Level
        level_scores = {
            LogLevel.INFO: 1.0,
            LogLevel.WARNING: 3.0,
            LogLevel.ERROR: 5.0,
            LogLevel.CRITICAL: 10.0
        }
        score += level_scores[level]
        
        # Wichtige Schlüsselwörter
        critical_keywords = [
            'kernel panic', 'panic', 'fatal', 'corruption', 'corrupted',
            'disk full', 'out of memory', 'oom', 'segmentation fault',
            'authentication failed', 'unauthorized access', 'malware',
            'virus', 'trojan', 'backdoor', 'rootkit'
        ]
        
        warning_keywords = [
            'warning', 'failed', 'failure', 'timeout', 'connection refused',
            'permission denied', 'quota exceeded', 'high cpu usage',
            'high memory usage', 'disk space low'
        ]
        
        line_lower = line.lower()
        
        for keyword in critical_keywords:
            if keyword in line_lower:
                score += 5.0
        
        for keyword in warning_keywords:
            if keyword in line_lower:
                score += 2.0
        
        # Source-spezifische Gewichtung
        source_weights = {
            'security': 1.5,
            'filesystem': 1.3,
            'system': 1.0,
            'install': 0.8
        }
        
        for source_key, weight in source_weights.items():
            if source_key in source:
                score *= weight
                break
        
        return min(score, 20.0)  # Maximaler Score
    
    def analyze_with_ollama(self) -> None:
        """Verwendet Ollama zur KI-gestützten Analyse"""
        if not self._check_ollama_connection():
            console.print("[red]❌ Ollama ist nicht erreichbar. Bitte starten Sie Ollama.[/red]")
            return
        
        console.print("[bold blue]Analysiere Logs mit Ollama...[/bold blue]")
        
        # Priorisiere Logs nach Score
        high_priority_logs = sorted(
            [entry for entry in self.log_entries if entry.priority_score >= 5.0],
            key=lambda x: x.priority_score,
            reverse=True
        )[:50]  # Top 50 für Analyse
        
        if not high_priority_logs:
            console.print("[yellow]Keine hochpriorisierten Logs gefunden.[/yellow]")
            return
        
        # Erstelle Analyse-Prompt
        analysis_prompt = self._create_analysis_prompt(high_priority_logs)
        
        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": "llama2",  # oder ein anderes verfügbares Modell
                    "prompt": analysis_prompt,
                    "stream": False
                },
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                self._parse_ollama_response(result.get('response', ''), high_priority_logs)
            else:
                console.print(f"[red]Fehler bei Ollama-Anfrage: {response.status_code}[/red]")
                
        except Exception as e:
            console.print(f"[red]Fehler bei der Ollama-Analyse: {e}[/red]")
    
    def _create_analysis_prompt(self, logs: List[LogEntry]) -> str:
        """Erstellt den Prompt für Ollama"""
        system_info = f"""
System-Informationen:
- Hostname: {self.system_info.get('hostname', 'Unbekannt')}
- OS Version: {self.system_info.get('os_version', 'Unbekannt')}
- CPU Cores: {self.system_info.get('cpu_count', 'Unbekannt')}
- Speicher: {self.system_info.get('memory_total', 0) // (1024**3)} GB
- Disk Usage: {self.system_info.get('disk_usage', 0)}%
"""
        
        log_summary = "\n".join([
            f"[{entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {entry.level.value} ({entry.source}): {entry.message[:200]}..."
            for entry in logs[:20]  # Erste 20 für Prompt
        ])
        
        return f"""
Du bist ein erfahrener macOS-Systemadministrator. Analysiere die folgenden Log-Einträge und identifiziere:

1. **Kritische Systemprobleme** (Kernel Panics, Hardware-Fehler, etc.)
2. **Sicherheitsprobleme** (Authentifizierungsfehler, unbefugte Zugriffe, etc.)
3. **Performance-Probleme** (hohe CPU/Memory-Nutzung, Timeouts, etc.)
4. **Anwendungsfehler** (App-Crashes, Service-Fehler, etc.)
5. **Netzwerkprobleme** (Verbindungsfehler, DNS-Probleme, etc.)

{system_info}

Log-Einträge:
{log_summary}

Antworte im folgenden JSON-Format:
{{
    "anomalies": [
        {{
            "description": "Kurze Beschreibung des Problems",
            "severity": "CRITICAL|ERROR|WARNING|INFO",
            "affected_components": ["Liste betroffener Komponenten"],
            "recommendations": ["Liste von Empfehlungen"],
            "evidence": ["Relevante Log-Zeilen als Beweis"]
        }}
    ],
    "summary": "Kurze Zusammenfassung der wichtigsten Probleme"
}}
"""
    
    def _parse_ollama_response(self, response: str, logs: List[LogEntry]) -> None:
        """Parst die Ollama-Antwort"""
        try:
            # Versuche JSON aus der Antwort zu extrahieren
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start != -1 and json_end != 0:
                json_str = response[json_start:json_end]
                data = json.loads(json_str)
                
                # Anomalien erstellen
                for anomaly_data in data.get('anomalies', []):
                    severity = LogLevel(anomaly_data.get('severity', 'INFO'))
                    anomaly = Anomaly(
                        description=anomaly_data.get('description', ''),
                        severity=severity,
                        affected_components=anomaly_data.get('affected_components', []),
                        recommendations=anomaly_data.get('recommendations', []),
                        evidence=anomaly_data.get('evidence', []),
                        priority_score=self._calculate_anomaly_priority(severity, anomaly_data)
                    )
                    self.anomalies.append(anomaly)
                
                console.print(f"[green]✓ {len(self.anomalies)} Anomalien identifiziert[/green]")
                
        except json.JSONDecodeError as e:
            console.print(f"[yellow]Warnung: Konnte Ollama-Antwort nicht parsen: {e}[/yellow]")
            console.print(f"[dim]Antwort: {response[:500]}...[/dim]")
    
    def _calculate_anomaly_priority(self, severity: LogLevel, anomaly_data: Dict) -> float:
        """Berechnet Priorität für eine Anomalie"""
        base_scores = {
            LogLevel.CRITICAL: 10.0,
            LogLevel.ERROR: 7.0,
            LogLevel.WARNING: 4.0,
            LogLevel.INFO: 2.0
        }
        
        score = base_scores[severity]
        
        # Zusätzliche Punkte für Anzahl der Empfehlungen und Beweise
        score += len(anomaly_data.get('recommendations', [])) * 0.5
        score += len(anomaly_data.get('evidence', [])) * 0.3
        
        return min(score, 20.0)
    
    def display_results(self) -> None:
        """Zeigt die Analyseergebnisse an"""
        console.print("\n" + "="*80)
        console.print("[bold blue]macOS Logfile-Analyse Ergebnisse[/bold blue]")
        console.print("="*80)
        
        # System-Übersicht
        system_panel = Panel(
            f"Hostname: {self.system_info.get('hostname', 'Unbekannt')}\n"
            f"OS Version: {self.system_info.get('os_version', 'Unbekannt')}\n"
            f"CPU Cores: {self.system_info.get('cpu_count', 'Unbekannt')}\n"
            f"Speicher: {self.system_info.get('memory_total', 0) // (1024**3)} GB\n"
            f"Disk Usage: {self.system_info.get('disk_usage', 0)}%",
            title="System-Informationen",
            border_style="blue"
        )
        console.print(system_panel)
        
        # Anomalien-Tabelle
        if self.anomalies:
            console.print("\n[bold red]🚨 Identifizierte Anomalien (Priorisiert)[/bold red]")
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Priorität", style="cyan", width=8)
            table.add_column("Schweregrad", style="red", width=12)
            table.add_column("Beschreibung", style="white", width=40)
            table.add_column("Betroffene Komponenten", style="yellow", width=20)
            
            # Sortiere nach Priorität
            sorted_anomalies = sorted(self.anomalies, key=lambda x: x.priority_score, reverse=True)
            
            for i, anomaly in enumerate(sorted_anomalies, 1):
                severity_color = {
                    LogLevel.CRITICAL: "red",
                    LogLevel.ERROR: "orange",
                    LogLevel.WARNING: "yellow",
                    LogLevel.INFO: "blue"
                }[anomaly.severity]
                
                table.add_row(
                    f"#{i}",
                    f"[{severity_color}]{anomaly.severity.value}[/{severity_color}]",
                    anomaly.description[:38] + "..." if len(anomaly.description) > 40 else anomaly.description,
                    ", ".join(anomaly.affected_components[:2]) + ("..." if len(anomaly.affected_components) > 2 else "")
                )
            
            console.print(table)
            
            # Detaillierte Anomalien
            console.print("\n[bold]📋 Detaillierte Anomalien-Analyse[/bold]")
            for i, anomaly in enumerate(sorted_anomalies, 1):
                console.print(f"\n[bold cyan]{i}. {anomaly.description}[/bold cyan]")
                console.print(f"   Schweregrad: [{severity_color}]{anomaly.severity.value}[/{severity_color}]")
                console.print(f"   Betroffene Komponenten: {', '.join(anomaly.affected_components)}")
                
                if anomaly.recommendations:
                    console.print("   [bold green]Empfehlungen:[/bold green]")
                    for rec in anomaly.recommendations:
                        console.print(f"   • {rec}")
                
                if anomaly.evidence:
                    console.print("   [bold yellow]Beweise:[/bold yellow]")
                    for evidence in anomaly.evidence[:3]:  # Maximal 3 Beweise
                        console.print(f"   • {evidence}")
        
        # Log-Statistiken
        console.print("\n[bold]📊 Log-Statistiken[/bold]")
        
        level_counts = {}
        source_counts = {}
        
        for entry in self.log_entries:
            level_counts[entry.level] = level_counts.get(entry.level, 0) + 1
            source_counts[entry.source] = source_counts.get(entry.source, 0) + 1
        
        stats_table = Table(show_header=True, header_style="bold green")
        stats_table.add_column("Kategorie", style="cyan")
        stats_table.add_column("Anzahl", style="white")
        
        for level, count in sorted(level_counts.items(), key=lambda x: x[1], reverse=True):
            stats_table.add_row(f"Log-Level: {level.value}", str(count))
        
        for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            stats_table.add_row(f"Quelle: {source}", str(count))
        
        console.print(stats_table)
        
        # Zusammenfassung
        if self.anomalies:
            critical_count = len([a for a in self.anomalies if a.severity == LogLevel.CRITICAL])
            error_count = len([a for a in self.anomalies if a.severity == LogLevel.ERROR])
            
            summary_text = f"""
[bold]Zusammenfassung:[/bold]
• {len(self.log_entries)} Log-Einträge analysiert
• {len(self.anomalies)} Anomalien identifiziert
• {critical_count} kritische Probleme
• {error_count} Fehler gefunden

[bold red]Nächste Schritte:[/bold red]
1. Überprüfen Sie die kritischen Probleme sofort
2. Implementieren Sie die empfohlenen Lösungen
3. Überwachen Sie das System kontinuierlich
"""
            console.print(Panel(summary_text, title="Zusammenfassung", border_style="red"))
        else:
            console.print(Panel("✅ Keine kritischen Probleme gefunden!", title="Zusammenfassung", border_style="green"))

def main():
    """Hauptfunktion"""
    console.print("[bold blue]macOS Logfile-Analysator mit Ollama-Integration[/bold blue]")
    console.print("="*60)
    
    # Überprüfe Ollama-Verbindung
    analyzer = LogAnalyzer()
    
    if not analyzer._check_ollama_connection():
        console.print("[red]❌ Ollama ist nicht erreichbar unter http://localhost:11434[/red]")
        console.print("[yellow]Bitte starten Sie Ollama mit: ollama serve[/yellow]")
        console.print("[yellow]Und installieren Sie ein Modell mit: ollama pull llama2[/yellow]")
        return
    
    console.print("[green]✅ Ollama-Verbindung erfolgreich[/green]")
    
    # Sammle Logs
    try:
        analyzer.collect_logs(hours_back=24)
        
        if not analyzer.log_entries:
            console.print("[yellow]Keine Logs in den letzten 24 Stunden gefunden.[/yellow]")
            return
        
        # Analysiere mit Ollama
        analyzer.analyze_with_ollama()
        
        # Zeige Ergebnisse
        analyzer.display_results()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Analyse abgebrochen.[/yellow]")
    except Exception as e:
        console.print(f"[red]Fehler bei der Analyse: {e}[/red]")

if __name__ == "__main__":
    main() 