#!/usr/bin/env python3
"""
Konfigurationsdatei für den macOS Logfile-Analysator
"""

import os
from typing import List, Dict, Any

class Config:
    """Konfigurationsklasse für den Logfile-Analysator"""
    
    # Ollama-Einstellungen
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama2")
    OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))
    
    # Log-Analyse-Einstellungen
    DEFAULT_HOURS_BACK = int(os.getenv("DEFAULT_HOURS_BACK", "24"))
    MAX_LOG_ENTRIES = int(os.getenv("MAX_LOG_ENTRIES", "10000"))
    HIGH_PRIORITY_THRESHOLD = float(os.getenv("HIGH_PRIORITY_THRESHOLD", "5.0"))
    MAX_ANALYSIS_LOGS = int(os.getenv("MAX_ANALYSIS_LOGS", "50"))
    
    # Log-Quellen
    LOG_SOURCES = [
        ("/var/log/system.log", "system"),
        ("/var/log/install.log", "install"),
        ("/var/log/secure.log", "security"),
        ("/var/log/fsck_hfs.log", "filesystem"),
        ("/var/log/fsck_apfs.log", "filesystem"),
        ("/var/log/fsck_exfat.log", "filesystem"),
        ("/var/log/wifi.log", "network"),
        ("/var/log/airport.log", "network"),
        ("/var/log/DiagnosticReports", "diagnostics"),
    ]
    
    # Launch-Service-Verzeichnisse
    LAUNCH_DIRECTORIES = [
        "/Library/LaunchDaemons",
        "/System/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        f"{os.path.expanduser('~')}/Library/LaunchAgents",
    ]
    
    # Prioritäts-Schlüsselwörter
    CRITICAL_KEYWORDS = [
        'kernel panic', 'panic', 'fatal', 'corruption', 'corrupted',
        'disk full', 'out of memory', 'oom', 'segmentation fault',
        'authentication failed', 'unauthorized access', 'malware',
        'virus', 'trojan', 'backdoor', 'rootkit', 'exploit',
        'buffer overflow', 'stack overflow', 'null pointer',
        'hardware error', 'cpu fault', 'memory fault'
    ]
    
    WARNING_KEYWORDS = [
        'warning', 'failed', 'failure', 'timeout', 'connection refused',
        'permission denied', 'quota exceeded', 'high cpu usage',
        'high memory usage', 'disk space low', 'slow performance',
        'network timeout', 'dns resolution failed', 'ssl error',
        'certificate error', 'authentication timeout'
    ]
    
    # Source-spezifische Gewichtungen
    SOURCE_WEIGHTS = {
        'security': 1.5,
        'filesystem': 1.3,
        'network': 1.2,
        'diagnostics': 1.1,
        'system': 1.0,
        'install': 0.8,
    }
    
    # Log-Level Scores
    LOG_LEVEL_SCORES = {
        'INFO': 1.0,
        'WARNING': 3.0,
        'ERROR': 5.0,
        'CRITICAL': 10.0,
    }
    
    # Ausgabe-Einstellungen
    OUTPUT_FORMATS = ['terminal', 'json', 'csv', 'html']
    DEFAULT_OUTPUT_FORMAT = 'terminal'
    
    # Farben für Terminal-Ausgabe
    COLORS = {
        'CRITICAL': 'red',
        'ERROR': 'orange',
        'WARNING': 'yellow',
        'INFO': 'blue',
        'SUCCESS': 'green',
    }
    
    # Ollama-Prompt-Templates
    ANALYSIS_PROMPT_TEMPLATE = """
Du bist ein erfahrener macOS-Systemadministrator mit umfassender Erfahrung in der Log-Analyse und Systemdiagnose.

Analysiere die folgenden Log-Einträge systematisch und identifiziere:

1. **Kritische Systemprobleme** (Kernel Panics, Hardware-Fehler, System-Crashes)
2. **Sicherheitsprobleme** (Authentifizierungsfehler, unbefugte Zugriffe, Malware-Indikatoren)
3. **Performance-Probleme** (hohe CPU/Memory-Nutzung, Timeouts, Ressourcen-Engpässe)
4. **Anwendungsfehler** (App-Crashes, Service-Fehler, Dependency-Probleme)
5. **Netzwerkprobleme** (Verbindungsfehler, DNS-Probleme, SSL/TLS-Fehler)
6. **Dateisystem-Probleme** (Disk-Fehler, Permission-Probleme, Quota-Überschreitungen)

System-Informationen:
{system_info}

Log-Einträge:
{log_entries}

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

Wichtige Hinweise:
- Sei präzise und technisch korrekt
- Priorisiere nach Schweregrad und Systemauswirkung
- Gib konkrete, umsetzbare Empfehlungen
- Verwende nur die bereitgestellten Log-Daten als Beweis
"""
    
    # Erweiterte Analyse-Optionen
    ENABLE_MACHINE_LEARNING = os.getenv("ENABLE_ML", "false").lower() == "true"
    ENABLE_PATTERN_DETECTION = os.getenv("ENABLE_PATTERNS", "true").lower() == "true"
    ENABLE_TREND_ANALYSIS = os.getenv("ENABLE_TRENDS", "true").lower() == "true"
    
    # Berichts-Einstellungen
    REPORT_INCLUDE_STATISTICS = True
    REPORT_INCLUDE_RECOMMENDATIONS = True
    REPORT_INCLUDE_EVIDENCE = True
    REPORT_MAX_EVIDENCE_LINES = 5
    
    # Performance-Einstellungen
    BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))
    MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT", "3"))
    
    @classmethod
    def get_log_sources(cls) -> List[tuple]:
        """Gibt die konfigurierten Log-Quellen zurück"""
        return cls.LOG_SOURCES
    
    @classmethod
    def get_critical_keywords(cls) -> List[str]:
        """Gibt die kritischen Schlüsselwörter zurück"""
        return cls.CRITICAL_KEYWORDS
    
    @classmethod
    def get_warning_keywords(cls) -> List[str]:
        """Gibt die Warnungs-Schlüsselwörter zurück"""
        return cls.WARNING_KEYWORDS
    
    @classmethod
    def get_source_weight(cls, source: str) -> float:
        """Gibt die Gewichtung für eine Log-Quelle zurück"""
        for source_key, weight in cls.SOURCE_WEIGHTS.items():
            if source_key in source:
                return weight
        return 1.0
    
    @classmethod
    def get_log_level_score(cls, level: str) -> float:
        """Gibt den Score für ein Log-Level zurück"""
        return cls.LOG_LEVEL_SCORES.get(level.upper(), 1.0)
    
    @classmethod
    def get_color(cls, level: str) -> str:
        """Gibt die Farbe für ein Log-Level zurück"""
        return cls.COLORS.get(level.upper(), 'white')
    
    @classmethod
    def validate_config(cls) -> bool:
        """Validiert die Konfiguration"""
        try:
            # Überprüfe Ollama-URL
            if not cls.OLLAMA_URL.startswith(('http://', 'https://')):
                return False
            
            # Überprüfe Timeouts
            if cls.OLLAMA_TIMEOUT <= 0:
                return False
            
            # Überprüfe Log-Einstellungen
            if cls.DEFAULT_HOURS_BACK <= 0 or cls.MAX_LOG_ENTRIES <= 0:
                return False
            
            return True
        except Exception:
            return False 