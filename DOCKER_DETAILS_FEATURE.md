# Erweiterte Docker-Container-Details und Problem-Erkennung

## Übersicht

Das System wurde erweitert, um detaillierte Informationen über laufende Docker-Container und deren Probleme zu sammeln. Diese Erweiterung ermöglicht eine umfassende Analyse der Container-Umgebung und identifiziert automatisch potenzielle Probleme.

## Neue Features

### 1. Detaillierte Container-Analyse

Das System sammelt jetzt für jeden laufenden Container:

- **Health-Status**: Überprüfung des Container-Health-Checks
- **Container-Logs**: Letzte 50 Zeilen der Container-Logs
- **Log-Analyse**: Automatische Erkennung von Fehlern und Warnungen
- **Container-Statistiken**: CPU, Memory, Netzwerk und Block-I/O
- **Restart-Policy**: Konfigurierte Neustart-Richtlinie
- **Uptime**: Startzeitpunkt des Containers
- **Exit-Codes**: Für gestoppte Container

### 2. Erweiterte Problem-Erkennung

Das System identifiziert automatisch:

- **Gestoppte Container mit Fehlern**: Container mit Exit-Code ≠ 0
- **Health-Check-Fehler**: Container mit fehlgeschlagenen Health-Checks
- **Hohe Ressourcen-Nutzung**: Container mit >80% CPU oder Memory
- **Docker-Daemon-Probleme**: Fehler in den Docker-Daemon-Logs
- **Ungenutzte Ressourcen**: Dangling Images und Volumes

### 3. Log-Analyse

Automatische Analyse der Container-Logs:

- **Fehler-Erkennung**: Keywords: 'error', 'fatal', 'failed', 'exception', 'panic'
- **Warnungs-Erkennung**: Keywords: 'warn', 'warning', 'deprecated'
- **Letzte 10 Fehler/Warnungen**: Speicherung der relevantesten Log-Einträge

## Technische Implementierung

### Erweiterte `_analyze_docker()` Funktion

```python
def _analyze_docker(self) -> Dict[str, Any]:
    """Analysiert Docker mit erweiterten Container-Details"""
    
    # DETAILLIERTE CONTAINER-ANALYSE
    running_container_names = self.execute_remote_command('docker ps --format "{{.Names}}"')
    if running_container_names and running_container_names.strip():
        container_names = [name.strip() for name in running_container_names.split('\n') if name.strip()]
        
        container_details = {}
        container_stats = {}
        container_problems = []
        
        for container_name in container_names:
            # Container-Inspect
            inspect_cmd = f'docker inspect {container_name}'
            inspect_result = self.execute_remote_command(inspect_cmd)
            
            # Container-Logs (letzte 50 Zeilen)
            logs_cmd = f'docker logs --tail 50 {container_name} 2>&1'
            logs_result = self.execute_remote_command(logs_cmd)
            
            # Log-Analyse auf Fehler und Warnungen
            error_lines = []
            warning_lines = []
            for line in logs_result.split('\n'):
                line_lower = line.lower()
                if any(error_word in line_lower for error_word in ['error', 'fatal', 'failed', 'exception', 'panic']):
                    error_lines.append(line.strip())
                elif any(warning_word in line_lower for warning_word in ['warn', 'warning', 'deprecated']):
                    warning_lines.append(line.strip())
            
            # Container-Statistiken
            stats_cmd = f'docker stats {container_name} --no-stream --format "table {{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}"'
            stats_result = self.execute_remote_command(stats_cmd)
            
            # Health-Check
            health_cmd = f'docker inspect {container_name} --format "{{{{.State.Health.Status}}}}"'
            health_result = self.execute_remote_command(health_cmd)
            
            # Weitere Details...
```

### Neue Datenstrukturen

#### `container_details`
```python
{
    'container_name': {
        'inspect': 'vollständige inspect-Ausgabe',
        'name': 'container_name',
        'logs': 'letzte 50 Log-Zeilen',
        'errors': ['error1', 'error2', ...],
        'warnings': ['warning1', 'warning2', ...],
        'health_status': 'healthy|unhealthy|starting',
        'health_logs': 'Health-Check-Logs (falls unhealthy)',
        'restart_policy': 'unless-stopped|always|no',
        'started_at': '2024-07-01T10:30:00Z',
        'exit_code': '0'  # nur bei gestoppten Containern
    }
}
```

#### `container_stats`
```python
{
    'container_name': 'NAME                CPU %               MEM USAGE / LIMIT     MEM %               NET I/O             BLOCK I/O\ncontainer_name      0.5%                45.2MB / 512MB        8.8%                1.2MB / 856KB        2.1MB / 1.8MB'
}
```

#### `problems`
```python
[
    'Container database: Health-Check fehlgeschlagen',
    'Container database: Hohe CPU-Nutzung (85.2%)',
    'Gestoppter Container mit Fehler: old-backup (Exit-Code: 1)',
    'Docker-Daemon-Fehler:\n2025-07-24 19:00:00 docker[1234]: error: failed to start container database'
]
```

## System-Context Integration

Die neuen Docker-Details werden in den System-Context integriert:

### DOCKER-SYSTEM Bereich
- Basis-Docker-Informationen
- Laufende und alle Container
- Images, Volumes, Netzwerke
- System-Nutzung

### DETAILLIERTE CONTAINER-ANALYSE Bereich
- Health-Status für jeden Container
- Health-Check-Fehler (falls vorhanden)
- Restart-Policy und Uptime
- Letzte 5 Fehler und Warnungen aus den Logs

### CONTAINER-STATISTIKEN Bereich
- CPU, Memory, Netzwerk und Block-I/O für jeden Container

### DOCKER-PROBLEME Bereich
- Liste aller identifizierten Probleme mit Details

## Report-Integration

Die Docker-Details werden automatisch in den generierten Systembericht integriert:

### Docker-Details Sektion im Report
```
## Docker-Details (falls vorhanden)
- Version: 20.10.17
- Laufende Container: 3 Container
- Docker-Images: 5 Images
- Docker-Volumes: 4 Volumes
- Docker-Netzwerke: 3 Netzwerke
- System-Nutzung: 1.61GB Images, 0.1GB Container, 0.5GB Volumes

### Container-spezifische Details
- **my-prf**: Healthy, 2 Fehler in Logs, 0.5% CPU, 8.8% Memory
- **database**: Unhealthy, 5 Fehler in Logs, 85.2% CPU, 60.0% Memory
- **redis-cache**: Healthy, 0 Fehler, 2.1% CPU, 12.5% Memory

### Identifizierte Probleme
1. Container database: Health-Check fehlgeschlagen
2. Container database: Hohe CPU-Nutzung (85.2%)
3. Gestoppter Container mit Fehler: old-backup (Exit-Code: 1)
```

## Verwendung

### Automatische Erkennung
Die erweiterten Docker-Details werden automatisch gesammelt, wenn Docker auf dem Zielsystem erkannt wird.

### Manuelle Auslösung
```bash
# Normale Systemanalyse (enthält Docker-Details)
python ssh_chat_system.py --host example.com --username user

# Auto-Report mit Docker-Details
python ssh_chat_system.py --host example.com --username user --auto-report
```

### Chat-Integration
Im interaktiven Chat können Docker-spezifische Fragen gestellt werden:
- "Zeige mir die Docker-Container-Details"
- "Welche Container haben Probleme?"
- "Analysiere die Container-Logs"

## Vorteile

### 1. Umfassende Container-Überwachung
- Automatische Erkennung von Container-Problemen
- Detaillierte Performance-Metriken
- Log-basierte Problem-Identifikation

### 2. Proaktive Problem-Erkennung
- Health-Check-Überwachung
- Ressourcen-Nutzung-Alarme
- Docker-Daemon-Fehler-Erkennung

### 3. Detaillierte Berichterstattung
- Spezifische Container-Informationen im Systembericht
- Problem-Priorisierung
- Konkrete Handlungsempfehlungen

### 4. Debugging-Unterstützung
- Vollständige Log-Analyse
- Container-Inspect-Informationen
- Statistiken für Performance-Optimierung

## Beispiele

### Beispiel 1: Gesunder Container
```
--- Container: my-prf ---
Health-Status: healthy
Restart-Policy: unless-stopped
Gestartet: 2024-07-01T10:30:00Z
Letzte Fehler in Logs:
  ERROR: 2025-07-24 19:02:33 - 1#1: *4 upstream timed out (110: Connection timed out)
  ERROR: 2025-07-24 18:58:15 - 1#1: *8 upstream timed out (110: Connection timed out)
Letzte Warnungen in Logs:
  WARN: 2025-07-24 19:03:45 - 1#1: *3 client sent invalid method while reading client request line
```

### Beispiel 2: Problembehafteter Container
```
--- Container: database ---
Health-Status: unhealthy
Restart-Policy: always
Gestartet: 2024-07-08T15:45:00Z
Health-Check-Fehler:
2025-07-24 19:05:00 - Health check failed: Connection refused
2025-07-24 19:04:30 - Health check failed: Connection refused
Letzte Fehler in Logs:
  ERROR: 2025-07-24 19:05:00 - [ERROR] MySQL server has gone away
  ERROR: 2025-07-24 19:04:30 - [ERROR] Connection timeout
```

## Nächste Schritte

### Geplante Erweiterungen
1. **Container-Monitoring**: Echtzeit-Überwachung der Container
2. **Automatische Reparatur**: Automatische Neustarts bei Problemen
3. **Performance-Optimierung**: Empfehlungen basierend auf Statistiken
4. **Backup-Integration**: Automatische Backup-Strategien für Container

### Verbesserungen
1. **Erweiterte Log-Analyse**: Machine Learning für Anomalie-Erkennung
2. **Container-Security**: Sicherheits-Scans für Container-Images
3. **Resource-Prediction**: Vorhersage von Ressourcen-Bedarf
4. **Multi-Host-Support**: Analyse von Docker-Swarm oder Kubernetes-Clustern

## Fazit

Die erweiterten Docker-Container-Details bieten eine umfassende Lösung für die Überwachung und Analyse von Docker-Umgebungen. Sie ermöglichen proaktive Problem-Erkennung und liefern detaillierte Informationen für effektive Systemadministration und Troubleshooting. 