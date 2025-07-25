# Dynamische Menü-Funktionalität

## Übersicht

Die dynamische Menü-Funktionalität zeigt nur die Module an, die tatsächlich auf dem Zielsystem vorhanden sind. Dies macht die Benutzeroberfläche übersichtlicher und relevanter.

## Funktionsweise

### Modul-Erkennung

Das System erkennt automatisch, welche Module auf dem Zielsystem installiert sind:

- **Kubernetes**: Erkennung durch `which kubectl`
- **Proxmox**: Erkennung durch `which pvesh`
- **Docker**: Erkennung durch `which docker`
- **Mailserver**: Erkennung durch verschiedene Checks (Mailcow, Postfix, etc.)

### Menü-Generierung

Das intelligente Menü wird basierend auf den erkannten Modulen dynamisch erstellt:

```python
def create_intelligent_menu(shortcuts: Dict, system_info: Dict[str, Any] = None) -> str:
    # Prüfe welche Module auf dem System vorhanden sind
    available_modules = {
        'system': True,  # System ist immer verfügbar
        'kubernetes': False,
        'proxmox': False,
        'docker': False,
        'mailservers': False,
        'network-security': True,  # Netzwerk-Sicherheit ist immer verfügbar
        'tools': True  # Tools sind immer verfügbar
    }
    
    if system_info:
        # Prüfe erkannte Module
        if system_info.get('kubernetes_detected', False):
            available_modules['kubernetes'] = True
        # ... weitere Module
```

## Beispiele

### System ohne spezielle Module

```
Verfügbare Kürzelwörter:

System:
  • s1 / 'services' - Zeige alle wichtigen Services und ihren Status
  • s2 / 'storage' - Analysiere Speicherplatz und -nutzung
  • s3 / 'security' - Führe Sicherheitsanalyse durch
  • s4 / 'processes' - Zeige laufende Prozesse und Ressourcenverbrauch
  • s5 / 'performance' - Analysiere System-Performance
  • s6 / 'users' - Zeige aktuelle Benutzer und Login-Statistiken
  • s7 / 'updates' - Prüfe verfügbare System-Updates
  • s8 / 'logs' - Analysiere wichtige Log-Dateien

Netzwerk-Sicherheit:
  • n1 / 'network-security' - Führe umfassende Netzwerk-Sicherheitsanalyse durch
  • n2 / 'exposed-services' - Identifiziere nach außen exponierte Services
  • n3 / 'port-scan' - Führe Port-Scan durch
  • n4 / 'service-test' - Teste Service-Erreichbarkeit

Berichte & Tools:
  • t1 / 'report' - Generiere detaillierten Systembericht
  • t2 / 'cache' - Zeige Cache-Status
  • t3 / 'clear' - Lösche Cache

🔍 Keine spezielle Module erkannt (nur Standard-System)
```

### System mit Docker

```
Verfügbare Kürzelwörter:

System:
  • s1 / 'services' - Zeige alle wichtigen Services und ihren Status
  • s2 / 'storage' - Analysiere Speicherplatz und -nutzung
  • s3 / 'security' - Führe Sicherheitsanalyse durch
  • s4 / 'processes' - Zeige laufende Prozesse und Ressourcenverbrauch
  • s5 / 'performance' - Analysiere System-Performance
  • s6 / 'users' - Zeige aktuelle Benutzer und Login-Statistiken
  • s7 / 'updates' - Prüfe verfügbare System-Updates
  • s8 / 'logs' - Analysiere wichtige Log-Dateien

Docker:
  • d1 / 'docker' - Zeige Docker-Status und -Informationen
  • d2 / 'docker-problems' - Identifiziere Docker-Probleme
  • d3 / 'docker-containers' - Zeige alle Docker-Container
  • d4 / 'docker-images' - Zeige alle Docker-Images

Netzwerk-Sicherheit:
  • n1 / 'network-security' - Führe umfassende Netzwerk-Sicherheitsanalyse durch
  • n2 / 'exposed-services' - Identifiziere nach außen exponierte Services
  • n3 / 'port-scan' - Führe Port-Scan durch
  • n4 / 'service-test' - Teste Service-Erreichbarkeit

Berichte & Tools:
  • t1 / 'report' - Generiere detaillierten Systembericht
  • t2 / 'cache' - Zeige Cache-Status
  • t3 / 'clear' - Lösche Cache

🔍 Erkannte Module: Docker
```

### System mit mehreren Modulen

```
Verfügbare Kürzelwörter:

System:
  • s1 / 'services' - Zeige alle wichtigen Services und ihren Status
  • s2 / 'storage' - Analysiere Speicherplatz und -nutzung
  • s3 / 'security' - Führe Sicherheitsanalyse durch
  • s4 / 'processes' - Zeige laufende Prozesse und Ressourcenverbrauch
  • s5 / 'performance' - Analysiere System-Performance
  • s6 / 'users' - Zeige aktuelle Benutzer und Login-Statistiken
  • s7 / 'updates' - Prüfe verfügbare System-Updates
  • s8 / 'logs' - Analysiere wichtige Log-Dateien

Kubernetes:
  • k1 / 'k8s' - Zeige Kubernetes-Cluster-Status
  • k2 / 'k8s-problems' - Identifiziere Kubernetes-Probleme
  • k3 / 'k8s-pods' - Zeige alle Pods und ihren Status
  • k4 / 'k8s-nodes' - Zeige alle Nodes und ihren Status
  • k5 / 'k8s-resources' - Zeige Ressourcen-Auslastung

Proxmox:
  • p1 / 'proxmox' - Zeige Proxmox VE-Status
  • p2 / 'proxmox-problems' - Identifiziere Proxmox-Probleme
  • p3 / 'proxmox-vms' - Zeige alle VMs und ihren Status
  • p4 / 'proxmox-containers' - Zeige alle Container und ihren Status
  • p5 / 'proxmox-storage' - Zeige Storage-Status

Docker:
  • d1 / 'docker' - Zeige Docker-Status und -Informationen
  • d2 / 'docker-problems' - Identifiziere Docker-Probleme
  • d3 / 'docker-containers' - Zeige alle Docker-Container
  • d4 / 'docker-images' - Zeige alle Docker-Images

Mailserver:
  • m1 / 'mailservers' - Zeige Mailserver-Status
  • m2 / 'mailcow' - Zeige Mailcow-Status
  • m3 / 'mailcow-problems' - Identifiziere Mailcow-Probleme
  • m4 / 'postfix' - Zeige Postfix-Status
  • m5 / 'postfix-problems' - Identifiziere Postfix-Probleme

Netzwerk-Sicherheit:
  • n1 / 'network-security' - Führe umfassende Netzwerk-Sicherheitsanalyse durch
  • n2 / 'exposed-services' - Identifiziere nach außen exponierte Services
  • n3 / 'port-scan' - Führe Port-Scan durch
  • n4 / 'service-test' - Teste Service-Erreichbarkeit

Berichte & Tools:
  • t1 / 'report' - Generiere detaillierten Systembericht
  • t2 / 'cache' - Zeige Cache-Status
  • t3 / 'clear' - Lösche Cache

🔍 Erkannte Module: Kubernetes, Proxmox, Docker, Mailserver
```

## Vorteile

### 1. Übersichtlichkeit
- Nur relevante Module werden angezeigt
- Reduzierte kognitive Belastung
- Fokus auf verfügbare Funktionen

### 2. Relevanz
- Keine verwirrenden Optionen für nicht vorhandene Module
- Klare Information über erkannte Module
- Bessere Benutzerführung

### 3. Effizienz
- Schnellere Navigation
- Weniger Scrollen
- Direkter Zugriff auf verfügbare Funktionen

## Technische Details

### Erkennungslogik

```python
# Prüfe Kubernetes
if system_info.get('kubernetes_detected', False):
    available_modules['kubernetes'] = True

# Prüfe Proxmox
if system_info.get('proxmox_detected', False):
    available_modules['proxmox'] = True

# Prüfe Docker
if system_info.get('docker_detected', False):
    available_modules['docker'] = True

# Prüfe Mailserver
if (system_info.get('mailcow_detected', False) or 
    system_info.get('postfix_detected', False) or
    system_info.get('mailserver_detected', False)):
    available_modules['mailservers'] = True
```

### Menü-Generierung

```python
for category, shortcut_list in categories.items():
    # Zeige nur Kategorien an, die verfügbar sind
    if not available_modules.get(category, True):
        continue
    
    # Erstelle Kategorie-Header
    if category == 'system':
        menu_parts.append(f"\n[bold green]System:[/bold green]")
    elif category == 'docker':
        menu_parts.append(f"\n[bold cyan]Docker:[/bold cyan]")
    # ... weitere Kategorien
    
    # Füge Shortcuts hinzu
    for code, shortcut in shortcut_list:
        if shortcut in shortcuts:
            question = shortcuts[shortcut]['question']
            menu_parts.append(f"  • {code} / '{shortcut}' - {question}")
```

## Tests

Die Funktionalität wird durch `test_dynamic_menu.py` umfassend getestet:

```bash
python test_dynamic_menu.py
```

### Test-Szenarien

1. **System ohne spezielle Module**: Prüft, ob nur System und Tools angezeigt werden
2. **System mit Docker**: Prüft, ob Docker-Modul korrekt angezeigt wird
3. **System mit mehreren Modulen**: Prüft, ob alle erkannten Module angezeigt werden
4. **System mit nur Mailserver**: Prüft, ob nur relevante Module angezeigt werden
5. **Menü-Längen-Vergleich**: Prüft, ob Menüs korrekte Längen haben
6. **Shortcut-Verfügbarkeit**: Prüft, ob alle erwarteten Shortcuts vorhanden sind

## Integration

Die dynamische Menü-Funktionalität ist vollständig in das bestehende System integriert:

- **Chat-System**: Menü wird automatisch beim Start angezeigt
- **Help-Befehl**: Dynamisches Menü bei `help`, `m` oder `menu`
- **Shortcut-Interpolation**: Funktioniert weiterhin mit allen verfügbaren Shortcuts
- **Ollama-Integration**: Keine Änderungen an der KI-Integration

## Zukunft

### Erweiterte Module
- **Monitoring-Systeme** (Prometheus, Grafana, etc.)
- **Databases** (MySQL, PostgreSQL, MongoDB, etc.)
- **Web-Server** (Apache, Nginx, etc.)
- **Load Balancer** (HAProxy, Nginx, etc.)

### Intelligente Erkennung
- **Automatische Konfigurationsanalyse**
- **Service-Dependency-Erkennung**
- **Performance-basierte Modul-Priorisierung**

## Status

✅ **Implementiert** - Dynamische Menü-Funktionalität ist vollständig implementiert und getestet 