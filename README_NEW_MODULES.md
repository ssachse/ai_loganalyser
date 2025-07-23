# Neue Module: Docker & Mailserver-Analyse

## Übersicht

Das SSH-Log-Analyse-System wurde um umfassende Module für **Docker** und **Mailserver** erweitert. Diese Module ermöglichen eine detaillierte Analyse von Container-Umgebungen und E-Mail-Services.

## 🐳 Docker-Modul

### Funktionen

- **Automatische Erkennung**: Erkennt Docker-Installationen automatisch
- **Container-Überwachung**: Zeigt laufende und gestoppte Container
- **Image-Management**: Listet verfügbare Docker-Images
- **Volume-Überwachung**: Zeigt Docker-Volumes und deren Status
- **Netzwerk-Analyse**: Überwacht Docker-Netzwerke
- **Problem-Erkennung**: Identifiziert Docker-spezifische Probleme

### Erkennung

```bash
# Prüft ob Docker verfügbar ist
which docker

# Docker-Version
docker --version

# Docker-Info
docker info
```

### Analysierte Bereiche

1. **Container-Status**
   - Laufende Container mit Details
   - Gestoppte Container
   - Container-Statistiken

2. **Image-Management**
   - Verfügbare Images
   - Ungenutzte (dangling) Images
   - Image-Größen und Erstellungsdaten

3. **System-Ressourcen**
   - Docker-System-Nutzung
   - Speicherplatz-Verbrauch
   - Daemon-Status

4. **Probleme**
   - Gestoppte Container
   - Ungenutzte Images
   - Ungenutzte Volumes
   - Inaktiver Docker-Daemon

### Shortcuts

- `docker` - Allgemeiner Docker-Status
- `docker-problems` - Docker-Probleme
- `docker-containers` - Container-Übersicht
- `docker-images` - Image-Übersicht

## 📧 Mailserver-Modul

### Unterstützte Mailserver

#### Mailcow
- **Erkennung**: `/opt/mailcow-dockerized/`
- **Analyse**: Container-Status, Logs, Konfiguration
- **Probleme**: Gestoppte Container, Fehler in Logs

#### Postfix
- **Erkennung**: `which postfix`
- **Analyse**: Service-Status, Queue, Konfiguration
- **Probleme**: Queue-Probleme, Spam/Blacklist-Issues

#### Andere Mailserver
- **Dovecot**: IMAP/POP3-Server
- **Exim**: Alternative MTA
- **Sendmail**: Legacy MTA

### Mailcow-Analyse

```bash
# Mailcow-Status
cd /opt/mailcow-dockerized && docker-compose ps

# Mailcow-Logs
cd /opt/mailcow-dockerized && docker-compose logs --tail=50

# Mailcow-Konfiguration
cat /opt/mailcow-dockerized/mailcow.conf
```

### Postfix-Analyse

```bash
# Postfix-Status
systemctl status postfix

# Postfix-Konfiguration
postconf -n

# Queue-Status
mailq

# Mail-Logs
tail -50 /var/log/mail.log
```

### Shortcuts

- `mailservers` - Übersicht aller Mailserver
- `mailcow` - Mailcow-Status
- `mailcow-problems` - Mailcow-Probleme
- `postfix` - Postfix-Status
- `postfix-problems` - Postfix-Probleme

## 🔍 Keyword-Interpolation

### Docker-Keywords
- `docker` → `docker`
- `docker container` → `docker-containers`
- `docker containers` → `docker-containers`
- `docker image` → `docker-images`
- `docker images` → `docker-images`

### Mailserver-Keywords
- `mailcow` → `mailcow`
- `postfix` → `postfix`
- `mail` → `mailservers`
- `email` → `mailservers`
- `e-mail` → `mailservers`

## 📋 Menü-Integration

### Neue Kategorien

```
🐳 Docker:
  • 'docker' - Wie ist der Docker-Status und welche Container laufen?
  • 'docker-problems' - Welche Docker-Probleme gibt es?
  • 'docker-containers' - Welche Docker-Container laufen?
  • 'docker-images' - Welche Docker-Images sind installiert?

📧 Mailserver:
  • 'mailservers' - Welche Mailserver sind installiert und aktiv?
  • 'mailcow' - Wie ist der Mailcow-Status?
  • 'mailcow-problems' - Welche Mailcow-Probleme gibt es?
  • 'postfix' - Wie ist der Postfix-Status?
  • 'postfix-problems' - Welche Postfix-Probleme gibt es?
```

### Intelligente Anzeige

- Kategorien werden nur angezeigt, wenn entsprechende Services erkannt werden
- Dynamische Menü-Generierung basierend auf verfügbaren Komponenten
- Farbkodierung für bessere Übersichtlichkeit

## 🔧 Systemkontext-Integration

### Docker-Kontext

```
=== DOCKER ===
Version: Docker version 20.10.21
Laufende Container:
  [Container-Liste]
Alle Container:
  [Container-Liste]
Docker-Images:
  [Image-Liste]
Docker-System-Nutzung:
  [Nutzungs-Statistiken]

DOCKER-PROBLEME (2 gefunden):
Problem 1: Gestoppte Container: container1, container2
Problem 2: Ungenutzte Images: image1, image2
```

### Mailserver-Kontext

```
=== MAILSERVER ===
Mailcow:
  Version: 2023.01
  Status: [Status-Informationen]
  Container: [Container-Liste]
  Probleme: 1 gefunden

Postfix:
  Version: postfix-3.6.4
  Status: [Status-Informationen]
  Queue: [Queue-Status]
  Probleme: 0 gefunden

Andere Mailserver:
  dovecot: [Status]
```

## 🧪 Testing

### Test-Skript

```bash
python3 test_new_modules.py
```

### Test-Bereiche

1. **Docker-Analyse**
   - Erkennung von Docker-Installationen
   - Container- und Image-Analyse
   - Problem-Erkennung

2. **Mailserver-Analyse**
   - Mailcow-Erkennung und -Analyse
   - Postfix-Erkennung und -Analyse
   - Andere Mailserver-Erkennung

3. **Menü-Integration**
   - Dynamische Kategorie-Anzeige
   - Shortcut-Verfügbarkeit
   - Keyword-Interpolation

4. **Systemkontext**
   - Integration in Systemkontext
   - Problem-Reporting
   - Datenstrukturierung

## 🚀 Verwendung

### Automatische Erkennung

Die neuen Module werden automatisch bei der Systemanalyse ausgeführt:

```python
# Automatische Erkennung und Analyse
system_info = collector.analyze_system()
```

### Manuelle Abfrage

```python
# Docker-Analyse
docker_info = collector._analyze_docker()

# Mailserver-Analyse
mailserver_info = collector._analyze_mailservers()

# Spezifische Mailserver
mailcow_info = collector._analyze_mailcow()
postfix_info = collector._analyze_postfix()
```

### Chat-Befehle

```
# Docker
docker
docker-problems
docker-containers
docker-images

# Mailserver
mailservers
mailcow
mailcow-problems
postfix
postfix-problems
```

## 🔧 Konfiguration

### Voraussetzungen

- SSH-Zugang zum Zielsystem
- Root-Rechte oder entsprechende Berechtigungen
- Docker installiert (für Docker-Analyse)
- Mailserver installiert (für Mailserver-Analyse)

### Berechtigungen

```bash
# Docker-Befehle
sudo usermod -aG docker $USER

# Mailserver-Logs
sudo chmod 644 /var/log/mail.log
sudo chmod 644 /var/log/maillog

# Mailcow-Verzeichnis
sudo chmod 755 /opt/mailcow-dockerized/
```

## 📊 Monitoring

### Docker-Monitoring

- Container-Status-Überwachung
- Ressourcen-Nutzung
- Image-Management
- Volume-Überwachung

### Mailserver-Monitoring

- Service-Status
- Queue-Überwachung
- Log-Analyse
- Spam/Blacklist-Monitoring

## 🔍 Troubleshooting

### Häufige Probleme

1. **Docker nicht erkannt**
   - Prüfen Sie Docker-Installation: `which docker`
   - Prüfen Sie Berechtigungen: `groups $USER`

2. **Mailcow nicht erkannt**
   - Prüfen Sie Installation: `ls -la /opt/mailcow-dockerized/`
   - Prüfen Sie Berechtigungen

3. **Postfix nicht erkannt**
   - Prüfen Sie Installation: `which postfix`
   - Prüfen Sie Service-Status: `systemctl status postfix`

### Debug-Modus

```python
# Aktivieren Sie Debug-Ausgaben
collector.debug = True
```

## 📈 Erweiterungen

### Geplante Features

- **Docker-Compose-Analyse**: Automatische Erkennung von Compose-Projekten
- **Mailserver-Metriken**: Detaillierte Performance-Metriken
- **Backup-Überwachung**: Mailserver-Backup-Status
- **Sicherheits-Scanning**: Container- und Mailserver-Sicherheit

### Custom-Erweiterungen

Die Module sind modular aufgebaut und können einfach erweitert werden:

```python
def _analyze_custom_mailserver(self):
    """Analysiert einen benutzerdefinierten Mailserver"""
    # Implementierung hier
    pass
```

## 📝 Changelog

### Version 1.0.0
- ✅ Docker-Modul hinzugefügt
- ✅ Mailcow-Analyse hinzugefügt
- ✅ Postfix-Analyse hinzugefügt
- ✅ Andere Mailserver-Erkennung
- ✅ Menü-Integration
- ✅ Keyword-Interpolation
- ✅ Systemkontext-Integration
- ✅ Test-Suite
- ✅ Dokumentation 