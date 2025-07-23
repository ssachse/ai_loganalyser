# AI Log-Analyzer mit Docker, Mailserver und Kubernetes-Unterstützung

Ein intelligenter SSH-basierter Linux-Log-Analyzer mit integriertem Ollama-Chat, Docker-Container-Analyse, Mailserver-Überwachung und Kubernetes-Cluster-Analyse.

## 🌍 **Dynamische AI-gesteuerte Internationalisierung**
- **POSIX-konform**: Verwendet Standard-gettext ohne externe Abhängigkeiten
- **Automatische Spracherkennung**: Erkennt Sprache aus Shell-Locale (`LANG`, `LC_ALL`, `LC_MESSAGES`)
- **Unterstützte Sprachen**: Deutsch (Standard) und Englisch
- **Dynamische Übersetzung**: Automatische KI-Übersetzung für unbekannte Locales
- **Ollama-Integration**: Echtzeit-Übersetzungsgenerierung mit AI
- **Fallback-System**: Robuste Übersetzungen auch ohne gettext-Dateien
- **Persistierung**: Dynamische Übersetzungen werden gespeichert und wiederverwendet
- **Runtime-Sprachwechsel**: Wechsel zwischen Sprachen zur Laufzeit

## 🚀 Features

### 🔍 **Umfassende System-Analyse**
- **Basis-System-Informationen**: Hostname, Distribution, Kernel, CPU, RAM, Uptime
- **Speicherplatz-Analyse**: Disk-Usage, größte Dateien und Verzeichnisse
- **Service-Status**: Laufende Services und Prozesse
- **Sicherheits-Analyse**: Anmeldungen, fehlgeschlagene Login-Versuche
- **Performance-Monitoring**: CPU, Memory, Load Average

### ☸️ **Kubernetes-Cluster-Analyse**
- **Automatische Erkennung**: Prüft `kubectl` und `k9s` Verfügbarkeit
- **Cluster-Informationen**: Version, Nodes, Namespaces, Pods, Services
- **Problem-Erkennung**: Nicht-ready Nodes, nicht-running Pods, kritische Events
- **Ressourcen-Monitoring**: Node- und Pod-Ressourcen-Auslastung
- **Storage-Analyse**: Persistent Volumes und deren Status

### 🐳 **Docker-Container-Analyse**
- **Automatische Erkennung**: Prüft Docker-Installation und -Daemon
- **Container-Überwachung**: Laufende und gestoppte Container
- **Image-Management**: Verfügbare Images und ungenutzte Images
- **Volume-Überwachung**: Docker-Volumes und deren Status
- **Netzwerk-Analyse**: Docker-Netzwerke und deren Konfiguration
- **Problem-Erkennung**: Gestoppte Container, ungenutzte Ressourcen

### 📧 **Mailserver-Analyse**
- **Mailcow-Integration**: Container-Status, Logs, Konfiguration
- **Postfix-Analyse**: Service-Status, Queue, Konfiguration
- **Andere Mailserver**: Dovecot, Exim, Sendmail Erkennung
- **Queue-Überwachung**: E-Mail-Queue-Status und -Probleme
- **Log-Analyse**: Mailserver-Logs und Fehler-Erkennung
- **Spam/Blacklist-Monitoring**: Spam- und Blacklist-Probleme

### 🤖 **Intelligenter Ollama-Chat**
- **Dynamische Modell-Auswahl**: Intelligente Auswahl basierend auf Komplexität
- **Kürzelwörter**: Schnelle Zugriffe auf häufige Fragen
- **Intelligentes Caching**: Optimierte Performance für wiederholte Fragen
- **Automatische System-Analyse**: Detaillierte Einblicke beim Start
- **Deutsche Übersetzungen**: Vollständig lokalisierte Benutzeroberfläche
- **Automatische Berichterstellung**: Professionelle Systemberichte mit Handlungsanweisungen

### ⚡ **Performance-Optimierungen**
- **Quick-Modus**: Überspringt zeitaufwändige Analysen
- **Intelligente Fehlerbehandlung**: Gruppierte Fehler-Zusammenfassung
- **Modell-Auswahl**: Automatische Komplexitäts-Erkennung
- **Cache-System**: Vermeidung redundanter API-Aufrufe
- **Asynchrone Analyse**: Hintergrund-Analyse für sofortige Menü-Anzeige
- **Debug-Modus**: Detaillierte Ausgaben für Entwickler

### 🔐 **Intelligente Sudo-Unterstützung**
- **Automatische Rechte-Prüfung**: Erkennt Permission-Denied-Fehler und prüft Sudo-Verfügbarkeit
- **Sichere Befehls-Whitelist**: Nur lesende Befehle werden mit Sudo ausgeführt
- **Gefährliche Befehle blockiert**: Lösch-, Modifikations- und System-Befehle werden niemals mit Sudo ausgeführt
- **Passwortlose Sudo-Prüfung**: Testet automatisch ob Sudo ohne Passwort funktioniert
- **Fallback-Mechanismus**: Bei Sudo-Problemen wird normaler Modus verwendet
- **Transparente Ausführung**: Benutzer wird über Sudo-Nutzung informiert

### 🔒 **Netzwerk-Sicherheitsanalyse**
- **Interne Service-Erkennung**: Lauschende Ports, Firewall-Status, externe Interfaces
- **Externe Erreichbarkeitstests**: Nmap-Scans, Banner-Grabbing, Service-Versionen
- **Automatisierte Verbindungstests**: Telnet, Netcat, HTTP, SSH
- **Sicherheitsbewertung**: Risiko-Level (low/medium/high/critical), Empfehlungen, Compliance-Probleme
- **Chat-Integration**: `network-security`, `exposed-services`, `port-scan`, `service-test` Shortcuts
- **Sichere Sudo-Nutzung**: Netzwerk-Tools werden nur mit Sudo ausgeführt wenn sicher

## 📋 Voraussetzungen

### System-Anforderungen
- **Python 3.8+**
- **SSH-Zugang** zum Zielsystem
- **Ollama** lokal installiert und laufend
- **kubectl** (optional, für Kubernetes-Analyse)

### Python-Pakete
```bash
pip install rich requests paramiko
```

## 🛠️ Installation

### Basis-Installation

1. **Repository klonen**:
```bash
git clone https://github.com/ssachse/ai_loganalyser.git
cd ai_loganalyser
```

2. **Abhängigkeiten installieren**:
```bash
pip install -r requirements.txt
```

3. **Ollama starten**:
```bash
ollama serve
```

### Übersetzungen generieren

Die Übersetzungen werden automatisch mit Ollama generiert:

```bash
# Statische Übersetzungen generieren (erfordert Ollama)
python3 generate_translations.py

# Dynamische Übersetzungen werden automatisch generiert
# wenn unbekannte Locales erkannt werden

# Oder manuell mit gettext (erfordert gettext-Installation)
msgfmt -o locale/de/LC_MESSAGES/ai_loganalyser.mo locale/de/LC_MESSAGES/ai_loganalyser.po
msgfmt -o locale/en/LC_MESSAGES/ai_loganalyser.mo locale/en/LC_MESSAGES/ai_loganalyser.po
```

**Hinweis**: Falls gettext nicht installiert ist:
- **macOS**: `brew install gettext`
- **Ubuntu**: `sudo apt-get install gettext`
- **Windows**: Download von https://www.gnu.org/software/gettext/

### Dynamische Übersetzung testen

```bash
# Demo der dynamischen Übersetzung
python3 demo_dynamic_translation.py

# Umfassende Tests
python3 test_dynamic_translation.py
```

## 🚀 Verwendung

### Grundlegende Verwendung
```bash
python3 ssh_chat_system.py user@hostname
```

### Erweiterte Optionen
```bash
# Quick-Modus (schnelle Analyse)
python3 ssh_chat_system.py user@hostname --quick

# Ohne Log-Sammlung (nur System-Info)
python3 ssh_chat_system.py user@hostname --no-logs

# Debug-Modus (detaillierte Ausgaben)
python3 ssh_chat_system.py user@hostname --debug

# Benutzerdefinierte SSH-Parameter
python3 ssh_chat_system.py user@hostname --port 2222 --key-file ~/.ssh/id_rsa

# Temporäre Dateien behalten
python3 ssh_chat_system.py user@hostname --keep-files
```

### Chat-Kürzelwörter
```
System:
services    - Welche Services laufen auf dem System?
storage     - Wie ist der Speicherplatz?
security    - Gibt es Sicherheitsprobleme?
performance - Wie ist die System-Performance?
users       - Welche Benutzer sind aktiv?
updates     - Gibt es verfügbare System-Updates?
logs        - Was zeigen die Logs?

Kubernetes:
k8s         - Wie ist der Kubernetes-Cluster-Status?
k8s-problems- Welche Kubernetes-Probleme gibt es?
k8s-pods    - Welche Pods laufen im Cluster?
k8s-nodes   - Wie ist der Node-Status?
k8s-resources- Wie ist die Ressourcen-Auslastung?

Proxmox:
proxmox     - Wie ist der Proxmox VE-Status?
proxmox-problems- Welche Proxmox-Probleme gibt es?
proxmox-vms - Welche VMs laufen auf Proxmox?
proxmox-containers- Welche Container laufen auf Proxmox?
proxmox-storage- Wie ist der Proxmox-Speicherplatz?

Docker:
docker      - Wie ist der Docker-Status und welche Container laufen?
docker-problems- Welche Docker-Probleme gibt es?
docker-containers- Welche Docker-Container laufen?
docker-images- Welche Docker-Images sind installiert?

Mailserver:
mailservers - Welche Mailserver sind installiert und aktiv?
mailcow     - Wie ist der Mailcow-Status?
mailcow-problems- Welche Mailcow-Probleme gibt es?
postfix     - Wie ist der Postfix-Status?
postfix-problems- Welche Postfix-Probleme gibt es?

Berichte & Tools:
report      - Erstelle einen detaillierten Systembericht mit Handlungsanweisungen
help        - Zeige verfügbare Kürzelwörter
```

## 🔧 Konfiguration

### SSH-Verbindung
- **Standard-Port**: 22
- **Authentifizierung**: Passwort oder SSH-Key
- **Timeout**: 30 Sekunden pro Befehl

### Ollama-Integration
- **Standard-Port**: 11434
- **Modelle**: Intelligente Auswahl basierend auf Modellnamen und Komplexität
- **Cache**: Intelligentes Caching für optimale Performance
- **Modell-Prioritäten**: 
  - **Menü**: `qwen:0.5b` (ultraschnell)
  - **Einfache Analysen**: `qwen:0.5b` → `llama3.2:3b`
  - **Komplexe Analysen**: `llama3.1:8b` → `deepseek-r1:14b` → `mistral:7b`
- **Report-Generierung**: Verwendet `llama3.1:8b` für professionelle Berichte

### Kubernetes-Analyse
- **Automatische Erkennung**: Prüft `kubectl` Verfügbarkeit
- **Berechtigungen**: Erfordert Cluster-Zugriff
- **Fehlerbehandlung**: Gruppierte kubectl-Fehler

### Docker-Analyse
- **Automatische Erkennung**: Prüft `docker` Verfügbarkeit
- **Berechtigungen**: Erfordert Docker-Gruppen-Mitgliedschaft
- **Container-Überwachung**: Laufende und gestoppte Container
- **Image-Management**: Verfügbare und ungenutzte Images
- **Volume-Überwachung**: Docker-Volumes und deren Status

### Mailserver-Analyse
- **Mailcow-Erkennung**: Prüft `/opt/mailcow-dockerized/` Verzeichnis
- **Postfix-Erkennung**: Prüft `postfix` Service und Konfiguration
- **Andere Mailserver**: Automatische Erkennung von Dovecot, Exim, Sendmail
- **Log-Analyse**: Mailserver-Logs und Fehler-Erkennung
- **Queue-Überwachung**: E-Mail-Queue-Status und -Probleme

### 📊 **Automatische Berichterstellung**
- **CRAFT-Prompt**: Professioneller Enterprise-Architekt-Prompt
- **Markdown-Export**: Strukturierte Berichte als `.md` Dateien
- **Automatische Speicherung**: `system_reports/` Verzeichnis mit Timestamp
- **Deutsche Berichte**: Vollständig auf Deutsch erstellte Berichte
- **Strukturierte Ausgabe**: Executive Summary, Maßnahmenübersicht, Detail-Actionplan
- **Priorisierung**: Impact/Aufwand-Bewertung mit Quick Wins → Mid-Term → Long-Term

## 📊 Ausgabe-Beispiele

### System-Übersicht
```
📊 System-Übersicht
============================================================
                    System-Basis-Informationen                     
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Eigenschaft          ┃ Wert                                     ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Hostname             │ server.example.com                       │
│ Distribution         │ Ubuntu 22.04.5 LTS                       │
│ Kernel               │ 5.15.0-139-generic                       │
│ CPU                  │ AMD EPYC-Rome Processor                  │
│ RAM                  │ 30Gi                                     │
└──────────────────────┴──────────────────────────────────────────┘
```

### Kubernetes-Cluster
```
☸️ Kubernetes-Cluster
============================================================
Cluster-Informationen:
Kubernetes control plane is running at https://142.132.176.3:6443

⚠️  3 Probleme gefunden:
- Nicht-ready Nodes
- Nicht-running Pods  
- Problematische Persistent Volumes
```

### Intelligente Fehlerbehandlung
```
⚠️  Fehler-Zusammenfassung (8 Fehler):

🔒 Fehlende Rechte (5 Fehler):
   Weitere Analyse aufgrund fehlender Rechte nicht möglich.
   Betroffene Bereiche:
   • Speicherplatz-Analyse
   • Log-Datei-Zugriff

💡 Tipp: Verwenden Sie einen Benutzer mit erweiterten Rechten für vollständige Analyse.
```

### Docker-Container-Analyse
```
🐳 Docker-Container-Analyse
============================================================
✅ Docker erkannt und analysiert
📋 Version: Docker version 20.10.21
📋 Laufende Container gefunden
📋 Alle Container gefunden
📋 Docker-Images gefunden
📋 System-Nutzung gefunden

⚠️  2 Probleme gefunden:
- Gestoppte Container: container1, container2
- Ungenutzte Images: image1, image2
```

### Mailserver-Analyse
```
📧 Mailserver-Analyse
============================================================
✅ Mailserver erkannt und analysiert
📧 Mailcow erkannt
  📋 Version: 2023.01
  📋 Status verfügbar
📧 Postfix erkannt
  📋 Version: postfix-3.6.4
  📋 Status verfügbar
  📋 Queue-Status verfügbar
```

### 📄 **Automatische Berichterstellung**
```
✅ Bericht erfolgreich erstellt:
📄 system_reports/system_report_server_20250723_143022.md

# Systembericht: server.example.com

**Erstellt am:** 23.07.2025 um 14:30 Uhr
**System:** server.example.com
**Distribution:** Ubuntu 22.04.5 LTS
**Kernel:** 5.15.0-139-generic

---

## Executive Summary

Das System zeigt mehrere kritische Punkte, die sofortige Aufmerksamkeit erfordern.

## Priorisierte Maßnahmenübersicht

| ID | Thema | Maßnahme | Impact | Aufwand | Priorität |
|----|-------|----------|--------|---------|-----------|
| 1 | Speicherplatz | Root-Partition erweitern | Hoch | Mittel | Kritisch |
| 2 | Sicherheit | SSH-Konfiguration härten | Hoch | Niedrig | Hoch |
| 3 | Performance | Log-Rotation implementieren | Mittel | Niedrig | Mittel |

## Detail-Actionplan

### 1. Speicherplatz-Optimierung
- **Was:** Root-Partition erweitern oder Daten migrieren
- **Warum:** 75% Auslastung ist kritisch
- **Wie:** LVM erweitern oder /var auf separate Partition
- **Aufwand:** 2-4 Stunden
- **Verantwortlich:** System-Administrator
```

## 🔒 Sicherheit

### SSH-Sicherheit
- **Verschlüsselte Verbindung**: Standard SSH-Verschlüsselung
- **Key-basierte Authentifizierung**: Unterstützt SSH-Keys
- **Timeout-Schutz**: Verhindert hängende Verbindungen

### Daten-Schutz
- **Lokale Verarbeitung**: Alle Daten bleiben lokal
- **Temporäre Dateien**: Automatische Bereinigung
- **Sensible Daten**: Werden nicht gespeichert

## 🤝 Beitragen

1. **Fork** das Repository
2. **Feature-Branch** erstellen (`git checkout -b feature/AmazingFeature`)
3. **Commit** die Änderungen (`git commit -m 'Add some AmazingFeature'`)
4. **Push** zum Branch (`git push origin feature/AmazingFeature`)
5. **Pull Request** erstellen

## 📝 Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert - siehe [LICENSE](LICENSE) Datei für Details.

## 🙏 Danksagungen

- **Ollama**: Für die lokale LLM-Integration
- **Rich**: Für die schöne Terminal-Ausgabe
- **Paramiko**: Für die SSH-Funktionalität
- **Kubernetes**: Für die Container-Orchestrierung

## 📞 Support

Bei Fragen oder Problemen:
- **Issues**: [GitHub Issues](https://github.com/ssachse/ai_loganalyser/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ssachse/ai_loganalyser/discussions)

---

**Entwickelt mit ❤️ für DevOps und System-Administratoren** 