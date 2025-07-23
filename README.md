# AI Log-Analyzer mit Kubernetes-Unterstützung

Ein intelligenter SSH-basierter Linux-Log-Analyzer mit integriertem Ollama-Chat und Kubernetes-Cluster-Analyse.

## 🌍 **Gettext-basierte Internationalisierung**
- **POSIX-konform**: Verwendet Standard-gettext ohne externe Abhängigkeiten
- **Automatische Spracherkennung**: Erkennt Sprache aus Shell-Locale (`LANG`, `LC_ALL`, `LC_MESSAGES`)
- **Unterstützte Sprachen**: Deutsch (Standard) und Englisch
- **Ollama-Integration**: Automatische Übersetzungsgenerierung mit KI
- **Fallback-System**: Robuste Übersetzungen auch ohne gettext-Dateien
- **Einfache Erweiterung**: Neue Sprachen über .po/.mo Dateien hinzufügbar

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

### 🤖 **Intelligenter Ollama-Chat**
- **Zwei-Tier-Modell-System**: Schnelle und komplexe Analysen
- **Kürzelwörter**: Schnelle Zugriffe auf häufige Fragen
- **Intelligentes Caching**: Optimierte Performance für wiederholte Fragen
- **Automatische System-Analyse**: Detaillierte Einblicke beim Start

### ⚡ **Performance-Optimierungen**
- **Quick-Modus**: Überspringt zeitaufwändige Analysen
- **Intelligente Fehlerbehandlung**: Gruppierte Fehler-Zusammenfassung
- **Modell-Auswahl**: Automatische Komplexitäts-Erkennung
- **Cache-System**: Vermeidung redundanter API-Aufrufe

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
# Übersetzungen generieren (erfordert Ollama)
python3 generate_translations.py

# Oder manuell mit gettext (erfordert gettext-Installation)
msgfmt -o locale/de/LC_MESSAGES/ai_loganalyser.mo locale/de/LC_MESSAGES/ai_loganalyser.po
msgfmt -o locale/en/LC_MESSAGES/ai_loganalyser.mo locale/en/LC_MESSAGES/ai_loganalyser.po
```

**Hinweis**: Falls gettext nicht installiert ist:
- **macOS**: `brew install gettext`
- **Ubuntu**: `sudo apt-get install gettext`
- **Windows**: Download von https://www.gnu.org/software/gettext/

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

# Benutzerdefinierte SSH-Parameter
python3 ssh_chat_system.py user@hostname --port 2222 --key-file ~/.ssh/id_rsa

# Temporäre Dateien behalten
python3 ssh_chat_system.py user@hostname --keep-files
```

### Chat-Kürzelwörter
```
services    - Welche Services laufen auf dem System?
storage     - Wie ist der Speicherplatz?
security    - Gibt es Sicherheitsprobleme?
performance - Wie ist die System-Performance?
users       - Welche Benutzer sind aktiv?
updates     - Gibt es verfügbare System-Updates?
k8s         - Wie ist der Kubernetes-Cluster-Status?
k8s-problems- Welche Kubernetes-Probleme gibt es?
help        - Zeige verfügbare Kürzelwörter
```

## 🔧 Konfiguration

### SSH-Verbindung
- **Standard-Port**: 22
- **Authentifizierung**: Passwort oder SSH-Key
- **Timeout**: 30 Sekunden pro Befehl

### Ollama-Integration
- **Standard-Port**: 11434
- **Modelle**: Automatische Auswahl basierend auf Komplexität
- **Cache**: Intelligentes Caching für optimale Performance

### Kubernetes-Analyse
- **Automatische Erkennung**: Prüft `kubectl` Verfügbarkeit
- **Berechtigungen**: Erfordert Cluster-Zugriff
- **Fehlerbehandlung**: Gruppierte kubectl-Fehler

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