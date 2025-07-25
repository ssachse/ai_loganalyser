# 🔍 SSH-basierter Linux-Log-Analyzer mit Chat

Ein intelligenter Log-Analyzer für Linux-Systeme mit SSH-Zugang, der automatisch System-Informationen sammelt, Logs analysiert und einen interaktiven Chat mit KI-Unterstützung bereitstellt.

## 🚀 Features

- **🔍 Automatische System-Analyse**: Sammelt umfassende System-Informationen
- **📊 Log-Analyse**: Analysiert System-Logs mit KI-Unterstützung
- **🤖 KI-Chat**: Interaktiver Chat mit Ollama für System-Fragen
- **🐳 Docker-Analyse**: Detaillierte Docker-Container-Analyse
- **☸️ Kubernetes-Support**: Kubernetes-Cluster-Analyse
- **🖥️ Proxmox-Integration**: Proxmox-Cluster-Monitoring
- **📧 Mailserver-Analyse**: Mailcow, Postfix und andere Mailserver
- **🔐 Sicherheitsanalyse**: Netzwerk-Sicherheit und CVE-Checks
- **📄 Automatische Berichte**: Systemberichte mit `--auto-report` oder `--report-and-chat`
- **🔍 CVE-Sicherheitsanalyse**: Echte CVE-Datenbanken (NIST NVD, Europäische DBs) + KI-Analyse
- **🇪🇺 EU-Compliance**: Europäische CVE-Datenbanken für GDPR und NIS-Richtlinie

## 📦 Installation

### Voraussetzungen

- Python 3.8+
- SSH-Zugang zum Zielsystem
- Ollama (für KI-Funktionen)

### Installation

```bash
# Repository klonen
git clone <repository-url>
cd macos-loganalyser

# Abhängigkeiten installieren
pip install -r requirements.txt

# Ollama installieren (falls nicht vorhanden)
curl -fsSL https://ollama.ai/install.sh | sh
```

## 🎯 Verwendung

### Grundlegende Verwendung

```bash
# Einfache Analyse
python3 ssh_chat_system.py user@hostname

# Mit Passwort
python3 ssh_chat_system.py user@hostname --password meinpasswort

# Mit SSH-Key
python3 ssh_chat_system.py user@hostname --key-file ~/.ssh/id_rsa
```

### CVE-Sicherheitsanalyse

```bash
# CVE-Analyse mit Hybrid-Ansatz (NVD + Ollama) - Empfohlen
python3 ssh_chat_system.py user@hostname --with-cve --cve-database hybrid

# Nur NIST NVD-Datenbank
python3 ssh_chat_system.py user@hostname --with-cve --cve-database nvd

# Nur Ollama-KI-Analyse
python3 ssh_chat_system.py user@hostname --with-cve --cve-database ollama

# Europäische CVE-Datenbanken (BSI, NCSC, ENISA, CERT-EU)
python3 ssh_chat_system.py user@hostname --with-cve --cve-database european

# Hybrid mit europäischen Datenbanken
python3 ssh_chat_system.py user@hostname --with-cve --cve-database hybrid-european

# EU-Compliance-Modus (GDPR, NIS-Richtlinie)
python3 ssh_chat_system.py user@hostname --with-cve --cve-database european --eu-compliance

# Mit Caching für bessere Performance
python3 ssh_chat_system.py user@hostname --with-cve --cve-cache

# Offline-Modus (nur lokale Daten)
python3 ssh_chat_system.py user@hostname --with-cve --cve-offline
```

### Automatische Berichte

```bash
# Nur Bericht generieren und beenden
python3 ssh_chat_system.py user@hostname --auto-report

# Bericht generieren und dann Chat starten
python3 ssh_chat_system.py user@hostname --report-and-chat

# Bericht mit CVE-Analyse
python3 ssh_chat_system.py user@hostname --auto-report --with-cve --cve-database hybrid

# Bericht mit europäischer CVE-Analyse
python3 ssh_chat_system.py user@hostname --auto-report --with-cve --cve-database european --eu-compliance
```

### Erweiterte Optionen

```bash
# Quick-Modus (schnellere Analyse)
python3 ssh_chat_system.py user@hostname --quick

# Ohne Log-Sammlung
python3 ssh_chat_system.py user@hostname --no-logs

# Debug-Modus
python3 ssh_chat_system.py user@hostname --debug

# Netzwerk-Sicherheitsanalyse
python3 ssh_chat_system.py user@hostname --include-network-security

# Kombinierte Analyse
python3 ssh_chat_system.py user@hostname --with-cve --cve-database hybrid --report-and-chat --include-network-security
```

## 🔧 Verfügbare Optionen

| Option | Beschreibung |
|--------|-------------|
| `--username USERNAME` | SSH-Benutzername |
| `--password PASSWORD` | SSH-Passwort |
| `--key-file KEY_FILE` | SSH-Key-Datei |
| `--port PORT` | SSH-Port (Standard: 22) |
| `--ollama-port OLLAMA_PORT` | Ollama-Port (Standard: 11434) |
| `--no-port-forwarding` | Deaktiviere Port-Forwarding |
| `--hours HOURS` | Log-Analyse-Zeitraum (Standard: 24) |
| `--keep-files` | Behalte temporäre Dateien |
| `--output OUTPUT` | Ausgabe-Verzeichnis |
| `--quick` | Quick-Modus für schnelle Analyse |
| `--no-logs` | Überspringe Log-Sammlung |
| `--debug` | Debug-Modus |
| `--include-network-security` | Netzwerk-Sicherheitsanalyse |
| `--auto-report` | Generiere automatisch Systembericht |
| `--report-and-chat` | Bericht generieren und Chat starten |
| `--with-cve` | CVE-Sicherheitsanalyse |
| `--cve-database {ollama,nvd,hybrid,european,hybrid-european}` | CVE-Datenbank (Standard: hybrid) |
| `--cve-cache` | Verwende lokalen CVE-Cache |
| `--cve-offline` | Nur lokale CVE-Daten verwenden |
| `--eu-compliance` | Aktiviere EU-Compliance-Modus (GDPR, NIS-Richtlinie) |

## 🔍 CVE-Sicherheitsanalyse

Das System unterstützt verschiedene CVE-Datenbanken:

### 🔗 NIST NVD (National Vulnerability Database)
- **Offizielle US-Regierungs-Datenbank**
- **Vollständige CVE-Daten**
- **Kostenlos und öffentlich zugänglich**
- **Rate Limiting**: 5 Requests pro 6 Sekunden

### 🇪🇺 Europäische CVE-Datenbanken
- **BSI (Deutschland)**: Bundesamt für Sicherheit in der Informationstechnik
- **NCSC (UK)**: National Cyber Security Centre
- **ENISA (EU)**: European Union Agency for Cybersecurity
- **CERT-EU**: Computer Emergency Response Team für EU-Institutionen
- **GDPR-Compliance**: Datenschutz-Grundverordnung
- **NIS-Richtlinie**: Netzwerk- und Informationssicherheits-Richtlinie

### 🤖 Ollama KI-Analyse
- **Intelligente Analyse und Kontextverständnis**
- **Training-basierte CVE-Informationen**
- **Schnelle Verarbeitung**

### 🔄 Hybrid-Ansätze
- **Hybrid (Standard)**: Kombiniert NVD-Daten mit Ollama-Analyse
- **Hybrid-Europäisch**: Kombiniert europäische DBs mit Ollama-Analyse
- **NVD**: Für aktuelle, offizielle CVE-Daten
- **Europäisch**: Für EU-spezifische Compliance und lokale Bedrohungen
- **Ollama**: Für intelligente Analyse und Empfehlungen
- **Caching**: Für Performance-Optimierung

### 📊 CVE-Kategorien
- **Critical**: CVSS Score ≥ 9.0
- **High**: CVSS Score ≥ 7.0
- **Medium**: CVSS Score ≥ 4.0
- **Low**: CVSS Score < 4.0

## 📄 Beispiel-Ausgabe

```
🔍 CVE-Sicherheitsanalyse
============================================================
Datenbank: hybrid-european, Cache: Aktiviert, Offline: Nein

✅ NVD CVE-Analyse abgeschlossen
📊 3 Services analysiert
🔍 5 CVEs gefunden
📈 Gesamtrisiko: High

✅ Ollama CVE-Analyse abgeschlossen
📊 15 Pakete analysiert
🔧 8 Services geprüft

🇪🇺 Europäische CVE-Analyse abgeschlossen
🇪🇺 4 EU-Datenbanken geprüft
🔍 3 europäische CVEs gefunden
🔒 GDPR-konform: Ja
🏛️ NIS-Richtlinie: Ja

🚨 2 kritische CVEs gefunden!
⚠️ 3 hohe CVEs gefunden

Kritische CVEs in: openssh-server, docker-ce
Hohe CVEs in: apache2, nginx, mysql-server
```

## 🎯 Chat-Funktionen

Nach der Analyse können Sie Fragen stellen:

### System-Fragen
- `s1` - Welche Services laufen?
- `s2` - Speicherplatz-Status?
- `s3` - Sicherheitsprobleme?
- `s4` - Top-Prozesse?
- `s5` - System-Performance?

### Docker-Fragen
- `d1` - Docker-Status und Container?
- `d2` - Docker-Probleme?
- `d3` - Laufende Container?
- `d4` - Docker-Images?

### Kubernetes-Fragen
- `k1` - Cluster-Status?
- `k2` - Kubernetes-Probleme?
- `k3` - Laufende Pods?

### Proxmox-Fragen
- `p1` - Proxmox-Status?
- `p2` - Proxmox-Probleme?
- `p3` - Laufende VMs?

### Netzwerk-Sicherheit
- `n1` - Vollständige Netzwerk-Sicherheitsanalyse
- `n2` - Extern erreichbare Services
- `n3` - Port-Scan
- `n4` - Service-Tests

## 📁 Ausgabe

### Systemberichte
- **Speicherort**: `system_reports/`
- **Format**: Markdown
- **Inhalt**: Vollständige System-Analyse mit Empfehlungen

### Log-Archive
- **Format**: `.tar.gz`
- **Inhalt**: Gesammelte Logs und System-Informationen

### CVE-Cache
- **Speicherort**: `cve_cache.json`
- **Gültigkeit**: 24 Stunden
- **Inhalt**: Gecachte CVE-Daten für bessere Performance

### Europäischer CVE-Cache
- **Speicherort**: `european_cve_cache.json`
- **Gültigkeit**: 24 Stunden
- **Inhalt**: Gecachte europäische CVE-Daten

## 🔧 Konfiguration

### NVD API-Key (Optional)
Für höhere Rate Limits können Sie einen NVD API-Key verwenden:

```bash
export NVD_API_KEY="your-api-key-here"
```

### Ollama-Modelle
Das System wählt automatisch das beste verfügbare Modell:
- **Komplexe Analysen**: `llama3.2:70b` oder `llama3.1:70b`
- **Standard-Chat**: `llama3.2:8b` oder `llama3.1:8b`

## 🐛 Troubleshooting

### SSH-Verbindungsprobleme
```bash
# Teste SSH-Verbindung
ssh user@hostname

# Prüfe SSH-Key-Berechtigungen
chmod 600 ~/.ssh/id_rsa
```

### Ollama-Probleme
```bash
# Starte Ollama
ollama serve

# Prüfe verfügbare Modelle
ollama list
```

### CVE-Analyse-Probleme
```bash
# Teste NVD-API
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=openssh"

# Lösche CVE-Cache
rm cve_cache.json
rm european_cve_cache.json
```

## 📈 Performance-Tipps

1. **Quick-Modus**: Verwende `--quick` für schnelle Analysen
2. **Caching**: Aktiviere `--cve-cache` für wiederholte Analysen
3. **Offline-Modus**: Verwende `--cve-offline` für lokale Daten
4. **NVD API-Key**: Für höhere Rate Limits
5. **Europäische DBs**: Für EU-spezifische Compliance

## 🤝 Beitragen

1. Fork das Repository
2. Erstelle einen Feature-Branch
3. Committe deine Änderungen
4. Push zum Branch
5. Erstelle einen Pull Request

## 📄 Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert.

## 🔗 Links

- [NIST NVD](https://nvd.nist.gov/) - National Vulnerability Database
- [BSI](https://www.bsi.bund.de/) - Bundesamt für Sicherheit in der Informationstechnik
- [NCSC](https://www.ncsc.gov.uk/) - National Cyber Security Centre
- [ENISA](https://www.enisa.europa.eu/) - European Union Agency for Cybersecurity
- [CERT-EU](https://cert.europa.eu/) - Computer Emergency Response Team für EU-Institutionen
- [Ollama](https://ollama.ai/) - Lokale LLM-Engine
- [MITRE CVE](https://cve.mitre.org/) - Common Vulnerabilities and Exposures 