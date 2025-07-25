# 🔍 CVE-Sicherheitsanalyse Feature

## Übersicht

Das neue `--with-cve` Flag ermöglicht eine umfassende CVE-Sicherheitsanalyse für alle installierten Services und Pakete auf dem Zielsystem. Die Analyse wird mit Ollama durchgeführt und liefert detaillierte Informationen über bekannte Sicherheitslücken, deren Schweregrad und konkrete Handlungsempfehlungen.

## 🚀 Verwendung

### Grundlegende Verwendung
```bash
# CVE-Sicherheitsanalyse für alle installierten Services
python3 ssh_chat_system.py user@hostname --with-cve
```

### Kombination mit anderen Flags
```bash
# Schnelle CVE-Analyse
python3 ssh_chat_system.py user@hostname --with-cve --quick

# CVE-Analyse ohne Log-Sammlung
python3 ssh_chat_system.py user@hostname --with-cve --no-logs

# CVE-Analyse mit Debug-Informationen
python3 ssh_chat_system.py user@hostname --with-cve --debug

# CVE-Analyse + Auto-Report
python3 ssh_chat_system.py user@hostname --with-cve --auto-report

# CVE-Analyse + Report + Chat
python3 ssh_chat_system.py user@hostname --with-cve --report-and-chat

# CVE-Analyse + Netzwerk-Sicherheit
python3 ssh_chat_system.py user@hostname --with-cve --include-network-security
```

## 🔧 Funktionsweise

### 1. Paket-Sammlung
- **Debian/Ubuntu**: Verwendet `dpkg -l` für installierte Pakete
- **RHEL/CentOS**: Verwendet `rpm -qa` für installierte Pakete
- **Service-Erkennung**: Identifiziert wichtige Services (SSH, Apache, Nginx, MySQL, Docker, etc.)

### 2. Ollama-basierte Analyse
- **KI-gestützte CVE-Erkennung**: Verwendet Ollama für intelligente CVE-Analyse
- **Aktuelle Datenbanken**: Zugriff auf aktuelle CVE-Datenbanken über Ollama
- **Schweregrad-Bewertung**: Automatische Klassifizierung (Critical, High, Medium, Low)

### 3. Strukturierte Ausgabe
- **Kategorisierte CVEs**: Nach Schweregrad sortiert
- **Update-Empfehlungen**: Konkrete Versions-Upgrades
- **Sofortige Maßnahmen**: Handlungsanweisungen für Administratoren

## 📊 Beispiel-Ausgabe

```
🔍 CVE-Sicherheitsanalyse
============================================================
🔍 Analysiere CVE-Sicherheitslücken...
✅ CVE-Analyse abgeschlossen
📊 50 Pakete analysiert
🔧 15 Services geprüft
📝 CVE-Analyse (erste Zeilen):
  ## CVE-SICHERHEITSANALYSE

  ### KRITISCHE SICHERHEITSLÜCKEN (Critical)
  - OpenSSH CVE-2021-28041: Remote code execution vulnerability
  - Apache2 CVE-2021-41773: Path traversal vulnerability

  ### HOHE SICHERHEITSLÜCKEN (High)
  - Docker CVE-2021-41190: Container escape vulnerability
  - MySQL CVE-2021-2156: Privilege escalation vulnerability

  ### UPDATE-EMPFEHLUNGEN
  - openssh-server: 1:7.9p1-10+deb10u2 → 1:8.2p1-1
  - apache2: 2.4.38-3+deb10u8 → 2.4.51-1

  ### SICHERHEITSZUSAMMENFASSUNG
  - Anzahl kritische CVEs: 2
  - Anzahl hohe CVEs: 2
  - Gesamtrisiko: Critical
```

## 🎯 Unterstützte Services

### Web-Server
- **Apache2**: CVE-Analyse für Apache HTTP Server
- **Nginx**: CVE-Analyse für Nginx Web Server
- **Lighttpd**: CVE-Analyse für Lighttpd

### Datenbanken
- **MySQL**: CVE-Analyse für MySQL Server
- **PostgreSQL**: CVE-Analyse für PostgreSQL
- **MariaDB**: CVE-Analyse für MariaDB

### Container & Virtualisierung
- **Docker**: CVE-Analyse für Docker Engine
- **Containerd**: CVE-Analyse für Containerd
- **Kubernetes**: CVE-Analyse für Kubernetes-Komponenten
- **Proxmox**: CVE-Analyse für Proxmox VE

### Netzwerk & Sicherheit
- **OpenSSH**: CVE-Analyse für SSH Server
- **OpenVPN**: CVE-Analyse für VPN Server
- **Fail2ban**: CVE-Analyse für Fail2ban

### Mailserver
- **Postfix**: CVE-Analyse für Postfix
- **Dovecot**: CVE-Analyse für Dovecot
- **Exim**: CVE-Analyse für Exim
- **Mailcow**: CVE-Analyse für Mailcow

## 🔍 CVE-Kategorien

### Kritische Sicherheitslücken (Critical)
- **Remote Code Execution (RCE)**: Vollständige Systemübernahme möglich
- **Privilege Escalation**: Root-Zugriff erreichbar
- **Authentication Bypass**: Umgehung von Authentifizierung
- **SQL Injection**: Datenbankmanipulation möglich

### Hohe Sicherheitslücken (High)
- **Information Disclosure**: Sensible Daten zugänglich
- **Denial of Service (DoS)**: Systemausfälle möglich
- **Cross-Site Scripting (XSS)**: Client-seitige Angriffe
- **Directory Traversal**: Dateisystemzugriff

### Mittlere Sicherheitslücken (Medium)
- **Cross-Site Request Forgery (CSRF)**: Unerwünschte Aktionen
- **Information Leakage**: Teilweise Datenzugänglichkeit
- **Weak Cryptography**: Schwache Verschlüsselung
- **Default Credentials**: Standard-Anmeldedaten

### Niedrige Sicherheitslücken (Low)
- **Information Disclosure**: Minimale Datenzugänglichkeit
- **Denial of Service**: Geringe Auswirkungen
- **Security Misconfiguration**: Konfigurationsfehler
- **Outdated Software**: Veraltete Versionen

## 📋 Integration in Reports

### System-Context Integration
Die CVE-Analyse wird automatisch in den System-Context integriert und erscheint in allen Berichten:

```
=== CVE-SICHERHEITSANALYSE ===
CVE-Analyse:
## CVE-SICHERHEITSANALYSE

### KRITISCHE SICHERHEITSLÜCKEN (Critical)
- OpenSSH CVE-2021-28041: Remote code execution vulnerability

Service-Versionen:
  openssh-server: 1:7.9p1-10+deb10u2
  apache2: 2.4.38-3+deb10u8

Analysierte Pakete: 50
```

### Report-Integration
CVE-Informationen werden in Systemberichten als separater Abschnitt dargestellt:

```
## SICHERHEITSANALYSE

### CVE-SICHERHEITSLÜCKEN
- **Kritische CVEs**: 2 gefunden
- **Hohe CVEs**: 3 gefunden
- **Mittlere CVEs**: 5 gefunden
- **Niedrige CVEs**: 8 gefunden

### SOFORTIGE MASSNAHMEN
1. Update OpenSSH auf Version 8.2p1 oder höher
2. Update Apache2 auf Version 2.4.51 oder höher
3. Überprüfen Sie alle Docker-Container auf Sicherheitslücken
```

## 🧪 Tests

### Test-Suite
```bash
# Führe alle Tests für das CVE-Feature aus
python3 test_cve_feature.py
```

### Test-Bereiche
- **Argument-Parsing**: Korrekte Erkennung des `--with-cve` Flags
- **CVE-Analyse-Logik**: Funktionalität der Paket-Sammlung und -Analyse
- **Ollama-Integration**: Korrekte Prompt-Erstellung und -Verarbeitung
- **System-Context-Integration**: Einbindung in Berichte und Chat
- **Flag-Kombinationen**: Kompatibilität mit anderen Flags

## 🔄 Workflow-Beispiele

### Standard-Sicherheitsanalyse
```bash
# 1. Vollständige CVE-Analyse
python3 ssh_chat_system.py admin@server.example.com --with-cve

# 2. Im Chat weitere Sicherheitsfragen stellen
# - "security" für allgemeine Sicherheitsanalyse
# - "network-security" für Netzwerk-Sicherheit
# - "docker" für Container-Sicherheit
```

### Schnelle Sicherheitsprüfung
```bash
# Schnelle CVE-Analyse ohne Log-Sammlung
python3 ssh_chat_system.py admin@server.example.com --with-cve --quick --no-logs
```

### Automatisierte Sicherheitsberichte
```bash
# CVE-Analyse + automatischer Report
python3 ssh_chat_system.py admin@server.example.com --with-cve --auto-report
```

### Umfassende Sicherheitsanalyse
```bash
# CVE + Netzwerk-Sicherheit + Report + Chat
python3 ssh_chat_system.py admin@server.example.com --with-cve --include-network-security --report-and-chat
```

## 🎯 Best Practices

### Empfohlene Verwendung
1. **Regelmäßige Prüfungen**: Verwende `--with-cve` für wöchentliche Sicherheitsprüfungen
2. **Vor Updates**: Führe CVE-Analyse vor System-Updates durch
3. **Nach Incidents**: Verwende CVE-Analyse nach Sicherheitsvorfällen
4. **Compliance**: Nutze für Compliance-Reporting und Audits

### Flag-Kombinationen
- **`--with-cve --quick`**: Schnelle Überprüfung für regelmäßige Prüfungen
- **`--with-cve --auto-report`**: Automatisierte Sicherheitsberichte
- **`--with-cve --include-network-security`**: Umfassende Sicherheitsanalyse
- **`--with-cve --debug`**: Detaillierte Ausgaben für Entwickler

## 🔮 Zukünftige Erweiterungen

### Geplante Features
- **CVE-Datenbank-Cache**: Lokale Caching für schnellere Analysen
- **Automatische Updates**: Automatische Update-Empfehlungen
- **Vulnerability Scoring**: CVSS-Scoring für bessere Bewertung
- **Patch-Management**: Integration mit Patch-Management-Systemen

### Erweiterte Integration
- **SIEM-Systeme**: Integration mit Security Information and Event Management
- **Ticketing-Systeme**: Automatische Ticket-Erstellung für kritische CVEs
- **Monitoring-Systeme**: Integration mit Sicherheits-Monitoring
- **Compliance-Frameworks**: Unterstützung für ISO 27001, NIST, etc.

## 📝 Changelog

### Version 1.7.0 (Aktuell)
- ✅ Neues `--with-cve` Flag hinzugefügt
- ✅ Ollama-basierte CVE-Analyse implementiert
- ✅ Unterstützung für Debian/Ubuntu und RHEL/CentOS
- ✅ Automatische Service-Erkennung und -Analyse
- ✅ Integration in System-Context und Reports
- ✅ Umfassende Test-Suite erstellt
- ✅ Dokumentation aktualisiert

### Technische Details
- **Paket-Sammlung**: Intelligente Erkennung von Distribution und Paket-Manager
- **Service-Mapping**: Automatische Zuordnung von Paketen zu Services
- **Ollama-Prompts**: Spezialisierte Prompts für CVE-Analyse
- **Fehlerbehandlung**: Robuste Behandlung von Netzwerk- und Analyse-Fehlern
- **Performance**: Optimierte Paket-Sammlung (begrenzt auf 50 Pakete für Performance)

### Geplante Versionen
- **1.8.0**: CVE-Datenbank-Cache und erweiterte Scoring
- **1.9.0**: Automatische Update-Empfehlungen und Patch-Management
- **2.0.0**: Integration mit externen Sicherheits-Systemen 