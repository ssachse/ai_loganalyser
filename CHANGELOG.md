# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

## [1.8.0] - 2025-07-25

### 🔍 Neue Features
- **Echte CVE-Datenbanken**: Integration von NIST NVD (National Vulnerability Database)
- **Hybrid-CVE-Analyse**: Kombiniert echte CVE-Datenbanken mit Ollama-KI-Analyse
- **CVE-Caching-System**: Lokales Caching für bessere Performance
- **Erweiterte CVE-Optionen**: Neue Flags für verschiedene CVE-Datenbanken
- **NVD API-Integration**: Direkte Abfrage der offiziellen US-Regierungs-Datenbank
- **CVSS-Score-Kategorisierung**: Automatische Kategorisierung nach CVSS v3.1 Scores

### 🔧 Verbesserungen
- **Rate Limiting**: Automatische Pausen zwischen NVD API-Calls
- **API-Key-Support**: Höhere Rate Limits mit NVD API-Key
- **Offline-Modus**: Verwendung nur lokaler Daten
- **Strukturierte CVE-Daten**: Vollständige CVE-Metadaten (Beschreibung, Referenzen, etc.)
- **Performance-Optimierung**: 24-Stunden-Cache für CVE-Daten

### 📁 Neue Dateien
- `cve_database_checker.py`: Neue Klasse für CVE-Datenbank-Integration
- `test_cve_database_integration.py`: Test-Suite für CVE-Datenbank-Features
- `CVE_DATABASE_INTEGRATION_PROPOSAL.md`: Detaillierter Implementierungsvorschlag

### 🎯 Neue Command Line Options
- `--cve-database {ollama,nvd,hybrid}`: Wähle CVE-Datenbank (Standard: hybrid)
- `--cve-cache`: Verwende lokalen CVE-Cache
- `--cve-offline`: Nur lokale CVE-Daten verwenden

### 🔄 CVE Database Features
- **NIST NVD**: Offizielle US-Regierungs-Datenbank, kostenlos, vollständig
- **Rate Limiting**: 5 Requests pro 6 Sekunden (erhöhbar mit API-Key)
- **Caching**: 24-Stunden-Cache für bessere Performance
- **CVSS v3.1**: Aktuelle CVSS-Score-Bewertung
- **Strukturierte Daten**: Vollständige CVE-Metadaten (Beschreibung, Referenzen, etc.)

### 🔄 Integration
- **Hybrid-Ansatz**: Kombiniert NVD-Daten mit Ollama-Analyse
- **System-Context**: Erweiterte CVE-Daten werden in Berichte integriert
- **Report-Generierung**: Detaillierte CVE-Informationen in allen Systemberichten
- **Chat-Integration**: Erweiterte CVE-Daten sind im interaktiven Chat verfügbar

## [1.7.0] - 2025-01-25

### 🔍 Neue Features
- **CVE-Sicherheitsanalyse**: Neues `--with-cve` Flag für umfassende Sicherheitsanalyse
- **Ollama-basierte CVE-Erkennung**: KI-gestützte Analyse bekannter Sicherheitslücken
- **Multi-Distribution Support**: Unterstützung für Debian/Ubuntu und RHEL/CentOS
- **Automatische Service-Erkennung**: Intelligente Erkennung wichtiger Services
- **Strukturierte CVE-Kategorisierung**: Klassifizierung nach Schweregrad (Critical, High, Medium, Low)

### 🔧 Verbesserungen
- **Paket-Sammlung**: Intelligente Erkennung von Distribution und Paket-Manager
- **Service-Mapping**: Automatische Zuordnung von Paketen zu Services
- **Ollama-Prompts**: Spezialisierte Prompts für CVE-Analyse
- **Fehlerbehandlung**: Robuste Behandlung von Netzwerk- und Analyse-Fehlern
- **Performance**: Optimierte Paket-Sammlung (begrenzt auf 50 Pakete)

### 📁 Neue Dateien
- `CVE_SECURITY_FEATURE.md`: Umfassende Dokumentation des CVE-Features
- `test_cve_feature.py`: Test-Suite für CVE-Sicherheitsanalyse

### 🎯 Sicherheitsanalyse
- **Kritische CVEs**: Remote Code Execution, Privilege Escalation, Authentication Bypass
- **Hohe CVEs**: Information Disclosure, Denial of Service, Cross-Site Scripting
- **Mittlere CVEs**: Cross-Site Request Forgery, Information Leakage, Weak Cryptography
- **Niedrige CVEs**: Security Misconfiguration, Outdated Software

### 🔄 Integration
- **System-Context**: CVE-Daten werden automatisch in Berichte integriert
- **Report-Generierung**: CVE-Informationen erscheinen in allen Systemberichten
- **Chat-Integration**: CVE-Daten sind im interaktiven Chat verfügbar
- **Flag-Kombinationen**: Vollständige Kompatibilität mit allen anderen Flags

## [1.6.0] - 2025-01-25

### 🚀 Neue Features
- **Report-and-Chat Flag**: Neues `--report-and-chat` Flag für automatische Report-Generierung gefolgt von Chat-Start
- **Hilfsfunktion für Report-Generierung**: Wiederverwendbare `generate_system_report()` Funktion
- **Flexible Report-Workflows**: Drei verschiedene Modi für Report-Generierung
  - `--auto-report`: Nur Report, dann beenden
  - `--report-and-chat`: Report + Chat
  - Normaler Modus: Manuelle Report-Generierung im Chat

### 🔧 Verbesserungen
- **Code-Refactoring**: Report-Generierung in separate Hilfsfunktion ausgelagert
- **Bessere Fehlerbehandlung**: Robuste Behandlung von Report-Generierungsfehlern
- **Konsistente Ausgabe**: Einheitliche Feedback-Meldungen für alle Report-Modi
- **Flag-Kompatibilität**: Vollständige Kompatibilität mit allen bestehenden Flags

### 📁 Neue Dateien
- `REPORT_AND_CHAT_FEATURE.md`: Umfassende Dokumentation des neuen Features
- `test_report_and_chat_flag.py`: Test-Suite für das neue Flag

### 🎯 Workflow-Optimierung
- **Zeitersparnis**: Kein manueller Report-Befehl im Chat nötig
- **Konsistenz**: Immer aktueller Report beim Chat-Start
- **Flexibilität**: Kombinierbar mit allen anderen Flags
- **Automatisierung**: Ein-Klick-Lösung für Report + Chat

## [1.5.0] - 2025-01-24

### 🐳 Neue Features
- **Erweiterte Docker-Container-Details**: Detaillierte Analyse aller laufenden Container
- **Container Health-Check-Überwachung**: Automatische Erkennung von fehlgeschlagenen Health-Checks
- **Container-Log-Analyse**: Automatische Erkennung von Fehlern und Warnungen in Container-Logs
- **Container-Statistiken**: CPU, Memory, Netzwerk und Block-I/O für jeden Container
- **Erweiterte Problem-Erkennung**: Identifikation von gestoppten Containern, hoher Ressourcen-Nutzung und Docker-Daemon-Fehlern
- **Container-Metadaten**: Restart-Policies, Uptime, Exit-Codes und Start-Zeitpunkte
- **Docker-Daemon-Log-Analyse**: Überwachung von Docker-Daemon-Fehlern in System-Logs

### 🔧 Verbesserungen
- **System-Context erweitert**: Detaillierte Docker-Informationen werden in Berichte integriert
- **Report-Integration**: Container-spezifische Details und Probleme werden im Systembericht angezeigt
- **Chat-Integration**: Docker-spezifische Fragen können im interaktiven Chat gestellt werden
- **Automatische Erkennung**: Docker-Details werden automatisch gesammelt, wenn Docker verfügbar ist

### 📁 Neue Dateien
- `DOCKER_DETAILS_FEATURE.md`: Umfassende Dokumentation der neuen Docker-Features
- `test_docker_details.py`: Test-Skript für erweiterte Docker-Container-Details

## [1.4.0] - 2025-01-23

### 🔒 Neue Features
- **Netzwerk-Sicherheitsanalyse**: Vollständige Analyse aller lauschenden Services und externer Erreichbarkeit
- **Interne Service-Erkennung**: `analyze_listening_services()` für Ports, Firewall-Status und externe Interfaces
- **Externe Erreichbarkeitstests**: `test_external_accessibility()` mit Nmap, Banner-Grabbing und Service-Versionen
- **Sicherheitsbewertung**: `assess_network_security()` mit Risiko-Level, Empfehlungen und Compliance-Problemen
- **Chat-Integration**: Neue Shortcuts `network-security`, `exposed-services`, `port-scan`, `service-test`
- **Automatische Netzwerk-Analyse**: `--include-network-security` Option für automatische Ausführung am Anfang
- **Proxmox-Container-Analyse**: Detaillierte Container-Informationen mit CPU, Memory, Uptime und Netzwerk pro Node
- **Erweiterte Sudo-Unterstützung**: Automatische Sudo-Erkennung und sichere Befehlsausführung
- **Chat-Integration**: `proxmox-containers` Shortcut für gezielte Container-Abfragen
- **Sichere Befehls-Whitelist**: Nur lesende Befehle werden mit Sudo ausgeführt
- **Gefährliche Befehle blockiert**: Löschoperationen werden niemals mit Sudo ausgeführt
- **Sudo-Test-Funktionalität**: Neue `test_sudo_availability()` Methode für Diagnose

### 🔧 Verbesserungen
- **Systemkontext erweitert**: Netzwerk-Sicherheitsdaten werden in `create_system_context()` integriert
- **Menü erweitert**: Neue Kategorie "Netzwerk-Sicherheit" mit entsprechenden Shortcuts
- **Interpolation verbessert**: Netzwerk-Sicherheits-Keywords für intelligente Shortcut-Erkennung
- **Automatische Rechte-Prüfung**: Erkennt Permission-Denied-Fehler und prüft Sudo-Verfügbarkeit
- **Fallback-Mechanismus**: Bei Sudo-Problemen wird automatisch auf normalen Modus zurückgegriffen
- **Erweiterte Fehlerbehandlung**: Bessere Kategorisierung von Berechtigungsfehlern
- **Sicherheits-First-Ansatz**: Im Zweifelsfall werden keine erhöhten Rechte verwendet

### 📁 Neue Dateien
- `test_network_security.py`: Test-Skript für Netzwerk-Sicherheitsanalyse
- `test_network_security_detailed.py`: Detailliertes Test-Skript mit JSON-Export
- `test_network_security_quick.py`: Schnelles Test-Skript für Überprüfung
- `test_sudo_functionality.py`: Test-Skript für Sudo-Funktionalität

### 🔒 Sicherheit
- **Whitelist-basierte Sicherheit**: Nur explizit erlaubte Befehle werden mit Sudo ausgeführt
- **Lesende Operationen nur**: Keine Lösch-, Modifikations- oder System-Befehle mit Sudo
- **Transparente Protokollierung**: Alle Sudo-Operationen werden dokumentiert
- **Netzwerk-Sicherheitsanalyse**: Automatische Erkennung von Sicherheitsrisiken und Compliance-Problemen

## [1.3.0] - 2025-01-23

### 🔐 Neue Features
- **Intelligente Sudo-Unterstützung**: Automatische Erkennung und sichere Nutzung von Sudo-Rechten
- **Sichere Befehls-Whitelist**: Nur lesende Befehle werden mit Sudo ausgeführt
- **Gefährliche Befehle blockiert**: Lösch-, Modifikations- und System-Befehle werden niemals mit Sudo ausgeführt
- **Passwortlose Sudo-Prüfung**: Automatische Erkennung ob Sudo ohne Passwort funktioniert
- **Transparente Ausführung**: Benutzer wird über Sudo-Nutzung informiert
- **Sudo-Test-Funktionalität**: Neue `test_sudo_availability()` Methode für Diagnose

### 🔧 Verbesserungen
- **Automatische Rechte-Prüfung**: Erkennt Permission-Denied-Fehler und prüft Sudo-Verfügbarkeit
- **Fallback-Mechanismus**: Bei Sudo-Problemen wird automatisch auf normalen Modus zurückgegriffen
- **Erweiterte Fehlerbehandlung**: Bessere Kategorisierung von Berechtigungsfehlern
- **Sicherheits-First-Ansatz**: Im Zweifelsfall werden keine erhöhten Rechte verwendet

### 📁 Neue Dateien
- `test_sudo_functionality.py`: Test-Skript für Sudo-Funktionalität

### 🔒 Sicherheit
- **Whitelist-basierte Sicherheit**: Nur explizit erlaubte Befehle werden mit Sudo ausgeführt
- **Lesende Operationen nur**: Keine Lösch-, Modifikations- oder System-Befehle mit Sudo
- **Transparente Protokollierung**: Alle Sudo-Operationen werden dokumentiert

## [1.3.0] - 2025-01-24

### 🚀 Neue Features
- **Automatische Report-Generierung**: Neues `--auto-report` Flag für automatische Berichterstellung
- **Batch-Verarbeitung**: Unterstützung für automatisierte Workflows
- **Dynamische Menü-Funktionalität**: Zeigt nur Module an, die tatsächlich auf dem System vorhanden sind
- **Intelligente Modul-Erkennung**: Automatische Erkennung von Kubernetes, Proxmox, Docker und Mailservern
- **Verbesserte Fehlerbehandlung**: Robuste Behandlung von Report-Speicherung
- **Fallback-Hostnamen**: Automatische Verwendung von IP-Adressen bei fehlenden Hostnamen

### 🔧 Verbesserungen
- **Benutzeroberfläche**: Übersichtlichere Menüs durch dynamische Modul-Anzeige
- **Relevanz**: Nur verfügbare Module werden angezeigt, reduzierte kognitive Belastung
- **Effizienz**: Schnellere Navigation und direkter Zugriff auf verfügbare Funktionen

## [1.2.0] - 2025-01-23

### 🚀 Neue Features
- **Automatische Berichterstellung**: Neuer `report` Kürzel für professionelle Systemberichte
- **CRAFT-Prompt Integration**: Enterprise-Architekt-Prompt für strukturierte Berichte
- **Markdown-Export**: Automatische Speicherung von Berichten als `.md` Dateien
- **Deutsche Übersetzungen**: Vollständig lokalisierte Benutzeroberfläche
- **Debug-Modus**: Neuer `--debug` Parameter für detaillierte Entwickler-Ausgaben
- **Asynchrone Analyse**: Hintergrund-Analyse für sofortige Menü-Anzeige

### 🔧 Verbesserungen
- **Intelligente Modell-Auswahl**: Priorisierung basierend auf Modellnamen statt Größe
- **Erweiterte Kürzelwörter**: Neue Kürzel für Logs, Kubernetes-Details und Proxmox
- **Verbesserte Fehlerbehandlung**: Robustere Behandlung von API-Fehlern
- **Optimierte Performance**: Schnellere Menü-Anzeige durch asynchrone Verarbeitung

### 🐛 Bugfixes
- **Übersetzungsprobleme**: Behoben - Chat und Menü sind jetzt vollständig auf Deutsch
- **Doppelte Modell-Wechsel-Meldungen**: Entfernt
- **Variable Scope Fehler**: `get_text` Variable in Shortcuts-Dictionary behoben
- **Report-Speicherung**: Berichte werden jetzt korrekt in `system_reports/` gespeichert

### 📊 Modell-Auswahl
- **Menü**: `qwen:0.5b` (ultraschnell)
- **Einfache Analysen**: `qwen:0.5b` → `llama3.2:3b`
- **Komplexe Analysen**: `llama3.1:8b` → `deepseek-r1:14b` → `mistral:7b`
- **Report-Generierung**: `llama3.1:8b` (8B Parameter für professionelle Berichte)

### 📁 Neue Dateien
- `system_reports/` Verzeichnis für automatisch generierte Berichte
- Timestamp-basierte Dateinamen: `system_report_HOSTNAME_YYYYMMDD_HHMMSS.md`

### 🔄 Entfernte Dateien
- Test-Dateien während der Entwicklung bereinigt

## [1.1.0] - 2025-01-22

### 🚀 Neue Features
- **Kubernetes-Cluster-Analyse**: Automatische Erkennung und Analyse von K8s-Clustern
- **Proxmox VE Integration**: Analyse von Proxmox Virtual Environment
- **Intelligente Fehlerbehandlung**: Gruppierte Fehler-Zusammenfassung
- **Quick-Modus**: Schnelle Analyse ohne zeitaufwändige Prüfungen

### 🔧 Verbesserungen
- **Erweiterte System-Analyse**: Mehr Details zu Services, Sicherheit und Performance
- **Verbesserte SSH-Verbindung**: Robustere Fehlerbehandlung
- **Optimierte Ausgabe**: Schönere Tabellen und Formatierung

## [1.0.0] - 2025-01-21

### 🚀 Erste Version
- **SSH-basierte Log-Analyse**: Grundlegende System-Informationen sammeln
- **Ollama-Chat Integration**: Intelligente Analyse mit lokalen LLMs
- **Basis-System-Analyse**: CPU, RAM, Speicherplatz, Services
- **Kürzelwörter-System**: Schnelle Zugriffe auf häufige Fragen

---

**Entwickelt mit ❤️ für DevOps und System-Administratoren** 