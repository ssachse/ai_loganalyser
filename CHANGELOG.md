# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

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