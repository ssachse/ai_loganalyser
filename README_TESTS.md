# Test-Dokumentation

## Übersicht

Dieses Projekt enthält Tests, die ausschließlich **echte Sourcecode-Funktionen** verwenden und dem **DRY-Prinzip** (Don't Repeat Yourself) folgen. Alle Tests importieren und testen die originalen Funktionen aus dem Sourcecode, ohne Code zu kopieren.

## Test-Philosophie

- **DRY-Prinzip**: Keine Code-Duplikation in Tests
- **Echte Integration**: Tests verwenden nur originale Sourcecode-Funktionen
- **Automatisierung**: Vollständig automatisierte Testläufe
- **Plausibilität**: Tests prüfen auch die Qualität der Antworten

## Verbliebene Tests

### 1. `test_menu_automation_real_source.py` - Haupttest für Menü-Automatisierung

**Zweck**: Umfassender Test der Menü-Automatisierung mit echten Sourcecode-Funktionen

**Getestete Funktionen**:
- `get_shortcuts()` - Zentrale Shortcuts-Definition
- `create_intelligent_menu()` - Intelligente Menü-Erstellung
- `interpolate_user_input_to_shortcut()` - Eingabe-Interpolation
- `query_ollama()` - Ollama-Integration
- `detect_and_correct_nonsense()` - Unsinn-Erkennung

**Test-Szenarien**:
1. **Shortcuts-Import**: Prüft ob alle Shortcuts korrekt geladen werden
2. **Menü-Erstellung**: Testet Menü-Generierung mit numerischen Kürzeln
3. **Eingabe-Interpolation**: Prüft Keyword-Mapping und numerische Kürzel
4. **Ollama-Verbindung**: Testet echte Ollama-Integration
5. **Unsinn-Erkennung**: Prüft automatische Korrektur von Unsinn-Antworten
6. **Automatisierte Menü-Tests**: Vollständige Tests mit Ollama und Plausibilitätsprüfung

**Ausführung**:
```bash
python3 test_menu_automation_real_source.py
```

**Erwartetes Ergebnis**: 100% Erfolgsrate mit detaillierten Fortschrittsanzeigen

### 2. `test_interpolation.py` - Einfacher Interpolationstest

**Zweck**: Schneller Test der Eingabe-Interpolation ohne Ollama

**Getestete Funktionen**:
- `interpolate_user_input_to_shortcut()` - Eingabe-Interpolation

**Test-Szenarien**:
- Keyword-Mapping (z.B. 'lxc' → 'proxmox-containers')
- Numerische Kürzel
- Nicht-interpolierbare Eingaben

**Ausführung**:
```bash
python3 test_interpolation.py
```

### 3. `test_model_selection.py` - Modell-Auswahl-Test

**Zweck**: Test der intelligenten Modell-Auswahl

**Getestete Funktionen**:
- `get_available_models()` - Verfügbare Modelle abrufen
- `select_best_model()` - Intelligente Modell-Auswahl

**Test-Szenarien**:
- Menü-Generierung (schnelles Modell)
- Einfache Analyse (Standard-Modell)
- Komplexe Analyse (leistungsstarkes Modell)

**Ausführung**:
```bash
python3 test_model_selection.py
```

### 4. `tests/test_ssh_collector.py` - SSH-Collector Unit Tests

**Zweck**: Unit Tests für SSH-Log-Collector mit Mocking

**Getestete Klassen**:
- `SSHLogCollector` - SSH-Verbindung und Log-Sammlung
- `LinuxLogAnalyzer` - Linux-Log-Analyse

**Test-Szenarien**:
- SSH-Verbindungsaufbau (erfolgreich/fehlgeschlagen)
- System-Informationen-Sammlung
- Log-Sammlung und -Analyse
- Archiv-Erstellung und Cleanup
- Vollständiger Workflow

**Ausführung**:
```bash
python3 -m unittest tests.test_ssh_collector
```

### 5. `tests/test_log_analyzer.py` - Log-Analyzer Unit Tests

**Zweck**: Unit Tests für macOS Log-Analyzer

**Getestete Klassen**:
- `LogAnalyzer` - Hauptanalyse-Klasse
- `LogEntry` - Log-Eintrag-Dataclass
- `LogLevel` - Log-Level-Enum
- `Anomaly` - Anomalie-Dataclass

**Test-Szenarien**:
- Log-Parsing (verschiedene Formate)
- Prioritäts-Berechnung
- Ollama-Integration
- Anomalie-Erkennung
- Vollständiger Analyse-Workflow

**Ausführung**:
```bash
python3 -m unittest tests.test_log_analyzer
```

## Test-Ausführung

### Einzelne Tests
```bash
# Haupttest für Menü-Automatisierung
python3 test_menu_automation_real_source.py

# Schnelle Interpolation-Tests
python3 test_interpolation.py
python3 test_model_selection.py

# Unit Tests
python3 -m unittest tests.test_ssh_collector
python3 -m unittest tests.test_log_analyzer
```

### Alle Tests ausführen
```bash
# Alle Unit Tests
python3 -m unittest discover tests

# Haupttest + Unit Tests
python3 test_menu_automation_real_source.py && python3 -m unittest discover tests
```

## Test-Ergebnisse

### Erfolgskriterien
- **100% Erfolgsrate** bei allen Tests
- **Keine Code-Duplikation** in Tests
- **Echte Sourcecode-Integration** - Tests verwenden originale Funktionen
- **Automatisierte Plausibilitätsprüfung** bei Ollama-Antworten

### Beispiel-Output
```
[21:51:37] INFO: === STARTE MENÜ-AUTOMATISIERUNGSTESTS MIT ECHTEN SOURCECODE-FUNKTIONEN ===
[21:51:37] INFO: ✓ Shortcuts-Import: ERFOLGREICH
[21:51:37] INFO: ✓ Menü-Erstellung: ERFOLGREICH
[21:51:37] INFO: ✓ Eingabe-Interpolation: ERFOLGREICH
[21:51:37] INFO: ✓ Ollama-Verbindung: ERFOLGREICH
[21:51:37] INFO: ✓ Unsinn-Erkennung: ERFOLGREICH
[21:51:37] INFO: ✓ Automatisierte Menü-Tests: ERFOLGREICH
[21:51:37] INFO: 🎉 ALLE TESTS ERFOLGREICH!
[21:51:37] INFO: Erfolgsrate: 100.0%
```

## Wartung

### Neue Tests hinzufügen
1. **DRY-Prinzip befolgen**: Nur echte Sourcecode-Funktionen importieren
2. **Keine Code-Duplikation**: Funktionen nicht nachbauen
3. **Dokumentation**: Test-Zweck und getestete Funktionen dokumentieren

### Tests aktualisieren
- Bei Änderungen an Sourcecode-Funktionen Tests entsprechend anpassen
- Neue Funktionen in bestehende Tests integrieren
- Plausibilitätsprüfungen bei Bedarf erweitern

## Entfernte Tests

Folgende Tests wurden entfernt, da sie dem DRY-Prinzip nicht folgten:
- Tests mit kopiertem Sourcecode
- Tests mit nachgebauten Funktionen
- Tests ohne echte Sourcecode-Integration
- Automatisch generierte Test-Reports

## Fazit

Die verbliebenen Tests folgen dem DRY-Prinzip und testen ausschließlich echte Sourcecode-Funktionen. Sie bieten:
- **Zuverlässige Qualitätssicherung**
- **Echte Integrationstests**
- **Automatisierte Plausibilitätsprüfung**
- **Wartbare Test-Struktur** 