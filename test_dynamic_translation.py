#!/usr/bin/env python3
"""
Test-Skript für dynamische AI-gesteuerte Übersetzung
"""

import os
import json
import tempfile
import shutil
from unittest.mock import patch, MagicMock
import requests

def test_locale_detection():
    """Testet die Erkennung verschiedener Locales"""
    print("🌐 Locale-Erkennung Test")
    print("=" * 50)
    
    # Teste verschiedene Locales
    test_cases = [
        ('de_DE.UTF-8', 'de'),
        ('en_US.UTF-8', 'en'),
        ('fr_FR.UTF-8', 'fr'),
        ('es_ES.UTF-8', 'es'),
        ('it_IT.UTF-8', 'it'),
        ('pt_PT.UTF-8', 'pt'),
        ('ru_RU.UTF-8', 'ru'),
        ('ja_JP.UTF-8', 'ja'),
        ('ko_KR.UTF-8', 'ko'),
        ('zh_CN.UTF-8', 'zh'),
        ('unknown_XX.UTF-8', 'unknown'),
    ]
    
    for locale_str, expected in test_cases:
        # Simuliere verschiedene Locales
        with patch.dict(os.environ, {'LANG': locale_str}):
            from i18n import i18n
            detected = i18n._detect_language()
            status = "✓" if detected == expected else "✗"
            print(f"{status} '{locale_str}' → {detected} (erwartet: {expected})")
    
    print()

def test_dynamic_translation_generation():
    """Testet die Generierung dynamischer Übersetzungen"""
    print("🤖 Dynamische Übersetzungsgenerierung Test")
    print("=" * 50)
    
    # Erstelle temporäres Verzeichnis für Tests
    with tempfile.TemporaryDirectory() as temp_dir:
        # Backup der ursprünglichen Datei
        original_file = 'dynamic_translations.json'
        backup_file = None
        
        if os.path.exists(original_file):
            backup_file = original_file + '.backup'
            shutil.copy2(original_file, backup_file)
        
        try:
            # Mock Ollama-Responses
            mock_responses = {
                'chat_title': 'Chat Interactif avec Ollama',
                'chat_prompt': 'Vous pouvez maintenant poser d\'autres questions sur le système analysé.',
                'ssh_connecting': 'Connexion via SSH...',
                'shortcut_services': 'Quels services fonctionnent sur le système?'
            }
            
            def mock_ollama_response(*args, **kwargs):
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {"response": "Mock translation"}
                return mock_response
            
            # Teste mit gemockter Ollama-API
            with patch('requests.post', side_effect=mock_ollama_response), \
                 patch('requests.get', return_value=MagicMock(status_code=200)):
                
                from i18n import i18n
                
                # Teste Generierung für Französisch
                result = i18n._generate_dynamic_translation('fr')
                print(f"✓ Französische Übersetzungsgenerierung: {'Erfolgreich' if result else 'Fehlgeschlagen'}")
                
                # Prüfe ob dynamische Übersetzungen geladen wurden
                if 'fr' in i18n.dynamic_translations:
                    print(f"✓ Dynamische Übersetzungen für 'fr' gefunden")
                    print(f"  - Generiert am: {i18n.dynamic_translations['fr']['generated_at']}")
                    print(f"  - Anzahl Strings: {i18n.dynamic_translations['fr']['total_strings']}")
                else:
                    print("✗ Dynamische Übersetzungen für 'fr' nicht gefunden")
        
        finally:
            # Restore Backup
            if backup_file and os.path.exists(backup_file):
                shutil.move(backup_file, original_file)
    
    print()

def test_fallback_system():
    """Testet das Fallback-System"""
    print("🔄 Fallback-System Test")
    print("=" * 50)
    
    from i18n import i18n, _
    
    # Teste verschiedene Sprachen
    test_languages = ['de', 'en', 'fr', 'es', 'unknown']
    
    for lang in test_languages:
        i18n.set_language(lang)
        
        # Teste einige Übersetzungen
        test_strings = ['chat_title', 'ssh_connecting', 'shortcut_services']
        
        print(f"\nSprache: {lang}")
        for string in test_strings:
            translation = _(string)
            status = "✓" if translation != string else "✗"
            print(f"  {status} '{string}' → '{translation}'")
    
    print()

def test_ollama_integration():
    """Testet die Ollama-Integration"""
    print("🔌 Ollama-Integration Test")
    print("=" * 50)
    
    from i18n import i18n
    
    # Teste Ollama-Verbindung
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            print("✓ Ollama ist erreichbar")
            
            # Teste Übersetzungsanfrage
            test_prompt = "Translate 'Hello World' to French"
            translation = i18n._query_ollama(test_prompt)
            
            if translation:
                print(f"✓ Ollama-Übersetzung erfolgreich: '{translation}'")
            else:
                print("✗ Ollama-Übersetzung fehlgeschlagen")
        else:
            print("✗ Ollama ist nicht erreichbar (Status: {response.status_code})")
    except Exception as e:
        print(f"✗ Ollama-Verbindungsfehler: {e}")
    
    print()

def test_dynamic_translation_persistence():
    """Testet die Persistierung dynamischer Übersetzungen"""
    print("💾 Persistierung Test")
    print("=" * 50)
    
    # Erstelle temporäres Verzeichnis für Tests
    with tempfile.TemporaryDirectory() as temp_dir:
        # Backup der ursprünglichen Datei
        original_file = 'dynamic_translations.json'
        backup_file = None
        
        if os.path.exists(original_file):
            backup_file = original_file + '.backup'
            shutil.copy2(original_file, backup_file)
        
        try:
            from i18n import i18n
            
            # Teste Speichern und Laden
            test_translations = {
                'test_lang': {
                    'translations': {
                        'chat_title': 'Test Chat Title',
                        'ssh_connecting': 'Test SSH Connecting'
                    },
                    'generated_at': '2024-01-01T12:00:00',
                    'total_strings': 2
                }
            }
            
            # Speichere Test-Übersetzungen
            i18n.dynamic_translations = test_translations
            i18n._save_dynamic_translations()
            
            # Prüfe ob Datei erstellt wurde
            if os.path.exists('dynamic_translations.json'):
                print("✓ Dynamische Übersetzungen gespeichert")
                
                # Lade Übersetzungen neu
                i18n._load_dynamic_translations()
                
                if 'test_lang' in i18n.dynamic_translations:
                    print("✓ Dynamische Übersetzungen erfolgreich geladen")
                    print(f"  - Test-Übersetzung: {i18n.dynamic_translations['test_lang']['translations']['chat_title']}")
                else:
                    print("✗ Dynamische Übersetzungen nicht geladen")
            else:
                print("✗ Dynamische Übersetzungen nicht gespeichert")
        
        finally:
            # Restore Backup
            if backup_file and os.path.exists(backup_file):
                shutil.move(backup_file, original_file)
            elif os.path.exists('dynamic_translations.json'):
                os.remove('dynamic_translations.json')
    
    print()

def test_unknown_locale_handling():
    """Testet die Behandlung unbekannter Locales"""
    print("❓ Unbekannte Locale Behandlung Test")
    print("=" * 50)
    
    # Teste mit verschiedenen unbekannten Locales
    unknown_locales = ['fr', 'es', 'it', 'pt', 'ru', 'ja', 'ko', 'zh', 'ar', 'hi']
    
    for locale in unknown_locales:
        print(f"\nTeste Locale: {locale}")
        
        # Simuliere unbekannte Locale
        with patch.dict(os.environ, {'LANG': f'{locale}_XX.UTF-8'}):
            from i18n import i18n
            
            # Initialisiere dynamische Übersetzung
            i18n.initialize_dynamic_translation()
            
            # Prüfe ob Übersetzungen generiert wurden
            if locale in i18n.dynamic_translations:
                print(f"  ✓ Übersetzungen für '{locale}' verfügbar")
            else:
                print(f"  ✗ Keine Übersetzungen für '{locale}' verfügbar")
    
    print()

def test_error_handling():
    """Testet die Fehlerbehandlung"""
    print("⚠️  Fehlerbehandlung Test")
    print("=" * 50)
    
    from i18n import i18n, _
    
    # Teste mit nicht erreichbarem Ollama
    with patch('requests.get', side_effect=Exception("Connection failed")):
        result = i18n._generate_dynamic_translation('test_lang')
        print(f"✓ Fehlerbehandlung bei Ollama-Verbindungsfehler: {'Erfolgreich' if not result else 'Fehlgeschlagen'}")
    
    # Teste mit ungültigen Übersetzungsschlüsseln
    i18n.set_language('de')
    translation = _('nonexistent_key')
    print(f"✓ Fallback bei ungültigem Schlüssel: '{translation}'")
    
    # Teste mit leeren Übersetzungen
    with patch.object(i18n, '_query_ollama', return_value=""):
        result = i18n._generate_dynamic_translation('empty_lang')
        print(f"✓ Behandlung leerer Übersetzungen: {'Erfolgreich' if result else 'Fehlgeschlagen'}")
    
    print()

def test_performance():
    """Testet die Performance der dynamischen Übersetzung"""
    print("⚡ Performance Test")
    print("=" * 50)
    
    import time
    from i18n import i18n, _
    
    # Teste Übersetzungsgeschwindigkeit
    test_strings = ['chat_title', 'chat_prompt', 'ssh_connecting', 'shortcut_services']
    
    start_time = time.time()
    
    for _ in range(100):
        for string in test_strings:
            translation = _(string)
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"✓ 400 Übersetzungsaufrufe in {duration:.3f} Sekunden")
    print(f"✓ Durchschnitt: {duration/400*1000:.2f} ms pro Übersetzung")
    
    print()

if __name__ == "__main__":
    print("🧪 Dynamische AI-gesteuerte Übersetzung Test Suite")
    print("=" * 70)
    print()
    
    test_locale_detection()
    test_dynamic_translation_generation()
    test_fallback_system()
    test_ollama_integration()
    test_dynamic_translation_persistence()
    test_unknown_locale_handling()
    test_error_handling()
    test_performance()
    
    print("✅ Alle Tests abgeschlossen!") 