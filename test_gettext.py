#!/usr/bin/env python3
"""
Test-Skript für gettext-basierte Internationalisierung
"""

import os
import locale
import gettext

def test_gettext_direct():
    """Testet gettext direkt"""
    print("🔧 Gettext Direkt-Test")
    print("=" * 50)
    
    # Pfad zu den Übersetzungsdateien
    locale_dir = os.path.join(os.path.dirname(__file__), 'locale')
    print(f"Locale-Verzeichnis: {locale_dir}")
    
    # Prüfe ob Dateien existieren
    de_mo = os.path.join(locale_dir, 'de', 'LC_MESSAGES', 'ai_loganalyser.mo')
    en_mo = os.path.join(locale_dir, 'en', 'LC_MESSAGES', 'ai_loganalyser.mo')
    
    print(f"Deutsche .mo Datei: {'✓' if os.path.exists(de_mo) else '✗'}")
    print(f"Englische .mo Datei: {'✓' if os.path.exists(en_mo) else '✗'}")
    
    # Teste deutsche Übersetzung
    try:
        de_translation = gettext.translation('ai_loganalyser', locale_dir, languages=['de'])
        de_translation.install()
        
        test_string = "chat_title"
        result = gettext.gettext(test_string)
        print(f"Deutsche Übersetzung von '{test_string}': {result}")
        
    except Exception as e:
        print(f"Fehler bei deutscher Übersetzung: {e}")
    
    # Teste englische Übersetzung
    try:
        en_translation = gettext.translation('ai_loganalyser', locale_dir, languages=['en'])
        en_translation.install()
        
        test_string = "chat_title"
        result = gettext.gettext(test_string)
        print(f"Englische Übersetzung von '{test_string}': {result}")
        
    except Exception as e:
        print(f"Fehler bei englischer Übersetzung: {e}")
    
    print()

def test_i18n_module():
    """Testet das i18n-Modul"""
    print("🌍 i18n-Modul Test")
    print("=" * 50)
    
    try:
        from i18n import i18n, _
        
        # Aktuelle Sprache
        current_lang = i18n.get_language()
        print(f"Aktuelle Sprache: {current_lang}")
        
        # Test-Übersetzungen
        test_strings = [
            'chat_title',
            'chat_prompt',
            'ssh_connecting',
            'shortcut_services'
        ]
        
        for string in test_strings:
            translation = _(string)
            print(f"'{string}' → '{translation}'")
        
        # Sprachwechsel testen
        print(f"\nSprachwechsel zu Englisch...")
        i18n.set_language('en')
        
        for string in test_strings:
            translation = _(string)
            print(f"'{string}' → '{translation}'")
        
        # Zurück zu Deutsch
        i18n.set_language('de')
        
    except Exception as e:
        print(f"Fehler im i18n-Modul: {e}")
    
    print()

def test_locale_detection():
    """Testet die Locale-Erkennung"""
    print("🌐 Locale-Erkennung Test")
    print("=" * 50)
    
    # Aktuelle Locale
    print(f"System Locale: {locale.getdefaultlocale()}")
    print(f"LANG: {os.environ.get('LANG', 'Nicht gesetzt')}")
    print(f"LC_ALL: {os.environ.get('LC_ALL', 'Nicht gesetzt')}")
    print(f"LC_MESSAGES: {os.environ.get('LC_MESSAGES', 'Nicht gesetzt')}")
    
    # Teste verschiedene Locales
    test_locales = [
        'de_DE.UTF-8',
        'en_US.UTF-8',
        'fr_FR.UTF-8',
        'es_ES.UTF-8'
    ]
    
    for test_locale in test_locales:
        lang_code = test_locale.split('_')[0].lower()
        if lang_code in ['de', 'deutsch', 'german']:
            detected = 'de'
        else:
            detected = 'en'
        print(f"'{test_locale}' → {detected}")
    
    print()

if __name__ == "__main__":
    print("🧪 Gettext Internationalisierung Test Suite")
    print("=" * 60)
    print()
    
    test_gettext_direct()
    test_i18n_module()
    test_locale_detection()
    
    print("✅ Alle Tests abgeschlossen!") 