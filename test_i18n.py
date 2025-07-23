#!/usr/bin/env python3
"""
Test-Skript für die Internationalisierung
"""

import os
import locale
from i18n import i18n, _

def test_language_detection():
    """Testet die automatische Spracherkennung"""
    print("🌍 Spracherkennung Test")
    print("=" * 50)
    
    # Aktuelle Locale anzeigen
    print(f"System Locale: {locale.getdefaultlocale()}")
    print(f"LANG: {os.environ.get('LANG', 'Nicht gesetzt')}")
    print(f"LC_ALL: {os.environ.get('LC_ALL', 'Nicht gesetzt')}")
    print(f"LC_MESSAGES: {os.environ.get('LC_MESSAGES', 'Nicht gesetzt')}")
    
    # Erkannte Sprache
    detected_lang = i18n.get_language()
    print(f"Erkannte Sprache: {detected_lang}")
    
    # Unterstützte Sprachen
    supported = i18n.get_supported_languages()
    print(f"Unterstützte Sprachen: {', '.join(supported)}")
    
    print()

def test_translations():
    """Testet verschiedene Übersetzungen"""
    print("📝 Übersetzungs-Test")
    print("=" * 50)
    
    # Test-Übersetzungen
    test_keys = [
        'chat_title',
        'chat_prompt',
        'ssh_connecting',
        'ssh_success',
        'error_summary',
        'shortcut_services',
        'shortcut_storage',
        'shortcut_security'
    ]
    
    for key in test_keys:
        translation = _(key)
        print(f"{key}: {translation}")
    
    print()

def test_language_switching():
    """Testet das Umschalten der Sprache"""
    print("🔄 Sprach-Umschaltung Test")
    print("=" * 50)
    
    # Aktuelle Sprache
    current_lang = i18n.get_language()
    print(f"Aktuelle Sprache: {current_lang}")
    
    # Test-Übersetzung
    test_key = 'chat_title'
    translation = _(test_key)
    print(f"'{test_key}' auf {current_lang}: {translation}")
    
    # Sprache wechseln
    new_lang = 'en' if current_lang == 'de' else 'de'
    i18n.set_language(new_lang)
    print(f"Sprache gewechselt zu: {new_lang}")
    
    # Neue Übersetzung
    translation = _(test_key)
    print(f"'{test_key}' auf {new_lang}: {translation}")
    
    # Zurück zur ursprünglichen Sprache
    i18n.set_language(current_lang)
    print(f"Sprache zurück zu: {current_lang}")
    
    print()

def test_formatting():
    """Testet Formatierung mit Parametern"""
    print("🔧 Formatierungs-Test")
    print("=" * 50)
    
    # Test mit Parametern (falls verfügbar)
    try:
        # Beispiel für formatierte Übersetzung
        formatted = _('ssh_connecting').format(host='example.com')
        print(f"Formatierte Übersetzung: {formatted}")
    except Exception as e:
        print(f"Formatierung nicht verfügbar: {e}")
    
    print()

if __name__ == "__main__":
    print("🧪 Internationalisierung Test Suite")
    print("=" * 60)
    print()
    
    test_language_detection()
    test_translations()
    test_language_switching()
    test_formatting()
    
    print("✅ Alle Tests abgeschlossen!") 