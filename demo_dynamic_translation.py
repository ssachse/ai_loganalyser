#!/usr/bin/env python3
"""
Demo-Skript für dynamische AI-gesteuerte Übersetzung
"""

import os
import sys

def demo_french_translation():
    """Demo für französische Übersetzung"""
    print("🇫🇷 Französische Übersetzung Demo")
    print("=" * 50)
    
    # Simuliere französische Locale
    os.environ['LANG'] = 'fr_FR.UTF-8'
    
    # Importiere i18n nach Locale-Setup
    from i18n import i18n, _
    
    print(f"Erkannte Sprache: {i18n.get_language()}")
    print(f"Unterstützte Sprachen: {i18n.get_supported_languages()}")
    
    # Teste Übersetzungen
    test_strings = [
        'chat_title',
        'chat_prompt', 
        'ssh_connecting',
        'shortcut_services',
        'chat_goodbye'
    ]
    
    print("\nÜbersetzungen:")
    for string in test_strings:
        translation = _(string)
        print(f"  '{string}' → '{translation}'")
    
    print()

def demo_spanish_translation():
    """Demo für spanische Übersetzung"""
    print("🇪🇸 Spanische Übersetzung Demo")
    print("=" * 50)
    
    # Simuliere spanische Locale
    os.environ['LANG'] = 'es_ES.UTF-8'
    
    # Importiere i18n nach Locale-Setup
    from i18n import i18n, _
    
    print(f"Erkannte Sprache: {i18n.get_language()}")
    print(f"Unterstützte Sprachen: {i18n.get_supported_languages()}")
    
    # Teste Übersetzungen
    test_strings = [
        'chat_title',
        'chat_prompt', 
        'ssh_connecting',
        'shortcut_services',
        'chat_goodbye'
    ]
    
    print("\nÜbersetzungen:")
    for string in test_strings:
        translation = _(string)
        print(f"  '{string}' → '{translation}'")
    
    print()

def demo_italian_translation():
    """Demo für italienische Übersetzung"""
    print("🇮🇹 Italienische Übersetzung Demo")
    print("=" * 50)
    
    # Simuliere italienische Locale
    os.environ['LANG'] = 'it_IT.UTF-8'
    
    # Importiere i18n nach Locale-Setup
    from i18n import i18n, _
    
    print(f"Erkannte Sprache: {i18n.get_language()}")
    print(f"Unterstützte Sprachen: {i18n.get_supported_languages()}")
    
    # Teste Übersetzungen
    test_strings = [
        'chat_title',
        'chat_prompt', 
        'ssh_connecting',
        'shortcut_services',
        'chat_goodbye'
    ]
    
    print("\nÜbersetzungen:")
    for string in test_strings:
        translation = _(string)
        print(f"  '{string}' → '{translation}'")
    
    print()

def demo_japanese_translation():
    """Demo für japanische Übersetzung"""
    print("🇯🇵 Japanische Übersetzung Demo")
    print("=" * 50)
    
    # Simuliere japanische Locale
    os.environ['LANG'] = 'ja_JP.UTF-8'
    
    # Importiere i18n nach Locale-Setup
    from i18n import i18n, _
    
    print(f"Erkannte Sprache: {i18n.get_language()}")
    print(f"Unterstützte Sprachen: {i18n.get_supported_languages()}")
    
    # Teste Übersetzungen
    test_strings = [
        'chat_title',
        'chat_prompt', 
        'ssh_connecting',
        'shortcut_services',
        'chat_goodbye'
    ]
    
    print("\nÜbersetzungen:")
    for string in test_strings:
        translation = _(string)
        print(f"  '{string}' → '{translation}'")
    
    print()

def demo_runtime_language_switch():
    """Demo für Runtime-Sprachwechsel"""
    print("🔄 Runtime-Sprachwechsel Demo")
    print("=" * 50)
    
    from i18n import i18n, _
    
    # Starte mit Deutsch
    i18n.set_language('de')
    print(f"Aktuelle Sprache: {i18n.get_language()}")
    print(f"'chat_title' auf Deutsch: {_('chat_title')}")
    
    # Wechsle zu Französisch (dynamisch generiert)
    print("\nWechsle zu Französisch...")
    i18n.set_language('fr')
    print(f"Aktuelle Sprache: {i18n.get_language()}")
    print(f"'chat_title' auf Französisch: {_('chat_title')}")
    
    # Wechsle zu Spanisch (dynamisch generiert)
    print("\nWechsle zu Spanisch...")
    i18n.set_language('es')
    print(f"Aktuelle Sprache: {i18n.get_language()}")
    print(f"'chat_title' auf Spanisch: {_('chat_title')}")
    
    # Zurück zu Deutsch
    print("\nZurück zu Deutsch...")
    i18n.set_language('de')
    print(f"Aktuelle Sprache: {i18n.get_language()}")
    print(f"'chat_title' auf Deutsch: {_('chat_title')}")
    
    print()

def demo_error_handling():
    """Demo für Fehlerbehandlung"""
    print("⚠️  Fehlerbehandlung Demo")
    print("=" * 50)
    
    from i18n import i18n, _
    
    # Teste mit nicht erreichbarem Ollama
    print("Teste mit nicht erreichbarem Ollama...")
    
    # Simuliere Ollama-Ausfall
    import requests
    original_get = requests.get
    
    def mock_failed_get(*args, **kwargs):
        raise Exception("Ollama not available")
    
    requests.get = mock_failed_get
    
    try:
        i18n.set_language('unknown_lang')
        print(f"Fallback-Sprache: {i18n.get_language()}")
        print(f"Fallback-Übersetzung: {_('chat_title')}")
    finally:
        requests.get = original_get
    
    print()

def main():
    """Hauptfunktion"""
    print("🎭 Dynamische AI-gesteuerte Übersetzung Demo")
    print("=" * 60)
    print()
    
    # Prüfe Ollama-Verbindung
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            print("✅ Ollama ist verfügbar - Demo kann durchgeführt werden")
        else:
            print("⚠️  Ollama ist nicht erreichbar - Demo verwendet Fallbacks")
    except Exception:
        print("⚠️  Ollama ist nicht erreichbar - Demo verwendet Fallbacks")
    
    print()
    
    # Führe Demos durch
    demo_french_translation()
    demo_spanish_translation()
    demo_italian_translation()
    demo_japanese_translation()
    demo_runtime_language_switch()
    demo_error_handling()
    
    print("🎉 Demo abgeschlossen!")
    print("\n💡 Tipp: Starte Ollama mit 'ollama serve' für vollständige Funktionalität")

if __name__ == "__main__":
    main() 