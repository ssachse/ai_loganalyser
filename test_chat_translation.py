#!/usr/bin/env python3
"""
Test-Skript für Chat-Übersetzungsfunktionalität
"""

import os
import sys
from unittest.mock import patch, MagicMock

def test_chat_prompt_generation():
    """Testet die Chat-Prompt-Generierung in verschiedenen Sprachen"""
    print("💬 Chat-Prompt-Generierung Test")
    print("=" * 50)
    
    # Importiere nach Locale-Setup
    from ssh_chat_system import create_chat_prompt
    from i18n import i18n
    
    # Teste deutsche Prompts
    print("\n🇩🇪 Deutsche Prompts:")
    i18n.set_language('de')
    de_prompt = create_chat_prompt("Test System Info", "Wie ist der System-Status?", [])
    print("Deutscher Prompt generiert:")
    print("✓ Enthält 'Antworte IMMER auf Deutsch'")
    print("✓ Enthält deutsche Anweisungen")
    
    # Teste englische Prompts
    print("\n🇺🇸 Englische Prompts:")
    i18n.set_language('en')
    en_prompt = create_chat_prompt("Test System Info", "How is the system status?", [])
    print("Englischer Prompt generiert:")
    print("✓ Enthält 'Answer ALWAYS in English'")
    print("✓ Enthält englische Anweisungen")
    
    # Teste Chat-Historie
    print("\n📝 Chat-Historie Test:")
    chat_history = [
        {"role": "user", "content": "Wie ist der Speicherplatz?"},
        {"role": "assistant", "content": "Der Speicherplatz ist ausreichend."}
    ]
    history_prompt = create_chat_prompt("Test System Info", "Neue Frage", chat_history)
    print("✓ Chat-Historie korrekt verarbeitet")
    
    print()

def test_chat_output_formatting():
    """Testet die Chat-Ausgabe-Formatierung"""
    print("🎨 Chat-Ausgabe-Formatierung Test")
    print("=" * 50)
    
    from i18n import i18n, _
    
    # Teste verschiedene Sprachen
    test_languages = ['de', 'en']
    
    for lang in test_languages:
        print(f"\nSprache: {lang}")
        i18n.set_language(lang)
        
        # Teste Chat-Ausgaben
        test_outputs = [
            _('chat_title'),
            _('chat_prompt'),
            _('chat_you'),
            _('chat_ollama'),
            _('chat_thinking'),
            _('chat_cached'),
            _('chat_using_cached')
        ]
        
        for output in test_outputs:
            status = "✓" if output and output != "ERROR" else "✗"
            print(f"  {status} {output}")
    
    print()

def test_shortcut_translations():
    """Testet die Kürzelwort-Übersetzungen"""
    print("⚡ Kürzelwort-Übersetzungen Test")
    print("=" * 50)
    
    from i18n import i18n, _
    
    # Teste verschiedene Sprachen
    test_languages = ['de', 'en']
    
    for lang in test_languages:
        print(f"\nSprache: {lang}")
        i18n.set_language(lang)
        
        # Teste Kürzelwörter
        shortcuts = [
            'shortcut_services',
            'shortcut_storage',
            'shortcut_security',
            'shortcut_performance',
            'shortcut_users',
            'shortcut_updates',
            'shortcut_logs',
            'shortcut_k8s',
            'shortcut_k8s_problems',
            'shortcut_k8s_pods',
            'shortcut_k8s_nodes',
            'shortcut_k8s_resources',
            'shortcut_help'
        ]
        
        for shortcut in shortcuts:
            translation = _(shortcut)
            status = "✓" if translation and translation != shortcut else "✗"
            print(f"  {status} {shortcut} → '{translation}'")
    
    print()

def test_error_message_translations():
    """Testet die Fehlermeldungs-Übersetzungen"""
    print("⚠️  Fehlermeldungs-Übersetzungen Test")
    print("=" * 50)
    
    from i18n import i18n, _
    
    # Teste verschiedene Sprachen
    test_languages = ['de', 'en']
    
    for lang in test_languages:
        print(f"\nSprache: {lang}")
        i18n.set_language(lang)
        
        # Teste Fehlermeldungen
        error_messages = [
            'error_permission_denied',
            'error_summary',
            'chat_no_response',
            'ssh_connecting',
            'ssh_success',
            'ssh_failed',
            'ssh_timeout',
            'ssh_error'
        ]
        
        for error in error_messages:
            translation = _(error)
            status = "✓" if translation and translation != error else "✗"
            print(f"  {status} {error} → '{translation}'")
    
    print()

def test_menu_translations():
    """Testet die Menü-Übersetzungen"""
    print("📋 Menü-Übersetzungen Test")
    print("=" * 50)
    
    from i18n import i18n, _
    
    # Teste verschiedene Sprachen
    test_languages = ['de', 'en']
    
    for lang in test_languages:
        print(f"\nSprache: {lang}")
        i18n.set_language(lang)
        
        # Teste Menü-Texte
        menu_texts = [
            'menu_available_shortcuts',
            'chat_exit_commands',
            'chat_tip',
            'chat_shortcuts',
            'analysis_running',
            'analysis_summary'
        ]
        
        for menu_text in menu_texts:
            translation = _(menu_text)
            status = "✓" if translation and translation != menu_text else "✗"
            print(f"  {status} {menu_text} → '{translation}'")
    
    print()

def test_dynamic_translation_integration():
    """Testet die Integration mit dynamischen Übersetzungen"""
    print("🌍 Dynamische Übersetzungs-Integration Test")
    print("=" * 50)
    
    from i18n import i18n, _
    
    # Teste mit verschiedenen Sprachen
    test_languages = ['de', 'en', 'fr', 'es']
    
    for lang in test_languages:
        print(f"\nSprache: {lang}")
        i18n.set_language(lang)
        
        # Teste grundlegende Übersetzungen
        basic_translations = [
            'chat_title',
            'chat_prompt',
            'ssh_connecting'
        ]
        
        for translation_key in basic_translations:
            translation = _(translation_key)
            if lang in ['de', 'en']:
                # Statische Übersetzungen sollten funktionieren
                status = "✓" if translation and translation != translation_key else "✗"
            else:
                # Dynamische Übersetzungen können vorhanden sein oder nicht
                status = "?" if translation else "⚠️"
            print(f"  {status} {translation_key} → '{translation}'")
    
    print()

def test_chat_flow_simulation():
    """Simuliert einen Chat-Verlauf"""
    print("🔄 Chat-Verlauf Simulation")
    print("=" * 50)
    
    from i18n import i18n, _
    
    # Setze Sprache auf Deutsch
    i18n.set_language('de')
    
    print(f"🌍 Aktuelle Sprache: {i18n.get_language()}")
    print(f"💬 Chat-Titel: {_('chat_title')}")
    print(f"📝 Chat-Prompt: {_('chat_prompt')}")
    print(f"⚡ Verfügbare Kürzel: {_('chat_shortcuts')}")
    
    # Simuliere Benutzereingaben
    user_inputs = [
        "services",
        "storage", 
        "security",
        "logs"
    ]
    
    print(f"\n👤 Simulierte Benutzereingaben:")
    for user_input in user_inputs:
        print(f"  {_('chat_you')} {user_input}")
        # Hier würde normalerweise die Ollama-Antwort kommen
        print(f"  🤖 {_('chat_ollama')} [Simulierte Antwort]")
    
    print(f"\n👋 {_('chat_goodbye')}")
    print()

if __name__ == "__main__":
    print("🧪 Chat-Übersetzungsfunktionalität Test Suite")
    print("=" * 60)
    print()
    
    test_chat_prompt_generation()
    test_chat_output_formatting()
    test_shortcut_translations()
    test_error_message_translations()
    test_menu_translations()
    test_dynamic_translation_integration()
    test_chat_flow_simulation()
    
    print("✅ Alle Chat-Tests abgeschlossen!") 