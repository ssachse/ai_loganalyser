#!/usr/bin/env python3
"""
Internationalisierung für den AI Log-Analyzer mit gettext
POSIX-konform und ohne externe Abhängigkeiten
"""

import os
import locale
import gettext
from typing import Dict, Any

class I18n:
    """Internationalisierungsklasse mit gettext-Unterstützung"""
    
    def __init__(self):
        self.current_language = self._detect_language()
        self._setup_gettext()
    
    def _detect_language(self) -> str:
        """Erkennt die Sprache aus der Shell-Locale"""
        try:
            # Versuche Shell-Locale zu lesen
            shell_locale = os.environ.get('LANG', '')
            if not shell_locale:
                shell_locale = os.environ.get('LC_ALL', '')
            if not shell_locale:
                shell_locale = os.environ.get('LC_MESSAGES', '')
            if not shell_locale:
                shell_locale = locale.getdefaultlocale()[0] or 'en_US'
            
            # Extrahiere Sprachcode
            lang_code = shell_locale.split('_')[0].lower()
            
            # Unterstützte Sprachen
            if lang_code in ['de', 'deutsch', 'german']:
                return 'de'
            else:
                return 'en'
                
        except Exception:
            return 'en'  # Fallback auf Englisch
    
    def _setup_gettext(self):
        """Richtet gettext für die aktuelle Sprache ein"""
        try:
            # Pfad zu den Übersetzungsdateien
            locale_dir = os.path.join(os.path.dirname(__file__), 'locale')
            
            # Übersetzungsfunktion für aktuelle Sprache
            if self.current_language == 'de':
                self.translation = gettext.translation('ai_loganalyser', locale_dir, languages=['de'])
            else:
                self.translation = gettext.translation('ai_loganalyser', locale_dir, languages=['en'])
            
            # Übersetzungsfunktion installieren
            self.translation.install()
            
        except Exception as e:
            # Fallback: Verwende Standard-gettext
            print(f"Warning: Could not load translations: {e}")
            self.translation = gettext.NullTranslations()
            self.translation.install()
    
    def get(self, key: str, **kwargs) -> str:
        """Holt eine Übersetzung für den gegebenen Schlüssel"""
        try:
            # Verwende gettext für Übersetzung
            translation = gettext.gettext(key)
            
            # Fallback auf manuelle Übersetzungen wenn gettext nicht funktioniert
            if translation == key:
                translation = self._get_fallback_translation(key)
            
            if kwargs:
                return translation.format(**kwargs)
            return translation
        except Exception:
            return self._get_fallback_translation(key)
    
    def _get_fallback_translation(self, key: str) -> str:
        """Fallback-Übersetzungen wenn gettext nicht funktioniert"""
        fallback_translations = {
            'de': {
                'chat_title': 'Interaktiver Chat mit Ollama',
                'chat_prompt': 'Sie können jetzt weitere Fragen über das analysierte System stellen.',
                'chat_shortcuts': 'Kürzelwörter für häufige Fragen:',
                'chat_exit_commands': 'zum Verlassen',
                'chat_tip': 'Tipp:',
                'chat_you': 'Sie:',
                'chat_ollama': 'Ollama:',
                'chat_thinking': 'Denke nach...',
                'chat_no_response': 'Keine Antwort von Ollama erhalten',
                'chat_goodbye': 'Auf Wiedersehen! Danke für die Nutzung des Log-Analyzers.',
                'chat_using_cached': 'Verwende gecachte Antwort für',
                'chat_cached': 'gecacht',
                'chat_using_model': 'Verwende Modell:',
                'chat_using_fast_model': 'Verwende schnelles Modell:',
                'chat_using_complex_model': 'Verwende komplexes Modell:',
                'shortcut_services': 'Welche Services laufen auf dem System?',
                'shortcut_storage': 'Wie ist der Speicherplatz?',
                'shortcut_security': 'Gibt es Sicherheitsprobleme?',
                'shortcut_processes': 'Was sind die Top-Prozesse?',
                'shortcut_performance': 'Wie ist die System-Performance?',
                'shortcut_users': 'Welche Benutzer sind aktiv?',
                'shortcut_updates': 'Gibt es verfügbare System-Updates?',
                'shortcut_logs': 'Was zeigen die Logs?',
                'shortcut_k8s': 'Wie ist der Kubernetes-Cluster-Status?',
                'shortcut_k8s_problems': 'Welche Kubernetes-Probleme gibt es?',
                'shortcut_k8s_pods': 'Welche Pods laufen im Cluster?',
                'shortcut_k8s_nodes': 'Wie ist der Node-Status?',
                'shortcut_k8s_resources': 'Wie ist die Ressourcen-Auslastung im Cluster?',
                'shortcut_help': 'Zeige verfügbare Kürzelwörter',
                'error_permission_denied': 'Fehlende Rechte',
                'error_summary': 'Fehler-Zusammenfassung',
                'menu_available_shortcuts': 'Verfügbare Kürzelwörter:',
                'ssh_connecting': 'Verbinde mit SSH...',
                'ssh_success': 'SSH-Verbindung erfolgreich',
                'ssh_failed': 'SSH-Verbindung fehlgeschlagen',
                'ssh_timeout': 'SSH-Verbindung Timeout',
                'ssh_error': 'SSH-Fehler',
                'analysis_running': 'Führe automatische System-Analyse durch...',
                'analysis_summary': 'System-Analyse:',
            },
            'en': {
                'chat_title': 'Interactive Chat with Ollama',
                'chat_prompt': 'You can now ask further questions about the analyzed system.',
                'chat_shortcuts': 'Shortcuts for common questions:',
                'chat_exit_commands': 'to exit',
                'chat_tip': 'Tip:',
                'chat_you': 'You:',
                'chat_ollama': 'Ollama:',
                'chat_thinking': 'Thinking...',
                'chat_no_response': 'No response received from Ollama',
                'chat_goodbye': 'Goodbye! Thank you for using the Log Analyzer.',
                'chat_using_cached': 'Using cached response for',
                'chat_cached': 'cached',
                'chat_using_model': 'Using model:',
                'chat_using_fast_model': 'Using fast model:',
                'chat_using_complex_model': 'Using complex model:',
                'shortcut_services': 'Which services are running on the system?',
                'shortcut_storage': 'How is the storage space?',
                'shortcut_security': 'Are there security issues?',
                'shortcut_processes': 'What are the top processes?',
                'shortcut_performance': 'How is the system performance?',
                'shortcut_users': 'Which users are active?',
                'shortcut_updates': 'Are there available system updates?',
                'shortcut_logs': 'What do the logs show?',
                'shortcut_k8s': 'How is the Kubernetes cluster status?',
                'shortcut_k8s_problems': 'What Kubernetes problems are there?',
                'shortcut_k8s_pods': 'Which pods are running in the cluster?',
                'shortcut_k8s_nodes': 'How is the node status?',
                'shortcut_k8s_resources': 'How is the resource usage in the cluster?',
                'shortcut_help': 'Show available shortcuts',
                'error_permission_denied': 'Permission denied',
                'error_summary': 'Error Summary',
                'menu_available_shortcuts': 'Available shortcuts:',
                'ssh_connecting': 'Connecting via SSH...',
                'ssh_success': 'SSH connection successful',
                'ssh_failed': 'SSH connection failed',
                'ssh_timeout': 'SSH connection timeout',
                'ssh_error': 'SSH error',
                'analysis_running': 'Running automatic system analysis...',
                'analysis_summary': 'System Analysis:',
            }
        }
        
        return fallback_translations.get(self.current_language, {}).get(key, key)
    
    def get_language(self) -> str:
        """Gibt die aktuelle Sprache zurück"""
        return self.current_language
    
    def set_language(self, language: str):
        """Setzt die Sprache manuell"""
        if language in ['de', 'en']:
            self.current_language = language
            self._setup_gettext()
    
    def get_supported_languages(self) -> list:
        """Gibt unterstützte Sprachen zurück"""
        return ['de', 'en']

# Globale Instanz
i18n = I18n()

def _(key: str, **kwargs) -> str:
    """Kurze Funktion für Übersetzungen"""
    return i18n.get(key, **kwargs) 