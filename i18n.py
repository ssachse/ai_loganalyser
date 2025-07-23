#!/usr/bin/env python3
"""
Internationalisierung für den AI Log-Analyzer mit gettext
POSIX-konform und ohne externe Abhängigkeiten
"""

import os
import locale
import gettext
import json
import requests
from typing import Dict, Any
from datetime import datetime

class I18n:
    """Internationalisierungsklasse mit gettext-Unterstützung"""
    
    def __init__(self):
        self.current_language = self._detect_language()
        self._setup_gettext()
        self.dynamic_translations = {}
        self._load_dynamic_translations()
    
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
            elif lang_code in ['en', 'english']:
                return 'en'
            else:
                # Unbekannte Locale - verwende Sprachcode für dynamische Übersetzung
                return lang_code
                
        except Exception:
            return 'de'  # Fallback auf Deutsch statt Englisch
    
    def _force_german_locale(self):
        """Erzwingt deutsche Locale für gettext"""
        try:
            # Setze Locale explizit
            locale.setlocale(locale.LC_ALL, 'de_DE.UTF-8')
        except:
            try:
                locale.setlocale(locale.LC_ALL, 'de_DE')
            except:
                pass  # Fallback auf Standard
    
    def _setup_gettext(self):
        """Richtet gettext für die aktuelle Sprache ein"""
        try:
            # Erzwinge deutsche Locale wenn erkannt
            if self.current_language == 'de':
                self._force_german_locale()
            
            # Pfad zu den Übersetzungsdateien
            locale_dir = os.path.join(os.path.dirname(__file__), 'locale')
            
            # Übersetzungsfunktion für aktuelle Sprache
            if self.current_language in ['de', 'en']:
                self.translation = gettext.translation('ai_loganalyser', locale_dir, languages=[self.current_language])
            else:
                # Unbekannte Sprache - verwende Null-Übersetzung
                self.translation = gettext.NullTranslations()
            
            # Übersetzungsfunktion installieren
            self.translation.install()
            
            # Teste ob Übersetzungen funktionieren
            test_translation = self.translation.gettext('chat_title')
            if test_translation == 'chat_title':
                print(f"Warning: Translations not loaded properly for {self.current_language}")
                # Versuche Fallback auf Fallback-Dictionary
                self._load_fallback_translations()
            
        except Exception as e:
            # Fallback: Verwende Standard-gettext
            print(f"Warning: Could not load translations: {e}")
            self.translation = gettext.NullTranslations()
            self.translation.install()
            self._load_fallback_translations()
    
    def _load_dynamic_translations(self):
        """Lädt dynamisch generierte Übersetzungen"""
        try:
            dynamic_file = os.path.join(os.path.dirname(__file__), 'dynamic_translations.json')
            if os.path.exists(dynamic_file):
                with open(dynamic_file, 'r', encoding='utf-8') as f:
                    self.dynamic_translations = json.load(f)
        except Exception:
            self.dynamic_translations = {}
    
    def _load_fallback_translations(self):
        """Lädt Fallback-Übersetzungen wenn gettext nicht funktioniert"""
        try:
            fallback_dict = self._get_fallback_translation_dict(self.current_language)
            self.fallback_translations = fallback_dict
        except Exception:
            self.fallback_translations = {}
    
    def _save_dynamic_translations(self):
        """Speichert dynamisch generierte Übersetzungen"""
        try:
            dynamic_file = os.path.join(os.path.dirname(__file__), 'dynamic_translations.json')
            with open(dynamic_file, 'w', encoding='utf-8') as f:
                json.dump(self.dynamic_translations, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Warning: Could not save dynamic translations: {e}")
    
    def _query_ollama(self, prompt: str, model: str = "llama2") -> str:
        """Fragt Ollama nach einer Übersetzung"""
        try:
            url = "http://localhost:11434/api/generate"
            data = {
                "model": model,
                "prompt": prompt,
                "stream": False
            }
            
            response = requests.post(url, json=data, timeout=30)
            if response.status_code == 200:
                return response.json()["response"].strip()
            else:
                return ""
        except Exception as e:
            print(f"Ollama error: {e}")
            return ""
    
    def _generate_dynamic_translation(self, language_code: str) -> bool:
        """Generiert dynamische Übersetzungen für eine unbekannte Sprache"""
        try:
            print(f"\n🌍 Unbekannte Locale erkannt: {language_code}")
            print("🤖 Generiere dynamische Übersetzungen mit Ollama...")
            
            # Prüfe Ollama-Verbindung
            try:
                response = requests.get("http://localhost:11434/api/tags", timeout=5)
                if response.status_code != 200:
                    print("❌ Ollama ist nicht erreichbar. Verwende Englisch als Fallback.")
                    return False
            except Exception:
                print("❌ Ollama ist nicht erreichbar. Verwende Englisch als Fallback.")
                return False
            
            # Alle zu übersetzenden Strings
            all_strings = self._get_all_translatable_strings()
            
            # Generiere Übersetzungen
            translations = {}
            total_strings = len(all_strings)
            
            print(f"📝 Übersetze {total_strings} Strings ins {language_code}...")
            
            for i, string in enumerate(all_strings, 1):
                print(f"  [{i}/{total_strings}] Übersetze: {string}")
                
                # Erstelle Prompt basierend auf Sprachcode
                if language_code in ['fr', 'es', 'it', 'pt', 'ru', 'ja', 'ko', 'zh']:
                    # Bekannte Sprachen mit spezifischen Prompts
                    language_names = {
                        'fr': 'Französisch', 'es': 'Spanisch', 'it': 'Italienisch',
                        'pt': 'Portugiesisch', 'ru': 'Russisch', 'ja': 'Japanisch',
                        'ko': 'Koreanisch', 'zh': 'Chinesisch'
                    }
                    lang_name = language_names.get(language_code, language_code)
                    prompt = f"""Übersetze den folgenden deutschen Text ins {lang_name}.
Gib nur die Übersetzung zurück, ohne Erklärungen oder zusätzlichen Text.

Text: "{string}"

{lang_name} Übersetzung:"""
                else:
                    # Generischer Prompt für unbekannte Sprachen
                    prompt = f"""Translate the following German text to {language_code.upper()}.
Return only the translation, without explanations or additional text.

Text: "{string}"

{language_code.upper()} translation:"""
                
                translation = self._query_ollama(prompt)
                if translation:
                    # Bereinige die Antwort
                    translation = translation.strip().strip('"').strip("'")
                    translations[string] = translation
                else:
                    # Fallback: Verwende Original
                    translations[string] = string
            
            # Speichere dynamische Übersetzungen
            self.dynamic_translations[language_code] = {
                'translations': translations,
                'generated_at': datetime.now().isoformat(),
                'total_strings': total_strings
            }
            
            self._save_dynamic_translations()
            
            print(f"✅ Dynamische Übersetzungen für {language_code} erfolgreich generiert!")
            return True
            
        except Exception as e:
            print(f"❌ Fehler bei der Generierung dynamischer Übersetzungen: {e}")
            return False
    
    def _get_all_translatable_strings(self) -> list:
        """Gibt alle zu übersetzenden Strings zurück"""
        # Alle Strings aus den Fallback-Übersetzungen
        all_strings = set()
        
        # Aus deutschen Fallback-Übersetzungen
        fallback_de = self._get_fallback_translation_dict('de')
        all_strings.update(fallback_de.keys())
        
        # Aus englischen Fallback-Übersetzungen
        fallback_en = self._get_fallback_translation_dict('en')
        all_strings.update(fallback_en.keys())
        
        return sorted(list(all_strings))
    
    def _get_fallback_translation_dict(self, language: str) -> dict:
        """Gibt Fallback-Übersetzungen als Dictionary zurück"""
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
                'shortcut_report': 'Erstelle einen detaillierten Systembericht',
                'shortcut_k8s': 'Wie ist der Kubernetes-Cluster-Status?',
                'shortcut_k8s_problems': 'Welche Kubernetes-Probleme gibt es?',
                'shortcut_k8s_pods': 'Welche Pods laufen im Cluster?',
                'shortcut_k8s_nodes': 'Wie ist der Node-Status?',
                'shortcut_k8s_resources': 'Wie ist die Ressourcen-Auslastung im Cluster?',
                'shortcut_help': 'Zeige verfügbare Kürzelwörter',
                'shortcut_proxmox': 'Wie ist der Proxmox VE-Status?',
                'shortcut_proxmox_problems': 'Welche Proxmox-Probleme gibt es?',
                'shortcut_proxmox_vms': 'Welche VMs laufen auf Proxmox?',
                'shortcut_proxmox_containers': 'Welche Container laufen auf Proxmox?',
                'shortcut_proxmox_storage': 'Wie ist der Proxmox-Speicherplatz?',
                'error_permission_denied': 'Fehlende Rechte',
                'error_summary': 'Fehler-Zusammenfassung',
                'menu_available_shortcuts': 'Verfügbare Kürzelwörter:',
                'category_system': 'System',
                'category_kubernetes': 'Kubernetes',
                'category_proxmox': 'Proxmox',
                'menu_tip_free_questions': 'Tipp: Sie können auch freie Fragen stellen, z.B. "Was sind LXC Container?"',
                'intent_recognition_role': 'Du bist ein intelligenter Assistent, der Benutzereingaben zu verfügbaren Kürzelwörtern zuordnet.',
                'available_shortcuts': 'Verfügbare Kürzelwörter',
                'user_input': 'Benutzereingabe',
                'intent_recognition_instructions': 'Antworte NUR mit dem passenden Kürzelwort oder "none" wenn keine Übereinstimmung.',
                'intent_examples': 'Beispiele:\n- "LXC" -> "proxmox-containers"\n- "Container" -> "proxmox-containers"\n- "VMs" -> "proxmox-vms"\n- "Kubernetes" -> "k8s"\n- "Speicherplatz" -> "storage"\n- "Was ist das Wetter?" -> "none"',
                'response_format': 'Antwort:',
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
                'shortcut_report': 'Create a detailed system report',
                'shortcut_k8s': 'How is the Kubernetes cluster status?',
                'shortcut_k8s_problems': 'What Kubernetes problems are there?',
                'shortcut_k8s_pods': 'Which pods are running in the cluster?',
                'shortcut_k8s_nodes': 'How is the node status?',
                'shortcut_k8s_resources': 'How is the resource usage in the cluster?',
                'shortcut_help': 'Show available shortcuts',
                'shortcut_proxmox': 'How is the Proxmox VE status?',
                'shortcut_proxmox_problems': 'What Proxmox problems are there?',
                'shortcut_proxmox_vms': 'Which VMs are running on Proxmox?',
                'shortcut_proxmox_containers': 'Which containers are running on Proxmox?',
                'shortcut_proxmox_storage': 'How is the Proxmox storage space?',
                'error_permission_denied': 'Permission denied',
                'error_summary': 'Error Summary',
                'menu_available_shortcuts': 'Available shortcuts:',
                'category_system': 'System',
                'category_kubernetes': 'Kubernetes',
                'category_proxmox': 'Proxmox',
                'menu_tip_free_questions': 'Tip: You can also ask free questions, e.g. "What are LXC containers?"',
                'intent_recognition_role': 'You are an intelligent assistant that maps user inputs to available shortcuts.',
                'available_shortcuts': 'Available shortcuts',
                'user_input': 'User input',
                'intent_recognition_instructions': 'Answer ONLY with the matching shortcut or "none" if no match.',
                'intent_examples': 'Examples:\n- "LXC" -> "proxmox-containers"\n- "Container" -> "proxmox-containers"\n- "VMs" -> "proxmox-vms"\n- "Kubernetes" -> "k8s"\n- "Storage" -> "storage"\n- "What is the weather?" -> "none"',
                'response_format': 'Answer:',
                'ssh_connecting': 'Connecting via SSH...',
                'ssh_success': 'SSH connection successful',
                'ssh_failed': 'SSH connection failed',
                'ssh_timeout': 'SSH connection timeout',
                'ssh_error': 'SSH error',
                'analysis_running': 'Running automatic system analysis...',
                'analysis_summary': 'System Analysis:',
            }
        }
        
        return fallback_translations.get(language, {})
    
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
        # Prüfe geladene Fallback-Übersetzungen
        if hasattr(self, 'fallback_translations') and key in self.fallback_translations:
            return self.fallback_translations[key]
        
        # Prüfe zuerst dynamische Übersetzungen
        if self.current_language in self.dynamic_translations:
            dynamic_trans = self.dynamic_translations[self.current_language]['translations']
            if key in dynamic_trans:
                return dynamic_trans[key]
        
        # Fallback auf statische Übersetzungen
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
                'shortcut_report': 'Erstelle einen detaillierten Systembericht',
                'shortcut_k8s': 'Wie ist der Kubernetes-Cluster-Status?',
                'shortcut_k8s_problems': 'Welche Kubernetes-Probleme gibt es?',
                'shortcut_k8s_pods': 'Welche Pods laufen im Cluster?',
                'shortcut_k8s_nodes': 'Wie ist der Node-Status?',
                'shortcut_k8s_resources': 'Wie ist die Ressourcen-Auslastung im Cluster?',
                'shortcut_help': 'Zeige verfügbare Kürzelwörter',
                'error_permission_denied': 'Fehlende Rechte',
                'error_summary': 'Fehler-Zusammenfassung',
                'menu_available_shortcuts': 'Verfügbare Kürzelwörter:',
                'category_system': 'System',
                'category_kubernetes': 'Kubernetes',
                'category_proxmox': 'Proxmox',
                'menu_tip_free_questions': 'Tipp: Sie können auch freie Fragen stellen, z.B. "Was sind LXC Container?"',
                'intent_recognition_role': 'Du bist ein intelligenter Assistent, der Benutzereingaben zu verfügbaren Kürzelwörtern zuordnet.',
                'available_shortcuts': 'Verfügbare Kürzelwörter',
                'user_input': 'Benutzereingabe',
                'intent_recognition_instructions': 'Antworte NUR mit dem passenden Kürzelwort oder "none" wenn keine Übereinstimmung.',
                'intent_examples': 'Beispiele:\n- "LXC" -> "proxmox-containers"\n- "Container" -> "proxmox-containers"\n- "VMs" -> "proxmox-vms"\n- "Kubernetes" -> "k8s"\n- "Speicherplatz" -> "storage"\n- "Was ist das Wetter?" -> "none"',
                'response_format': 'Antwort:',
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
                'shortcut_report': 'Create a detailed system report',
                'shortcut_k8s': 'How is the Kubernetes cluster status?',
                'shortcut_k8s_problems': 'What Kubernetes problems are there?',
                'shortcut_k8s_pods': 'Which pods are running in the cluster?',
                'shortcut_k8s_nodes': 'How is the node status?',
                'shortcut_k8s_resources': 'How is the resource usage in the cluster?',
                'shortcut_help': 'Show available shortcuts',
                'shortcut_proxmox': 'How is the Proxmox VE status?',
                'shortcut_proxmox_problems': 'What Proxmox problems are there?',
                'shortcut_proxmox_vms': 'Which VMs are running on Proxmox?',
                'shortcut_proxmox_containers': 'Which containers are running on Proxmox?',
                'shortcut_proxmox_storage': 'How is the Proxmox storage space?',
                'error_permission_denied': 'Permission denied',
                'error_summary': 'Error Summary',
                'menu_available_shortcuts': 'Available shortcuts:',
                'category_system': 'System',
                'category_kubernetes': 'Kubernetes',
                'category_proxmox': 'Proxmox',
                'menu_tip_free_questions': 'Tip: You can also ask free questions, e.g. "What are LXC containers?"',
                'intent_recognition_role': 'You are an intelligent assistant that maps user inputs to available shortcuts.',
                'available_shortcuts': 'Available shortcuts',
                'user_input': 'User input',
                'intent_recognition_instructions': 'Answer ONLY with the matching shortcut or "none" if no match.',
                'intent_examples': 'Examples:\n- "LXC" -> "proxmox-containers"\n- "Container" -> "proxmox-containers"\n- "VMs" -> "proxmox-vms"\n- "Kubernetes" -> "k8s"\n- "Storage" -> "storage"\n- "What is the weather?" -> "none"',
                'response_format': 'Answer:',
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
        else:
            # Unbekannte Sprache - generiere dynamische Übersetzungen
            if language not in self.dynamic_translations:
                if self._generate_dynamic_translation(language):
                    self.current_language = language
                    self._setup_gettext()
                else:
                    print(f"⚠️  Konnte keine Übersetzungen für {language} generieren. Verwende Englisch.")
                    self.current_language = 'en'
                    self._setup_gettext()
            else:
                self.current_language = language
                self._setup_gettext()
    
    def get_supported_languages(self) -> list:
        """Gibt unterstützte Sprachen zurück"""
        supported = ['de', 'en']
        # Füge dynamisch generierte Sprachen hinzu
        supported.extend(list(self.dynamic_translations.keys()))
        return supported
    
    def initialize_dynamic_translation(self):
        """Initialisiert dynamische Übersetzungen für unbekannte Locales"""
        if self.current_language not in ['de', 'en']:
            if self.current_language not in self.dynamic_translations:
                print(f"\n🌍 Unknown locale detected: {self.current_language}")
                print("🤖 Generating dynamic translations with AI...")
                
                if self._generate_dynamic_translation(self.current_language):
                    print(f"✅ Dynamic translations for {self.current_language} successfully generated!")
                    print(f"🚀 Continuing in {self.current_language}...")
                else:
                    print("⚠️  Could not generate translations. Using English as fallback.")
                    self.current_language = 'en'
                    self._setup_gettext()

# Globale Instanz
i18n = I18n()

# Stelle sicher, dass die Übersetzungen geladen sind
try:
    # Teste ob Übersetzungen funktionieren
    test_translation = i18n.get('chat_title')
    if test_translation == 'chat_title':
        print("Warning: Translations not loaded, forcing reload...")
        i18n._load_fallback_translations()
except Exception as e:
    print(f"Warning: Could not initialize translations: {e}")

def _(key: str, **kwargs) -> str:
    """Kurze Funktion für Übersetzungen"""
    return i18n.get(key, **kwargs) 