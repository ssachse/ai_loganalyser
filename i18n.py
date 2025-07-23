#!/usr/bin/env python3
"""
Internationalisierung für den AI Log-Analyzer
Unterstützt Deutsch und Englisch mit automatischer Spracherkennung
"""

import os
import locale
from typing import Dict, Any

class I18n:
    """Internationalisierungsklasse für mehrsprachige Unterstützung"""
    
    def __init__(self):
        self.current_language = self._detect_language()
        self.translations = self._load_translations()
    
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
    
    def _load_translations(self) -> Dict[str, Dict[str, str]]:
        """Lädt alle Übersetzungen"""
        return {
            'de': {
                # Allgemeine UI
                'loading': 'Lade...',
                'error': 'Fehler',
                'success': 'Erfolgreich',
                'warning': 'Warnung',
                'info': 'Information',
                'yes': 'Ja',
                'no': 'Nein',
                'cancel': 'Abbrechen',
                'continue': 'Fortfahren',
                'back': 'Zurück',
                'next': 'Weiter',
                'finish': 'Beenden',
                
                # SSH-Verbindung
                'ssh_connecting': 'Verbinde mit SSH...',
                'ssh_success': 'SSH-Verbindung erfolgreich',
                'ssh_failed': 'SSH-Verbindung fehlgeschlagen',
                'ssh_timeout': 'SSH-Verbindung Timeout',
                'ssh_error': 'SSH-Fehler',
                
                # System-Analyse
                'system_analysis': 'System-Analyse',
                'system_info': 'System-Informationen',
                'storage_analysis': 'Speicherplatz-Analyse',
                'service_analysis': 'Service-Analyse',
                'security_analysis': 'Sicherheits-Analyse',
                'performance_analysis': 'Performance-Analyse',
                'kubernetes_analysis': 'Kubernetes-Analyse',
                
                # Kubernetes
                'kubernetes_detected': 'Kubernetes erkannt',
                'kubernetes_not_detected': 'Kubernetes nicht erkannt',
                'cluster_info': 'Cluster-Informationen',
                'nodes': 'Nodes',
                'pods': 'Pods',
                'services': 'Services',
                'deployments': 'Deployments',
                'problems_found': 'Probleme gefunden',
                'no_problems': 'Keine Probleme gefunden',
                
                # Chat
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
                
                # Kürzelwörter
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
                
                # Fehler
                'error_permission_denied': 'Fehlende Rechte',
                'error_file_not_found': 'Datei nicht gefunden',
                'error_command_not_found': 'Befehl nicht gefunden',
                'error_kubectl': 'Kubectl-Fehler',
                'error_other': 'Andere Fehler',
                'error_summary': 'Fehler-Zusammenfassung',
                'error_tip_permissions': 'Verwenden Sie einen Benutzer mit erweiterten Rechten für vollständige Analyse.',
                'error_affected_areas': 'Betroffene Bereiche:',
                
                # System-Informationen
                'hostname': 'Hostname',
                'distribution': 'Distribution',
                'kernel': 'Kernel',
                'cpu': 'CPU',
                'ram': 'RAM',
                'uptime': 'Uptime',
                'disk_usage': 'Festplatten-Auslastung',
                'memory_usage': 'Speicher-Auslastung',
                'load_average': 'Durchschnittslast',
                
                # Log-Sammlung
                'collecting_logs': 'Sammle Logs...',
                'logs_collected': 'Logs gesammelt',
                'creating_archive': 'Erstelle Archiv...',
                'archive_created': 'Archiv erstellt',
                'cleaning_up': 'Räume auf...',
                'cleanup_complete': 'Aufräumen abgeschlossen',
                
                # Ollama
                'ollama_connecting': 'Verbinde mit Ollama...',
                'ollama_connected': 'Ollama verbunden',
                'ollama_error': 'Ollama-Fehler',
                'ollama_no_models': 'Keine Ollama-Modelle gefunden',
                'ollama_model_selected': 'Modell ausgewählt:',
                
                # Menü
                'menu_available_shortcuts': 'Verfügbare Kürzelwörter:',
                'menu_quit_commands': 'exit, quit, q, bye, beenden',
                'menu_help_commands': 'help oder m',
                
                # Analyse
                'analysis_running': 'Führe automatische System-Analyse durch...',
                'analysis_complete': 'System-Analyse abgeschlossen',
                'analysis_summary': 'System-Analyse:',
                
                # Status
                'status_ready': 'Bereit',
                'status_running': 'Läuft',
                'status_stopped': 'Gestoppt',
                'status_error': 'Fehler',
                'status_warning': 'Warnung',
                'status_ok': 'OK',
                'status_critical': 'Kritisch',
                
                # Netzwerk
                'network_connection': 'Netzwerkverbindung',
                'network_error': 'Netzwerkfehler',
                'network_timeout': 'Netzwerk-Timeout',
                
                # Empfehlungen
                'recommendations': 'Empfehlungen',
                'recommendation_security': 'Sicherheitsempfehlung',
                'recommendation_performance': 'Performance-Empfehlung',
                'recommendation_maintenance': 'Wartungsempfehlung',
                
                # Version
                'version_info': 'Versions-Informationen',
                'kubernetes_version': 'Kubernetes-Version',
                'cluster_config': 'Cluster-Konfiguration',
            },
            
            'en': {
                # General UI
                'loading': 'Loading...',
                'error': 'Error',
                'success': 'Success',
                'warning': 'Warning',
                'info': 'Information',
                'yes': 'Yes',
                'no': 'No',
                'cancel': 'Cancel',
                'continue': 'Continue',
                'back': 'Back',
                'next': 'Next',
                'finish': 'Finish',
                
                # SSH Connection
                'ssh_connecting': 'Connecting via SSH...',
                'ssh_success': 'SSH connection successful',
                'ssh_failed': 'SSH connection failed',
                'ssh_timeout': 'SSH connection timeout',
                'ssh_error': 'SSH error',
                
                # System Analysis
                'system_analysis': 'System Analysis',
                'system_info': 'System Information',
                'storage_analysis': 'Storage Analysis',
                'service_analysis': 'Service Analysis',
                'security_analysis': 'Security Analysis',
                'performance_analysis': 'Performance Analysis',
                'kubernetes_analysis': 'Kubernetes Analysis',
                
                # Kubernetes
                'kubernetes_detected': 'Kubernetes detected',
                'kubernetes_not_detected': 'Kubernetes not detected',
                'cluster_info': 'Cluster Information',
                'nodes': 'Nodes',
                'pods': 'Pods',
                'services': 'Services',
                'deployments': 'Deployments',
                'problems_found': 'problems found',
                'no_problems': 'No problems found',
                
                # Chat
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
                
                # Shortcuts
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
                
                # Errors
                'error_permission_denied': 'Permission denied',
                'error_file_not_found': 'File not found',
                'error_command_not_found': 'Command not found',
                'error_kubectl': 'Kubectl errors',
                'error_other': 'Other errors',
                'error_summary': 'Error Summary',
                'error_tip_permissions': 'Use a user with extended permissions for complete analysis.',
                'error_affected_areas': 'Affected areas:',
                
                # System Information
                'hostname': 'Hostname',
                'distribution': 'Distribution',
                'kernel': 'Kernel',
                'cpu': 'CPU',
                'ram': 'RAM',
                'uptime': 'Uptime',
                'disk_usage': 'Disk Usage',
                'memory_usage': 'Memory Usage',
                'load_average': 'Load Average',
                
                # Log Collection
                'collecting_logs': 'Collecting logs...',
                'logs_collected': 'Logs collected',
                'creating_archive': 'Creating archive...',
                'archive_created': 'Archive created',
                'cleaning_up': 'Cleaning up...',
                'cleanup_complete': 'Cleanup complete',
                
                # Ollama
                'ollama_connecting': 'Connecting to Ollama...',
                'ollama_connected': 'Ollama connected',
                'ollama_error': 'Ollama error',
                'ollama_no_models': 'No Ollama models found',
                'ollama_model_selected': 'Model selected:',
                
                # Menu
                'menu_available_shortcuts': 'Available shortcuts:',
                'menu_quit_commands': 'exit, quit, q, bye, beenden',
                'menu_help_commands': 'help or m',
                
                # Analysis
                'analysis_running': 'Running automatic system analysis...',
                'analysis_complete': 'System analysis complete',
                'analysis_summary': 'System Analysis:',
                
                # Status
                'status_ready': 'Ready',
                'status_running': 'Running',
                'status_stopped': 'Stopped',
                'status_error': 'Error',
                'status_warning': 'Warning',
                'status_ok': 'OK',
                'status_critical': 'Critical',
                
                # Network
                'network_connection': 'Network connection',
                'network_error': 'Network error',
                'network_timeout': 'Network timeout',
                
                # Recommendations
                'recommendations': 'Recommendations',
                'recommendation_security': 'Security recommendation',
                'recommendation_performance': 'Performance recommendation',
                'recommendation_maintenance': 'Maintenance recommendation',
                
                # Version
                'version_info': 'Version Information',
                'kubernetes_version': 'Kubernetes Version',
                'cluster_config': 'Cluster Configuration',
            }
        }
    
    def get(self, key: str, **kwargs) -> str:
        """Holt eine Übersetzung für den gegebenen Schlüssel"""
        try:
            translation = self.translations[self.current_language].get(key, key)
            if kwargs:
                return translation.format(**kwargs)
            return translation
        except Exception:
            return key
    
    def get_language(self) -> str:
        """Gibt die aktuelle Sprache zurück"""
        return self.current_language
    
    def set_language(self, language: str):
        """Setzt die Sprache manuell"""
        if language in self.translations:
            self.current_language = language
    
    def get_supported_languages(self) -> list:
        """Gibt unterstützte Sprachen zurück"""
        return list(self.translations.keys())

# Globale Instanz
i18n = I18n()

def _(key: str, **kwargs) -> str:
    """Kurze Funktion für Übersetzungen"""
    return i18n.get(key, **kwargs) 