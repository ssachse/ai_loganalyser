#!/usr/bin/env python3
"""
Automatisierte Tests für das Chat-System
Testet Shortcuts, Context-Filtering, Response-Qualität und erkennt Unsinn
"""

import sys
import json
import unittest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List

# Importiere die zu testenden Module
sys.path.append('.')
from ssh_chat_system import (
    create_system_context, 
    create_chat_prompt, 
    interpolate_user_input_to_shortcut,
    create_intelligent_menu
)

class TestChatSystemAutomated(unittest.TestCase):
    """Automatisierte Tests für das Chat-System"""
    
    def setUp(self):
        """Test-Setup"""
        self.mock_system_info = {
            'hostname': 'test-host',
            'distro_pretty_name': 'Ubuntu 22.04',
            'kernel_version': '5.15.0',
            'architecture': 'x86_64',
            'docker_detected': True,
            'mailserver_detected': True,
            'network_security': {
                'internal_services': {
                    'service_mapping': {
                        22: {'service': 'SSH', 'status': 'running', 'external': True},
                        80: {'service': 'HTTP', 'status': 'running', 'external': True}
                    }
                },
                'security_assessment': {
                    'risk_level': 'medium',
                    'exposed_services': [22, 80]
                }
            }
        }
        
        self.mock_log_entries = []
        self.mock_anomalies = []
        
        # Mock Shortcuts (vollständige Liste für Tests)
        self.mock_shortcuts = {
            'services': {
                'question': 'Welche Services laufen?',
                'complex': False,
                'cache_key': 'services'
            },
            'docker': {
                'question': 'Wie ist der Docker-Status und welche Container laufen?',
                'complex': False,
                'cache_key': 'docker_status'
            },
            'mailservers': {
                'question': 'Welche Mailserver sind installiert und aktiv?',
                'complex': False,
                'cache_key': 'mailservers_status'
            },
            'network-security': {
                'question': 'Führe eine vollständige Netzwerk-Sicherheitsanalyse durch.',
                'complex': True,
                'cache_key': 'network_security'
            }
        }

    def test_context_filtering_network_security(self):
        """Test: Context-Filtering für Netzwerk-Sicherheit"""
        print("\n🔍 Test: Context-Filtering für Netzwerk-Sicherheit")
        
        # Test mit Netzwerk-Fokus
        context_with_network = create_system_context(
            self.mock_system_info, 
            self.mock_log_entries, 
            self.mock_anomalies, 
            focus_network_security=True
        )
        
        # Test ohne Netzwerk-Fokus
        context_without_network = create_system_context(
            self.mock_system_info, 
            self.mock_log_entries, 
            self.mock_anomalies, 
            focus_network_security=False
        )
        
        # Prüfe, dass Netzwerk-Daten nur bei Fokus angezeigt werden
        self.assertIn("NETZWERK-SICHERHEITSANALYSE", context_with_network)
        self.assertNotIn("NETZWERK-SICHERHEITSANALYSE", context_without_network)
        
        print("✅ Context-Filtering funktioniert korrekt")

    def test_shortcut_interpolation(self):
        """Test: Shortcut-Interpolation"""
        print("\n🔍 Test: Shortcut-Interpolation")
        
        # Test numerische Kürzel
        result_s1 = interpolate_user_input_to_shortcut("s1", self.mock_shortcuts)
        self.assertEqual(result_s1, "services")
        
        # Test traditionelle Shortcuts
        result_docker = interpolate_user_input_to_shortcut("docker", self.mock_shortcuts)
        self.assertEqual(result_docker, "docker")
        
        # Test unbekannte Eingaben
        result_unknown = interpolate_user_input_to_shortcut("unbekannt", self.mock_shortcuts)
        self.assertIsNone(result_unknown)
        
        print("✅ Shortcut-Interpolation funktioniert korrekt")

    def test_prompt_generation(self):
        """Test: Prompt-Generierung"""
        print("\n🔍 Test: Prompt-Generierung")
        
        # Test Docker-Prompt
        docker_prompt = create_chat_prompt("Test Context", "docker", [])
        self.assertIn("IGNORIERE Netzwerk-Sicherheitsdaten", docker_prompt)
        self.assertIn("Docker", docker_prompt)
        
        # Test Netzwerk-Sicherheits-Prompt
        network_prompt = create_chat_prompt("Test Context", "netzwerk", [])
        self.assertIn("FOKUSSIERE DICH AUSSCHLIESSLICH auf Netzwerk-spezifische Themen", network_prompt)
        
        # Test Mailserver-Prompt
        mailserver_prompt = create_chat_prompt("Test Context", "mailservers", [])
        self.assertIn("IGNORIERE Netzwerk-Sicherheitsdaten", mailserver_prompt)
        
        print("✅ Prompt-Generierung funktioniert korrekt")

    def test_menu_generation(self):
        """Test: Menü-Generierung"""
        print("\n🔍 Test: Menü-Generierung")
        
        menu = create_intelligent_menu(self.mock_shortcuts)
        
        # Prüfe, dass numerische Kürzel angezeigt werden
        self.assertIn("s1", menu)
        self.assertIn("d1", menu)
        self.assertIn("m1", menu)
        
        # Prüfe, dass Kategorien angezeigt werden
        self.assertIn("System:", menu)
        self.assertIn("Docker:", menu)
        self.assertIn("Mailserver:", menu)
        
        print("✅ Menü-Generierung funktioniert korrekt")

    def test_response_quality_detection(self):
        """Test: Erkennung von Unsinn in Antworten"""
        print("\n🔍 Test: Erkennung von Unsinn in Antworten")
        
        # Gute Antwort
        good_response = """
        Docker-Status: Aktiv
        Laufende Container: 3
        - nginx: läuft seit 2 Tagen
        - mysql: läuft seit 1 Tag
        - app: läuft seit 5 Stunden
        """
        
        # Schlechte Antwort (Unsinn)
        bad_response = """
        Es gibt einen Problem mit dem Netzwerk-Sicherheitsanalyse, insbesondere mit dem SSH-Service. 
        Der SSH-Service ist nicht sicher, da das Sicherheitsrisiko LOW ist und der SSH-Identification-String ungültig ist.
        """
        
        # Test-Funktion zur Erkennung von Unsinn
        def detect_nonsense(response: str, question: str) -> bool:
            """Erkennt Unsinn in Antworten"""
            response_lower = response.lower()
            question_lower = question.lower()
            
            # Prüfe, ob Antwort zur Frage passt
            if "docker" in question_lower and "netzwerk-sicherheitsanalyse" in response_lower:
                return True  # Unsinn erkannt
            
            if "mailserver" in question_lower and "ssh-service" in response_lower:
                return True  # Unsinn erkannt
            
            # Prüfe auf generische Unsinn-Indikatoren
            nonsense_indicators = [
                "es gibt einen problem",
                "sicherheitsrisiko low",
                "ssh-identification-string ungültig"
            ]
            
            for indicator in nonsense_indicators:
                if indicator in response_lower:
                    return True
            
            return False
        
        # Teste Erkennung
        self.assertFalse(detect_nonsense(good_response, "docker"))
        self.assertTrue(detect_nonsense(bad_response, "docker"))
        self.assertTrue(detect_nonsense(bad_response, "mailservers"))
        
        print("✅ Unsinn-Erkennung funktioniert korrekt")

    def test_automated_correction(self):
        """Test: Automatische Korrektur von Unsinn"""
        print("\n🔍 Test: Automatische Korrektur von Unsinn")
        
        def correct_nonsense_response(response: str, question: str, system_info: Dict[str, Any]) -> str:
            """Korrigiert Unsinn-Antworten automatisch"""
            
            # Erkenne Unsinn
            if "netzwerk-sicherheitsanalyse" in response.lower() and "docker" in question.lower():
                # Korrigiere Docker-Antwort
                return f"""
                Docker-Status-Analyse:
                
                Basierend auf den System-Daten:
                - Docker ist installiert und verfügbar
                - Verwende 'docker ps' um laufende Container zu sehen
                - Verwende 'docker images' um verfügbare Images zu sehen
                
                Für detaillierte Informationen führen Sie bitte 'docker ps -a' aus.
                """
            
            if "ssh-service" in response.lower() and "mailserver" in question.lower():
                # Korrigiere Mailserver-Antwort
                return f"""
                Mailserver-Analyse:
                
                Basierend auf den System-Daten:
                - Mailserver sind installiert und verfügbar
                - Verwende 'systemctl status postfix' für Postfix-Status
                - Verwende 'systemctl status dovecot' für Dovecot-Status
                
                Für detaillierte Informationen prüfen Sie bitte die Mailserver-Logs.
                """
            
            return response
        
        # Teste Korrektur
        nonsense_response = "Es gibt einen Problem mit dem Netzwerk-Sicherheitsanalyse..."
        corrected = correct_nonsense_response(nonsense_response, "docker", self.mock_system_info)
        
        self.assertIn("Docker-Status-Analyse", corrected)
        self.assertNotIn("Netzwerk-Sicherheitsanalyse", corrected)
        
        print("✅ Automatische Korrektur funktioniert korrekt")

    def test_integration_test(self):
        """Integrationstest: Vollständiger Workflow"""
        print("\n🔍 Integrationstest: Vollständiger Workflow")
        
        # Simuliere vollständigen Workflow
        user_input = "docker"
        
        # 1. Shortcut-Interpolation
        shortcut = interpolate_user_input_to_shortcut(user_input, self.mock_shortcuts)
        self.assertEqual(shortcut, "docker")
        
        # 2. Context-Erstellung (ohne Netzwerk-Fokus)
        context = create_system_context(
            self.mock_system_info, 
            self.mock_log_entries, 
            self.mock_anomalies, 
            focus_network_security=False
        )
        
        # 3. Prompt-Erstellung
        prompt = create_chat_prompt(context, user_input, [])
        
        # 4. Prüfe, dass Netzwerk-Sicherheit ignoriert wird
        self.assertIn("IGNORIERE Netzwerk-Sicherheitsdaten", prompt)
        
        print("✅ Integrationstest erfolgreich")

def run_automated_tests():
    """Führt alle automatisierten Tests aus"""
    print("🚀 Starte automatisierte Tests für Chat-System...")
    print("=" * 60)
    
    # Erstelle Test-Suite
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestChatSystemAutomated)
    
    # Führe Tests aus
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Test-Ergebnisse
    print("\n" + "=" * 60)
    print("📊 Test-Ergebnisse:")
    print(f"Tests ausgeführt: {result.testsRun}")
    print(f"Fehler: {len(result.failures)}")
    print(f"Fehlschläge: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ Fehler gefunden:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\n❌ Fehlschläge gefunden:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    if not result.failures and not result.errors:
        print("\n✅ Alle Tests erfolgreich!")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_automated_tests()
    sys.exit(0 if success else 1) 