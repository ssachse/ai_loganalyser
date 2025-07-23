#!/usr/bin/env python3
"""
Spezialisierte Tests für Unsinn-Erkennung und automatische Korrektur
"""

import sys
import unittest
from typing import Dict, Any, List

class NonsenseDetector:
    """Erkennt und korrigiert Unsinn in Chat-Antworten"""
    
    def __init__(self):
        self.nonsense_patterns = [
            "es gibt einen problem",
            "sicherheitsrisiko low",
            "ssh-identification-string ungültig"
        ]
        
        self.context_mismatches = {
            "docker": ["netzwerk-sicherheitsanalyse", "ssh-service", "mailserver"],
            "mailserver": ["netzwerk-sicherheitsanalyse", "ssh-service", "docker"],
            "netzwerk": ["docker", "mailserver", "container"],
            "services": ["netzwerk-sicherheitsanalyse", "docker", "mailserver"]
        }
    
    def detect_nonsense(self, response: str, question: str) -> bool:
        """Erkennt Unsinn in Antworten"""
        response_lower = response.lower()
        question_lower = question.lower()
        
        # Prüfe Context-Mismatches
        for context, forbidden_terms in self.context_mismatches.items():
            if context in question_lower:
                for term in forbidden_terms:
                    if term in response_lower:
                        return True
        
        # Prüfe generische Unsinn-Indikatoren
        for pattern in self.nonsense_patterns:
            if pattern in response_lower:
                return True
        
        return False
    
    def correct_nonsense(self, response: str, question: str, system_info: Dict[str, Any]) -> str:
        """Korrigiert Unsinn-Antworten automatisch"""
        
        if not self.detect_nonsense(response, question):
            return response
        
        question_lower = question.lower()
        
        # Docker-Korrektur
        if "docker" in question_lower:
            return self._correct_docker_response(system_info)
        
        # Mailserver-Korrektur
        if "mailserver" in question_lower:
            return self._correct_mailserver_response(system_info)
        
        # Services-Korrektur
        if "services" in question_lower or "dienste" in question_lower:
            return self._correct_services_response(system_info)
        
        # Netzwerk-Korrektur
        if "netzwerk" in question_lower:
            return self._correct_network_response(system_info)
        
        # Generische Korrektur
        return self._correct_generic_response(question, system_info)
    
    def _correct_docker_response(self, system_info: Dict[str, Any]) -> str:
        """Korrigiert Docker-Antworten"""
        docker_status = "verfügbar" if system_info.get('docker_detected', False) else "nicht verfügbar"
        
        return f"""
Docker-Status-Analyse:

Basierend auf den System-Daten:
- Docker ist {docker_status}
- Verwende 'docker ps' um laufende Container zu sehen
- Verwende 'docker images' um verfügbare Images zu sehen
- Verwende 'docker system df' um Speicherplatz zu prüfen

Für detaillierte Informationen führen Sie bitte 'docker ps -a' aus.
"""
    
    def _correct_mailserver_response(self, system_info: Dict[str, Any]) -> str:
        """Korrigiert Mailserver-Antworten"""
        mailserver_status = "verfügbar" if system_info.get('mailserver_detected', False) else "nicht verfügbar"
        
        return f"""
Mailserver-Analyse:

Basierend auf den System-Daten:
- Mailserver sind {mailserver_status}
- Verwende 'systemctl status postfix' für Postfix-Status
- Verwende 'systemctl status dovecot' für Dovecot-Status
- Verwende 'netstat -tlnp | grep :25' für SMTP-Port

Für detaillierte Informationen prüfen Sie bitte die Mailserver-Logs.
"""
    
    def _correct_services_response(self, system_info: Dict[str, Any]) -> str:
        """Korrigiert Services-Antworten"""
        return f"""
System-Services-Analyse:

Basierend auf den System-Daten:
- Hostname: {system_info.get('hostname', 'unbekannt')}
- Distribution: {system_info.get('distro_pretty_name', 'unbekannt')}
- Kernel: {system_info.get('kernel_version', 'unbekannt')}

Verwende 'systemctl list-units --type=service --state=running' für laufende Services.
"""
    
    def _correct_network_response(self, system_info: Dict[str, Any]) -> str:
        """Korrigiert Netzwerk-Antworten"""
        return f"""
Netzwerk-Sicherheitsanalyse:

Basierend auf den System-Daten:
- Führe 'netstat -tlnp' für lauschende Ports aus
- Führe 'ss -tuln' für Socket-Status aus
- Führe 'iptables -L' für Firewall-Regeln aus

Für eine vollständige Netzwerk-Sicherheitsanalyse verwenden Sie den 'netzwerk' Shortcut.
"""
    
    def _correct_generic_response(self, question: str, system_info: Dict[str, Any]) -> str:
        """Generische Korrektur für unbekannte Fragen"""
        return f"""
System-Analyse:

Basierend auf den System-Daten:
- Hostname: {system_info.get('hostname', 'unbekannt')}
- Distribution: {system_info.get('distro_pretty_name', 'unbekannt')}

Für spezifische Informationen verwenden Sie bitte die verfügbaren Shortcuts.
"""

class TestNonsenseDetection(unittest.TestCase):
    """Tests für Unsinn-Erkennung und Korrektur"""
    
    def setUp(self):
        """Test-Setup"""
        self.detector = NonsenseDetector()
        self.mock_system_info = {
            'hostname': 'test-host',
            'distro_pretty_name': 'Ubuntu 22.04',
            'kernel_version': '5.15.0',
            'docker_detected': True,
            'mailserver_detected': True
        }
    
    def test_docker_nonsense_detection(self):
        """Test: Docker-Unsinn-Erkennung"""
        print("\n🔍 Test: Docker-Unsinn-Erkennung")
        
        # Gute Docker-Antwort
        good_response = """
        Docker-Status: Aktiv
        Laufende Container: 3
        - nginx: läuft seit 2 Tagen
        - mysql: läuft seit 1 Tag
        """
        
        # Schlechte Docker-Antwort (Unsinn)
        bad_response = """
        Es gibt einen Problem mit dem Netzwerk-Sicherheitsanalyse, insbesondere mit dem SSH-Service. 
        Der SSH-Service ist nicht sicher, da das Sicherheitsrisiko LOW ist.
        """
        
        self.assertFalse(self.detector.detect_nonsense(good_response, "docker"))
        self.assertTrue(self.detector.detect_nonsense(bad_response, "docker"))
        
        print("✅ Docker-Unsinn-Erkennung funktioniert")
    
    def test_mailserver_nonsense_detection(self):
        """Test: Mailserver-Unsinn-Erkennung"""
        print("\n🔍 Test: Mailserver-Unsinn-Erkennung")
        
        # Gute Mailserver-Antwort
        good_response = """
        Mailserver-Status:
        - Postfix: aktiv
        - Dovecot: aktiv
        - SMTP-Port 25: offen
        """
        
        # Schlechte Mailserver-Antwort (Unsinn)
        bad_response = """
        Es gibt einen Problem mit dem SSH-Service und Docker-Containern.
        Der SSH-Identification-String ist ungültig.
        """
        
        self.assertFalse(self.detector.detect_nonsense(good_response, "mailserver"))
        self.assertTrue(self.detector.detect_nonsense(bad_response, "mailserver"))
        
        print("✅ Mailserver-Unsinn-Erkennung funktioniert")
    
    def test_network_nonsense_detection(self):
        """Test: Netzwerk-Unsinn-Erkennung"""
        print("\n🔍 Test: Netzwerk-Unsinn-Erkennung")
        
        # Gute Netzwerk-Antwort
        good_response = """
        Netzwerk-Sicherheitsanalyse:
        - SSH-Port 22: offen
        - HTTP-Port 80: offen
        - Firewall: aktiv
        """
        
        # Schlechte Netzwerk-Antwort (Unsinn)
        bad_response = """
        Docker-Container laufen und Mailserver sind aktiv.
        Es gibt einen Problem mit dem Container-System.
        """
        
        self.assertFalse(self.detector.detect_nonsense(good_response, "netzwerk"))
        self.assertTrue(self.detector.detect_nonsense(bad_response, "netzwerk"))
        
        print("✅ Netzwerk-Unsinn-Erkennung funktioniert")
    
    def test_automated_correction(self):
        """Test: Automatische Korrektur"""
        print("\n🔍 Test: Automatische Korrektur")
        
        # Test Docker-Korrektur
        nonsense_docker = "Es gibt einen Problem mit dem Netzwerk-Sicherheitsanalyse..."
        corrected_docker = self.detector.correct_nonsense(nonsense_docker, "docker", self.mock_system_info)
        
        self.assertIn("Docker-Status-Analyse", corrected_docker)
        self.assertIn("verfügbar", corrected_docker)
        self.assertNotIn("Netzwerk-Sicherheitsanalyse", corrected_docker)
        
        # Test Mailserver-Korrektur
        nonsense_mailserver = "Es gibt einen Problem mit dem SSH-Service..."
        corrected_mailserver = self.detector.correct_nonsense(nonsense_mailserver, "mailserver", self.mock_system_info)
        
        self.assertIn("Mailserver-Analyse", corrected_mailserver)
        self.assertIn("verfügbar", corrected_mailserver)
        self.assertNotIn("SSH-Service", corrected_mailserver)
        
        print("✅ Automatische Korrektur funktioniert")
    
    def test_context_aware_correction(self):
        """Test: Context-bewusste Korrektur"""
        print("\n🔍 Test: Context-bewusste Korrektur")
        
        # Test mit verschiedenen System-Konfigurationen
        system_no_docker = self.mock_system_info.copy()
        system_no_docker['docker_detected'] = False
        
        corrected_no_docker = self.detector.correct_nonsense("Es gibt einen Problem mit dem Netzwerk-Sicherheitsanalyse", "docker", system_no_docker)
        self.assertIn("nicht verfügbar", corrected_no_docker)
        
        corrected_with_docker = self.detector.correct_nonsense("Es gibt einen Problem mit dem SSH-Service", "docker", self.mock_system_info)
        self.assertIn("verfügbar", corrected_with_docker)
        
        print("✅ Context-bewusste Korrektur funktioniert")
    
    def test_edge_cases(self):
        """Test: Edge Cases"""
        print("\n🔍 Test: Edge Cases")
        
        # Leere Antwort
        self.assertFalse(self.detector.detect_nonsense("", "docker"))
        
        # Antwort ohne Unsinn
        normal_response = "Das ist eine normale Antwort ohne Unsinn."
        self.assertFalse(self.detector.detect_nonsense(normal_response, "docker"))
        
        # Unbekannte Frage
        corrected_unknown = self.detector.correct_nonsense("Es gibt einen Problem mit dem SSH-Service", "unbekannte_frage", self.mock_system_info)
        self.assertIn("System-Analyse", corrected_unknown)
        
        print("✅ Edge Cases funktionieren")

def run_nonsense_tests():
    """Führt alle Unsinn-Erkennung-Tests aus"""
    print("🚀 Starte Unsinn-Erkennung Tests...")
    print("=" * 60)
    
    # Erstelle Test-Suite
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestNonsenseDetection)
    
    # Führe Tests aus
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Test-Ergebnisse
    print("\n" + "=" * 60)
    print("📊 Unsinn-Erkennung Test-Ergebnisse:")
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
        print("\n✅ Alle Unsinn-Erkennung Tests erfolgreich!")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_nonsense_tests()
    sys.exit(0 if success else 1) 