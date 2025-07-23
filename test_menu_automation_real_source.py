#!/usr/bin/env python3
"""
Test für Menü-Automatisierung mit echten Sourcecode-Funktionen
Verwendet die originalen Funktionen aus ssh_chat_system.py
"""

import sys
import os
import time
import json
from typing import Dict, List, Optional, Tuple
import subprocess
import threading
from datetime import datetime

# Füge das Projektverzeichnis zum Python-Pfad hinzu
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importiere die echten Funktionen aus dem Sourcecode
from ssh_chat_system import (
    get_shortcuts,
    create_intelligent_menu,
    interpolate_user_input_to_shortcut,
    query_ollama,
    detect_and_correct_nonsense
)

class MenuAutomationTester:
    def __init__(self):
        self.test_results = []
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.start_time = None
        
    def log(self, message: str, level: str = "INFO"):
        """Logging mit Zeitstempel"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    def test_shortcuts_import(self) -> bool:
        """Test 1: Prüfe ob Shortcuts korrekt importiert werden können"""
        self.log("Test 1: Prüfe Shortcuts-Import...")
        try:
            shortcuts = get_shortcuts()
            if not shortcuts:
                self.log("FEHLER: Shortcuts sind leer", "ERROR")
                return False
                
            # Prüfe ob wichtige Shortcuts vorhanden sind
            required_shortcuts = ['services', 'storage', 'security', 'docker', 'proxmox']
            missing = [s for s in required_shortcuts if s not in shortcuts]
            if missing:
                self.log(f"FEHLER: Fehlende Shortcuts: {missing}", "ERROR")
                return False
                
            self.log(f"✓ Shortcuts erfolgreich importiert ({len(shortcuts)} Einträge)")
            return True
            
        except Exception as e:
            self.log(f"FEHLER beim Shortcuts-Import: {e}", "ERROR")
            return False
    
    def test_menu_creation(self) -> bool:
        """Test 2: Prüfe Menü-Erstellung mit echten Shortcuts"""
        self.log("Test 2: Prüfe Menü-Erstellung...")
        try:
            shortcuts = get_shortcuts()
            menu = create_intelligent_menu(shortcuts)
            
            if not menu:
                self.log("FEHLER: Menü ist leer", "ERROR")
                return False
                
            # Prüfe ob numerische Kürzel im Menü vorhanden sind
            if "s1" not in menu or "s2" not in menu:
                self.log("FEHLER: Numerische Kürzel fehlen im Menü", "ERROR")
                return False
                
            self.log("✓ Menü erfolgreich erstellt mit numerischen Kürzeln")
            return True
            
        except Exception as e:
            self.log(f"FEHLER bei Menü-Erstellung: {e}", "ERROR")
            return False
    
    def test_input_interpolation(self) -> bool:
        """Test 3: Prüfe Eingabe-Interpolation mit echten Shortcuts"""
        self.log("Test 3: Prüfe Eingabe-Interpolation...")
        try:
            shortcuts = get_shortcuts()
            
            # Teste verschiedene Eingabeformate
            test_cases = [
                ("s1", "services"),
                ("s2", "storage"), 
                ("s3", "security"),
                ("d1", "docker"),
                ("p1", "proxmox"),
                ("services", "services"),
                ("docker", "docker"),
                ("proxmox", "proxmox")
            ]
            
            for input_text, expected_shortcut in test_cases:
                result = interpolate_user_input_to_shortcut(input_text, shortcuts)
                if result != expected_shortcut:
                    self.log(f"FEHLER: '{input_text}' sollte '{expected_shortcut}' ergeben, aber war '{result}'", "ERROR")
                    return False
                    
            self.log("✓ Eingabe-Interpolation funktioniert korrekt")
            return True
            
        except Exception as e:
            self.log(f"FEHLER bei Eingabe-Interpolation: {e}", "ERROR")
            return False
    
    def test_ollama_connection(self) -> bool:
        """Test 4: Prüfe Ollama-Verbindung"""
        self.log("Test 4: Prüfe Ollama-Verbindung...")
        try:
            # Teste mit einem einfachen Prompt
            response = query_ollama("Hallo, antworte nur mit 'Test erfolgreich'", model="llama3.2")
            
            if not response:
                self.log("FEHLER: Keine Antwort von Ollama", "ERROR")
                return False
                
            if "Test erfolgreich" not in response:
                self.log(f"FEHLER: Unerwartete Antwort: {response[:100]}...", "ERROR")
                return False
                
            self.log("✓ Ollama-Verbindung funktioniert")
            return True
            
        except Exception as e:
            self.log(f"FEHLER bei Ollama-Verbindung: {e}", "ERROR")
            return False
    
    def test_nonsense_detection(self) -> bool:
        """Test 5: Prüfe Unsinn-Erkennung"""
        self.log("Test 5: Prüfe Unsinn-Erkennung...")
        try:
            # Teste mit Unsinn-Text, der in den Mustern definiert ist
            nonsense_text = "es gibt einen problem mit dem system"
            question = "Wie ist der Systemstatus?"
            system_info = {"hostname": "testhost", "distro_pretty_name": "Ubuntu 22.04"}
            
            corrected = detect_and_correct_nonsense(nonsense_text, question, system_info)
            
            # Die Korrektur sollte eine sinnvolle Antwort enthalten
            if not corrected or len(corrected) < 50:
                self.log("FEHLER: Unsinn-Erkennung funktioniert nicht", "ERROR")
                return False
                
            # Prüfe ob die Korrektur System-Informationen enthält
            if "testhost" not in corrected or "Ubuntu" not in corrected:
                self.log("FEHLER: Unsinn-Erkennung korrigiert nicht korrekt", "ERROR")
                return False
                
            self.log("✓ Unsinn-Erkennung funktioniert")
            return True
            
        except Exception as e:
            self.log(f"FEHLER bei Unsinn-Erkennung: {e}", "ERROR")
            return False
    
    def test_menu_automation_with_ollama(self) -> bool:
        """Test 6: Automatisierte Menü-Tests mit Ollama"""
        self.log("Test 6: Starte automatisierte Menü-Tests mit Ollama...")
        
        try:
            shortcuts = get_shortcuts()
            menu = create_intelligent_menu(shortcuts)
            
            # Wähle eine Auswahl von Shortcuts für Tests
            test_shortcuts = ['services', 'storage', 'docker', 'proxmox']
            total_shortcuts = len(test_shortcuts)
            
            for i, shortcut_key in enumerate(test_shortcuts, 1):
                self.log(f"  Test {i}/{total_shortcuts}: {shortcut_key}")
                
                if shortcut_key not in shortcuts:
                    self.log(f"    FEHLER: Shortcut '{shortcut_key}' nicht gefunden", "ERROR")
                    continue
                    
                shortcut = shortcuts[shortcut_key]
                question = shortcut['question']
                
                # Teste mit Ollama
                response = query_ollama(
                    f"Antworte kurz auf diese Frage: {question}",
                    model="llama3.2",
                    complex_analysis=shortcut['complex']
                )
                
                if not response:
                    self.log(f"    FEHLER: Keine Antwort für {shortcut_key}", "ERROR")
                    continue
                    
                # Prüfe Plausibilität
                if len(response) < 20:
                    self.log(f"    WARNUNG: Sehr kurze Antwort für {shortcut_key}", "WARN")
                    
                self.log(f"    ✓ {shortcut_key}: {len(response)} Zeichen")
                
                # Kurze Pause zwischen Tests
                time.sleep(1)
                
            self.log("✓ Automatisierte Menü-Tests abgeschlossen")
            return True
            
        except Exception as e:
            self.log(f"FEHLER bei automatisierten Tests: {e}", "ERROR")
            return False
    
    def run_all_tests(self):
        """Führe alle Tests aus"""
        self.start_time = time.time()
        self.log("=== STARTE MENÜ-AUTOMATISIERUNGSTESTS MIT ECHTEN SOURCECODE-FUNKTIONEN ===")
        
        tests = [
            ("Shortcuts-Import", self.test_shortcuts_import),
            ("Menü-Erstellung", self.test_menu_creation),
            ("Eingabe-Interpolation", self.test_input_interpolation),
            ("Ollama-Verbindung", self.test_ollama_connection),
            ("Unsinn-Erkennung", self.test_nonsense_detection),
            ("Automatisierte Menü-Tests", self.test_menu_automation_with_ollama)
        ]
        
        for test_name, test_func in tests:
            self.total_tests += 1
            self.log(f"\n--- Test {self.total_tests}: {test_name} ---")
            
            try:
                if test_func():
                    self.passed_tests += 1
                    self.log(f"✓ {test_name}: ERFOLGREICH")
                else:
                    self.failed_tests += 1
                    self.log(f"✗ {test_name}: FEHLGESCHLAGEN")
            except Exception as e:
                self.failed_tests += 1
                self.log(f"✗ {test_name}: EXCEPTION - {e}", "ERROR")
        
        self.print_summary()
    
    def print_summary(self):
        """Zeige Test-Zusammenfassung"""
        duration = time.time() - self.start_time
        
        self.log("\n" + "="*60)
        self.log("TEST-ZUSAMMENFASSUNG")
        self.log("="*60)
        self.log(f"Gesamte Tests: {self.total_tests}")
        self.log(f"Erfolgreich: {self.passed_tests}")
        self.log(f"Fehlgeschlagen: {self.failed_tests}")
        self.log(f"Erfolgsrate: {(self.passed_tests/self.total_tests)*100:.1f}%")
        self.log(f"Dauer: {duration:.1f} Sekunden")
        
        if self.failed_tests == 0:
            self.log("🎉 ALLE TESTS ERFOLGREICH!")
        else:
            self.log(f"⚠️  {self.failed_tests} Test(s) fehlgeschlagen")
        
        self.log("="*60)

def main():
    """Hauptfunktion"""
    tester = MenuAutomationTester()
    tester.run_all_tests()

if __name__ == "__main__":
    main() 