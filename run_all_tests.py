#!/usr/bin/env python3
"""
Umfassender Test-Runner für alle automatisierten Tests
Führt alle Tests aus und erstellt einen detaillierten Bericht
"""

import sys
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Tuple

class TestRunner:
    """Führt alle Tests aus und erstellt Berichte"""
    
    def __init__(self):
        self.test_modules = [
            "test_chat_system_automated.py",
            "test_nonsense_detection.py"
        ]
        
        self.results = {}
        self.start_time = None
        self.end_time = None
    
    def run_all_tests(self) -> bool:
        """Führt alle Tests aus"""
        print("🚀 Starte umfassende Test-Suite...")
        print("=" * 80)
        
        self.start_time = time.time()
        all_successful = True
        
        for module in self.test_modules:
            print(f"\n📋 Führe Tests aus: {module}")
            print("-" * 50)
            
            try:
                result = subprocess.run(
                    [sys.executable, module],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                success = result.returncode == 0
                self.results[module] = {
                    'success': success,
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
                
                if success:
                    print(f"✅ {module}: Erfolgreich")
                else:
                    print(f"❌ {module}: Fehlgeschlagen")
                    all_successful = False
                
            except subprocess.TimeoutExpired:
                print(f"⏰ {module}: Timeout")
                self.results[module] = {
                    'success': False,
                    'returncode': -1,
                    'stdout': '',
                    'stderr': 'Timeout nach 60 Sekunden'
                }
                all_successful = False
                
            except Exception as e:
                print(f"💥 {module}: Fehler - {e}")
                self.results[module] = {
                    'success': False,
                    'returncode': -1,
                    'stdout': '',
                    'stderr': str(e)
                }
                all_successful = False
        
        self.end_time = time.time()
        return all_successful
    
    def generate_report(self) -> str:
        """Erstellt einen detaillierten Test-Bericht"""
        duration = self.end_time - self.start_time if self.start_time and self.end_time else 0
        
        report = f"""
{'='*80}
📊 AUTOMATISIERTE TEST-BERICHT
{'='*80}
Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Dauer: {duration:.2f} Sekunden
Gesamt-Status: {'✅ ERFOLGREICH' if all(r['success'] for r in self.results.values()) else '❌ FEHLGESCHLAGEN'}

{'='*80}
📋 TEST-ERGEBNISSE IM DETAIL:
{'='*80}
"""
        
        for module, result in self.results.items():
            status = "✅ ERFOLGREICH" if result['success'] else "❌ FEHLGESCHLAGEN"
            report += f"""
📁 {module}
Status: {status}
Return Code: {result['returncode']}

📤 STDOUT:
{result['stdout']}

📥 STDERR:
{result['stderr']}
{'-'*80}
"""
        
        # Zusammenfassung
        successful_tests = sum(1 for r in self.results.values() if r['success'])
        total_tests = len(self.results)
        
        report += f"""
{'='*80}
📈 ZUSAMMENFASSUNG:
{'='*80}
Tests erfolgreich: {successful_tests}/{total_tests}
Erfolgsrate: {(successful_tests/total_tests)*100:.1f}%

"""
        
        if successful_tests == total_tests:
            report += """
🎉 ALLE TESTS ERFOLGREICH!

Das System funktioniert korrekt:
✅ Chat-System-Automatisierung
✅ Unsinn-Erkennung und Korrektur
✅ Context-Filtering
✅ Shortcut-Interpolation
✅ Prompt-Generierung
✅ Menü-Generierung
✅ Integrationstests

Das System ist bereit für den produktiven Einsatz!
"""
        else:
            report += """
⚠️  EINIGE TESTS FEHLGESCHLAGEN!

Bitte überprüfen Sie die Fehler und korrigieren Sie die Probleme.
"""
        
        return report
    
    def save_report(self, filename: str = None) -> str:
        """Speichert den Test-Bericht in eine Datei"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"test_report_{timestamp}.txt"
        
        report = self.generate_report()
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        return filename

def main():
    """Hauptfunktion"""
    runner = TestRunner()
    
    # Führe alle Tests aus
    success = runner.run_all_tests()
    
    # Erstelle Bericht
    report = runner.generate_report()
    print(report)
    
    # Speichere Bericht
    filename = runner.save_report()
    print(f"\n📄 Test-Bericht gespeichert: {filename}")
    
    # Exit-Code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 