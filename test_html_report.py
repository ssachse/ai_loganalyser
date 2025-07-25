#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test für HTML-Report-Feature
"""

import sys
import os

# Füge das aktuelle Verzeichnis zum Python-Pfad hinzu
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ssh_chat_system import create_html_report, save_html_report

def test_html_report():
    """Testet die HTML-Report-Generierung"""
    
    # Mock-System-Info für Tests
    system_info = {
        'hostname': 'test-server',
        'distro_pretty_name': 'Ubuntu 22.04.5 LTS',
        'distro_name': 'Ubuntu',
        'cpu_usage_percent': '12.5%',
        'memory_usage_percent': '67.8%',
        'load_average_1min': '2.34',
        'uptime': 'up 15 days, 2:34',
        'kernel_version': '5.15.0-139-generic'
    }
    
    # Mock-Log-Entries
    log_entries = []
    
    # Mock-Anomalies
    anomalies = []
    
    # Mock-CVE-Info
    cve_info = {
        'database_summary': {
            'total_services': 1,
            'total_cves': 0,
            'critical_cves': 0,
            'high_cves': 0,
            'overall_risk': 'Low'
        }
    }
    
    print("🔍 Teste HTML-Report-Generierung...")
    
    try:
        # Erstelle HTML-Report
        html_content = create_html_report(system_info, log_entries, anomalies, cve_info)
        
        if html_content:
            print("✅ HTML-Content erfolgreich generiert")
            
            # Speichere HTML-Report
            html_filename = save_html_report(html_content, system_info)
            
            if html_filename and os.path.exists(html_filename):
                print(f"✅ HTML-Report erfolgreich gespeichert: {html_filename}")
                
                # Zeige Dateigröße
                file_size = os.path.getsize(html_filename)
                print(f"📊 Dateigröße: {file_size} Bytes")
                
                # Prüfe HTML-Content
                if '<html' in html_content and '</html>' in html_content:
                    print("✅ HTML-Struktur ist korrekt")
                else:
                    print("❌ HTML-Struktur ist fehlerhaft")
                
                # Öffne im Browser
                try:
                    import webbrowser
                    webbrowser.open(f'file://{os.path.abspath(html_filename)}')
                    print("🌐 HTML-Report wurde im Browser geöffnet")
                except Exception as e:
                    print(f"⚠️ Konnte HTML-Report nicht automatisch öffnen: {e}")
                    print(f"📁 Öffne manuell: {os.path.abspath(html_filename)}")
                
                return True
            else:
                print("❌ Fehler beim Speichern des HTML-Reports")
                return False
        else:
            print("❌ HTML-Content konnte nicht generiert werden")
            return False
            
    except Exception as e:
        print(f"❌ Fehler bei HTML-Report-Test: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

if __name__ == "__main__":
    print("🚀 Starte HTML-Report-Test...")
    success = test_html_report()
    
    if success:
        print("\n✅ HTML-Report-Test erfolgreich!")
        sys.exit(0)
    else:
        print("\n❌ HTML-Report-Test fehlgeschlagen!")
        sys.exit(1) 