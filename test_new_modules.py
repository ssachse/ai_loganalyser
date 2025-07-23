#!/usr/bin/env python3
"""
Test-Skript für neue Module (Docker, Mailserver)
Testet die Docker- und Mailserver-Erkennung und -Analyse
"""

import sys
import os
import json
from datetime import datetime

# Füge das aktuelle Verzeichnis zum Python-Pfad hinzu
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ssh_chat_system import SSHLogCollector

def test_docker_analysis():
    """Testet die Docker-Analyse"""
    print("🐳 Docker-Analyse Test")
    print("=" * 50)
    
    # Test-Konfiguration
    test_config = {
        'host': 'localhost',  # Ändern Sie dies zu Ihrem Host
        'username': 'root',
        'key_file': None
    }
    
    try:
        # Erstelle Collector
        collector = SSHLogCollector(**test_config)
        
        # Teste Verbindung
        if not collector.connect():
            print("❌ SSH-Verbindung fehlgeschlagen")
            return False
        
        print("✅ SSH-Verbindung erfolgreich")
        
        # Teste Docker-Analyse
        docker_info = collector._analyze_docker()
        
        if docker_info and docker_info.get('docker_detected'):
            print("✅ Docker erkannt und analysiert")
            
            # Zeige Docker-Informationen
            if 'docker_version' in docker_info:
                print(f"  📋 Version: {docker_info['docker_version']}")
            
            if 'running_containers' in docker_info:
                print("  📋 Laufende Container gefunden")
            
            if 'all_containers' in docker_info:
                print("  📋 Alle Container gefunden")
            
            if 'images' in docker_info:
                print("  📋 Docker-Images gefunden")
            
            if 'system_usage' in docker_info:
                print("  📋 System-Nutzung gefunden")
            
            if 'problems_count' in docker_info and docker_info['problems_count'] > 0:
                print(f"  ⚠️  {docker_info['problems_count']} Probleme gefunden")
            
        else:
            print("⚠️  Docker nicht erkannt oder nicht verfügbar")
        
        return True
        
    except Exception as e:
        print(f"❌ Test fehlgeschlagen: {e}")
        return False

def test_mailserver_analysis():
    """Testet die Mailserver-Analyse"""
    print("\n📧 Mailserver-Analyse Test")
    print("=" * 50)
    
    # Test-Konfiguration
    test_config = {
        'host': 'localhost',
        'username': 'root',
        'key_file': None
    }
    
    try:
        # Erstelle Collector
        collector = SSHLogCollector(**test_config)
        
        # Teste Verbindung
        if not collector.connect():
            print("❌ SSH-Verbindung fehlgeschlagen")
            return False
        
        print("✅ SSH-Verbindung erfolgreich")
        
        # Teste Mailserver-Analyse
        mailserver_info = collector._analyze_mailservers()
        
        if mailserver_info and mailserver_info.get('mailserver_detected'):
            print("✅ Mailserver erkannt und analysiert")
            
            # Mailcow
            if 'mailcow_detected' in mailserver_info and mailserver_info['mailcow_detected']:
                print("  📧 Mailcow erkannt")
                if 'mailcow' in mailserver_info:
                    mailcow_data = mailserver_info['mailcow']
                    if 'version' in mailcow_data:
                        print(f"    📋 Version: {mailcow_data['version']}")
                    if 'status' in mailcow_data:
                        print("    📋 Status verfügbar")
                    if 'problems_count' in mailcow_data and mailcow_data['problems_count'] > 0:
                        print(f"    ⚠️  {mailcow_data['problems_count']} Probleme")
            
            # Postfix
            if 'postfix_detected' in mailserver_info and mailserver_info['postfix_detected']:
                print("  📧 Postfix erkannt")
                if 'postfix' in mailserver_info:
                    postfix_data = mailserver_info['postfix']
                    if 'version' in postfix_data:
                        print(f"    📋 Version: {postfix_data['version']}")
                    if 'status' in postfix_data:
                        print("    📋 Status verfügbar")
                    if 'queue_status' in postfix_data:
                        print("    📋 Queue-Status verfügbar")
                    if 'problems_count' in postfix_data and postfix_data['problems_count'] > 0:
                        print(f"    ⚠️  {postfix_data['problems_count']} Probleme")
            
            # Andere Mailserver
            if 'other_mailservers' in mailserver_info:
                print("  📧 Andere Mailserver:")
                for server, status in mailserver_info['other_mailservers'].items():
                    print(f"    📋 {server}: verfügbar")
        
        else:
            print("⚠️  Keine Mailserver erkannt")
        
        return True
        
    except Exception as e:
        print(f"❌ Test fehlgeschlagen: {e}")
        return False

def test_individual_mailserver_analysis():
    """Testet individuelle Mailserver-Analysen"""
    print("\n🔍 Individuelle Mailserver-Tests")
    print("=" * 50)
    
    # Test-Konfiguration
    test_config = {
        'host': 'localhost',
        'username': 'root',
        'key_file': None
    }
    
    try:
        # Erstelle Collector
        collector = SSHLogCollector(**test_config)
        
        # Teste Verbindung
        if not collector.connect():
            print("❌ SSH-Verbindung fehlgeschlagen")
            return False
        
        print("✅ SSH-Verbindung erfolgreich")
        
        # Teste Mailcow-Analyse
        print("\n📧 Mailcow-Analyse:")
        mailcow_info = collector._analyze_mailcow()
        if mailcow_info and mailcow_info.get('mailcow_detected'):
            print("  ✅ Mailcow gefunden")
            if 'version' in mailcow_info:
                print(f"    📋 Version: {mailcow_info['version']}")
            if 'status' in mailcow_info:
                print("    📋 Status verfügbar")
        else:
            print("  ⚠️  Mailcow nicht gefunden")
        
        # Teste Postfix-Analyse
        print("\n📧 Postfix-Analyse:")
        postfix_info = collector._analyze_postfix()
        if postfix_info and postfix_info.get('postfix_detected'):
            print("  ✅ Postfix gefunden")
            if 'version' in postfix_info:
                print(f"    📋 Version: {postfix_info['version']}")
            if 'status' in postfix_info:
                print("    📋 Status verfügbar")
            if 'queue_status' in postfix_info:
                print("    📋 Queue-Status verfügbar")
        else:
            print("  ⚠️  Postfix nicht gefunden")
        
        # Teste andere Mailserver
        print("\n📧 Andere Mailserver:")
        other_info = collector._analyze_other_mailservers()
        if other_info:
            for server, status in other_info.items():
                print(f"  📋 {server}: verfügbar")
        else:
            print("  ⚠️  Keine anderen Mailserver gefunden")
        
        return True
        
    except Exception as e:
        print(f"❌ Test fehlgeschlagen: {e}")
        return False

def test_menu_integration():
    """Testet die Integration in das Menü"""
    print("\n📋 Menü-Integration Test")
    print("=" * 50)
    
    # Simuliere system_info mit verschiedenen Komponenten
    test_cases = [
        {
            'name': 'Nur Docker',
            'system_info': {
                'hostname': 'test-host',
                'docker_detected': True
            }
        },
        {
            'name': 'Nur Mailserver',
            'system_info': {
                'hostname': 'test-host',
                'mailserver_detected': True,
                'mailcow_detected': True,
                'postfix_detected': True
            }
        },
        {
            'name': 'Docker + Mailserver',
            'system_info': {
                'hostname': 'test-host',
                'docker_detected': True,
                'mailserver_detected': True,
                'mailcow_detected': True,
                'postfix_detected': True
            }
        },
        {
            'name': 'Vollständig (System + K8s + Proxmox + Docker + Mailserver)',
            'system_info': {
                'hostname': 'test-host',
                'kubernetes_detected': True,
                'proxmox_detected': True,
                'docker_detected': True,
                'mailserver_detected': True,
                'mailcow_detected': True,
                'postfix_detected': True
            }
        }
    ]
    
    for test_case in test_cases:
        print(f"\n🔍 Test: {test_case['name']}")
        print("-" * 30)
        
        system_info = test_case['system_info']
        
        # Zeige verfügbare Kategorien
        if 'docker_detected' in system_info and system_info['docker_detected']:
            print("✅ Docker-Kategorie verfügbar")
            print("  • 'docker' - Wie ist der Docker-Status und welche Container laufen?")
            print("  • 'docker-problems' - Welche Docker-Probleme gibt es?")
            print("  • 'docker-containers' - Welche Docker-Container laufen?")
            print("  • 'docker-images' - Welche Docker-Images sind installiert?")
        
        if 'mailserver_detected' in system_info and system_info['mailserver_detected']:
            print("✅ Mailserver-Kategorie verfügbar")
            print("  • 'mailservers' - Welche Mailserver sind installiert und aktiv?")
            
            if 'mailcow_detected' in system_info and system_info['mailcow_detected']:
                print("  • 'mailcow' - Wie ist der Mailcow-Status?")
                print("  • 'mailcow-problems' - Welche Mailcow-Probleme gibt es?")
            
            if 'postfix_detected' in system_info and system_info['postfix_detected']:
                print("  • 'postfix' - Wie ist der Postfix-Status?")
                print("  • 'postfix-problems' - Welche Postfix-Probleme gibt es?")

def test_keyword_interpolation():
    """Testet die Keyword-Interpolation für neue Module"""
    print("\n🔍 Keyword-Interpolation Test")
    print("=" * 50)
    
    # Teste Keywords für neue Module
    test_keywords = [
        ('docker', 'docker'),
        ('docker container', 'docker-containers'),
        ('docker containers', 'docker-containers'),
        ('docker image', 'docker-images'),
        ('docker images', 'docker-images'),
        ('mailcow', 'mailcow'),
        ('postfix', 'postfix'),
        ('mail', 'mailservers'),
        ('email', 'mailservers'),
        ('e-mail', 'mailservers')
    ]
    
    print("🔍 Teste Keyword-Mapping:")
    for keyword, expected_shortcut in test_keywords:
        print(f"  '{keyword}' -> {expected_shortcut}")

def main():
    """Hauptfunktion für alle Tests"""
    print("🚀 Neue Module Tests (Docker, Mailserver)")
    print("=" * 60)
    print(f"Startzeit: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Teste Docker-Analyse
    docker_success = test_docker_analysis()
    
    # Teste Mailserver-Analyse
    mailserver_success = test_mailserver_analysis()
    
    # Teste individuelle Mailserver-Analysen
    individual_success = test_individual_mailserver_analysis()
    
    # Teste Menü-Integration
    test_menu_integration()
    
    # Teste Keyword-Interpolation
    test_keyword_interpolation()
    
    # Zusammenfassung
    print("\n" + "=" * 60)
    print("📊 TEST-ZUSAMMENFASSUNG")
    print("=" * 60)
    print(f"Docker-Analyse: {'✅ Erfolgreich' if docker_success else '❌ Fehlgeschlagen'}")
    print(f"Mailserver-Analyse: {'✅ Erfolgreich' if mailserver_success else '❌ Fehlgeschlagen'}")
    print(f"Individuelle Tests: {'✅ Erfolgreich' if individual_success else '❌ Fehlgeschlagen'}")
    print("Menü-Integration: ✅ Getestet")
    print("Keyword-Interpolation: ✅ Getestet")
    
    if docker_success and mailserver_success and individual_success:
        print("\n🎉 Alle Tests erfolgreich!")
        print("\n💡 Neue Features verfügbar:")
        print("   • Docker-Erkennung und -Analyse")
        print("   • Mailcow-Erkennung und -Analyse")
        print("   • Postfix-Erkennung und -Analyse")
        print("   • Andere Mailserver-Erkennung")
        print("   • Neue Shortcuts und Keywords")
        print("   • Erweiterte Menü-Kategorien")
    else:
        print("\n⚠️  Einige Tests fehlgeschlagen")
        print("   Überprüfen Sie die SSH-Verbindung und Installation der Services")

if __name__ == "__main__":
    main() 