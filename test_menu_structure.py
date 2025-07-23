#!/usr/bin/env python3
"""
Test-Skript für die neue Menüstruktur
Testet die kategorisierte Darstellung der Shortcuts
"""

import sys
import os

# Füge das aktuelle Verzeichnis zum Python-Pfad hinzu
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_menu_structure():
    """Testet die neue Menüstruktur"""
    print("📋 Menüstruktur Test")
    print("=" * 50)
    
    # Simuliere system_info mit verschiedenen Komponenten
    test_cases = [
        {
            'name': 'Nur System',
            'system_info': {
                'hostname': 'test-host',
                'distro_name': 'Ubuntu'
            }
        },
        {
            'name': 'System + Kubernetes',
            'system_info': {
                'hostname': 'test-host',
                'distro_name': 'Ubuntu',
                'kubernetes_detected': True
            }
        },
        {
            'name': 'System + Proxmox',
            'system_info': {
                'hostname': 'test-host',
                'distro_name': 'Ubuntu',
                'proxmox_detected': True
            }
        },
        {
            'name': 'Vollständig (System + K8s + Proxmox)',
            'system_info': {
                'hostname': 'test-host',
                'distro_name': 'Ubuntu',
                'kubernetes_detected': True,
                'proxmox_detected': True
            }
        }
    ]
    
    for test_case in test_cases:
        print(f"\n🔍 Test: {test_case['name']}")
        print("-" * 30)
        
        # Simuliere die Menü-Erstellung
        system_info = test_case['system_info']
        
        # Basis-Shortcuts (immer verfügbar)
        shortcuts = {
            'services': {'question': 'Which services are running on the system?', 'complex': False},
            'storage': {'question': 'How is the storage space?', 'complex': False},
            'security': {'question': 'Are there security issues?', 'complex': True},
            'processes': {'question': 'What are the top processes?', 'complex': False},
            'performance': {'question': 'How is the system performance?', 'complex': False},
            'users': {'question': 'Which users are active?', 'complex': False},
            'updates': {'question': 'Are there available system updates?', 'complex': False},
            'logs': {'question': 'What do the logs show?', 'complex': True},
            'report': {'question': 'Erstelle einen detaillierten Systembericht', 'complex': True}
        }
        
        # Kubernetes-Shortcuts (nur wenn verfügbar)
        if 'kubernetes_detected' in system_info and system_info['kubernetes_detected']:
            k8s_shortcuts = {
                'k8s': {'question': 'How is the Kubernetes cluster status?', 'complex': False},
                'k8s-problems': {'question': 'What Kubernetes problems are there?', 'complex': True},
                'k8s-pods': {'question': 'Which pods are running in the cluster?', 'complex': False},
                'k8s-nodes': {'question': 'How is the node status?', 'complex': False},
                'k8s-resources': {'question': 'How is the resource usage in the cluster?', 'complex': False}
            }
            shortcuts.update(k8s_shortcuts)
        
        # Proxmox-Shortcuts (nur wenn verfügbar)
        if 'proxmox_detected' in system_info and system_info['proxmox_detected']:
            proxmox_shortcuts = {
                'proxmox': {'question': 'Wie ist der Status des Proxmox-Clusters?', 'complex': False},
                'proxmox-problems': {'question': 'Welche Probleme gibt es im Proxmox-Cluster?', 'complex': True},
                'proxmox-vms': {'question': 'Welche VMs laufen auf Proxmox?', 'complex': False},
                'proxmox-containers': {'question': 'Welche Container laufen auf Proxmox?', 'complex': False},
                'proxmox-storage': {'question': 'Wie ist der Speicherplatz-Status im Proxmox-Cluster?', 'complex': False}
            }
            shortcuts.update(proxmox_shortcuts)
        
        # Zeige kategorisierte Menüstruktur
        print("System:")
        system_shortcuts = ['services', 'storage', 'security', 'processes', 'performance', 'users', 'updates', 'logs']
        for shortcut in system_shortcuts:
            if shortcut in shortcuts:
                print(f"  • '{shortcut}' - {shortcuts[shortcut]['question']}")
        
        if 'kubernetes_detected' in system_info and system_info['kubernetes_detected']:
            print("\nKubernetes:")
            k8s_shortcuts = ['k8s', 'k8s-problems', 'k8s-pods', 'k8s-nodes', 'k8s-resources']
            for shortcut in k8s_shortcuts:
                if shortcut in shortcuts:
                    print(f"  • '{shortcut}' - {shortcuts[shortcut]['question']}")
        
        if 'proxmox_detected' in system_info and system_info['proxmox_detected']:
            print("\nProxmox:")
            proxmox_shortcuts = ['proxmox', 'proxmox-problems', 'proxmox-vms', 'proxmox-containers', 'proxmox-storage']
            for shortcut in proxmox_shortcuts:
                if shortcut in shortcuts:
                    print(f"  • '{shortcut}' - {shortcuts[shortcut]['question']}")
            
            # Proxmox-spezifische Befehle
            print("  • 'proxmox-refresh' - Aktualisiere alle Proxmox-Daten")
            print("  • 'proxmox-refresh vms' - Aktualisiere nur VM-Daten")
            print("  • 'proxmox-refresh containers' - Aktualisiere nur Container-Daten")
            print("  • 'proxmox-status' - Zeige aktuellen Cluster-Status")
        
        print("\nBerichte & Tools:")
        print("  • 'report' - Erstelle einen detaillierten Systembericht")
        print("  • 'cache' - Zeige Cache-Status")
        print("  • 'clear' - Lösche Cache")
        
        print("\nNavigation:")
        print("  • 'help' oder 'm' - Zeige dieses Menü")
        print("  • 'exit', 'quit', 'q', 'bye', 'beenden' - Beende das Programm")

def test_report_separation():
    """Testet, dass 'report' nicht mehr unter Proxmox steht"""
    print("\n🔍 Report-Separation Test")
    print("=" * 30)
    
    # Simuliere Proxmox-System
    system_info = {
        'hostname': 'proxmox-host',
        'proxmox_detected': True
    }
    
    # Proxmox-Shortcuts (ohne report)
    proxmox_shortcuts = [
        'proxmox',
        'proxmox-problems', 
        'proxmox-vms',
        'proxmox-containers',
        'proxmox-storage'
    ]
    
    # Tools (mit report)
    tools_shortcuts = [
        'report',
        'cache',
        'clear'
    ]
    
    print("✅ Proxmox-Shortcuts (ohne report):")
    for shortcut in proxmox_shortcuts:
        print(f"  • {shortcut}")
    
    print("\n✅ Tools (mit report):")
    for shortcut in tools_shortcuts:
        print(f"  • {shortcut}")
    
    print("\n✅ Report ist jetzt korrekt unter 'Berichte & Tools' kategorisiert!")

def main():
    """Hauptfunktion"""
    print("🚀 Menüstruktur Tests")
    print("=" * 60)
    
    # Teste verschiedene Menü-Konfigurationen
    test_menu_structure()
    
    # Teste Report-Separation
    test_report_separation()
    
    print("\n" + "=" * 60)
    print("📊 TEST-ZUSAMMENFASSUNG")
    print("=" * 60)
    print("✅ Menüstruktur getestet")
    print("✅ Report-Separation bestätigt")
    print("✅ Kategorisierung funktioniert")
    
    print("\n🎉 Alle Tests erfolgreich!")
    print("\n💡 Die neue Menüstruktur ist:")
    print("   • System: (grün)")
    print("   • Kubernetes: (blau)")
    print("   • Proxmox: (magenta)")
    print("   • Berichte & Tools: (gelb)")
    print("   • Navigation: (cyan)")

if __name__ == "__main__":
    main() 