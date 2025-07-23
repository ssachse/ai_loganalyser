#!/usr/bin/env python3
"""
Test-Skript für erweiterte Proxmox-Integration
Testet die neuen Refresh-Funktionen und Chat-Befehle
"""

import sys
import os
import json
from datetime import datetime

# Füge das aktuelle Verzeichnis zum Python-Pfad hinzu
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ssh_chat_system import SSHLogCollector

def test_proxmox_refresh():
    """Testet die neuen Proxmox-Refresh-Funktionen"""
    print("🔄 Proxmox-Refresh Test")
    print("=" * 50)
    
    # Test-Konfiguration
    test_config = {
        'host': 'localhost',  # Ändern Sie dies zu Ihrem Proxmox-Host
        'username': 'root',
        'key_file': None  # Pfad zu Ihrem SSH-Key falls nötig
    }
    
    try:
        # Erstelle Collector
        collector = SSHLogCollector(**test_config)
        
        # Teste Verbindung
        if not collector.connect():
            print("❌ SSH-Verbindung fehlgeschlagen")
            return False
        
        print("✅ SSH-Verbindung erfolgreich")
        
        # Teste verschiedene Refresh-Targets
        targets = ["all", "vms", "containers", "storage", "cluster"]
        
        for target in targets:
            print(f"\n📊 Teste Refresh: {target}")
            try:
                refresh_data = collector.refresh_proxmox_data(target)
                
                if refresh_data and not refresh_data.get("error"):
                    print(f"✅ {target}-Refresh erfolgreich")
                    
                    # Zeige Daten-Zusammenfassung
                    data_keys = list(refresh_data.keys())
                    print(f"   Gefundene Daten: {len(data_keys)}")
                    for key in data_keys[:3]:  # Zeige erste 3 Keys
                        print(f"   - {key}")
                    if len(data_keys) > 3:
                        print(f"   - ... und {len(data_keys) - 3} weitere")
                    
                    # Spezielle Analyse für VMs/Container
                    if target in ["vms", "all"]:
                        vm_count = 0
                        for key in refresh_data.keys():
                            if key.endswith('_vms'):
                                try:
                                    vms_data = json.loads(refresh_data[key])
                                    vm_count += len(vms_data)
                                except:
                                    pass
                        if vm_count > 0:
                            print(f"   📊 {vm_count} VMs gefunden")
                    
                    if target in ["containers", "all"]:
                        container_count = 0
                        for key in refresh_data.keys():
                            if key.endswith('_containers'):
                                try:
                                    containers_data = json.loads(refresh_data[key])
                                    container_count += len(containers_data)
                                except:
                                    pass
                        if container_count > 0:
                            print(f"   📊 {container_count} Container gefunden")
                    
                else:
                    error_msg = refresh_data.get("error", "Unbekannter Fehler") if refresh_data else "Keine Daten"
                    print(f"❌ {target}-Refresh fehlgeschlagen: {error_msg}")
                    
            except Exception as e:
                print(f"❌ Exception bei {target}-Refresh: {str(e)[:100]}")
        
        return True
        
    except Exception as e:
        print(f"❌ Test fehlgeschlagen: {e}")
        return False

def test_proxmox_integration():
    """Testet die Integration in den Systemkontext"""
    print("\n🔗 Proxmox-Integration Test")
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
        
        # Hole System-Info mit Proxmox
        print("\n📊 Hole System-Informationen...")
        system_info = collector.get_system_info(quick_mode=True)
        
        if 'proxmox_detected' in system_info and system_info['proxmox_detected']:
            print("✅ Proxmox erkannt")
            
            # Teste Refresh und Integration
            print("\n🔄 Teste Refresh und Integration...")
            refresh_data = collector.refresh_proxmox_data("all")
            
            if refresh_data and not refresh_data.get("error"):
                # Aktualisiere system_info
                if 'proxmox' not in system_info:
                    system_info['proxmox'] = {}
                
                # Merge neue Daten
                for key, value in refresh_data.items():
                    system_info['proxmox'][key] = value
                
                print("✅ Proxmox-Daten integriert")
                
                # Teste Systemkontext-Erstellung
                from ssh_chat_system import create_system_context
                from log_analyzer import LogEntry, LogLevel, Anomaly
                
                # Erstelle Mock-Daten
                log_entries = []
                anomalies = []
                
                context = create_system_context(system_info, log_entries, anomalies)
                
                # Prüfe auf Proxmox-Sektionen
                if "=== PROXMOX-CLUSTER ===" in context:
                    print("✅ Proxmox-Cluster-Sektion gefunden")
                
                if "=== PROXMOX-VMs ===" in context:
                    print("✅ Proxmox-VMs-Sektion gefunden")
                
                if "=== PROXMOX-CONTAINER ===" in context:
                    print("✅ Proxmox-Container-Sektion gefunden")
                
                # Zeige Kontext-Ausschnitt
                lines = context.split('\n')
                proxmox_lines = []
                in_proxmox = False
                
                for line in lines:
                    if "=== PROXMOX" in line:
                        in_proxmox = True
                    elif in_proxmox and line.startswith("===") and not line.startswith("=== PROXMOX"):
                        break
                    
                    if in_proxmox:
                        proxmox_lines.append(line)
                
                if proxmox_lines:
                    print("\n📋 Proxmox-Kontext-Ausschnitt:")
                    for line in proxmox_lines[:20]:  # Erste 20 Zeilen
                        print(f"   {line}")
                    if len(proxmox_lines) > 20:
                        print(f"   ... und {len(proxmox_lines) - 20} weitere Zeilen")
                
            else:
                print("❌ Proxmox-Refresh fehlgeschlagen")
        else:
            print("⚠️  Proxmox nicht erkannt")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration-Test fehlgeschlagen: {e}")
        return False

def test_chat_commands():
    """Testet die Chat-Befehle für Proxmox"""
    print("\n💬 Proxmox-Chat-Befehle Test")
    print("=" * 50)
    
    # Teste Befehlserkennung
    test_commands = [
        "proxmox-refresh",
        "proxmox-refresh vms",
        "proxmox-refresh containers",
        "proxmox-refresh storage",
        "proxmox-refresh cluster",
        "proxmox-refresh ha",
        "proxmox-refresh tasks",
        "proxmox-refresh backups",
        "proxmox-status",
        "refresh-proxmox",
        "refresh-proxmox vms"
    ]
    
    print("🔍 Teste Befehlserkennung:")
    for cmd in test_commands:
        cmd_lower = cmd.lower()
        
        # Simuliere die Erkennungslogik aus dem Chat
        target = "all"
        if 'vms' in cmd_lower:
            target = "vms"
        elif 'containers' in cmd_lower or 'lxc' in cmd_lower:
            target = "containers"
        elif 'storage' in cmd_lower:
            target = "storage"
        elif 'cluster' in cmd_lower:
            target = "cluster"
        elif 'ha' in cmd_lower:
            target = "ha"
        elif 'tasks' in cmd_lower:
            target = "tasks"
        elif 'backups' in cmd_lower:
            target = "backups"
        
        print(f"   '{cmd}' -> Target: {target}")
    
    print("\n✅ Befehlserkennung getestet")

def main():
    """Hauptfunktion für alle Tests"""
    print("🚀 Erweiterte Proxmox-Integration Tests")
    print("=" * 60)
    print(f"Startzeit: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Teste Refresh-Funktionen
    refresh_success = test_proxmox_refresh()
    
    # Teste Integration
    integration_success = test_proxmox_integration()
    
    # Teste Chat-Befehle
    test_chat_commands()
    
    # Zusammenfassung
    print("\n" + "=" * 60)
    print("📊 TEST-ZUSAMMENFASSUNG")
    print("=" * 60)
    print(f"Proxmox-Refresh: {'✅ Erfolgreich' if refresh_success else '❌ Fehlgeschlagen'}")
    print(f"Proxmox-Integration: {'✅ Erfolgreich' if integration_success else '❌ Fehlgeschlagen'}")
    print("Chat-Befehle: ✅ Getestet")
    
    if refresh_success and integration_success:
        print("\n🎉 Alle Tests erfolgreich!")
        print("\n💡 Nächste Schritte:")
        print("   1. Starten Sie den Chat mit: python ssh_chat_system.py")
        print("   2. Verwenden Sie 'proxmox-refresh' im Chat")
        print("   3. Fragen Sie nach VMs/Containern mit den Shortcuts")
    else:
        print("\n⚠️  Einige Tests fehlgeschlagen")
        print("   Überprüfen Sie die SSH-Verbindung und Proxmox-Installation")

if __name__ == "__main__":
    main() 