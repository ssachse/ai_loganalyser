#!/usr/bin/env python3
"""
Test für die Interpolation
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ssh_chat_system import interpolate_user_input_to_shortcut

def test_interpolation():
    print("🔍 Teste Interpolation...")
    
    # Simuliere shortcuts dictionary
    shortcuts = {
        'proxmox-containers': {
            'question': 'Welche Container laufen auf Proxmox?',
            'complex': False,
            'cache_key': 'proxmox_containers'
        },
        'proxmox-vms': {
            'question': 'Welche VMs laufen auf Proxmox?',
            'complex': False,
            'cache_key': 'proxmox_vms'
        },
        'storage': {
            'question': 'Wie ist der Speicherplatz?',
            'complex': False,
            'cache_key': 'storage_status'
        }
    }
    
    # Teste verschiedene Eingaben
    test_inputs = [
        'lxc',
        'container',
        'containers',
        'vm',
        'vms',
        'speicher',
        'storage',
        'was ist das wetter',  # Sollte nicht interpoliert werden
    ]
    
    for user_input in test_inputs:
        result = interpolate_user_input_to_shortcut(user_input, shortcuts)
        if result:
            shortcut_info = shortcuts[result]
            print(f"✅ '{user_input}' -> '{result}' -> '{shortcut_info['question']}' (complex={shortcut_info['complex']})")
        else:
            print(f"❌ '{user_input}' -> keine Interpolation")

if __name__ == "__main__":
    test_interpolation() 