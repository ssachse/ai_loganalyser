#!/usr/bin/env python3
"""
Test für die Modell-Auswahl
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ssh_chat_system import select_best_model, get_available_models

def test_model_selection():
    print("🔍 Teste Modell-Auswahl...")
    
    # Verfügbare Modelle abrufen
    models = get_available_models()
    print(f"📋 Verfügbare Modelle: {[m['name'] for m in models]}")
    
    # Teste verschiedene Szenarien
    test_cases = [
        ("Menü", False, True),
        ("Einfache Analyse", False, False),
        ("Komplexe Analyse", True, False),
    ]
    
    for name, complex_analysis, for_menu in test_cases:
        model = select_best_model(complex_analysis=complex_analysis, for_menu=for_menu)
        print(f"🎯 {name}: {model} (complex={complex_analysis}, menu={for_menu})")

if __name__ == "__main__":
    test_model_selection() 