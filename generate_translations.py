#!/usr/bin/env python3
"""
Generiert gettext-Übersetzungsdateien mit Hilfe von Ollama
"""

import os
import json
import subprocess
import requests
from typing import Dict, List

def query_ollama(prompt: str, model: str = "llama2") -> str:
    """Fragt Ollama nach einer Übersetzung"""
    try:
        url = "http://localhost:11434/api/generate"
        data = {
            "model": model,
            "prompt": prompt,
            "stream": False
        }
        
        response = requests.post(url, json=data, timeout=30)
        if response.status_code == 200:
            return response.json()["response"].strip()
        else:
            return ""
    except Exception as e:
        print(f"Ollama error: {e}")
        return ""

def extract_strings_from_code() -> List[str]:
    """Extrahiert alle zu übersetzenden Strings aus dem Code"""
    strings = []
    
    # Hauptskript durchsuchen
    with open('ssh_chat_system.py', 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Suche nach _('...') Aufrufen
    import re
    pattern = r"_\(['\"]([^'\"]+)['\"]\)"
    matches = re.findall(pattern, content)
    strings.extend(matches)
    
    # Duplikate entfernen und sortieren
    strings = sorted(list(set(strings)))
    return strings

def generate_pot_file(strings: List[str]) -> str:
    """Generiert eine .pot Datei (Template)"""
    pot_content = """# German translations for AI Log Analyzer.
# Copyright (C) 2024 AI Log Analyzer Team.
# This file is distributed under the same license as the AI Log Analyzer package.
msgid ""
msgstr ""
"Project-Id-Version: AI Log Analyzer 1.0\\n"
"Report-Msgid-Bugs-To: \\n"
"POT-Creation-Date: 2024-01-01 12:00+0000\\n"
"PO-Revision-Date: 2024-01-01 12:00+0000\\n"
"Last-Translator: Ollama AI\\n"
"Language-Team: German\\n"
"Language: de\\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=UTF-8\\n"
"Content-Transfer-Encoding: 8bit\\n"
"Plural-Forms: nplurals=2; plural=(n != 1);\\n"

"""
    
    for string in strings:
        pot_content += f'msgid "{string}"\n'
        pot_content += f'msgstr ""\n\n'
    
    return pot_content

def translate_with_ollama(strings: List[str], target_language: str) -> Dict[str, str]:
    """Übersetzt Strings mit Ollama"""
    translations = {}
    
    print(f"Übersetze {len(strings)} Strings ins {target_language}...")
    
    for i, string in enumerate(strings, 1):
        print(f"  [{i}/{len(strings)}] Übersetze: {string}")
        
        if target_language == "de":
            prompt = f"""Übersetze den folgenden englischen Text ins Deutsche. 
Gib nur die Übersetzung zurück, ohne Erklärungen oder zusätzlichen Text.

Text: "{string}"

Deutsche Übersetzung:"""
        else:
            prompt = f"""Translate the following German text to English.
Return only the translation, without explanations or additional text.

Text: "{string}"

English translation:"""
        
        translation = query_ollama(prompt)
        if translation:
            # Bereinige die Antwort
            translation = translation.strip().strip('"').strip("'")
            translations[string] = translation
        else:
            # Fallback: Verwende Original
            translations[string] = string
    
    return translations

def generate_po_file(strings: List[str], translations: Dict[str, str], language: str) -> str:
    """Generiert eine .po Datei"""
    if language == "de":
        header = """# German translations for AI Log Analyzer.
# Copyright (C) 2024 AI Log Analyzer Team.
# This file is distributed under the same license as the AI Log Analyzer package.
msgid ""
msgstr ""
"Project-Id-Version: AI Log Analyzer 1.0\\n"
"Report-Msgid-Bugs-To: \\n"
"POT-Creation-Date: 2024-01-01 12:00+0000\\n"
"PO-Revision-Date: 2024-01-01 12:00+0000\\n"
"Last-Translator: Ollama AI\\n"
"Language-Team: German\\n"
"Language: de\\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=UTF-8\\n"
"Content-Transfer-Encoding: 8bit\\n"
"Plural-Forms: nplurals=2; plural=(n != 1);\\n"

"""
    else:
        header = """# English translations for AI Log Analyzer.
# Copyright (C) 2024 AI Log Analyzer Team.
# This file is distributed under the same license as the AI Log Analyzer package.
msgid ""
msgstr ""
"Project-Id-Version: AI Log Analyzer 1.0\\n"
"Report-Msgid-Bugs-To: \\n"
"POT-Creation-Date: 2024-01-01 12:00+0000\\n"
"PO-Revision-Date: 2024-01-01 12:00+0000\\n"
"Last-Translator: Ollama AI\\n"
"Language-Team: English\\n"
"Language: en\\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=UTF-8\\n"
"Content-Transfer-Encoding: 8bit\\n"
"Plural-Forms: nplurals=2; plural=(n != 1);\\n"

"""
    
    po_content = header
    
    for string in strings:
        translation = translations.get(string, string)
        po_content += f'msgid "{string}"\n'
        po_content += f'msgstr "{translation}"\n\n'
    
    return po_content

def compile_mo_file(po_file: str, mo_file: str):
    """Kompiliert .po zu .mo Datei"""
    try:
        # Verwende msgfmt von gettext
        result = subprocess.run(['msgfmt', '-o', mo_file, po_file], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ {mo_file} kompiliert")
        else:
            print(f"✗ Fehler beim Kompilieren von {mo_file}: {result.stderr}")
    except FileNotFoundError:
        print("⚠️  msgfmt nicht gefunden. Installiere gettext:")
        print("   macOS: brew install gettext")
        print("   Ubuntu: sudo apt-get install gettext")
        print("   Windows: Download von https://www.gnu.org/software/gettext/")

def main():
    """Hauptfunktion"""
    print("🌍 Generiere gettext-Übersetzungen mit Ollama")
    print("=" * 60)
    
    # Prüfe Ollama-Verbindung
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code != 200:
            print("❌ Ollama ist nicht erreichbar. Starte Ollama mit: ollama serve")
            return
    except Exception:
        print("❌ Ollama ist nicht erreichbar. Starte Ollama mit: ollama serve")
        return
    
    # Extrahiere Strings
    print("📝 Extrahiere zu übersetzende Strings...")
    strings = extract_strings_from_code()
    print(f"✓ {len(strings)} Strings gefunden")
    
    # Generiere .pot Datei
    print("\n📄 Generiere .pot Template...")
    pot_content = generate_pot_file(strings)
    with open('locale/ai_loganalyser.pot', 'w', encoding='utf-8') as f:
        f.write(pot_content)
    print("✓ ai_loganalyser.pot erstellt")
    
    # Übersetze ins Deutsche
    print("\n🇩🇪 Übersetze ins Deutsche...")
    de_translations = translate_with_ollama(strings, "de")
    
    # Generiere deutsche .po Datei
    de_po_content = generate_po_file(strings, de_translations, "de")
    de_po_file = 'locale/de/LC_MESSAGES/ai_loganalyser.po'
    os.makedirs(os.path.dirname(de_po_file), exist_ok=True)
    with open(de_po_file, 'w', encoding='utf-8') as f:
        f.write(de_po_content)
    print("✓ ai_loganalyser.po (de) erstellt")
    
    # Kompiliere deutsche .mo Datei
    de_mo_file = 'locale/de/LC_MESSAGES/ai_loganalyser.mo'
    compile_mo_file(de_po_file, de_mo_file)
    
    # Übersetze ins Englische
    print("\n🇺🇸 Übersetze ins Englische...")
    en_translations = translate_with_ollama(strings, "en")
    
    # Generiere englische .po Datei
    en_po_content = generate_po_file(strings, en_translations, "en")
    en_po_file = 'locale/en/LC_MESSAGES/ai_loganalyser.po'
    os.makedirs(os.path.dirname(en_po_file), exist_ok=True)
    with open(en_po_file, 'w', encoding='utf-8') as f:
        f.write(en_po_content)
    print("✓ ai_loganalyser.po (en) erstellt")
    
    # Kompiliere englische .mo Datei
    en_mo_file = 'locale/en/LC_MESSAGES/ai_loganalyser.mo'
    compile_mo_file(en_po_file, en_mo_file)
    
    print("\n✅ Übersetzungen erfolgreich generiert!")
    print("\n📁 Erstellte Dateien:")
    print("   • locale/ai_loganalyser.pot (Template)")
    print("   • locale/de/LC_MESSAGES/ai_loganalyser.po (Deutsch)")
    print("   • locale/de/LC_MESSAGES/ai_loganalyser.mo (Deutsch kompiliert)")
    print("   • locale/en/LC_MESSAGES/ai_loganalyser.po (Englisch)")
    print("   • locale/en/LC_MESSAGES/ai_loganalyser.mo (Englisch kompiliert)")

if __name__ == "__main__":
    main() 