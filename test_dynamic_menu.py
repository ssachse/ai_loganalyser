#!/usr/bin/env python3
"""
Test für dynamische Menü-Funktionalität
Zeigt nur Module an, die tatsächlich auf dem System vorhanden sind
"""

import sys
import os
sys.path.append('.')

from ssh_chat_system import create_intelligent_menu, get_shortcuts
from rich.console import Console

console = Console()

def test_dynamic_menu():
    """Testet die dynamische Menü-Funktionalität"""
    
    console.print("[bold blue]🧪 Teste dynamische Menü-Funktionalität...[/bold blue]")
    
    # Hole Shortcuts
    shortcuts = get_shortcuts()
    
    # Test 1: System ohne spezielle Module
    console.print("\n[bold]Test 1: System ohne spezielle Module[/bold]")
    system_info_minimal = {
        'kubernetes_detected': False,
        'proxmox_detected': False,
        'docker_detected': False,
        'mailcow_detected': False,
        'postfix_detected': False,
        'mailserver_detected': False
    }
    
    menu_minimal = create_intelligent_menu(shortcuts, system_info_minimal)
    console.print(f"[green]✅ Menü erstellt (Länge: {len(menu_minimal)} Zeichen)[/green]")
    
    # Prüfe ob nur System und Tools angezeigt werden
    if "System:" in menu_minimal and "Tools:" in menu_minimal:
        console.print(f"[green]✅ System und Tools werden angezeigt[/green]")
    else:
        console.print(f"[red]❌ System oder Tools fehlen[/red]")
    
    # Prüfe ob spezielle Module NICHT angezeigt werden
    if "Kubernetes:" not in menu_minimal and "Proxmox:" not in menu_minimal and "Docker:" not in menu_minimal and "Mailserver:" not in menu_minimal:
        console.print(f"[green]✅ Spezielle Module werden korrekt ausgeblendet[/green]")
    else:
        console.print(f"[red]❌ Spezielle Module werden fälschlicherweise angezeigt[/red]")
    
    # Prüfe Info-Text
    if "Keine spezielle Module erkannt" in menu_minimal:
        console.print(f"[green]✅ Korrekte Info über fehlende Module[/green]")
    else:
        console.print(f"[red]❌ Falsche Info über Module[/red]")
    
    # Test 2: System mit Docker
    console.print("\n[bold]Test 2: System mit Docker[/bold]")
    system_info_docker = {
        'kubernetes_detected': False,
        'proxmox_detected': False,
        'docker_detected': True,
        'mailcow_detected': False,
        'postfix_detected': False,
        'mailserver_detected': False
    }
    
    menu_docker = create_intelligent_menu(shortcuts, system_info_docker)
    console.print(f"[green]✅ Menü erstellt (Länge: {len(menu_docker)} Zeichen)[/green]")
    
    # Prüfe ob Docker angezeigt wird
    if "Docker:" in menu_docker:
        console.print(f"[green]✅ Docker wird angezeigt[/green]")
    else:
        console.print(f"[red]❌ Docker wird nicht angezeigt[/red]")
    
    # Prüfe Info-Text
    if "Erkannte Module: Docker" in menu_docker:
        console.print(f"[green]✅ Korrekte Info über erkannte Module[/green]")
    else:
        console.print(f"[red]❌ Falsche Info über erkannte Module[/red]")
    
    # Test 3: System mit mehreren Modulen
    console.print("\n[bold]Test 3: System mit mehreren Modulen[/bold]")
    system_info_multi = {
        'kubernetes_detected': True,
        'proxmox_detected': True,
        'docker_detected': True,
        'mailcow_detected': True,
        'postfix_detected': False,
        'mailserver_detected': True
    }
    
    menu_multi = create_intelligent_menu(shortcuts, system_info_multi)
    console.print(f"[green]✅ Menü erstellt (Länge: {len(menu_multi)} Zeichen)[/green]")
    
    # Prüfe ob alle Module angezeigt werden
    expected_modules = ["Kubernetes:", "Proxmox:", "Docker:", "Mailserver:"]
    for module in expected_modules:
        if module in menu_multi:
            console.print(f"[green]✅ {module} wird angezeigt[/green]")
        else:
            console.print(f"[red]❌ {module} wird nicht angezeigt[/red]")
    
    # Prüfe Info-Text
    if "Erkannte Module: Kubernetes, Proxmox, Docker, Mailserver" in menu_multi:
        console.print(f"[green]✅ Korrekte Info über alle erkannten Module[/green]")
    else:
        console.print(f"[red]❌ Falsche Info über erkannte Module[/red]")
    
    # Test 4: System mit nur Mailserver
    console.print("\n[bold]Test 4: System mit nur Mailserver[/bold]")
    system_info_mail = {
        'kubernetes_detected': False,
        'proxmox_detected': False,
        'docker_detected': False,
        'mailcow_detected': True,
        'postfix_detected': False,
        'mailserver_detected': True
    }
    
    menu_mail = create_intelligent_menu(shortcuts, system_info_mail)
    console.print(f"[green]✅ Menü erstellt (Länge: {len(menu_mail)} Zeichen)[/green]")
    
    # Prüfe ob nur Mailserver angezeigt wird
    if "Mailserver:" in menu_mail:
        console.print(f"[green]✅ Mailserver wird angezeigt[/green]")
    else:
        console.print(f"[red]❌ Mailserver wird nicht angezeigt[/red]")
    
    # Prüfe ob andere Module NICHT angezeigt werden
    other_modules = ["Kubernetes:", "Proxmox:", "Docker:"]
    for module in other_modules:
        if module not in menu_mail:
            console.print(f"[green]✅ {module} wird korrekt ausgeblendet[/green]")
        else:
            console.print(f"[red]❌ {module} wird fälschlicherweise angezeigt[/red]")
    
    # Test 5: Vergleich der Menü-Längen
    console.print("\n[bold]Test 5: Menü-Längen-Vergleich[/bold]")
    lengths = {
        "Minimal": len(menu_minimal),
        "Docker": len(menu_docker),
        "Multi": len(menu_multi),
        "Mail": len(menu_mail)
    }
    
    console.print(f"[dim]Menü-Längen:[/dim]")
    for name, length in lengths.items():
        console.print(f"[dim]  {name}: {length} Zeichen[/dim]")
    
    # Das Multi-Menü sollte am längsten sein
    if lengths["Multi"] > lengths["Minimal"]:
        console.print(f"[green]✅ Multi-Menü ist länger als Minimal-Menü[/green]")
    else:
        console.print(f"[red]❌ Multi-Menü ist nicht länger als Minimal-Menü[/red]")
    
    # Test 6: Prüfe Shortcut-Verfügbarkeit
    console.print("\n[bold]Test 6: Shortcut-Verfügbarkeit[/bold]")
    
    # Prüfe ob alle erwarteten Shortcuts in den Menüs vorhanden sind
    test_cases = [
        ("Minimal", menu_minimal, ["s1", "s2", "t1", "t2"]),
        ("Docker", menu_docker, ["s1", "s2", "d1", "d2", "t1", "t2"]),
        ("Multi", menu_multi, ["s1", "s2", "k1", "k2", "p1", "p2", "d1", "d2", "m1", "m2", "t1", "t2"]),
        ("Mail", menu_mail, ["s1", "s2", "m1", "m2", "t1", "t2"])
    ]
    
    for name, menu, expected_shortcuts in test_cases:
        missing_shortcuts = []
        for shortcut in expected_shortcuts:
            if shortcut not in menu:
                missing_shortcuts.append(shortcut)
        
        if not missing_shortcuts:
            console.print(f"[green]✅ {name}: Alle erwarteten Shortcuts vorhanden[/green]")
        else:
            console.print(f"[red]❌ {name}: Fehlende Shortcuts: {missing_shortcuts}[/red]")
    
    console.print(f"\n[bold green]✅ Dynamische Menü-Tests abgeschlossen![/bold green]")

if __name__ == "__main__":
    test_dynamic_menu() 