#!/usr/bin/env python3
"""
Test-Runner für den macOS Logfile-Analysator
Führt alle Tests aus und generiert Berichte
"""

import unittest
import sys
import os
import time
import subprocess
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

def run_tests():
    """Führt alle Tests aus"""
    console.print("[bold blue]🧪 Test-Runner für macOS Logfile-Analysator[/bold blue]")
    console.print("="*60)
    
    # Test-Verzeichnis erstellen falls nicht vorhanden
    test_dir = Path("tests")
    test_dir.mkdir(exist_ok=True)
    
    # Finde alle Test-Dateien
    test_files = list(test_dir.glob("test_*.py"))
    
    if not test_files:
        console.print("[yellow]⚠️  Keine Test-Dateien gefunden[/yellow]")
        return False
    
    console.print(f"[blue]Gefunden: {len(test_files)} Test-Dateien[/blue]")
    
    # Test-Ergebnisse sammeln
    results = []
    total_tests = 0
    total_failures = 0
    total_errors = 0
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("Führe Tests aus...", total=len(test_files))
        
        for test_file in test_files:
            progress.update(task, description=f"Teste {test_file.name}...")
            
            # Führe Tests für diese Datei aus
            start_time = time.time()
            
            try:
                # Lade Tests
                loader = unittest.TestLoader()
                suite = loader.discover(str(test_dir), pattern=test_file.name)
                
                # Führe Tests aus
                runner = unittest.TextTestRunner(verbosity=0, stream=open(os.devnull, 'w'))
                result = runner.run(suite)
                
                end_time = time.time()
                duration = end_time - start_time
                
                # Sammle Ergebnisse
                file_results = {
                    'file': test_file.name,
                    'tests_run': result.testsRun,
                    'failures': len(result.failures),
                    'errors': len(result.errors),
                    'duration': duration,
                    'success': result.wasSuccessful()
                }
                
                results.append(file_results)
                total_tests += result.testsRun
                total_failures += len(result.failures)
                total_errors += len(result.errors)
                
            except Exception as e:
                console.print(f"[red]Fehler beim Ausführen von {test_file.name}: {e}[/red]")
                results.append({
                    'file': test_file.name,
                    'tests_run': 0,
                    'failures': 0,
                    'errors': 1,
                    'duration': 0,
                    'success': False
                })
                total_errors += 1
            
            progress.advance(task)
    
    # Zeige Ergebnisse
    display_results(results, total_tests, total_failures, total_errors)
    
    return total_failures == 0 and total_errors == 0

def display_results(results, total_tests, total_failures, total_errors):
    """Zeigt Test-Ergebnisse an"""
    console.print("\n[bold]📊 Test-Ergebnisse[/bold]")
    
    # Zusammenfassung
    success_rate = ((total_tests - total_failures - total_errors) / total_tests * 100) if total_tests > 0 else 0
    
    summary_panel = Panel(
        f"Tests ausgeführt: {total_tests}\n"
        f"Erfolgreich: {total_tests - total_failures - total_errors}\n"
        f"Fehler: {total_failures}\n"
        f"Exceptions: {total_errors}\n"
        f"Erfolgsrate: {success_rate:.1f}%",
        title="Zusammenfassung",
        border_style="green" if success_rate >= 90 else "yellow" if success_rate >= 70 else "red"
    )
    console.print(summary_panel)
    
    # Detaillierte Ergebnisse
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Datei", style="cyan", width=25)
    table.add_column("Tests", style="white", width=8)
    table.add_column("Fehler", style="red", width=8)
    table.add_column("Exceptions", style="red", width=10)
    table.add_column("Dauer", style="blue", width=10)
    table.add_column("Status", style="green", width=10)
    
    for result in results:
        status_color = "green" if result['success'] else "red"
        status_text = "✅ PASS" if result['success'] else "❌ FAIL"
        
        table.add_row(
            result['file'],
            str(result['tests_run']),
            str(result['failures']),
            str(result['errors']),
            f"{result['duration']:.2f}s",
            f"[{status_color}]{status_text}[/{status_color}]"
        )
    
    console.print(table)
    
    # Empfehlungen
    if total_failures > 0 or total_errors > 0:
        console.print("\n[bold red]🔧 Empfehlungen:[/bold red]")
        console.print("• Überprüfen Sie die fehlgeschlagenen Tests")
        console.print("• Stellen Sie sicher, dass alle Abhängigkeiten installiert sind")
        console.print("• Führen Sie einzelne Tests aus für detaillierte Fehlermeldungen")
    else:
        console.print("\n[bold green]🎉 Alle Tests erfolgreich![/bold green]")

def run_specific_test(test_name):
    """Führt einen spezifischen Test aus"""
    console.print(f"[blue]Führe spezifischen Test aus: {test_name}[/blue]")
    
    try:
        # Führe Test mit detaillierter Ausgabe aus
        result = subprocess.run([
            sys.executable, "-m", "unittest", f"tests.{test_name}", "-v"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            console.print("[green]✅ Test erfolgreich[/green]")
        else:
            console.print("[red]❌ Test fehlgeschlagen[/red]")
            console.print(result.stdout)
            console.print(result.stderr)
        
        return result.returncode == 0
        
    except Exception as e:
        console.print(f"[red]Fehler beim Ausführen des Tests: {e}[/red]")
        return False

def run_coverage():
    """Führt Tests mit Coverage-Analyse aus"""
    console.print("[blue]Führe Coverage-Analyse aus...[/blue]")
    
    try:
        # Prüfe ob coverage installiert ist
        import coverage
    except ImportError:
        console.print("[yellow]Coverage nicht installiert. Installiere...[/yellow]")
        subprocess.run([sys.executable, "-m", "pip", "install", "coverage"])
    
    try:
        # Führe Coverage aus
        result = subprocess.run([
            sys.executable, "-m", "coverage", "run", "--source=.", "-m", "unittest", "discover", "tests"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            # Generiere Coverage-Bericht
            subprocess.run([sys.executable, "-m", "coverage", "report"])
            subprocess.run([sys.executable, "-m", "coverage", "html"])
            console.print("[green]✅ Coverage-Bericht generiert[/green]")
            return True
        else:
            console.print("[red]❌ Coverage-Analyse fehlgeschlagen[/red]")
            return False
            
    except Exception as e:
        console.print(f"[red]Fehler bei Coverage-Analyse: {e}[/red]")
        return False

def main():
    """Hauptfunktion"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test-Runner für macOS Logfile-Analysator')
    parser.add_argument('--test', help='Führe spezifischen Test aus (z.B. test_log_analyzer)')
    parser.add_argument('--coverage', action='store_true', help='Führe Coverage-Analyse aus')
    parser.add_argument('--verbose', action='store_true', help='Detaillierte Ausgabe')
    
    args = parser.parse_args()
    
    if args.test:
        success = run_specific_test(args.test)
        sys.exit(0 if success else 1)
    elif args.coverage:
        success = run_coverage()
        sys.exit(0 if success else 1)
    else:
        success = run_tests()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 