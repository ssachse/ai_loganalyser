#!/usr/bin/env python3
"""
Test für echte Chat-Funktion mit Report
"""

import sys
import os
sys.path.append('.')

from ssh_chat_system import start_interactive_chat
from log_analyzer import LogEntry, LogLevel, Anomaly
from rich.console import Console

console = Console()

def test_real_chat_report():
    """Testet die echte Chat-Funktion mit Report-Shortcut"""
    
    # Mock system_info
    system_info = {
        'hostname': 'test-host',
        'distro_pretty_name': 'Debian GNU/Linux 12 (bookworm)',
        'kernel_version': '6.1.0-13-amd64',
        'ssh_host': 'test-host',
        'ssh_user': 'test-user',
        'current_user': 'test-user',
        'cpu_usage': '0.0%',
        'memory_usage': '12.2%',
        'load_average': '1.45',
        'uptime_days': '63',
        'docker': {
            'containers': [
                {
                    'name': 'my-prf',
                    'image': 'registry.gitlab.com/profiflitzer-gmbh/my-profiflitzer:latest',
                    'status': 'running',
                    'size': '1.61 GB',
                    'created': '3 weeks ago'
                }
            ]
        },
        'updates': {
            'available': 166
        }
    }
    
    # Mock log_entries
    from datetime import datetime
    log_entries = [
        LogEntry(
            timestamp=datetime.now(),
            level=LogLevel.INFO,
            source="systemd",
            message="System started",
            raw_line="System started"
        )
    ]
    
    # Mock anomalies
    anomalies = []
    
    # Mock args
    class MockArgs:
        def __init__(self):
            self.key_file = None
            self.port = 22
            self.ollama_port = 11434
            self.use_port_forwarding = True
    
    args = MockArgs()
    
    console.print("[bold blue]🧪 Teste echte Chat-Funktion mit Report...[/bold blue]")
    
    # Mock input für Test
    original_input = input
    test_inputs = ['report', 'q']
    input_index = 0
    
    def mock_input(prompt):
        nonlocal input_index
        if input_index < len(test_inputs):
            user_input = test_inputs[input_index]
            input_index += 1
            console.print(f"[dim]Simuliere Eingabe: {user_input}[/dim]")
            return user_input
        else:
            return 'q'
    
    # Ersetze input temporär
    import builtins
    builtins.input = mock_input
    
    try:
        # Starte Chat (wird nach 'q' beendet)
        start_interactive_chat(system_info, log_entries, anomalies, args)
        
        # Prüfe ob Reports erstellt wurden
        reports_dir = "system_reports"
        if os.path.exists(reports_dir):
            files = os.listdir(reports_dir)
            test_files = [f for f in files if f.startswith('system_report_test-host_')]
            console.print(f"[green]✅ {len(test_files)} Test-Reports gefunden[/green]")
            for file in test_files:
                console.print(f"[dim]📄 {file}[/dim]")
        else:
            console.print(f"[red]❌ Keine Reports gefunden[/red]")
            
    except Exception as e:
        console.print(f"[red]❌ Fehler in Chat-Funktion: {e}[/red]")
        import traceback
        traceback.print_exc()
    finally:
        # Stelle original input wieder her
        builtins.input = original_input

if __name__ == "__main__":
    test_real_chat_report() 