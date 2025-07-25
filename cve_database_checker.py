#!/usr/bin/env python3
"""
CVE-Datenbank-Checker für Integration mit echten CVE-Datenbanken
Unterstützt NIST NVD, Caching und Hybrid-Analyse
"""

import requests
import json
import time
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from rich.console import Console

console = Console()

class CVEDatabaseChecker:
    """CVE-Datenbank-Checker für NIST NVD und andere Quellen"""
    
    def __init__(self, cache_file: str = "cve_cache.json", enable_cache: bool = True):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.rate_limit_delay = 1.2  # 5 Requests pro 6 Sekunden = 1.2 Sekunden Pause
        self.cache_file = cache_file
        self.enable_cache = enable_cache
        self.cache = self._load_cache() if enable_cache else {}
        
        # API-Key für höhere Rate Limits (optional)
        self.api_key = os.getenv('NVD_API_KEY')
        if self.api_key:
            console.print("[dim]🔑 NVD API-Key gefunden - Höhere Rate Limits verfügbar[/dim]")
    
    def _load_cache(self) -> Dict:
        """Lädt den CVE-Cache aus der Datei"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
                    console.print(f"[dim]📦 CVE-Cache geladen: {len(cache)} Einträge[/dim]")
                    return cache
        except Exception as e:
            console.print(f"[yellow]⚠️ Fehler beim Laden des CVE-Cache: {e}[/yellow]")
        
        return {}
    
    def _save_cache(self):
        """Speichert den CVE-Cache in die Datei"""
        if not self.enable_cache:
            return
            
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=2, ensure_ascii=False)
            console.print(f"[dim]💾 CVE-Cache gespeichert: {len(self.cache)} Einträge[/dim]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Fehler beim Speichern des CVE-Cache: {e}[/yellow]")
    
    def _is_cache_valid(self, cached_data: Dict) -> bool:
        """Prüft ob gecachte Daten noch gültig sind"""
        if not cached_data:
            return False
        
        timestamp_str = cached_data.get("timestamp")
        ttl_hours = cached_data.get("ttl_hours", 24)
        
        if not timestamp_str:
            return False
        
        try:
            cached_time = datetime.fromisoformat(timestamp_str)
            expiry_time = cached_time + timedelta(hours=ttl_hours)
            return datetime.now() < expiry_time
        except Exception:
            return False
    
    def get_cached_cve(self, service: str, version: str) -> Optional[Dict]:
        """Holt gecachte CVE-Daten"""
        if not self.enable_cache:
            return None
            
        key = f"{service}_{version}"
        cached = self.cache.get(key)
        
        if cached and self._is_cache_valid(cached):
            console.print(f"[dim]📦 Verwende gecachte CVE-Daten für {service} {version}[/dim]")
            return cached["data"]
        
        return None
    
    def cache_cve_data(self, service: str, version: str, data: Dict):
        """Cached CVE-Daten"""
        if not self.enable_cache:
            return
            
        key = f"{service}_{version}"
        self.cache[key] = {
            "data": data,
            "timestamp": datetime.now().isoformat(),
            "ttl_hours": 24  # 24 Stunden gültig
        }
    
    def check_service_vulnerabilities(self, service_name: str, version: str) -> Dict:
        """Prüft einen Service auf CVEs in NVD"""
        
        # Prüfe Cache zuerst
        cached_result = self.get_cached_cve(service_name, version)
        if cached_result:
            return cached_result
        
        console.print(f"[dim]🔍 Prüfe {service_name} {version} in NVD...[/dim]")
        
        vulnerabilities = []
        
        # Suche nach CVEs für den Service
        search_terms = [
            f"{service_name} {version}",
            f"{service_name}",
            f"{service_name} {version.split('.')[0]}"  # Major Version
        ]
        
        for term in search_terms:
            cves = self._search_nvd(term)
            vulnerabilities.extend(cves)
            time.sleep(self.rate_limit_delay)  # Rate Limiting
        
        # Kategorisiere und cache die Ergebnisse
        result = self._categorize_vulnerabilities(vulnerabilities, service_name, version)
        self.cache_cve_data(service_name, version, result)
        
        return result
    
    def _search_nvd(self, search_term: str) -> List[Dict]:
        """Sucht in NVD nach CVEs"""
        params = {
            "keywordSearch": search_term,
            "pubStartDate": "2020-01-01T00:00:00:000 UTC-00:00",
            "pubEndDate": "2025-12-31T23:59:59:999 UTC-00:00"
        }
        
        # Füge API-Key hinzu falls verfügbar
        if self.api_key:
            params["apiKey"] = self.api_key
        
        try:
            response = requests.get(self.nvd_api_url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                console.print(f"[dim]  Gefunden: {len(vulnerabilities)} CVEs für '{search_term}'[/dim]")
                return vulnerabilities
            elif response.status_code == 429:
                console.print(f"[yellow]⚠️ Rate Limit erreicht für '{search_term}' - Warte länger...[/yellow]")
                time.sleep(self.rate_limit_delay * 2)  # Doppelte Wartezeit
                return []
            else:
                console.print(f"[yellow]⚠️ NVD API Fehler {response.status_code} für '{search_term}'[/yellow]")
                
        except requests.exceptions.Timeout:
            console.print(f"[yellow]⚠️ Timeout bei NVD API für '{search_term}'[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠️ NVD API Fehler für '{search_term}': {e}[/yellow]")
        
        return []
    
    def _categorize_vulnerabilities(self, vulnerabilities: List[Dict], service_name: str, version: str) -> Dict:
        """Kategorisiert CVEs nach Schweregrad"""
        categorized = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "summary": {
                "total": len(vulnerabilities),
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "service": service_name,
                "version": version
            }
        }
        
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "Unknown")
            description = cve_data.get("descriptions", [{}])[0].get("value", "Keine Beschreibung verfügbar")
            
            # CVSS v3.1 Score verwenden
            metrics = cve_data.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
            base_score = cvss_v31.get("cvssData", {}).get("baseScore", 0)
            
            # Erstelle strukturierte CVE-Information
            cve_info = {
                "id": cve_id,
                "description": description,
                "base_score": base_score,
                "published": cve_data.get("published", "Unknown"),
                "last_modified": cve_data.get("lastModified", "Unknown"),
                "cvss_data": cvss_v31.get("cvssData", {}),
                "references": cve_data.get("references", [])
            }
            
            # Kategorisiere nach CVSS Score
            if base_score >= 9.0:
                categorized["critical"].append(cve_info)
                categorized["summary"]["critical"] += 1
            elif base_score >= 7.0:
                categorized["high"].append(cve_info)
                categorized["summary"]["high"] += 1
            elif base_score >= 4.0:
                categorized["medium"].append(cve_info)
                categorized["summary"]["medium"] += 1
            else:
                categorized["low"].append(cve_info)
                categorized["summary"]["low"] += 1
        
        return categorized
    
    def get_cve_summary(self, service_results: Dict[str, Dict]) -> Dict:
        """Erstellt eine Zusammenfassung aller CVE-Ergebnisse"""
        total_summary = {
            "total_services": len(service_results),
            "total_cves": 0,
            "critical_cves": 0,
            "high_cves": 0,
            "medium_cves": 0,
            "low_cves": 0,
            "services_with_critical": [],
            "services_with_high": [],
            "overall_risk": "Low"
        }
        
        for service_name, result in service_results.items():
            summary = result.get("summary", {})
            total_summary["total_cves"] += summary.get("total", 0)
            total_summary["critical_cves"] += summary.get("critical", 0)
            total_summary["high_cves"] += summary.get("high", 0)
            total_summary["medium_cves"] += summary.get("medium", 0)
            total_summary["low_cves"] += summary.get("low", 0)
            
            if summary.get("critical", 0) > 0:
                total_summary["services_with_critical"].append(service_name)
            if summary.get("high", 0) > 0:
                total_summary["services_with_high"].append(service_name)
        
        # Bestimme Gesamtrisiko
        if total_summary["critical_cves"] > 0:
            total_summary["overall_risk"] = "Critical"
        elif total_summary["high_cves"] > 0:
            total_summary["overall_risk"] = "High"
        elif total_summary["medium_cves"] > 0:
            total_summary["overall_risk"] = "Medium"
        else:
            total_summary["overall_risk"] = "Low"
        
        return total_summary
    
    def cleanup_cache(self, max_age_hours: int = 168):  # 7 Tage
        """Bereinigt alte Cache-Einträge"""
        if not self.enable_cache:
            return
            
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        old_keys = []
        
        for key, cached_data in self.cache.items():
            timestamp_str = cached_data.get("timestamp")
            if timestamp_str:
                try:
                    cached_time = datetime.fromisoformat(timestamp_str)
                    if cached_time < cutoff_time:
                        old_keys.append(key)
                except Exception:
                    old_keys.append(key)
        
        for key in old_keys:
            del self.cache[key]
        
        if old_keys:
            console.print(f"[dim]🧹 {len(old_keys)} alte Cache-Einträge bereinigt[/dim]")
            self._save_cache()

class CVEAnalyzer:
    """Hauptklasse für CVE-Analyse mit Hybrid-Ansatz"""
    
    def __init__(self, enable_cache: bool = True, cache_file: str = "cve_cache.json"):
        self.cve_checker = CVEDatabaseChecker(cache_file, enable_cache)
        self.enable_cache = enable_cache
    
    def analyze_services(self, service_versions: Dict[str, str]) -> Dict[str, Any]:
        """Analysiert Services auf CVEs mit Hybrid-Ansatz"""
        
        console.print("[bold blue]🔍 CVE-Datenbank-Analyse[/bold blue]")
        console.print("="*60)
        
        results = {
            "database_results": {},
            "summary": {},
            "analysis_time": datetime.now().isoformat(),
            "services_analyzed": len(service_versions)
        }
        
        # 1. Echte CVE-Datenbanken abfragen
        for service, version in service_versions.items():
            console.print(f"[dim]Prüfe {service} {version} in NVD...[/dim]")
            vulns = self.cve_checker.check_service_vulnerabilities(service, version)
            results["database_results"][service] = vulns
        
        # 2. Erstelle Zusammenfassung
        results["summary"] = self.cve_checker.get_cve_summary(results["database_results"])
        
        # 3. Speichere Cache
        if self.enable_cache:
            self.cve_checker._save_cache()
        
        # 4. Zeige Ergebnisse
        self._display_results(results)
        
        return results
    
    def _display_results(self, results: Dict[str, Any]):
        """Zeigt CVE-Analyse-Ergebnisse an"""
        summary = results["summary"]
        
        console.print(f"\n[bold green]✅ CVE-Analyse abgeschlossen[/bold green]")
        console.print(f"[dim]📊 {summary['total_services']} Services analysiert[/dim]")
        console.print(f"[dim]🔍 {summary['total_cves']} CVEs gefunden[/dim]")
        
        if summary['critical_cves'] > 0:
            console.print(f"[bold red]🚨 {summary['critical_cves']} kritische CVEs gefunden![/bold red]")
        if summary['high_cves'] > 0:
            console.print(f"[bold yellow]⚠️ {summary['high_cves']} hohe CVEs gefunden[/bold yellow]")
        
        console.print(f"[dim]📈 Gesamtrisiko: {summary['overall_risk']}[/dim]")
        
        # Zeige Services mit kritischen/hohen CVEs
        if summary['services_with_critical']:
            console.print(f"[red]Kritische CVEs in: {', '.join(summary['services_with_critical'])}[/red]")
        if summary['services_with_high']:
            console.print(f"[yellow]Hohe CVEs in: {', '.join(summary['services_with_high'])}[/yellow]")

def create_cve_report_content(cve_results: Dict[str, Any]) -> str:
    """Erstellt einen formatierten CVE-Report"""
    
    summary = cve_results.get("summary", {})
    database_results = cve_results.get("database_results", {})
    
    report = f"""## CVE-SICHERHEITSANALYSE (NVD-Datenbank)

### ZUSAMMENFASSUNG
- **Analysierte Services**: {summary.get('total_services', 0)}
- **Gefundene CVEs**: {summary.get('total_cves', 0)}
- **Kritische CVEs**: {summary.get('critical_cves', 0)}
- **Hohe CVEs**: {summary.get('high_cves', 0)}
- **Mittlere CVEs**: {summary.get('medium_cves', 0)}
- **Niedrige CVEs**: {summary.get('low_cves', 0)}
- **Gesamtrisiko**: {summary.get('overall_risk', 'Unknown')}

"""
    
    # Kritische CVEs
    if summary.get('critical_cves', 0) > 0:
        report += "### KRITISCHE SICHERHEITSLÜCKEN (Critical)\n"
        for service_name in summary.get('services_with_critical', []):
            service_data = database_results.get(service_name, {})
            for cve in service_data.get('critical', []):
                report += f"- **{service_name}** {cve['id']}: {cve['description'][:100]}... (CVSS: {cve['base_score']})\n"
        report += "\n"
    
    # Hohe CVEs
    if summary.get('high_cves', 0) > 0:
        report += "### HOHE SICHERHEITSLÜCKEN (High)\n"
        for service_name in summary.get('services_with_high', []):
            service_data = database_results.get(service_name, {})
            for cve in service_data.get('high', []):
                report += f"- **{service_name}** {cve['id']}: {cve['description'][:100]}... (CVSS: {cve['base_score']})\n"
        report += "\n"
    
    # Detaillierte Service-Analyse
    report += "### DETAILLIERTE SERVICE-ANALYSE\n"
    for service_name, service_data in database_results.items():
        service_summary = service_data.get('summary', {})
        if service_summary.get('total', 0) > 0:
            report += f"\n**{service_name}** (Version: {service_summary.get('version', 'Unknown')}):\n"
            report += f"- Kritische CVEs: {service_summary.get('critical', 0)}\n"
            report += f"- Hohe CVEs: {service_summary.get('high', 0)}\n"
            report += f"- Mittlere CVEs: {service_summary.get('medium', 0)}\n"
            report += f"- Niedrige CVEs: {service_summary.get('low', 0)}\n"
    
    # Empfehlungen
    report += "\n### SOFORTIGE MASSNAHMEN\n"
    if summary.get('critical_cves', 0) > 0:
        report += "1. **KRITISCH**: Sofortige Updates für Services mit kritischen CVEs\n"
    if summary.get('high_cves', 0) > 0:
        report += "2. **HOCH**: Prioritäre Updates für Services mit hohen CVEs\n"
    if summary.get('medium_cves', 0) > 0:
        report += "3. **MITTEL**: Geplante Updates für Services mit mittleren CVEs\n"
    
    report += f"4. **ÜBERWACHUNG**: Regelmäßige CVE-Prüfungen implementieren\n"
    report += f"5. **PATCH-MANAGEMENT**: Automatisierte Update-Prozesse einrichten\n"
    
    return report

if __name__ == "__main__":
    # Test der CVE-Datenbank-Integration
    analyzer = CVEAnalyzer(enable_cache=True)
    
    # Test-Services
    test_services = {
        "openssh-server": "1:7.9p1-10+deb10u2",
        "apache2": "2.4.38-3+deb10u8",
        "docker-ce": "20.10.17-3~debian10"
    }
    
    results = analyzer.analyze_services(test_services)
    print("\n" + "="*60)
    print("CVE-REPORT:")
    print("="*60)
    print(create_cve_report_content(results)) 