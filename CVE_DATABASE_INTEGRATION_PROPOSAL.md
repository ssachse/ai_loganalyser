# 🔗 CVE-Datenbank-Integration Vorschlag

## Aktuelle Situation

Das `--with-cve` Feature verwendet aktuell **nur Ollama KI-Modelle** für die CVE-Analyse. Die KI-Modelle haben Zugang zu CVE-Informationen aus ihrem Training, aber dies ist nicht optimal für aktuelle und vollständige CVE-Daten.

## 🎯 Verbesserungsvorschlag: Echte CVE-Datenbanken integrieren

### 1. **NIST NVD (National Vulnerability Database)**
```python
# Beispiel-Integration
import requests

def check_nvd_cve(service_name: str, version: str) -> List[Dict]:
    """Prüft NVD für CVEs für einen spezifischen Service"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": f"{service_name} {version}",
        "pubStartDate": "2020-01-01T00:00:00:000 UTC-00:00",
        "pubEndDate": "2025-12-31T23:59:59:999 UTC-00:00"
    }
    
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json().get("vulnerabilities", [])
    return []
```

**Vorteile:**
- ✅ Offizielle US-Regierungs-Datenbank
- ✅ Vollständige CVE-Daten
- ✅ Kostenlos und öffentlich zugänglich
- ✅ Regelmäßige Updates
- ✅ API verfügbar

**Nachteile:**
- ❌ Rate-Limiting (5 Requests pro 6 Sekunden)
- ❌ Langsame API-Antworten
- ❌ Komplexe JSON-Struktur

### 2. **MITRE CVE Database**
```python
def check_mitre_cve(cve_id: str) -> Dict:
    """Holt detaillierte CVE-Informationen von MITRE"""
    url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    # Web Scraping oder API-Call
```

**Vorteile:**
- ✅ Offizielle CVE-Quelle
- ✅ Vollständige CVE-Details
- ✅ Autoritative Quelle

**Nachteile:**
- ❌ Keine direkte API
- ❌ Web Scraping erforderlich
- ❌ Langsam

### 3. **Vulners API**
```python
def check_vulners_api(service_name: str, version: str) -> List[Dict]:
    """Prüft Vulners für CVEs"""
    url = "https://vulners.com/api/v3/search/exploit/"
    headers = {"Content-Type": "application/json"}
    data = {
        "query": f"affectedSoftware.name:{service_name} AND affectedSoftware.version:{version}",
        "size": 100
    }
    
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        return response.json().get("data", {}).get("search", [])
    return []
```

**Vorteile:**
- ✅ Schnelle API
- ✅ Umfassende Datenbank
- ✅ Gute Dokumentation

**Nachteile:**
- ❌ Kostenpflichtig für kommerzielle Nutzung
- ❌ API-Key erforderlich

### 4. **CVE Details**
```python
def check_cve_details(service_name: str, version: str) -> List[Dict]:
    """Prüft CVE Details für CVEs"""
    url = f"https://www.cvedetails.com/json-feed.php"
    params = {
        "numrows": 100,
        "vendor_id": None,
        "product_id": None,
        "version_id": None,
        "hasexp": True,
        "opec": 1,
        "opov": 1,
        "oprf": 1,
        "oprs": 1,
        "opch": 1,
        "opcsrf": 1,
        "opgpriv": 1,
        "opsqli": 1,
        "opxss": 1,
        "opdirt": 1,
        "oprinf": 1,
        "opfileinc": 1,
        "opginf": 1,
        "cvssscoremin": 0,
        "cvssscoremax": 10,
        "year": 2024,
        "month": None,
        "cweid": None,
        "order": 1,
        "trc": 100,
        "sha": None
    }
    
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json()
    return []
```

**Vorteile:**
- ✅ Kostenlos
- ✅ JSON-API verfügbar
- ✅ Gute Filteroptionen

**Nachteile:**
- ❌ Nicht offiziell
- ❌ Möglicherweise unvollständig

## 🔧 Implementierungsvorschlag

### Phase 1: NIST NVD Integration
```python
class CVEDatabaseChecker:
    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.rate_limit_delay = 1.2  # 5 Requests pro 6 Sekunden = 1.2 Sekunden Pause
    
    def check_service_vulnerabilities(self, service_name: str, version: str) -> Dict:
        """Prüft einen Service auf CVEs in NVD"""
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
        
        return self._categorize_vulnerabilities(vulnerabilities)
    
    def _search_nvd(self, search_term: str) -> List[Dict]:
        """Sucht in NVD nach CVEs"""
        params = {
            "keywordSearch": search_term,
            "pubStartDate": "2020-01-01T00:00:00:000 UTC-00:00",
            "pubEndDate": "2025-12-31T23:59:59:999 UTC-00:00"
        }
        
        try:
            response = requests.get(self.nvd_api_url, params=params)
            if response.status_code == 200:
                data = response.json()
                return data.get("vulnerabilities", [])
        except Exception as e:
            console.print(f"[yellow]⚠️ NVD API Fehler: {e}[/yellow]")
        
        return []
    
    def _categorize_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict:
        """Kategorisiert CVEs nach Schweregrad"""
        categorized = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            metrics = cve_data.get("metrics", {})
            
            # CVSS v3.1 Score verwenden
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
            base_score = cvss_v31.get("cvssData", {}).get("baseScore", 0)
            
            if base_score >= 9.0:
                categorized["critical"].append(cve_data)
            elif base_score >= 7.0:
                categorized["high"].append(cve_data)
            elif base_score >= 4.0:
                categorized["medium"].append(cve_data)
            else:
                categorized["low"].append(cve_data)
        
        return categorized
```

### Phase 2: Hybrid-Ansatz
```python
def enhanced_cve_analysis(self, service_versions: Dict[str, str]) -> Dict[str, Any]:
    """Erweiterte CVE-Analyse mit echten Datenbanken + Ollama"""
    
    cve_checker = CVEDatabaseChecker()
    results = {
        "database_results": {},
        "ollama_analysis": None,
        "combined_analysis": {}
    }
    
    # 1. Echte CVE-Datenbanken abfragen
    for service, version in service_versions.items():
        console.print(f"[dim]Prüfe {service} {version} in NVD...[/dim]")
        vulns = cve_checker.check_service_vulnerabilities(service, version)
        results["database_results"][service] = vulns
    
    # 2. Ollama für zusätzliche Analyse
    ollama_prompt = self._create_enhanced_cve_prompt(
        service_versions, 
        results["database_results"]
    )
    results["ollama_analysis"] = self._perform_cve_analysis_with_ollama(ollama_prompt)
    
    # 3. Kombiniere Ergebnisse
    results["combined_analysis"] = self._combine_cve_results(
        results["database_results"], 
        results["ollama_analysis"]
    )
    
    return results
```

## 📊 Vergleich: Aktuell vs. Verbessert

| Aspekt | Aktuell (Ollama) | Verbessert (NVD + Ollama) |
|--------|------------------|---------------------------|
| **Aktualität** | Training-abhängig | ✅ Echtzeit |
| **Vollständigkeit** | Begrenzt | ✅ Vollständig |
| **Geschwindigkeit** | ✅ Schnell | ⚠️ Langsamer (Rate Limiting) |
| **Zuverlässigkeit** | ⚠️ KI-abhängig | ✅ Offiziell |
| **Kosten** | ✅ Kostenlos | ✅ Kostenlos (NVD) |
| **Wartung** | ✅ Einfach | ⚠️ API-Änderungen |

## 🎯 Empfohlene Implementierung

### Schritt 1: NIST NVD Integration
- Implementiere NVD API-Calls
- Rate Limiting beachten
- Caching für Performance

### Schritt 2: Hybrid-Ansatz
- Kombiniere NVD-Daten mit Ollama-Analyse
- Ollama für Kontext und Empfehlungen
- NVD für aktuelle CVE-Daten

### Schritt 3: Erweiterte Features
- Lokales CVE-Caching
- Automatische Updates
- CVSS-Scoring

## 🔧 Konfigurationsoptionen

```python
# Neue Konfigurationsoptionen
parser.add_argument('--cve-database', choices=['ollama', 'nvd', 'hybrid'], 
                   default='hybrid', help='CVE-Datenbank für Analyse')
parser.add_argument('--cve-cache', action='store_true', 
                   help='Verwende lokalen CVE-Cache')
parser.add_argument('--cve-offline', action='store_true', 
                   help='Nur lokale CVE-Daten verwenden')
```

## 📈 Performance-Optimierung

### Caching-Strategie
```python
class CVECache:
    def __init__(self, cache_file: str = "cve_cache.json"):
        self.cache_file = cache_file
        self.cache = self._load_cache()
    
    def get_cached_cve(self, service: str, version: str) -> Optional[Dict]:
        """Holt gecachte CVE-Daten"""
        key = f"{service}_{version}"
        cached = self.cache.get(key)
        
        if cached and self._is_cache_valid(cached):
            return cached["data"]
        return None
    
    def cache_cve_data(self, service: str, version: str, data: Dict):
        """Cached CVE-Daten"""
        key = f"{service}_{version}"
        self.cache[key] = {
            "data": data,
            "timestamp": datetime.now().isoformat(),
            "ttl_hours": 24  # 24 Stunden gültig
        }
        self._save_cache()
```

## 🚀 Fazit

Die Integration echter CVE-Datenbanken würde die Qualität und Aktualität der CVE-Analyse erheblich verbessern. Ein Hybrid-Ansatz mit NVD + Ollama wäre optimal:

- **NVD**: Für aktuelle, offizielle CVE-Daten
- **Ollama**: Für intelligente Analyse und Empfehlungen
- **Caching**: Für Performance-Optimierung

Soll ich diese Verbesserung implementieren? 🤔 