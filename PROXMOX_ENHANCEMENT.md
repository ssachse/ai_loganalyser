# 🖥️ Erweiterte Proxmox-Integration

## Übersicht

Das SSH-Log-Analyzer-System wurde um umfangreiche Proxmox VE-Integration erweitert. Diese Erweiterung ermöglicht:

1. **Automatische Proxmox-Datensammlung** beim ersten System-Scan
2. **Gezielte Proxmox-Updates** per Chat-Befehl
3. **Strukturierte Darstellung** von VMs, Containern und Cluster-Status
4. **Intelligente Kontext-Integration** für bessere AI-Antworten

## 🚀 Neue Funktionen

### 1. Automatische Proxmox-Erkennung

Beim ersten System-Scan wird automatisch erkannt, ob Proxmox VE installiert ist:

```bash
python ssh_chat_system.py --host your-proxmox-host --username root
```

**Erkannte Proxmox-Komponenten:**
- ✅ Proxmox VE Installation (`pvesh`)
- ✅ Cluster-Status und Konfiguration
- ✅ Node-Informationen
- ✅ Storage-Status (ZFS, Ceph)
- ✅ HA (High Availability) Status
- ✅ Backup-Jobs und Tasks

### 2. Chat-Befehle für Proxmox-Updates

#### Grundlegende Refresh-Befehle

```bash
# Alle Proxmox-Daten aktualisieren
proxmox-refresh

# Nur VM-Daten aktualisieren
proxmox-refresh vms

# Nur Container-Daten aktualisieren
proxmox-refresh containers

# Nur Storage-Informationen aktualisieren
proxmox-refresh storage

# Nur Cluster-Status aktualisieren
proxmox-refresh cluster

# Nur HA-Status aktualisieren
proxmox-refresh ha

# Nur aktuelle Tasks anzeigen
proxmox-refresh tasks

# Nur Backup-Jobs anzeigen
proxmox-refresh backups
```

#### Status-Befehle

```bash
# Aktuellen Cluster-Status anzeigen
proxmox-status
```

### 3. Erweiterte Shortcuts

Zusätzlich zu den bestehenden Shortcuts stehen neue Proxmox-spezifische Kürzel zur Verfügung:

```bash
# Proxmox-Grundstatus
proxmox

# Proxmox-Probleme identifizieren
proxmox-problems

# Laufende VMs anzeigen
proxmox-vms

# Laufende Container anzeigen
proxmox-containers

# Speicherplatz-Status
proxmox-storage
```

### 4. Intelligente Interpolation

Das System kann natürliche Sprache zu Proxmox-Shortcuts mappen:

- **"LXC"** → `proxmox-containers`
- **"Container"** → `proxmox-containers`
- **"VMs"** → `proxmox-vms`
- **"Proxmox-Speicher"** → `proxmox-storage`

## 📊 Datenstruktur

### Automatisch gesammelte Daten

```json
{
  "proxmox_detected": true,
  "proxmox_version": "pve-manager/8.1.4/...",
  "cluster_status": "...",
  "nodes": "...",
  "storage": "...",
  "ha_status": "...",
  "zfs_status": "...",
  "ceph_status": "...",
  "problems": [...],
  "problems_count": 2
}
```

### Refresh-Daten (strukturiert)

```json
{
  "proxmox": {
    "node1_vms": "[{vmid: 100, name: 'vm1', status: 'running', ...}]",
    "node1_containers": "[{vmid: 200, name: 'ct1', status: 'running', ...}]",
    "node1_status": "{cpu: 15, memory: {...}}",
    "node1_tasks": "[{id: 'UPID:node1:...', type: 'vzdump', ...}]",
    "cluster_status": "[{node: 'node1', status: 'online', ...}]",
    "storage": "[{storage: 'local', type: 'dir', ...}]"
  }
}
```

## 🔧 Technische Details

### SSH-Verbindung

Das System verwendet die bestehende SSH-Infrastruktur:

```python
# Automatische SSH-Verbindung für Proxmox-Befehle
collector = SSHLogCollector(host, username, key_file)
refresh_data = collector.refresh_proxmox_data("all")
```

### JSON-Parsing

Alle Proxmox-Daten werden als JSON gesammelt und strukturiert:

```python
# Beispiel für VM-Daten
vms_data = json.loads(proxmox_data['node1_vms'])
for vm in vms_data:
    print(f"VM {vm['vmid']}: {vm['name']} ({vm['status']})")
```

### Kontext-Integration

Proxmox-Daten werden automatisch in den Systemkontext integriert:

```
=== PROXMOX-CLUSTER ===
Version: pve-manager/8.1.4/...

=== PROXMOX-VMs ===
node1:
  VM 100: webserver (running) - CPU: 5%, RAM: 2048MB
  VM 101: database (running) - CPU: 12%, RAM: 4096MB

=== PROXMOX-CONTAINER ===
node1:
  CT 200: webapp (running) - CPU: 2%, RAM: 512MB
```

## 🧪 Testing

### Test-Skript ausführen

```bash
python test_proxmox_enhanced.py
```

**Testet:**
- ✅ SSH-Verbindung zu Proxmox-Host
- ✅ Refresh-Funktionen für alle Targets
- ✅ Integration in Systemkontext
- ✅ Chat-Befehlserkennung

### Manuelle Tests

```bash
# 1. Starte Chat-System
python ssh_chat_system.py --host your-proxmox-host --username root

# 2. Teste Refresh-Befehle
proxmox-refresh
proxmox-refresh vms
proxmox-status

# 3. Teste Shortcuts
proxmox-vms
proxmox-containers
proxmox-storage

# 4. Teste natürliche Sprache
"Welche VMs laufen?"
"Zeige mir die Container"
"LXC Status"
```

## 🎯 Verwendungsszenarien

### 1. System-Monitoring

```bash
# Täglicher Status-Check
proxmox-refresh
proxmox-problems
```

### 2. VM/Container-Management

```bash
# VM-Übersicht
proxmox-refresh vms
proxmox-vms

# Container-Übersicht
proxmox-refresh containers
proxmox-containers
```

### 3. Storage-Monitoring

```bash
# Storage-Status
proxmox-refresh storage
proxmox-storage
```

### 4. Cluster-Überwachung

```bash
# Cluster-Status
proxmox-refresh cluster
proxmox-status
```

## 🔍 Troubleshooting

### Häufige Probleme

#### 1. SSH-Verbindung fehlgeschlagen

```bash
# Prüfe SSH-Zugriff
ssh root@your-proxmox-host

# Prüfe SSH-Key
python ssh_chat_system.py --host your-proxmox-host --username root --key-file ~/.ssh/id_rsa
```

#### 2. Proxmox nicht erkannt

```bash
# Prüfe Proxmox-Installation
ssh root@your-proxmox-host "which pvesh"

# Prüfe Proxmox-Status
ssh root@your-proxmox-host "pvesh get /nodes"
```

#### 3. Refresh-Befehle funktionieren nicht

```bash
# Prüfe Proxmox-API-Zugriff
ssh root@your-proxmox-host "pvesh get /nodes --output-format=json"

# Prüfe Berechtigungen
ssh root@your-proxmox-host "pvesh get /nodes"
```

### Debug-Modus

```bash
# Starte mit Debug-Informationen
python ssh_chat_system.py --host your-proxmox-host --username root --debug
```

## 📈 Performance-Optimierungen

### 1. Selektive Updates

Verwenden Sie gezielte Refresh-Befehle für bessere Performance:

```bash
# Nur VMs (schneller als "all")
proxmox-refresh vms

# Nur Container (schneller als "all")
proxmox-refresh containers
```

### 2. Caching

Das System verwendet intelligentes Caching:

- **Context Cache**: Proxmox-Antworten werden gecacht
- **Automatische Cache-Invalidierung**: Bei Refresh-Befehlen
- **Topic-basiertes Caching**: Separate Caches für VMs, Container, etc.

### 3. JSON-Optimierung

- Alle Proxmox-Daten werden als JSON gesammelt
- Strukturierte Darstellung für bessere AI-Analyse
- Automatische Fehlerbehandlung bei JSON-Parsing

## 🔮 Zukünftige Erweiterungen

### Geplante Features

1. **Proxmox-Aktionen**: VM starten/stoppen per Chat
2. **Backup-Management**: Backup-Jobs erstellen/verwalten
3. **Performance-Monitoring**: Detaillierte Ressourcen-Überwachung
4. **Alerting**: Automatische Benachrichtigungen bei Problemen
5. **Multi-Cluster**: Unterstützung für mehrere Proxmox-Cluster

### API-Erweiterungen

```python
# Geplante API-Methoden
collector.start_vm(vmid)
collector.stop_vm(vmid)
collector.create_backup(vmid)
collector.get_performance_metrics(node)
```

## 📝 Changelog

### Version 1.0 (Aktuell)

- ✅ Automatische Proxmox-Erkennung
- ✅ Refresh-Befehle für alle Proxmox-Komponenten
- ✅ Strukturierte JSON-Datensammlung
- ✅ Integration in Systemkontext
- ✅ Chat-Befehle und Shortcuts
- ✅ Intelligente Interpolation
- ✅ Umfassende Test-Suite

---

**💡 Tipp:** Verwenden Sie `proxmox-refresh` regelmäßig, um aktuelle Daten zu erhalten, bevor Sie spezifische Fragen stellen! 