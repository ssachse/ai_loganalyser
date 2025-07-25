# 🔍 SSH-based Linux Log Analyzer with Chat

An intelligent log analyzer for Linux systems with SSH access that automatically collects system information, analyzes logs, and provides an interactive chat with AI support.

## 🚀 Features

- **🔍 Automatic System Analysis**: Collects comprehensive system information
- **📊 Log Analysis**: Analyzes system logs with AI support
- **🤖 AI Chat**: Interactive chat with Ollama for system questions
- **🐳 Docker Analysis**: Detailed Docker container analysis
- **☸️ Kubernetes Support**: Kubernetes cluster analysis
- **🖥️ Proxmox Integration**: Proxmox cluster monitoring
- **📧 Mail Server Analysis**: Mailcow, Postfix and other mail servers
- **🔐 Security Analysis**: Network security and CVE checks
- **📄 Automatic Reports**: System reports with `--auto-report` or `--report-and-chat`
- **🔍 CVE Security Analysis**: Real CVE databases (NIST NVD, European DBs) + AI analysis
- **🇪🇺 EU Compliance**: European CVE databases for GDPR and NIS directive
- **🌐 HTML5 Reports**: Interactive HTML5 reports with clickable elements and tabs

## 📦 Installation

### Prerequisites

- Python 3.8+
- SSH access to target system
- Ollama (for AI functions)

### Installation

```bash
# Clone repository
git clone <repository-url>
cd macos-loganalyser

# Install dependencies
pip install -r requirements.txt

# Install Ollama (if not available)
curl -fsSL https://ollama.ai/install.sh | sh
```

## 🎯 Usage

### Basic Usage

```bash
# Simple analysis
python3 ssh_chat_system.py user@hostname

# With password
python3 ssh_chat_system.py user@hostname --password mypassword

# With SSH key
python3 ssh_chat_system.py user@hostname --key-file ~/.ssh/id_rsa
```

### CVE Security Analysis

```bash
# CVE analysis with hybrid approach (NVD + Ollama) - Recommended
python3 ssh_chat_system.py user@hostname --with-cve --cve-database hybrid

# NIST NVD database only
python3 ssh_chat_system.py user@hostname --with-cve --cve-database nvd

# Ollama AI analysis only
python3 ssh_chat_system.py user@hostname --with-cve --cve-database ollama

# European CVE databases (BSI, NCSC, ENISA, CERT-EU)
python3 ssh_chat_system.py user@hostname --with-cve --cve-database european

# Hybrid with European databases
python3 ssh_chat_system.py user@hostname --with-cve --cve-database hybrid-european

# EU compliance mode (GDPR, NIS directive)
python3 ssh_chat_system.py user@hostname --with-cve --cve-database european --eu-compliance

# With caching for better performance
python3 ssh_chat_system.py user@hostname --with-cve --cve-cache

# Offline mode (local data only)
python3 ssh_chat_system.py user@hostname --with-cve --cve-offline
```

### Automatic Reports

```bash
# Generate report only and exit
python3 ssh_chat_system.py user@hostname --auto-report

# Generate report and then start chat
python3 ssh_chat_system.py user@hostname --report-and-chat

# Report with CVE analysis
python3 ssh_chat_system.py user@hostname --auto-report --with-cve --cve-database hybrid

# Report with European CVE analysis
python3 ssh_chat_system.py user@hostname --auto-report --with-cve --cve-database european --eu-compliance

# HTML5 report with clickable elements
python3 ssh_chat_system.py user@hostname --auto-report --html-report

# HTML5 report with CVE analysis
python3 ssh_chat_system.py user@hostname --auto-report --with-cve --html-report
```

### Advanced Options

```bash
# Quick mode (faster analysis)
python3 ssh_chat_system.py user@hostname --quick

# Without log collection
python3 ssh_chat_system.py user@hostname --no-logs

# Debug mode
python3 ssh_chat_system.py user@hostname --debug

# Network security analysis
python3 ssh_chat_system.py user@hostname --include-network-security

# Combined analysis
python3 ssh_chat_system.py user@hostname --with-cve --cve-database hybrid --report-and-chat --include-network-security
```

## 🔧 Available Options

| Option | Description |
|--------|-------------|
| `--username USERNAME` | SSH username |
| `--password PASSWORD` | SSH password |
| `--key-file KEY_FILE` | SSH key file |
| `--port PORT` | SSH port (default: 22) |
| `--ollama-port OLLAMA_PORT` | Ollama port (default: 11434) |
| `--no-port-forwarding` | Disable port forwarding |
| `--hours HOURS` | Log analysis timeframe (default: 24) |
| `--keep-files` | Keep temporary files |
| `--output OUTPUT` | Output directory |
| `--quick` | Quick mode for fast analysis |
| `--no-logs` | Skip log collection |
| `--debug` | Debug mode |
| `--include-network-security` | Network security analysis |
| `--auto-report` | Generate automatic system report |
| `--report-and-chat` | Generate report and start chat |
| `--with-cve` | CVE security analysis |
| `--cve-database {ollama,nvd,hybrid,european,hybrid-european}` | CVE database (default: hybrid) |
| `--cve-cache` | Use local CVE cache |
| `--cve-offline` | Use local CVE data only |
| `--eu-compliance` | Enable EU compliance mode (GDPR, NIS directive) |

## 🔍 CVE Security Analysis

The system supports various CVE databases:

### 🔗 NIST NVD (National Vulnerability Database)
- **Official US government database**
- **Complete CVE data**
- **Free and publicly accessible**
- **Rate limiting**: 5 requests per 6 seconds

### 🇪🇺 European CVE Databases
- **BSI (Germany)**: Federal Office for Information Security
- **NCSC (UK)**: National Cyber Security Centre
- **ENISA (EU)**: European Union Agency for Cybersecurity
- **CERT-EU**: Computer Emergency Response Team for EU Institutions
- **GDPR Compliance**: General Data Protection Regulation
- **NIS Directive**: Network and Information Security Directive

### 🤖 Ollama AI Analysis
- **Intelligent analysis and context understanding**
- **Training-based CVE information**
- **Fast processing**

### 🔄 Hybrid Approaches
- **Hybrid (Standard)**: Combines NVD data with Ollama analysis
- **Hybrid-European**: Combines European DBs with Ollama analysis
- **NVD**: For current, official CVE data
- **European**: For EU-specific compliance and local threats
- **Ollama**: For intelligent analysis and recommendations
- **Caching**: For performance optimization

### 📊 CVE Categories
- **Critical**: CVSS Score ≥ 9.0
- **High**: CVSS Score ≥ 7.0
- **Medium**: CVSS Score ≥ 4.0
- **Low**: CVSS Score < 4.0

## 📄 Example Output

```
🔍 CVE Security Analysis
============================================================
Database: hybrid-european, Cache: Enabled, Offline: No

✅ NVD CVE analysis completed
📊 3 services analyzed
🔍 5 CVEs found
📈 Overall risk: High

✅ Ollama CVE analysis completed
📊 15 packages analyzed
🔧 8 services checked

🇪🇺 European CVE analysis completed
🇪🇺 4 EU databases checked
🔍 3 European CVEs found
🔒 GDPR compliant: Yes
🏛️ NIS directive: Yes

🚨 2 critical CVEs found!
⚠️ 3 high CVEs found

Critical CVEs in: openssh-server, docker-ce
High CVEs in: apache2, nginx, mysql-server
```

## 🎯 Chat Functions

After analysis, you can ask questions:

### System Questions
- `s1` - Which services are running?
- `s2` - Storage space status?
- `s3` - Security issues?
- `s4` - Top processes?
- `s5` - System performance?

### Docker Questions
- `d1` - Docker status and containers?
- `d2` - Docker problems?
- `d3` - Running containers?
- `d4` - Docker images?

### Kubernetes Questions
- `k1` - Cluster status?
- `k2` - Kubernetes problems?
- `k3` - Running pods?

### Proxmox Questions
- `p1` - Proxmox status?
- `p2` - Proxmox problems?
- `p3` - Running VMs?

### Network Security
- `n1` - Complete network security analysis
- `n2` - Externally accessible services
- `n3` - Port scan
- `n4` - Service tests

## 📁 Output

### System Reports
- **Location**: `system_reports/`
- **Format**: Markdown
- **Content**: Complete system analysis with recommendations

### Log Archives
- **Format**: `.tar.gz`
- **Content**: Collected logs and system information

### CVE Cache
- **Location**: `cve_cache.json`
- **Validity**: 24 hours
- **Content**: Cached CVE data for better performance

### European CVE Cache
- **Location**: `european_cve_cache.json`
- **Validity**: 24 hours
- **Content**: Cached European CVE data

### HTML5 Reports
- **Location**: `system_reports/` (`.html` files)
- **Features**: 
  - 📋 Interactive tabs (Summary, Details, Security, Performance)
  - 🔽 Collapsible sections for detailed information
  - 📊 Status cards with hover effects
  - 📈 Progress bars for performance metrics
  - 🎨 Modern, responsive user interface
  - 🌐 Automatic browser opening
  - 📱 Mobile-optimized

## 🔧 Configuration

### NVD API Key (Optional)
For higher rate limits, you can use an NVD API key:

```bash
export NVD_API_KEY="your-api-key-here"
```

### Ollama Models
The system automatically selects the best available model:
- **Complex analyses**: `llama3.2:70b` or `llama3.1:70b`
- **Standard chat**: `llama3.2:8b` or `llama3.1:8b`

## 🐛 Troubleshooting

### SSH Connection Issues
```bash
# Test SSH connection
ssh user@hostname

# Check SSH key permissions
chmod 600 ~/.ssh/id_rsa
```

### Ollama Issues
```bash
# Start Ollama
ollama serve

# Check available models
ollama list
```

### CVE Analysis Issues
```bash
# Test NVD API
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=openssh"

# Delete CVE cache
rm cve_cache.json
rm european_cve_cache.json
```

## 📈 Performance Tips

1. **Quick Mode**: Use `--quick` for fast analyses
2. **Caching**: Enable `--cve-cache` for repeated analyses
3. **Offline Mode**: Use `--cve-offline` for local data
4. **NVD API Key**: For higher rate limits
5. **European DBs**: For EU-specific compliance

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a pull request

## 📄 License

This project is licensed under the MIT License.

## 🔗 Links

- [NIST NVD](https://nvd.nist.gov/) - National Vulnerability Database
- [BSI](https://www.bsi.bund.de/) - Federal Office for Information Security
- [NCSC](https://www.ncsc.gov.uk/) - National Cyber Security Centre
- [ENISA](https://www.enisa.europa.eu/) - European Union Agency for Cybersecurity
- [CERT-EU](https://cert.europa.eu/) - Computer Emergency Response Team for EU Institutions
- [Ollama](https://ollama.ai/) - Local LLM Engine
- [MITRE CVE](https://cve.mitre.org/) - Common Vulnerabilities and Exposures 