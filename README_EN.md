# AI Log-Analyzer with Kubernetes Support

An intelligent SSH-based Linux log analyzer with integrated Ollama chat and Kubernetes cluster analysis.

## 🌍 **Dynamic AI-driven Internationalization**
- **POSIX-compliant**: Uses standard gettext without external dependencies
- **Automatic Language Detection**: Detects language from shell locale (`LANG`, `LC_ALL`, `LC_MESSAGES`)
- **Supported Languages**: German (default) and English
- **Dynamic Translation**: Automatic AI translation for unknown locales
- **Ollama Integration**: Real-time translation generation with AI
- **Fallback System**: Robust translations even without gettext files
- **Persistence**: Dynamic translations are saved and reused
- **Runtime Language Switching**: Switch between languages at runtime

## 🚀 Features

### 🔍 **Comprehensive System Analysis**
- **Basic System Information**: Hostname, distribution, kernel, CPU, RAM, uptime
- **Storage Analysis**: Disk usage, largest files and directories
- **Service Status**: Running services and processes
- **Security Analysis**: Logins, failed login attempts
- **Performance Monitoring**: CPU, memory, load average

### ☸️ **Kubernetes Cluster Analysis**
- **Automatic Detection**: Checks `kubectl` and `k9s` availability
- **Cluster Information**: Version, nodes, namespaces, pods, services
- **Problem Detection**: Not-ready nodes, not-running pods, critical events
- **Resource Monitoring**: Node and pod resource usage
- **Storage Analysis**: Persistent volumes and their status

### 🤖 **Intelligent Ollama Chat**
- **Dynamic Model Selection**: Intelligent selection based on complexity
- **Shortcuts**: Quick access to frequent questions
- **Intelligent Caching**: Optimized performance for repeated questions
- **Automatic System Analysis**: Detailed insights on startup
- **German Translations**: Fully localized user interface
- **Automatic Report Generation**: Professional system reports with action items

### ⚡ **Performance Optimizations**
- **Quick Mode**: Skips time-consuming analyses
- **Intelligent Error Handling**: Grouped error summaries
- **Model Selection**: Automatic complexity detection
- **Cache System**: Avoids redundant API calls
- **Asynchronous Analysis**: Background analysis for immediate menu display
- **Debug Mode**: Detailed outputs for developers

## 📋 Requirements

### System Requirements
- **Python 3.8+**
- **SSH access** to target system
- **Ollama** locally installed and running
- **kubectl** (optional, for Kubernetes analysis)

### Python Packages
```bash
pip install rich requests paramiko
```

## 🛠️ Installation

1. **Clone Repository**:
```bash
git clone https://github.com/ssachse/ai_loganalyser.git
cd ai_loganalyser
```

2. **Install Dependencies**:
```bash
pip install -r requirements.txt
```

3. **Start Ollama**:
```bash
ollama serve
```

## 🚀 Usage

### Basic Usage
```bash
python3 ssh_chat_system.py user@hostname
```

### Advanced Options
```bash
# Quick mode (fast analysis)
python3 ssh_chat_system.py user@hostname --quick

# Without log collection (system info only)
python3 ssh_chat_system.py user@hostname --no-logs

# Debug mode (detailed outputs)
python3 ssh_chat_system.py user@hostname --debug

# Custom SSH parameters
python3 ssh_chat_system.py user@hostname --port 2222 --key-file ~/.ssh/id_rsa

# Keep temporary files
python3 ssh_chat_system.py user@hostname --keep-files
```

### Chat Shortcuts
```
services    - Which services are running on the system?
storage     - How is the storage space?
security    - Are there security issues?
performance - How is the system performance?
users       - Which users are active?
updates     - Are there available system updates?
logs        - What do the logs show?
k8s         - How is the Kubernetes cluster status?
k8s-problems- What Kubernetes problems are there?
k8s-pods    - Which pods are running in the cluster?
k8s-nodes   - How is the node status?
k8s-resources- How is the resource usage in the cluster?
proxmox     - How is the Proxmox VE status?
proxmox-problems- What Proxmox problems are there?
proxmox-vms - Which VMs are running on Proxmox?
proxmox-containers- Which containers are running on Proxmox?
proxmox-storage- How is the Proxmox storage space?
report      - Create a detailed system report with action items
help        - Show available shortcuts
```

## 🔧 Configuration

### SSH Connection
- **Default Port**: 22
- **Authentication**: Password or SSH key
- **Timeout**: 30 seconds per command

### Ollama Integration
- **Default Port**: 11434
- **Models**: Intelligent selection based on model names and complexity
- **Cache**: Intelligent caching for optimal performance
- **Model Priorities**: 
  - **Menu**: `qwen:0.5b` (ultra-fast)
  - **Simple Analysis**: `qwen:0.5b` → `llama3.2:3b`
  - **Complex Analysis**: `llama3.1:8b` → `deepseek-r1:14b` → `mistral:7b`
- **Report Generation**: Uses `llama3.1:8b` for professional reports

### Kubernetes Analysis
- **Automatic Detection**: Checks `kubectl` availability
- **Permissions**: Requires cluster access
- **Error Handling**: Grouped kubectl errors

### 📊 **Automatic Report Generation**
- **CRAFT Prompt**: Professional Enterprise Architect prompt
- **Markdown Export**: Structured reports as `.md` files
- **Automatic Storage**: `system_reports/` directory with timestamp
- **German Reports**: Fully German-generated reports
- **Structured Output**: Executive Summary, action overview, detailed action plan
- **Prioritization**: Impact/effort assessment with Quick Wins → Mid-Term → Long-Term

## 📊 Output Examples

### System Overview
```
📊 System Overview
============================================================
                    System Basic Information                     
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property             ┃ Value                                   ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Hostname             │ server.example.com                      │
│ Distribution         │ Ubuntu 22.04.5 LTS                      │
│ Kernel               │ 5.15.0-139-generic                      │
│ CPU                  │ AMD EPYC-Rome Processor                 │
│ RAM                  │ 30Gi                                    │
└──────────────────────┴──────────────────────────────────────────┘
```

### Kubernetes Cluster
```
☸️ Kubernetes Cluster
============================================================
Cluster Information:
Kubernetes control plane is running at https://142.132.176.3:6443

⚠️  3 problems found:
- Not-ready nodes
- Not-running pods  
- Problematic persistent volumes
```

### Intelligent Error Handling
```
⚠️  Error Summary (8 errors):

🔒 Permission Denied (5 errors):
   Further analysis not possible due to missing permissions.
   Affected areas:
   • Storage analysis
   • Log file access

💡 Tip: Use a user with extended permissions for complete analysis.
```

### 📄 **Automatic Report Generation**
```
✅ Report successfully created:
📄 system_reports/system_report_server_20250723_143022.md

# System Report: server.example.com

**Created on:** 23.07.2025 at 14:30
**System:** server.example.com
**Distribution:** Ubuntu 22.04.5 LTS
**Kernel:** 5.15.0-139-generic

---

## Executive Summary

The system shows several critical points that require immediate attention.

## Prioritized Action Overview

| ID | Topic | Action | Impact | Effort | Priority |
|----|-------|--------|--------|--------|----------|
| 1 | Storage | Extend root partition | High | Medium | Critical |
| 2 | Security | Harden SSH configuration | High | Low | High |
| 3 | Performance | Implement log rotation | Medium | Low | Medium |

## Detailed Action Plan

### 1. Storage Optimization
- **What:** Extend root partition or migrate data
- **Why:** 75% usage is critical
- **How:** Extend LVM or move /var to separate partition
- **Effort:** 2-4 hours
- **Responsible:** System Administrator
```

## 🔒 Security

### SSH Security
- **Encrypted Connection**: Standard SSH encryption
- **Key-based Authentication**: Supports SSH keys
- **Timeout Protection**: Prevents hanging connections

### Data Protection
- **Local Processing**: All data remains local
- **Temporary Files**: Automatic cleanup
- **Sensitive Data**: Not stored

## 🤝 Contributing

1. **Fork** the repository
2. **Create Feature Branch** (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open Pull Request**

## 📝 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Ollama**: For local LLM integration
- **Rich**: For beautiful terminal output
- **Paramiko**: For SSH functionality
- **Kubernetes**: For container orchestration

## 📞 Support

For questions or issues:
- **Issues**: [GitHub Issues](https://github.com/ssachse/ai_loganalyser/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ssachse/ai_loganalyser/discussions)

---

**Developed with ❤️ for DevOps and System Administrators** 