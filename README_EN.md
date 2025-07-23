# AI Log-Analyzer with Kubernetes Support

An intelligent SSH-based Linux log analyzer with integrated Ollama chat and Kubernetes cluster analysis.

## 🌍 **Multi-Language Support**
- **Automatic Language Detection**: Detects language from shell locale
- **Supported Languages**: German (default) and English
- **Dynamic Translation**: All UI texts and messages translated
- **Easy Extension**: New languages easily addable

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
- **Two-Tier Model System**: Fast and complex analyses
- **Shortcuts**: Quick access to frequent questions
- **Intelligent Caching**: Optimized performance for repeated questions
- **Automatic System Analysis**: Detailed insights on startup

### ⚡ **Performance Optimizations**
- **Quick Mode**: Skips time-consuming analyses
- **Intelligent Error Handling**: Grouped error summaries
- **Model Selection**: Automatic complexity detection
- **Cache System**: Avoids redundant API calls

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
k8s         - How is the Kubernetes cluster status?
k8s-problems- What Kubernetes problems are there?
help        - Show available shortcuts
```

## 🔧 Configuration

### SSH Connection
- **Default Port**: 22
- **Authentication**: Password or SSH key
- **Timeout**: 30 seconds per command

### Ollama Integration
- **Default Port**: 11434
- **Models**: Automatic selection based on complexity
- **Cache**: Intelligent caching for optimal performance

### Kubernetes Analysis
- **Automatic Detection**: Checks `kubectl` availability
- **Permissions**: Requires cluster access
- **Error Handling**: Grouped kubectl errors

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