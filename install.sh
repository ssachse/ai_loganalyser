#!/bin/bash

# macOS Logfile-Analysator Installations-Skript
# Dieses Skript installiert alle notwendigen Abhängigkeiten

set -e

echo "🚀 macOS Logfile-Analysator Installation"
echo "========================================"

# Farben für Ausgabe
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funktionen
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Überprüfe macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    print_error "Dieses Skript ist nur für macOS gedacht!"
    exit 1
fi

print_info "Überprüfe System-Voraussetzungen..."

# Überprüfe Python
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 ist nicht installiert!"
    print_info "Bitte installieren Sie Python 3 von https://python.org"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
print_success "Python $PYTHON_VERSION gefunden"

# Überprüfe Homebrew
if ! command -v brew &> /dev/null; then
    print_warning "Homebrew ist nicht installiert. Installiere Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    print_success "Homebrew installiert"
else
    print_success "Homebrew gefunden"
fi

# Installiere Ollama
print_info "Installiere Ollama..."
if ! command -v ollama &> /dev/null; then
    brew install ollama
    print_success "Ollama installiert"
else
    print_success "Ollama bereits installiert"
fi

# Starte Ollama Service
print_info "Starte Ollama Service..."
if ! pgrep -x "ollama" > /dev/null; then
    ollama serve &
    sleep 3
    print_success "Ollama Service gestartet"
else
    print_success "Ollama Service läuft bereits"
fi

# Überprüfe verfügbare Modelle
print_info "Überprüfe verfügbare Ollama-Modelle..."
if ollama list | grep -q "llama2"; then
    print_success "llama2 Modell bereits installiert"
else
    print_warning "llama2 Modell nicht gefunden. Installiere es..."
    ollama pull llama2
    print_success "llama2 Modell installiert"
fi

# Erstelle virtuelle Umgebung
print_info "Erstelle Python virtuelle Umgebung..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_success "Virtuelle Umgebung erstellt"
else
    print_success "Virtuelle Umgebung bereits vorhanden"
fi

# Aktiviere virtuelle Umgebung
print_info "Aktiviere virtuelle Umgebung..."
source venv/bin/activate

# Upgrade pip
print_info "Upgrade pip..."
pip install --upgrade pip

# Installiere Python-Abhängigkeiten
print_info "Installiere Python-Abhängigkeiten..."
pip install -r requirements.txt
print_success "Python-Abhängigkeiten installiert"

# Mache das Hauptskript ausführbar
print_info "Mache Log-Analysator ausführbar..."
chmod +x log_analyzer.py
print_success "Log-Analysator ist ausführbar"

# Teste Ollama-Verbindung
print_info "Teste Ollama-Verbindung..."
if curl -s http://localhost:11434/api/tags > /dev/null; then
    print_success "Ollama-Verbindung erfolgreich"
else
    print_warning "Ollama-Verbindung fehlgeschlagen. Bitte starten Sie Ollama manuell:"
    echo "  ollama serve"
fi

echo ""
echo "🎉 Installation abgeschlossen!"
echo "=============================="
echo ""
echo "Verwendung:"
echo "  source venv/bin/activate"
echo "  sudo python3 log_analyzer.py"
echo ""
echo "Oder direkt:"
echo "  sudo ./venv/bin/python log_analyzer.py"
echo ""
echo "Hinweise:"
echo "• Administrator-Rechte (sudo) sind für Log-Zugriff erforderlich"
echo "• Stellen Sie sicher, dass Ollama läuft: ollama serve"
echo "• Weitere Modelle können installiert werden: ollama pull mistral"
echo ""
echo "Dokumentation: README.md" 