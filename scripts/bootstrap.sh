#!/bin/bash
#
# MobAI Bootstrap Script
# Bu script Python kurulum aracini calistirmak icin gereken minimum bagimliliklari kurar.
# Kullanim: ./scripts/bootstrap.sh
#

set -e

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logo
echo -e "${BLUE}"
cat << "EOF"
  __  __       _        _    ___
 |  \/  | ___ | |__    / \  |_ _|
 | |\/| |/ _ \| '_ \  / _ \  | |
 | |  | | (_) | |_) |/ ___ \ | |
 |_|  |_|\___/|_.__//_/   \_\___|

 Mobile Security Analyzer - Bootstrap
EOF
echo -e "${NC}"

# Fonksiyonlar
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Root kontrolu
if [ "$EUID" -eq 0 ]; then
    log_warning "Root olarak calistiriyorsunuz. Normal kullanici olarak calistirmaniz onerilir."
fi

# Script dizinine git
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

log_info "Proje dizini: $PROJECT_DIR"

# OS Tespiti
log_info "Isletim sistemi tespit ediliyor..."
OS=""
PACKAGE_MANAGER=""

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    case $OS in
        ubuntu|debian|linuxmint|pop)
            PACKAGE_MANAGER="apt"
            ;;
        fedora|rhel|centos|rocky|almalinux)
            PACKAGE_MANAGER="dnf"
            ;;
        arch|manjaro|endeavouros)
            PACKAGE_MANAGER="pacman"
            ;;
        opensuse*)
            PACKAGE_MANAGER="zypper"
            ;;
        *)
            PACKAGE_MANAGER="unknown"
            ;;
    esac
elif [ "$(uname)" == "Darwin" ]; then
    OS="macos"
    PACKAGE_MANAGER="brew"
fi

log_success "Isletim sistemi: $OS ($PACKAGE_MANAGER)"

# Python kontrolu
log_info "Python kontrolu yapiliyor..."

PYTHON_CMD=""
if check_command python3; then
    PYTHON_CMD="python3"
elif check_command python; then
    PYTHON_CMD="python"
fi

if [ -n "$PYTHON_CMD" ]; then
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
        log_success "Python $PYTHON_VERSION bulundu"
    else
        log_error "Python 3.8+ gerekli. Mevcut: $PYTHON_VERSION"
        exit 1
    fi
else
    log_error "Python bulunamadi!"
    log_info "Python kurmak icin:"
    case $PACKAGE_MANAGER in
        apt)
            echo "  sudo apt update && sudo apt install python3 python3-pip python3-venv"
            ;;
        dnf)
            echo "  sudo dnf install python3 python3-pip"
            ;;
        pacman)
            echo "  sudo pacman -S python python-pip"
            ;;
        brew)
            echo "  brew install python3"
            ;;
    esac
    exit 1
fi

# pip kontrolu
log_info "pip kontrolu yapiliyor..."

if ! $PYTHON_CMD -m pip --version &> /dev/null; then
    log_warning "pip bulunamadi, kurulmaya calisiliyor..."

    case $PACKAGE_MANAGER in
        apt)
            sudo apt update && sudo apt install -y python3-pip
            ;;
        dnf)
            sudo dnf install -y python3-pip
            ;;
        pacman)
            sudo pacman -S --noconfirm python-pip
            ;;
        brew)
            # macOS'ta pip genellikle python ile gelir
            ;;
    esac
fi

PIP_VERSION=$($PYTHON_CMD -m pip --version 2>&1 | awk '{print $2}')
log_success "pip $PIP_VERSION bulundu"

# venv modulu kontrolu
log_info "venv modulu kontrolu yapiliyor..."

if ! $PYTHON_CMD -m venv --help &> /dev/null; then
    log_warning "venv modulu bulunamadi, kurulmaya calisiliyor..."

    case $PACKAGE_MANAGER in
        apt)
            sudo apt install -y python3-venv
            ;;
        dnf)
            # Fedora'da genellikle dahil
            ;;
        pacman)
            # Arch'da genellikle dahil
            ;;
    esac
fi

log_success "venv modulu mevcut"

# Installer requirements kontrolu
log_info "Kurulum araci bagimliliklari kontrol ediliyor..."

REQUIREMENTS_FILE="$PROJECT_DIR/requirements-installer.txt"

if [ ! -f "$REQUIREMENTS_FILE" ]; then
    log_info "requirements-installer.txt olusturuluyor..."
    cat > "$REQUIREMENTS_FILE" << 'EOF'
# MobAI Installer Dependencies
rich>=13.0.0
click>=8.0.0
questionary>=2.0.0
requests>=2.28.0
psutil>=5.9.0
EOF
    log_success "requirements-installer.txt olusturuldu"
fi

# Installer venv olustur
INSTALLER_VENV="$PROJECT_DIR/.installer-venv"

if [ ! -d "$INSTALLER_VENV" ]; then
    log_info "Installer icin virtual environment olusturuluyor..."
    $PYTHON_CMD -m venv "$INSTALLER_VENV"
    log_success "Virtual environment olusturuldu: $INSTALLER_VENV"
fi

# Installer bagimliliklarini kur
log_info "Installer bagimliliklari kurulmaya calisiliyor..."

source "$INSTALLER_VENV/bin/activate"

pip install --upgrade pip -q
pip install -r "$REQUIREMENTS_FILE" -q

log_success "Installer bagimliliklari kuruldu"

deactivate

# install.py kontrolu
if [ -f "$PROJECT_DIR/install.py" ]; then
    log_success "Ana kurulum scripti hazir: install.py"
    echo ""
    echo -e "${GREEN}Bootstrap tamamlandi!${NC}"
    echo ""
    echo "Kurulum aracini baslatmak icin:"
    echo -e "  ${BLUE}./mobai${NC}              # Interaktif menu"
    echo -e "  ${BLUE}./mobai install${NC}      # Kurulum baslat"
    echo -e "  ${BLUE}./mobai --help${NC}       # Yardim"
else
    log_warning "install.py henuz olusturulmamis"
    echo ""
    echo -e "${YELLOW}Bootstrap tamamlandi, ancak install.py bekleniyor.${NC}"
fi

echo ""
