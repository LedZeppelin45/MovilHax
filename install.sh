#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  MOVILHAX - Installer v1.0
#  Installs Movilhax on Debian/Ubuntu, Fedora, Arch Linux
# ═══════════════════════════════════════════════════════════

set -e

# Colors
G='\033[92m'
R='\033[91m'
C='\033[96m'
Y='\033[93m'
W='\033[97m'
BD='\033[1m'
GY='\033[90m'
X='\033[0m'

INSTALL_DIR="/opt/movilhax"
BIN_LINK="/usr/local/bin/movilhax"

banner() {
    echo ""
    echo -e "${G}${BD}  ╔════════════════════════════════════════════╗${X}"
    echo -e "${G}${BD}  ║       MOVILHAX - Installer v1.0           ║${X}"
    echo -e "${G}${BD}  ║       Network Device Scanner              ║${X}"
    echo -e "${G}${BD}  ╚════════════════════════════════════════════╝${X}"
    echo ""
}

info()    { echo -e "  ${G}[*]${X} $1"; }
success() { echo -e "  ${G}[+]${X} $1"; }
warn()    { echo -e "  ${Y}[!]${X} $1"; }
fail()    { echo -e "  ${R}[!]${X} $1"; exit 1; }

# ── Check root ──
check_root() {
    if [[ $EUID -ne 0 ]]; then
        fail "This installer must be run as root.\n      Usage: ${W}sudo ./install.sh${X}"
    fi
}

# ── Detect package manager ──
detect_pm() {
    if command -v apt-get &>/dev/null; then
        PM="apt"
    elif command -v dnf &>/dev/null; then
        PM="dnf"
    elif command -v yum &>/dev/null; then
        PM="yum"
    elif command -v pacman &>/dev/null; then
        PM="pacman"
    else
        fail "Unsupported package manager. Install Python 3 and pip manually."
    fi
    info "Package manager: ${W}${PM}${X}"
}

# ── Install Python 3 ──
install_python() {
    if command -v python3 &>/dev/null; then
        PY_VER=$(python3 --version 2>&1)
        success "Python found: ${W}${PY_VER}${X}"
    else
        info "Installing Python 3..."
        case $PM in
            apt)    apt-get update -qq && apt-get install -y -qq python3 python3-pip ;;
            dnf)    dnf install -y python3 python3-pip ;;
            yum)    yum install -y python3 python3-pip ;;
            pacman) pacman -Sy --noconfirm python python-pip ;;
        esac
        success "Python 3 installed."
    fi
}

# ── Install pip ──
install_pip() {
    if command -v pip3 &>/dev/null || python3 -m pip --version &>/dev/null 2>&1; then
        success "pip3 available."
    else
        info "Installing pip3..."
        case $PM in
            apt)    apt-get install -y -qq python3-pip ;;
            dnf)    dnf install -y python3-pip ;;
            yum)    yum install -y python3-pip ;;
            pacman) pacman -Sy --noconfirm python-pip ;;
        esac
        success "pip3 installed."
    fi
}

# ── Install system dependencies ──
install_sys_deps() {
    info "Installing system dependencies..."
    case $PM in
        apt)
            apt-get install -y -qq libpcap-dev net-tools iproute2 2>/dev/null || true
            ;;
        dnf|yum)
            $PM install -y libpcap-devel net-tools iproute 2>/dev/null || true
            ;;
        pacman)
            pacman -Sy --noconfirm libpcap net-tools iproute2 2>/dev/null || true
            ;;
    esac
    success "System dependencies ready."
}

# ── Install Python packages ──
install_py_deps() {
    info "Installing Python packages (scapy)..."
    if python3 -m pip install scapy 2>/dev/null; then
        success "scapy installed."
    elif pip3 install scapy 2>/dev/null; then
        success "scapy installed."
    else
        fail "Could not install scapy. Try: pip3 install scapy"
    fi
}

# ── Install Movilhax ──
install_movilhax() {
    info "Installing Movilhax to ${W}${INSTALL_DIR}${X}..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ ! -f "$SCRIPT_DIR/movilhax.py" ]]; then
        fail "movilhax.py not found in $SCRIPT_DIR"
    fi

    mkdir -p "$INSTALL_DIR"
    cp "$SCRIPT_DIR/movilhax.py" "$INSTALL_DIR/movilhax.py"
    chmod 755 "$INSTALL_DIR/movilhax.py"

    # Create launcher
    cat > "$BIN_LINK" << 'EOF'
#!/bin/bash
exec python3 /opt/movilhax/movilhax.py "$@"
EOF
    chmod 755 "$BIN_LINK"

    success "Installed to ${W}${INSTALL_DIR}${X}"
    success "Launcher created at ${W}${BIN_LINK}${X}"
}

# ── Uninstall ──
uninstall() {
    banner
    info "Uninstalling Movilhax..."
    rm -f "$BIN_LINK"
    rm -rf "$INSTALL_DIR"
    success "Movilhax has been removed."
    echo ""
    exit 0
}

# ── Main ──

if [[ "$1" == "--uninstall" ]]; then
    check_root
    uninstall
fi

clear
banner
check_root

echo -e "  ${GY}─────────────────────────────────────────────${X}"
echo ""

detect_pm
echo ""
install_python
install_pip
echo ""
install_sys_deps
echo ""
install_py_deps
echo ""
install_movilhax

echo ""
echo -e "  ${G}${BD}╔════════════════════════════════════════════╗${X}"
echo -e "  ${G}${BD}║  ${W}Installation complete!                    ${G}${BD}║${X}"
echo -e "  ${G}${BD}║                                            ║${X}"
echo -e "  ${G}${BD}║  ${C}Run:  ${W}sudo movilhax                      ${G}${BD}║${X}"
echo -e "  ${G}${BD}║                                            ║${X}"
echo -e "  ${G}${BD}║  ${GY}Uninstall: sudo ./install.sh --uninstall ${G}${BD}║${X}"
echo -e "  ${G}${BD}╚════════════════════════════════════════════╝${X}"
echo ""
