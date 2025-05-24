#!/bin/bash

# WinRecon Improved Installation Script
# Handles missing tools gracefully and provides clear instructions

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/winrecon"
USER_CONFIG_DIR="$HOME/.config/winrecon"

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              WinRecon Installation Script                    ║"
    echo "║       Windows/Active Directory Enumeration Tool              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    log_info "Detected OS: $OS $VER"
}

install_python_dependencies() {
    log_info "Installing Python dependencies..."
    
    # Ensure pip is installed
    if ! command -v pip3 &> /dev/null; then
        apt-get update
        apt-get install -y python3-pip
    fi
    
    # Install Python packages system-wide
    pip3 install -r "$SCRIPT_DIR/requirements.txt" || {
        log_warn "Some Python packages failed to install"
        log_info "Trying with --break-system-packages flag (for newer systems)"
        pip3 install --break-system-packages -r "$SCRIPT_DIR/requirements.txt"
    }
    
    log_info "Python dependencies installed"
}

install_system_tools() {
    log_info "Checking and installing system tools..."
    
    # Update package list
    apt-get update
    
    # Core tools that we'll try to install
    CORE_TOOLS=(
        "nmap"
        "smbclient"
        "ldap-utils"  # provides ldapsearch
        "dnsutils"    # provides dig
        "curl"
        "wget"
        "git"
    )
    
    # Extended tools (optional but recommended)
    EXTENDED_TOOLS=(
        "enum4linux"
        "nikto"
        "gobuster"
        "crackmapexec"
        "impacket-scripts"
    )
    
    # Install core tools
    log_info "Installing core tools..."
    for tool in "${CORE_TOOLS[@]}"; do
        if apt-get install -y "$tool" 2>/dev/null; then
            log_info "Installed $tool"
        else
            log_warn "Failed to install $tool"
        fi
    done
    
    # Try to install extended tools
    log_info "Installing extended tools (optional)..."
    for tool in "${EXTENDED_TOOLS[@]}"; do
        if apt-get install -y "$tool" 2>/dev/null; then
            log_info "Installed $tool"
        else
            log_warn "$tool not available in repositories (install manually if needed)"
        fi
    done
}

install_specialized_tools() {
    log_info "Installing specialized tools from GitHub..."
    
    mkdir -p /opt
    
    # Install tools that require git cloning
    install_from_git() {
        local name=$1
        local url=$2
        local install_cmd=$3
        
        if [ ! -d "/opt/$name" ]; then
            log_info "Installing $name..."
            cd /opt
            git clone "$url" "$name" || {
                log_warn "Failed to clone $name"
                return 1
            }
            if [ -n "$install_cmd" ]; then
                cd "/opt/$name"
                eval "$install_cmd" || log_warn "Failed to install $name dependencies"
            fi
        else
            log_info "$name already installed"
        fi
    }
    
    # Install key tools
    install_from_git "windapsearch" "https://github.com/ropnop/windapsearch.git" "pip3 install python-ldap || true"
    install_from_git "BloodHound.py" "https://github.com/fox-it/BloodHound.py.git" "pip3 install . || true"
    install_from_git "ldapdomaindump" "https://github.com/dirkjanm/ldapdomaindump.git" "pip3 install ldap3 dnspython || true"
    
    # Download kerbrute binary
    if [ ! -f "/opt/kerbrute/kerbrute" ]; then
        log_info "Installing kerbrute..."
        mkdir -p /opt/kerbrute
        cd /opt/kerbrute
        KERBRUTE_URL="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64"
        wget -q "$KERBRUTE_URL" -O kerbrute 2>/dev/null || {
            log_warn "Failed to download kerbrute"
        }
        chmod +x kerbrute 2>/dev/null || true
    fi
}

setup_winrecon() {
    log_info "Setting up WinRecon..."
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    
    # Copy WinRecon files
    for file in winrecon.py winrecon-report.py winrecon-techniques.py winrecon-config.yaml; do
        if [ -f "$SCRIPT_DIR/$file" ]; then
            cp "$SCRIPT_DIR/$file" "$INSTALL_DIR/"
            log_info "Copied $file"
        else
            log_warn "File $file not found in source directory"
        fi
    done
    
    # Make main script executable
    chmod +x "$INSTALL_DIR/winrecon.py"
    
    # Create symbolic link
    ln -sf "$INSTALL_DIR/winrecon.py" /usr/local/bin/winrecon
    
    # Setup user configuration
    ACTUAL_USER=${SUDO_USER:-$USER}
    ACTUAL_HOME=$(eval echo ~$ACTUAL_USER)
    USER_CONFIG_DIR="$ACTUAL_HOME/.config/winrecon"
    
    mkdir -p "$USER_CONFIG_DIR"
    
    # Copy config file to user directory
    if [ -f "$INSTALL_DIR/winrecon-config.yaml" ]; then
        cp "$INSTALL_DIR/winrecon-config.yaml" "$USER_CONFIG_DIR/config.yaml"
        chown -R "$ACTUAL_USER:$ACTUAL_USER" "$USER_CONFIG_DIR"
        log_info "User configuration created at $USER_CONFIG_DIR"
    fi
}

verify_installation() {
    log_info "Verifying installation..."
    
    # Test Python import
    python3 -c "import yaml, asyncio, ipaddress" 2>/dev/null && {
        log_info "Python modules OK"
    } || {
        log_error "Python modules check failed"
    }
    
    # Test WinRecon
    if [ -x /usr/local/bin/winrecon ]; then
        winrecon --help >/dev/null 2>&1 && {
            log_info "WinRecon command OK"
        } || {
            log_warn "WinRecon command exists but may have issues"
        }
    else
        log_error "WinRecon command not found"
    fi
    
    # Check for essential tools
    local missing_tools=()
    for tool in nmap smbclient ldapsearch; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_warn "Missing tools: ${missing_tools[*]}"
        log_info "Install with: apt-get install nmap smbclient ldap-utils"
    else
        log_info "All essential tools installed"
    fi
}

print_usage() {
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                 Installation Complete!                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Usage examples:"
    echo "  winrecon 192.168.1.100"
    echo "  winrecon 192.168.1.0/24 -d domain.local -u user -p password"
    echo "  winrecon --help"
    echo ""
    echo "Configuration file: ~/.config/winrecon/config.yaml"
    echo ""
    
    if [ -f "$USER_CONFIG_DIR/config.yaml" ]; then
        log_info "Configuration file created successfully"
    fi
}

main() {
    print_banner
    
    # Parse arguments
    SKIP_TOOLS=false
    for arg in "$@"; do
        case $arg in
            --skip-tools)
                SKIP_TOOLS=true
                ;;
        esac
    done
    
    check_root
    detect_os
    
    # Install components
    install_python_dependencies
    
    if [ "$SKIP_TOOLS" = false ]; then
        install_system_tools
        install_specialized_tools
    else
        log_warn "Skipping system tools installation (--skip-tools)"
    fi
    
    setup_winrecon
    verify_installation
    
    echo ""
    print_usage
    
    log_info "Installation process completed!"
    log_info "Restart your terminal or run 'source ~/.bashrc' to use winrecon command"
}

# Run main function
main "$@"