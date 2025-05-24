#!/bin/bash

# WinRecon Installation Script
# Comprehensive installer with multiple installation methods

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

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

check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        log_error "Cannot detect OS version"
        exit 1
    fi
    log_info "Detected OS: $OS $VER"
}

install_method_native() {
    log_info "Installing WinRecon natively..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "Native installation requires root privileges"
        log_info "Please run: sudo $0"
        exit 1
    fi
    
    # Install system dependencies
    log_info "Installing system dependencies..."
    apt-get update
    apt-get install -y python3 python3-pip python3-venv
    
    # Install PyYAML
    log_info "Installing Python dependencies..."
    pip3 install PyYAML || pip3 install --break-system-packages PyYAML
    
    # Install WinRecon
    INSTALL_DIR="/opt/winrecon"
    mkdir -p "$INSTALL_DIR"
    
    # Copy files
    cp winrecon.py winrecon-report.py winrecon-techniques.py winrecon-config.yaml "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/winrecon.py"
    
    # Create symlink
    ln -sf "$INSTALL_DIR/winrecon.py" /usr/local/bin/winrecon
    
    # Setup user config
    USER_HOME="${HOME}"
    if [ -n "$SUDO_USER" ]; then
        USER_HOME=$(eval echo ~$SUDO_USER)
    fi
    
    CONFIG_DIR="$USER_HOME/.config/winrecon"
    mkdir -p "$CONFIG_DIR"
    cp winrecon-config.yaml "$CONFIG_DIR/config.yaml"
    
    if [ -n "$SUDO_USER" ]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$CONFIG_DIR"
    fi
    
    log_info "WinRecon installed successfully!"
    log_info "Configuration: $CONFIG_DIR/config.yaml"
    
    # Check for missing tools
    echo ""
    log_info "Checking system tools..."
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

install_method_user() {
    log_info "Installing WinRecon for current user..."
    
    # Install PyYAML for user
    log_info "Installing Python dependencies..."
    pip3 install --user PyYAML
    
    # Create user installation directory
    USER_BIN="$HOME/.local/bin"
    USER_LIB="$HOME/.local/lib/winrecon"
    mkdir -p "$USER_BIN" "$USER_LIB"
    
    # Copy files
    cp winrecon.py winrecon-report.py winrecon-techniques.py "$USER_LIB/"
    chmod +x "$USER_LIB/winrecon.py"
    
    # Create wrapper script
    cat > "$USER_BIN/winrecon" << 'EOF'
#!/bin/bash
exec python3 "$HOME/.local/lib/winrecon/winrecon.py" "$@"
EOF
    chmod +x "$USER_BIN/winrecon"
    
    # Setup config
    CONFIG_DIR="$HOME/.config/winrecon"
    mkdir -p "$CONFIG_DIR"
    cp winrecon-config.yaml "$CONFIG_DIR/config.yaml"
    
    log_info "WinRecon installed for user!"
    log_info "Make sure $USER_BIN is in your PATH"
    
    # Check if user bin is in PATH
    if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
        log_warn "$USER_BIN is not in PATH"
        log_info "Add to your ~/.bashrc:"
        echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

install_method_docker() {
    log_info "Setting up WinRecon with Docker..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        log_info "Install Docker first: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    # Build Docker image
    log_info "Building Docker image..."
    docker build -t winrecon:latest .
    
    # Create wrapper script
    WRAPPER_SCRIPT="winrecon-docker"
    cat > "$WRAPPER_SCRIPT" << 'EOF'
#!/bin/bash
# WinRecon Docker wrapper
docker run --rm -it \
    -v "$(pwd)/winrecon_results:/winrecon_results" \
    -v "$HOME/.config/winrecon/config.yaml:/root/.config/winrecon/config.yaml:ro" \
    --network host \
    winrecon:latest \
    python3 /opt/winrecon/winrecon.py "$@"
EOF
    chmod +x "$WRAPPER_SCRIPT"
    
    log_info "Docker image built successfully!"
    log_info "Use: ./$WRAPPER_SCRIPT <target>"
    log_info "Or: docker-compose run --rm winrecon winrecon <target>"
}

install_method_venv() {
    log_info "Installing WinRecon in virtual environment..."
    
    # Create virtual environment
    VENV_DIR="venv"
    python3 -m venv "$VENV_DIR"
    
    # Activate and install
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip
    pip install PyYAML
    
    # Create activation script
    cat > "activate-winrecon.sh" << EOF
#!/bin/bash
# Activate WinRecon virtual environment
source "$PWD/$VENV_DIR/bin/activate"
export PATH="$PWD:\$PATH"
echo "WinRecon environment activated"
echo "Use: python3 winrecon.py <target>"
EOF
    chmod +x activate-winrecon.sh
    
    # Make winrecon.py executable
    chmod +x winrecon.py
    
    log_info "Virtual environment created!"
    log_info "Activate with: source activate-winrecon.sh"
    
    deactivate
}

show_menu() {
    echo -e "${CYAN}Choose installation method:${NC}"
    echo "1) System-wide installation (requires root)"
    echo "2) User installation (no root required)"
    echo "3) Docker installation"
    echo "4) Virtual environment installation"
    echo "5) Run tests only"
    echo "6) Exit"
    echo ""
    read -p "Enter choice [1-6]: " choice
    
    case $choice in
        1)
            install_method_native
            ;;
        2)
            install_method_user
            ;;
        3)
            install_method_docker
            ;;
        4)
            install_method_venv
            ;;
        5)
            python3 test_winrecon.py
            ;;
        6)
            echo "Exiting..."
            exit 0
            ;;
        *)
            log_error "Invalid choice"
            exit 1
            ;;
    esac
}

print_usage() {
    echo ""
    echo -e "${GREEN}Installation complete!${NC}"
    echo ""
    echo "Usage examples:"
    echo "  winrecon 192.168.1.100"
    echo "  winrecon 192.168.1.0/24 -d domain.local -u user -p password"
    echo "  winrecon --help"
    echo ""
    echo "For more information, see winrecon-readme.md"
}

main() {
    print_banner
    check_os
    
    # If no arguments, show menu
    if [ $# -eq 0 ]; then
        show_menu
    else
        # Handle command line arguments
        case "$1" in
            --native|--system)
                install_method_native
                ;;
            --user)
                install_method_user
                ;;
            --docker)
                install_method_docker
                ;;
            --venv)
                install_method_venv
                ;;
            --test)
                python3 test_winrecon.py
                ;;
            --help|-h)
                echo "Usage: $0 [OPTION]"
                echo "Options:"
                echo "  --native    System-wide installation"
                echo "  --user      User installation"
                echo "  --docker    Docker installation"
                echo "  --venv      Virtual environment"
                echo "  --test      Run tests only"
                echo "  --help      Show this help"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for options"
                exit 1
                ;;
        esac
    fi
    
    print_usage
}

# Run main function
main "$@"