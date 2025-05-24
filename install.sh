#!/bin/bash

# WinRecon Installation Script
# Automatic installation with comprehensive error handling

set +e  # Don't exit on errors, we'll handle them

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
    echo "║              Automatic Installation v2.0                     ║"
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

# Global variables
INSTALL_DIR=""
IS_ROOT=false
HAS_SUDO=false
PYTHON_CMD=""
PIP_CMD=""
USE_SYSTEM_INSTALL=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

check_environment() {
    log_info "Checking system environment..."
    
    # Check if root
    if [[ $EUID -eq 0 ]]; then
        IS_ROOT=true
        log_info "Running as root"
    else
        # Check sudo availability
        if command -v sudo &> /dev/null && sudo -n true 2>/dev/null; then
            HAS_SUDO=true
            log_info "Sudo available"
        else
            log_info "Running as regular user (no root/sudo)"
        fi
    fi
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        # Check if it's Python 3
        if python --version 2>&1 | grep -q "Python 3"; then
            PYTHON_CMD="python"
        else
            log_error "Python 2 detected. Python 3 is required."
            exit 1
        fi
    else
        log_error "Python not found. Please install Python 3 first."
        exit 1
    fi
    log_info "Python found: $($PYTHON_CMD --version)"
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        PIP_CMD="pip3"
    elif command -v pip &> /dev/null; then
        PIP_CMD="pip"
    elif $PYTHON_CMD -m pip --version &> /dev/null; then
        PIP_CMD="$PYTHON_CMD -m pip"
    else
        log_warn "pip not found. Will try to install it."
        install_pip
    fi
    
    # Determine installation directory
    if $IS_ROOT || $HAS_SUDO; then
        INSTALL_DIR="/opt/winrecon"
        USE_SYSTEM_INSTALL=true
    else
        INSTALL_DIR="$HOME/.local/lib/winrecon"
        USE_SYSTEM_INSTALL=false
    fi
    log_info "Installation directory: $INSTALL_DIR"
}

install_pip() {
    log_info "Installing pip..."
    
    # Try ensurepip first
    if $PYTHON_CMD -m ensurepip 2>/dev/null; then
        log_info "pip installed via ensurepip"
        PIP_CMD="$PYTHON_CMD -m pip"
        return 0
    fi
    
    # Try get-pip.py
    log_info "Downloading get-pip.py..."
    local temp_pip="/tmp/get-pip.py"
    
    if command -v curl &> /dev/null; then
        curl -sS https://bootstrap.pypa.io/get-pip.py -o "$temp_pip"
    elif command -v wget &> /dev/null; then
        wget -q https://bootstrap.pypa.io/get-pip.py -O "$temp_pip"
    else
        log_error "Neither curl nor wget found. Cannot download pip."
        return 1
    fi
    
    if [ -f "$temp_pip" ]; then
        $PYTHON_CMD "$temp_pip" --user
        rm -f "$temp_pip"
        PIP_CMD="$PYTHON_CMD -m pip"
        return 0
    fi
    
    return 1
}

fix_apt_errors() {
    if ! $USE_SYSTEM_INSTALL; then
        return 0
    fi
    
    log_info "Attempting to fix APT errors..."
    
    # Function to run apt commands
    run_apt() {
        if $IS_ROOT; then
            "$@" 2>/dev/null
        elif $HAS_SUDO; then
            sudo "$@" 2>/dev/null
        fi
    }
    
    # Clean APT cache
    run_apt apt-get clean
    run_apt rm -rf /var/lib/apt/lists/*
    
    # Remove problematic repositories
    if $IS_ROOT || $HAS_SUDO; then
        # Find Neo4j and other unsigned repos
        local problem_repos=$(run_apt grep -l "neo4j\|mongodb" /etc/apt/sources.list.d/*.list 2>/dev/null || true)
        if [ -n "$problem_repos" ]; then
            log_warn "Disabling problematic repositories..."
            for repo in $problem_repos; do
                run_apt mv "$repo" "$repo.disabled" 2>/dev/null || true
            done
        fi
    fi
    
    # Update with various flags
    log_info "Updating package lists..."
    run_apt apt-get update --fix-missing || \
    run_apt apt-get update --allow-insecure-repositories || \
    run_apt apt-get update -o Acquire::AllowInsecureRepositories=true || \
    true
}

install_system_packages() {
    if ! $USE_SYSTEM_INSTALL; then
        log_info "Skipping system package installation (user install)"
        return 0
    fi
    
    # Check if apt-get exists
    if ! command -v apt-get &> /dev/null; then
        log_warn "apt-get not found. Skipping system packages."
        return 0
    fi
    
    log_info "Installing system packages..."
    
    # Function to run apt commands
    run_apt() {
        if $IS_ROOT; then
            "$@"
        elif $HAS_SUDO; then
            sudo "$@"
        fi
    }
    
    # Fix APT errors first
    fix_apt_errors
    
    # Try to install Python packages
    local python_packages="python3-pip python3-venv"
    if ! run_apt apt-get install -y $python_packages 2>/dev/null; then
        log_warn "Failed to install Python packages via APT"
        # Not critical, we can use pip instead
    fi
    
    # Install optional tools (don't fail if they can't be installed)
    log_info "Installing optional system tools..."
    local tools="nmap smbclient ldap-utils"
    for tool in $tools; do
        if ! command -v ${tool%% *} &> /dev/null; then
            run_apt apt-get install -y $tool 2>/dev/null || log_warn "Could not install $tool"
        fi
    done
}

install_python_packages() {
    log_info "Installing Python packages..."
    
    # Upgrade pip first
    $PIP_CMD install --upgrade pip 2>/dev/null || true
    
    # Determine pip install command
    local pip_install="$PIP_CMD install"
    
    if $USE_SYSTEM_INSTALL; then
        if $IS_ROOT; then
            # Check if we need --break-system-packages
            if $PIP_CMD install --help 2>&1 | grep -q "break-system-packages"; then
                pip_install="$PIP_CMD install --break-system-packages"
            fi
        elif $HAS_SUDO; then
            pip_install="sudo $PIP_CMD install"
        fi
    else
        pip_install="$PIP_CMD install --user"
    fi
    
    # Install PyYAML with multiple fallback methods
    log_info "Installing PyYAML..."
    
    if ! $pip_install PyYAML 2>/dev/null; then
        log_warn "First attempt failed. Trying alternative methods..."
        
        # Try with --user flag
        if ! $PIP_CMD install --user PyYAML 2>/dev/null; then
            # Try without any flags
            if ! $PIP_CMD install PyYAML 2>/dev/null; then
                # Last resort: install from source
                log_warn "Trying to install PyYAML from source..."
                local yaml_url="https://files.pythonhosted.org/packages/source/P/PyYAML/PyYAML-6.0.tar.gz"
                local temp_dir="/tmp/pyyaml_install"
                mkdir -p "$temp_dir"
                
                if command -v curl &> /dev/null; then
                    curl -sL "$yaml_url" | tar -xz -C "$temp_dir"
                elif command -v wget &> /dev/null; then
                    wget -qO- "$yaml_url" | tar -xz -C "$temp_dir"
                fi
                
                if [ -d "$temp_dir/PyYAML-6.0" ]; then
                    cd "$temp_dir/PyYAML-6.0"
                    $PYTHON_CMD setup.py install --user 2>/dev/null || true
                    cd "$SCRIPT_DIR"
                fi
                rm -rf "$temp_dir"
            fi
        fi
    fi
    
    # Verify installation
    if ! $PYTHON_CMD -c "import yaml" 2>/dev/null; then
        log_error "Failed to install PyYAML. Trying to continue anyway..."
        return 1
    else
        log_info "PyYAML installed successfully"
    fi
    
    return 0
}

install_winrecon_files() {
    log_info "Installing WinRecon files..."
    
    # Create directories
    if $USE_SYSTEM_INSTALL; then
        if $IS_ROOT; then
            mkdir -p "$INSTALL_DIR"
            mkdir -p "/usr/local/bin"
        elif $HAS_SUDO; then
            sudo mkdir -p "$INSTALL_DIR"
            sudo mkdir -p "/usr/local/bin"
        fi
    else
        mkdir -p "$INSTALL_DIR"
        mkdir -p "$HOME/.local/bin"
    fi
    
    # Create config directory
    local config_dir="$HOME/.config/winrecon"
    mkdir -p "$config_dir"
    
    # Copy files
    log_info "Copying WinRecon files to $INSTALL_DIR..."
    
    local files="winrecon.py winrecon-report.py winrecon-techniques.py"
    for file in $files; do
        if [ -f "$SCRIPT_DIR/$file" ]; then
            if $USE_SYSTEM_INSTALL; then
                if $IS_ROOT; then
                    cp "$SCRIPT_DIR/$file" "$INSTALL_DIR/"
                    chmod 755 "$INSTALL_DIR/$file"
                elif $HAS_SUDO; then
                    sudo cp "$SCRIPT_DIR/$file" "$INSTALL_DIR/"
                    sudo chmod 755 "$INSTALL_DIR/$file"
                fi
            else
                cp "$SCRIPT_DIR/$file" "$INSTALL_DIR/"
                chmod 755 "$INSTALL_DIR/$file"
            fi
        else
            log_warn "File not found: $file"
        fi
    done
    
    # Copy config file
    if [ -f "$SCRIPT_DIR/winrecon-config.yaml" ]; then
        cp "$SCRIPT_DIR/winrecon-config.yaml" "$config_dir/config.yaml"
    fi
    
    # Create executable wrapper
    local bin_dir wrapper_path
    if $USE_SYSTEM_INSTALL; then
        bin_dir="/usr/local/bin"
        wrapper_path="$bin_dir/winrecon"
    else
        bin_dir="$HOME/.local/bin"
        wrapper_path="$bin_dir/winrecon"
    fi
    
    # Create wrapper script
    local wrapper_content="#!/bin/bash
# WinRecon wrapper script
exec $PYTHON_CMD \"$INSTALL_DIR/winrecon.py\" \"\$@\"
"
    
    if $USE_SYSTEM_INSTALL; then
        if $IS_ROOT; then
            echo "$wrapper_content" > "$wrapper_path"
            chmod 755 "$wrapper_path"
        elif $HAS_SUDO; then
            echo "$wrapper_content" | sudo tee "$wrapper_path" > /dev/null
            sudo chmod 755 "$wrapper_path"
        fi
    else
        echo "$wrapper_content" > "$wrapper_path"
        chmod 755 "$wrapper_path"
    fi
    
    log_info "WinRecon installed successfully!"
}

check_installation() {
    log_info "Verifying installation..."
    
    # Check if winrecon is accessible
    local winrecon_cmd
    if $USE_SYSTEM_INSTALL; then
        winrecon_cmd="/usr/local/bin/winrecon"
    else
        winrecon_cmd="$HOME/.local/bin/winrecon"
    fi
    
    if [ -f "$winrecon_cmd" ] && [ -x "$winrecon_cmd" ]; then
        log_info "WinRecon executable found at: $winrecon_cmd"
    else
        log_warn "WinRecon executable not found at expected location"
    fi
    
    # Test Python imports
    log_info "Testing Python imports..."
    if $PYTHON_CMD -c "import yaml" 2>/dev/null; then
        log_info "PyYAML import: OK"
    else
        log_warn "PyYAML import: FAILED"
    fi
    
    # Check for system tools
    log_info "Checking system tools..."
    local tools=(nmap smbclient ldapsearch)
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_info "$tool: Found"
        else
            log_warn "$tool: Not found"
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo ""
        log_warn "Some system tools are missing: ${missing_tools[*]}"
        log_info "WinRecon will work but with limited functionality."
        log_info "To install missing tools later, run:"
        if $USE_SYSTEM_INSTALL; then
            echo "    sudo apt-get install ${missing_tools[*]}"
        else
            echo "    Ask your system administrator to install: ${missing_tools[*]}"
        fi
    fi
}

print_usage() {
    echo ""
    echo -e "${GREEN}Installation complete!${NC}"
    echo ""
    
    # Add PATH instructions if needed
    if ! $USE_SYSTEM_INSTALL; then
        if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
            echo -e "${YELLOW}Important:${NC} Add ~/.local/bin to your PATH"
            echo "Add this line to your ~/.bashrc or ~/.zshrc:"
            echo ""
            echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
            echo ""
            echo "Then reload your shell:"
            echo "    source ~/.bashrc"
            echo ""
        fi
    fi
    
    echo "Usage examples:"
    echo "  winrecon 192.168.1.100"
    echo "  winrecon 192.168.1.0/24 -d domain.local -u user -p password"
    echo "  winrecon --help"
    echo ""
    echo "Configuration file: $HOME/.config/winrecon/config.yaml"
    echo ""
}

main() {
    print_banner
    
    # Check environment
    check_environment
    
    # Install system packages (if possible)
    install_system_packages
    
    # Install Python packages
    install_python_packages
    
    # Install WinRecon files
    install_winrecon_files
    
    # Verify installation
    check_installation
    
    # Print usage
    print_usage
}

# Run main function
main "$@"