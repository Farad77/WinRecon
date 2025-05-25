#!/bin/bash

# WinRecon Tools Manual Installation Script
# Use this when automatic installation fails due to system issues

set +e  # Continue on errors

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           WinRecon Tools Installation Helper                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!]${NC} This script must be run as root"
        echo "    Please run: sudo $0"
        exit 1
    fi
}

# Fix common issues
fix_system_issues() {
    echo -e "${GREEN}[*]${NC} Fixing common system issues..."
    
    # Fix /tmp permissions
    chmod 1777 /tmp 2>/dev/null || true
    
    # Create apt directories if missing
    mkdir -p /var/lib/apt/lists/partial 2>/dev/null || true
    
    # Remove apt locks if stuck
    rm -f /var/lib/apt/lists/lock 2>/dev/null || true
    rm -f /var/cache/apt/archives/lock 2>/dev/null || true
    rm -f /var/lib/dpkg/lock* 2>/dev/null || true
    
    # Reconfigure dpkg if needed
    dpkg --configure -a 2>/dev/null || true
}

# Update package lists with multiple fallbacks
update_packages() {
    echo -e "${GREEN}[*]${NC} Updating package lists..."
    
    # Try various update methods
    apt-get update 2>/dev/null || \
    apt-get update --allow-insecure-repositories 2>/dev/null || \
    apt-get update -o Acquire::AllowInsecureRepositories=true 2>/dev/null || \
    echo -e "${YELLOW}[!]${NC} Package update failed, continuing anyway..."
}

# Install tools one by one
install_tools() {
    echo -e "${GREEN}[*]${NC} Installing WinRecon tools..."
    
    # Essential tools
    echo -e "\n${BLUE}Essential tools:${NC}"
    for tool in nmap smbclient ldap-utils; do
        if command -v ${tool%%-*} &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool already installed"
        else
            echo -e "  ${YELLOW}*${NC} Installing $tool..."
            apt-get install -y $tool 2>/dev/null || \
            apt-get install -y --allow-unauthenticated $tool 2>/dev/null || \
            echo -e "  ${RED}✗${NC} Failed to install $tool"
        fi
    done
    
    # Pentesting tools
    echo -e "\n${BLUE}Pentesting tools:${NC}"
    
    # Install enum4linux manually
    if ! command -v enum4linux &> /dev/null; then
        echo -e "  ${YELLOW}*${NC} Installing enum4linux..."
        wget -q https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl \
             -O /usr/local/bin/enum4linux 2>/dev/null && \
        chmod +x /usr/local/bin/enum4linux && \
        echo -e "  ${GREEN}✓${NC} enum4linux installed" || \
        echo -e "  ${RED}✗${NC} Failed to install enum4linux"
    else
        echo -e "  ${GREEN}✓${NC} enum4linux already installed"
    fi
    
    # Install other tools
    for tool in gobuster nikto python3-impacket; do
        pkg_name=${tool%%-*}
        if command -v $pkg_name &> /dev/null || dpkg -l $tool &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool already installed"
        else
            echo -e "  ${YELLOW}*${NC} Installing $tool..."
            apt-get install -y $tool 2>/dev/null || \
            echo -e "  ${RED}✗${NC} Failed to install $tool"
        fi
    done
    
    # Install kerbrute
    if ! command -v kerbrute &> /dev/null && ! [ -f /usr/local/bin/kerbrute ]; then
        echo -e "  ${YELLOW}*${NC} Installing kerbrute..."
        wget -q https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 \
             -O /usr/local/bin/kerbrute 2>/dev/null && \
        chmod +x /usr/local/bin/kerbrute && \
        echo -e "  ${GREEN}✓${NC} kerbrute installed" || \
        echo -e "  ${RED}✗${NC} Failed to install kerbrute"
    else
        echo -e "  ${GREEN}✓${NC} kerbrute already installed"
    fi
    
    # Python tools
    echo -e "\n${BLUE}Python tools:${NC}"
    
    # Ensure pip is available
    if ! command -v pip3 &> /dev/null; then
        echo -e "  ${YELLOW}*${NC} Installing pip3..."
        apt-get install -y python3-pip 2>/dev/null || \
        curl -sS https://bootstrap.pypa.io/get-pip.py | python3
    fi
    
    # Install bloodhound
    echo -e "  ${YELLOW}*${NC} Installing bloodhound-python..."
    pip3 install bloodhound 2>/dev/null && \
    echo -e "  ${GREEN}✓${NC} bloodhound-python installed" || \
    echo -e "  ${RED}✗${NC} Failed to install bloodhound-python"
    
    # Install crackmapexec via pipx
    if ! command -v crackmapexec &> /dev/null && ! command -v cme &> /dev/null; then
        echo -e "  ${YELLOW}*${NC} Installing crackmapexec..."
        
        # Install pipx if needed
        if ! command -v pipx &> /dev/null; then
            apt-get install -y pipx 2>/dev/null || pip3 install pipx
        fi
        
        # Install cme
        pipx install crackmapexec 2>/dev/null && \
        echo -e "  ${GREEN}✓${NC} crackmapexec installed" || \
        echo -e "  ${RED}✗${NC} Failed to install crackmapexec"
    else
        echo -e "  ${GREEN}✓${NC} crackmapexec already installed"
    fi
}

# Manual installation instructions
show_manual_instructions() {
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Manual Installation Instructions${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\nIf automatic installation failed, try these commands manually:\n"
    
    echo -e "${BLUE}1. Fix package manager:${NC}"
    echo "   sudo rm -rf /var/lib/apt/lists/*"
    echo "   sudo apt-get clean"
    echo "   sudo apt-get update --fix-missing"
    
    echo -e "\n${BLUE}2. Install essential tools:${NC}"
    echo "   sudo apt-get install -y nmap smbclient ldap-utils"
    
    echo -e "\n${BLUE}3. Install enum4linux manually:${NC}"
    echo "   sudo wget https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl -O /usr/local/bin/enum4linux"
    echo "   sudo chmod +x /usr/local/bin/enum4linux"
    
    echo -e "\n${BLUE}4. Install impacket:${NC}"
    echo "   sudo apt-get install -y python3-impacket"
    echo "   # OR"
    echo "   pip3 install impacket"
    
    echo -e "\n${BLUE}5. Install other tools:${NC}"
    echo "   sudo apt-get install -y gobuster nikto"
    echo "   pip3 install bloodhound"
    
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
}

# Main execution
main() {
    check_root
    fix_system_issues
    update_packages
    install_tools
    
    echo -e "\n${GREEN}[*]${NC} Installation process completed!"
    
    # Check what's still missing
    echo -e "\n${BLUE}Tool Status:${NC}"
    tools=("nmap" "smbclient" "ldapsearch" "enum4linux" "kerbrute" "gobuster" "nikto" "impacket-secretsdump" "crackmapexec" "bloodhound-python")
    missing=()
    
    for tool in "${tools[@]}"; do
        if command -v ${tool%%-*} &> /dev/null || [ -f "/usr/local/bin/${tool%%-*}" ]; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${RED}✗${NC} $tool"
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        show_manual_instructions
    else
        echo -e "\n${GREEN}All tools installed successfully!${NC}"
    fi
}

# Run main function
main