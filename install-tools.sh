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
    
    # Install gobuster and nikto from APT
    for tool in gobuster nikto; do
        if command -v $tool &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool already installed"
        else
            echo -e "  ${YELLOW}*${NC} Installing $tool..."
            apt-get install -y $tool 2>/dev/null || \
            echo -e "  ${RED}✗${NC} Failed to install $tool"
        fi
    done
    
    # Install Impacket (for secretsdump, GetNPUsers, etc.)
    echo -e "  ${YELLOW}*${NC} Installing Impacket suite..."
    if command -v impacket-secretsdump &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Impacket already installed"
    else
        # Try multiple methods
        # Method 1: From Kali/Debian repos
        apt-get install -y python3-impacket impacket-scripts 2>/dev/null
        
        # Method 2: From pip if apt fails
        if ! command -v impacket-secretsdump &> /dev/null; then
            pip3 install impacket 2>/dev/null
            
            # Create symlinks for impacket scripts
            if [ -d "/usr/local/lib/python3.*/dist-packages/impacket/examples" ]; then
                for script in /usr/local/lib/python3.*/dist-packages/impacket/examples/*.py; do
                    if [ -f "$script" ]; then
                        script_name=$(basename "$script" .py)
                        ln -sf "$script" "/usr/local/bin/impacket-$script_name" 2>/dev/null
                    fi
                done
            fi
        fi
        
        # Method 3: Clone from GitHub
        if ! command -v impacket-secretsdump &> /dev/null; then
            git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket 2>/dev/null && \
            cd /opt/impacket && \
            pip3 install . 2>/dev/null && \
            cd - > /dev/null
        fi
        
        if command -v impacket-secretsdump &> /dev/null || [ -f /usr/local/bin/secretsdump.py ]; then
            echo -e "  ${GREEN}✓${NC} Impacket installed"
        else
            echo -e "  ${RED}✗${NC} Failed to install Impacket"
        fi
    fi
    
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
    
    # Install bloodhound-python
    echo -e "  ${YELLOW}*${NC} Installing bloodhound-python..."
    if command -v bloodhound-python &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} bloodhound-python already installed"
    else
        # The correct package name is 'bloodhound'
        pip3 install bloodhound 2>/dev/null
        
        # Check if installed
        if python3 -c "import bloodhound" 2>/dev/null || command -v bloodhound-python &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} bloodhound-python installed"
        else
            echo -e "  ${RED}✗${NC} Failed to install bloodhound-python"
        fi
    fi
    
    # Install crackmapexec (now called NetExec)
    echo -e "  ${YELLOW}*${NC} Installing crackmapexec/netexec..."
    if command -v crackmapexec &> /dev/null || command -v cme &> /dev/null || command -v netexec &> /dev/null || command -v nxc &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} crackmapexec/netexec already installed"
    else
        # Method 1: Try apt (for Kali/Parrot)
        apt-get install -y crackmapexec 2>/dev/null
        
        # Method 2: Install via pipx (recommended)
        if ! command -v crackmapexec &> /dev/null && ! command -v cme &> /dev/null; then
            # Ensure pipx is installed
            if ! command -v pipx &> /dev/null; then
                apt-get install -y pipx 2>/dev/null || pip3 install --user pipx 2>/dev/null
                export PATH="$HOME/.local/bin:$PATH"
            fi
            
            # Try installing NetExec (new name)
            pipx install netexec 2>/dev/null
            
            # If that fails, try the old crackmapexec
            if ! command -v nxc &> /dev/null && ! command -v netexec &> /dev/null; then
                pipx install crackmapexec 2>/dev/null
            fi
        fi
        
        # Method 3: Direct pip install
        if ! command -v crackmapexec &> /dev/null && ! command -v cme &> /dev/null && ! command -v netexec &> /dev/null && ! command -v nxc &> /dev/null; then
            pip3 install crackmapexec 2>/dev/null || pip3 install netexec 2>/dev/null
        fi
        
        if command -v crackmapexec &> /dev/null || command -v cme &> /dev/null || command -v netexec &> /dev/null || command -v nxc &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} crackmapexec/netexec installed"
        else
            echo -e "  ${RED}✗${NC} Failed to install crackmapexec/netexec"
        fi
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
    echo "   # Method 1: From package manager"
    echo "   sudo apt-get install -y python3-impacket impacket-scripts"
    echo "   "
    echo "   # Method 2: From pip"
    echo "   pip3 install impacket"
    echo "   "
    echo "   # Method 3: From source"
    echo "   git clone https://github.com/SecureAuthCorp/impacket.git"
    echo "   cd impacket && pip3 install ."
    
    echo -e "\n${BLUE}5. Install crackmapexec/netexec:${NC}"
    echo "   # The tool was renamed to NetExec"
    echo "   pipx install netexec"
    echo "   # OR the old version"
    echo "   pipx install crackmapexec"
    echo "   "
    echo "   # Make sure ~/.local/bin is in PATH:"
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
    
    echo -e "\n${BLUE}6. Install bloodhound-python:${NC}"
    echo "   pip3 install bloodhound"
    echo "   # The package name is 'bloodhound' not 'bloodhound-python'"
    
    echo -e "\n${BLUE}7. Install other tools:${NC}"
    echo "   sudo apt-get install -y gobuster nikto"
    
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
    # Updated tool check list
    echo -e "  ${BLUE}Checking nmap:${NC} $(command -v nmap &> /dev/null && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}")"
    echo -e "  ${BLUE}Checking smbclient:${NC} $(command -v smbclient &> /dev/null && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}")"
    echo -e "  ${BLUE}Checking ldapsearch:${NC} $(command -v ldapsearch &> /dev/null && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}")"
    echo -e "  ${BLUE}Checking enum4linux:${NC} $(command -v enum4linux &> /dev/null && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}")"
    echo -e "  ${BLUE}Checking kerbrute:${NC} $(command -v kerbrute &> /dev/null && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}")"
    echo -e "  ${BLUE}Checking gobuster:${NC} $(command -v gobuster &> /dev/null && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}")"
    echo -e "  ${BLUE}Checking nikto:${NC} $(command -v nikto &> /dev/null && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}")"
    echo -e "  ${BLUE}Checking impacket:${NC} $(command -v impacket-secretsdump &> /dev/null || command -v secretsdump.py &> /dev/null && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}")"
    echo -e "  ${BLUE}Checking crackmapexec/netexec:${NC} $(command -v crackmapexec &> /dev/null || command -v cme &> /dev/null || command -v netexec &> /dev/null || command -v nxc &> /dev/null && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}")"
    echo -e "  ${BLUE}Checking bloodhound:${NC} $(python3 -c "import bloodhound" 2>/dev/null && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}")"
    
    # Count missing tools
    missing_count=0
    ! command -v impacket-secretsdump &> /dev/null && ! command -v secretsdump.py &> /dev/null && ((missing_count++))
    ! command -v crackmapexec &> /dev/null && ! command -v cme &> /dev/null && ! command -v netexec &> /dev/null && ! command -v nxc &> /dev/null && ((missing_count++))
    ! python3 -c "import bloodhound" 2>/dev/null && ((missing_count++))
    missing=()
    
    if [ $missing_count -gt 0 ]; then
        show_manual_instructions
    else
        echo -e "\n${GREEN}All tools installed successfully!${NC}"
    fi
}

# Run main function
main