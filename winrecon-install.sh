#!/bin/bash

# WinRecon Installation Script
# Installe tous les outils nécessaires pour l'énumération Windows/AD

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

TOOLS_DIR="/opt"
CURRENT_USER=$(whoami)

print_banner() {
    echo -e "${BLUE}"
    echo "██╗    ██╗██╗███╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo "██║    ██║██║████╗  ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    echo "██║ █╗ ██║██║██╔██╗ ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo "██║███╗██║██║██║╚██╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo "╚███╔███╔╝██║██║ ╚████║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    echo " ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
    echo ""
    echo "           Windows/Active Directory Enumeration Tool"
    echo "                     Installation Script"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
}

update_system() {
    log_info "Mise à jour du système..."
    apt-get update -y
    apt-get upgrade -y
}

install_base_tools() {
    log_info "Installation des outils de base..."
    
    # Outils système
    apt-get install -y \
        curl \
        wget \
        git \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        libssl-dev \
        libffi-dev \
        libldap2-dev \
        libsasl2-dev \
        libkrb5-dev \
        seclists \
        wordlists
    
    # Outils réseau et énumération
    apt-get install -y \
        nmap \
        masscan \
        rustscan \
        enum4linux \
        smbclient \
        smbmap \
        crackmapexec \
        ldap-utils \
        dnsutils \
        nikto \
        gobuster \
        feroxbuster \
        dirsearch \
        wfuzz \
        ffuf \
        whatweb \
        wafw00f
    
    # Impacket suite
    apt-get install -y \
        impacket-scripts \
        python3-impacket
    
    # Python packages
    pip3 install \
        asyncio \
        python-ldap \
        dnspython \
        requests \
        beautifulsoup4 \
        lxml \
        pyyaml \
        colorama \
        rich \
        typer
}

install_windapsearch() {
    log_info "Installation de windapsearch..."
    cd $TOOLS_DIR
    if [ ! -d "windapsearch" ]; then
        git clone https://github.com/ropnop/windapsearch.git
        cd windapsearch
        pip3 install python-ldap
    else
        log_warn "windapsearch déjà installé"
    fi
}

install_bloodhound_python() {
    log_info "Installation de BloodHound.py..."
    cd $TOOLS_DIR
    if [ ! -d "BloodHound.py" ]; then
        git clone https://github.com/fox-it/BloodHound.py.git
        cd BloodHound.py
        pip3 install .
    else
        log_warn "BloodHound.py déjà installé"
    fi
}

install_ldapdomaindump() {
    log_info "Installation de ldapdomaindump..."
    cd $TOOLS_DIR
    if [ ! -d "ldapdomaindump" ]; then
        git clone https://github.com/dirkjanm/ldapdomaindump.git
        cd ldapdomaindump
        pip3 install ldap3 dnspython
    else
        log_warn "ldapdomaindump déjà installé"
    fi
}

install_adidnsdump() {
    log_info "Installation de adidnsdump..."
    cd $TOOLS_DIR
    if [ ! -d "adidnsdump" ]; then
        git clone https://github.com/dirkjanm/adidnsdump.git
        cd adidnsdump
        pip3 install dnspython ldap3
    else
        log_warn "adidnsdump déjà installé"
    fi
}

install_kerbrute() {
    log_info "Installation de kerbrute..."
    cd $TOOLS_DIR
    if [ ! -d "kerbrute" ]; then
        mkdir kerbrute
        cd kerbrute
        # Télécharger la dernière version
        LATEST_RELEASE=$(curl -s https://api.github.com/repos/ropnop/kerbrute/releases/latest | grep "tag_name" | cut -d '"' -f 4)
        wget "https://github.com/ropnop/kerbrute/releases/download/${LATEST_RELEASE}/kerbrute_linux_amd64" -O kerbrute
        chmod +x kerbrute
    else
        log_warn "kerbrute déjà installé"
    fi
}

install_certipy() {
    log_info "Installation de Certipy..."
    cd $TOOLS_DIR
    if [ ! -d "Certipy" ]; then
        git clone https://github.com/ly4k/Certipy.git
        cd Certipy
        pip3 install .
    else
        log_warn "Certipy déjà installé"
    fi
}

install_coercer() {
    log_info "Installation de Coercer..."
    cd $TOOLS_DIR
    if [ ! -d "Coercer" ]; then
        git clone https://github.com/p0dalirius/Coercer.git
        cd Coercer
        pip3 install -r requirements.txt
    else
        log_warn "Coercer déjà installé"
    fi
}

install_petitpotam() {
    log_info "Installation de PetitPotam..."
    cd $TOOLS_DIR
    if [ ! -d "PetitPotam" ]; then
        git clone https://github.com/topotam/PetitPotam.git
    else
        log_warn "PetitPotam déjà installé"
    fi
}

install_dfscoerce() {
    log_info "Installation de DFSCoerce..."
    cd $TOOLS_DIR
    if [ ! -d "DFSCoerce" ]; then
        git clone https://github.com/Wh04m1001/DFSCoerce.git
        cd DFSCoerce
        pip3 install -r requirements.txt
    else
        log_warn "DFSCoerce déjà installé"
    fi
}

install_mitm6() {
    log_info "Installation de mitm6..."
    pip3 install mitm6
}

install_responder() {
    log_info "Installation de Responder..."
    cd $TOOLS_DIR
    if [ ! -d "Responder" ]; then
        git clone https://github.com/lgandx/Responder.git
        cd Responder
        pip3 install -r requirements.txt
    else
        log_warn "Responder déjà installé"
    fi
}

install_zerologon_tools() {
    log_info "Installation des outils Zerologon..."
    cd $TOOLS_DIR
    if [ ! -d "zerologon" ]; then
        mkdir zerologon
        cd zerologon
        wget https://raw.githubusercontent.com/dirkjanm/CVE-2020-1472/master/cve-2020-1472-exploit.py
        wget https://raw.githubusercontent.com/SecuraBV/CVE-2020-1472/master/zerologon_tester.py
        chmod +x *.py
    else
        log_warn "Outils Zerologon déjà installés"
    fi
}

install_printnightmare() {
    log_info "Installation des outils PrintNightmare..."
    cd $TOOLS_DIR
    if [ ! -d "CVE-2021-1675" ]; then
        git clone https://github.com/cube0x0/CVE-2021-1675.git
    else
        log_warn "Outils PrintNightmare déjà installés"
    fi
}

install_sharphound() {
    log_info "Installation de SharpHound..."
    cd $TOOLS_DIR
    if [ ! -d "SharpHound" ]; then
        mkdir SharpHound
        cd SharpHound
        # Télécharger la dernière version
        LATEST_RELEASE=$(curl -s https://api.github.com/repos/BloodHoundAD/SharpHound/releases/latest | grep "browser_download_url.*SharpHound.*exe" | cut -d '"' -f 4)
        wget "$LATEST_RELEASE" -O SharpHound.exe
    else
        log_warn "SharpHound déjà installé"
    fi
}

setup_winrecon() {
    log_info "Configuration de WinRecon..."
    
    # Créer le répertoire WinRecon
    mkdir -p /opt/winrecon
    
    # Copier les fichiers (assumant qu'ils sont dans le répertoire courant)
    if [ -f "winrecon.py" ]; then
        cp winrecon.py /opt/winrecon/
        chmod +x /opt/winrecon/winrecon.py
    fi
    
    if [ -f "winrecon_config.yaml" ]; then
        cp winrecon_config.yaml /opt/winrecon/
    fi
    
    # Créer un lien symbolique
    ln -sf /opt/winrecon/winrecon.py /usr/local/bin/winrecon
    
    # Créer le répertoire de configuration utilisateur
    USER_HOME=$(eval echo ~$SUDO_USER)
    USER_CONFIG_DIR="$USER_HOME/.config/winrecon"
    mkdir -p "$USER_CONFIG_DIR"
    
    if [ -f "/opt/winrecon/winrecon_config.yaml" ]; then
        cp /opt/winrecon/winrecon_config.yaml "$USER_CONFIG_DIR/config.yaml"
        chown -R $SUDO_USER:$SUDO_USER "$USER_CONFIG_DIR"
    fi
}

create_wordlists() {
    log_info "Préparation des wordlists..."
    
    # Créer le répertoire wordlists
    mkdir -p /opt/winrecon/wordlists
    
    # Listes d'utilisateurs AD communes
    cat > /opt/winrecon/wordlists/ad_users.txt << EOF
administrator
admin
guest
krbtgt
DefaultAccount
WDAGUtilityAccount
backup
service
support
test
user
user1
user2
service_account
svc_account
sql_service
web_service
ftp_service
mail_service
dns_service
dhcp_service
file_service
print_service
EOF

    # Listes de mots de passe communes pour AD
    cat > /opt/winrecon/wordlists/ad_passwords.txt << EOF
password
Password1
Password123
password123
admin
administrator
root
toor
pass
Pass123
Welcome1
Welcome123
P@ssw0rd
P@ssword1
123456
password1
qwerty
letmein
monkey
dragon
EOF

    # Listes de SPN communes
    cat > /opt/winrecon/wordlists/spn_services.txt << EOF
HTTP
MSSQL
MYSQL
FTP
IMAP
POP
SMTP
LDAP
DNS
CIFS
HOST
RPCSS
WSMAN
TERMSRV
SIP
VNC
SNMP
EOF
}

print_completion() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    Installation terminée!                    ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                              ║"
    echo "║  WinRecon est maintenant installé et prêt à l'emploi!       ║"
    echo "║                                                              ║"
    echo "║  Usage:                                                      ║"
    echo "║    winrecon 192.168.1.100                                   ║"
    echo "║    winrecon 192.168.1.0/24 -d domain.local -u user -p pwd  ║"
    echo "║    winrecon -t targets.txt --config ~/.config/winrecon/config.yaml ║"
    echo "║                                                              ║"
    echo "║  Configuration: ~/.config/winrecon/config.yaml              ║"
    echo "║  Outils installés dans: /opt/                               ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

main() {
    print_banner
    
    log_info "Début de l'installation de WinRecon..."
    
    check_root
    update_system
    install_base_tools
    install_windapsearch
    install_bloodhound_python
    install_ldapdomaindump
    install_adidnsdump
    install_kerbrute
    install_certipy
    install_coercer
    install_petitpotam
    install_dfscoerce
    install_mitm6
    install_responder
    install_zerologon_tools
    install_printnightmare
    install_sharphound
    setup_winrecon
    create_wordlists
    
    print_completion
    
    log_info "Installation terminée avec succès!"
    log_info "Redémarrez votre terminal ou sourcez votre .bashrc pour utiliser la commande 'winrecon'"
}

# Vérifier si le script est exécuté directement
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi