#!/usr/bin/env python3

"""
WinRecon - Windows/Active Directory Automated Enumeration Tool
Inspired by AutoRecon but specialized for Windows environments

Author: [Your Name]
Version: 1.0
Description: Multi-threaded Windows/AD reconnaissance tool with automated enumeration based on OCD mindmaps
"""

import argparse
import asyncio
import concurrent.futures
import ipaddress
import json
import logging
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
import yaml
import getpass

# Configuration par défaut
DEFAULT_CONFIG = {
    'output_dir': 'winrecon_results',
    'max_concurrent_scans': 10,
    'timeout': 3600,  # 1 heure
    'verbose': False,
    'domain': None,
    'username': None,
    'password': None,
    'hash': None,
    'dc_ip': None,
    'tools': {
        'nmap': '/usr/bin/nmap',
        'ldapsearch': '/usr/bin/ldapsearch',
        'smbclient': '/usr/bin/smbclient',
        'enum4linux': '/usr/bin/enum4linux',
        'windapsearch': 'python3 /opt/windapsearch/windapsearch.py',
        'bloodhound': 'python3 /opt/BloodHound.py/bloodhound.py',
        'crackmapexec': '/usr/bin/crackmapexec',
        'impacket-secretsdump': '/usr/bin/impacket-secretsdump',
        'impacket-GetNPUsers': '/usr/bin/impacket-GetNPUsers',
        'impacket-GetUserSPNs': '/usr/bin/impacket-GetUserSPNs',
        'kerbrute': '/opt/kerbrute/kerbrute',
        'gobuster': '/usr/bin/gobuster',
        'nikto': '/usr/bin/nikto'
    }
}

@dataclass
class Target:
    """Représente une cible à scanner"""
    ip: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    os_info: Optional[str] = None
    open_ports: List[int] = None
    services: Dict[int, str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = {}

class WinReconScanner:
    """Scanner principal pour l'énumération Windows/AD"""
    
    def __init__(self, config: Dict, no_prompt: bool = False, no_auto_detect: bool = False):
        self.config = config
        self.no_prompt = no_prompt
        self.no_auto_detect = no_auto_detect
        self.targets: List[Target] = []
        self.results_dir = Path(config['output_dir'])
        # Create results directory before setting up logging
        self.results_dir.mkdir(exist_ok=True)
        self.setup_logging()
        # Auto-detect and update tool paths (unless disabled)
        if not self.no_auto_detect:
            self.detect_and_update_tools()
        self.ensure_tools_available()
        
    def setup_logging(self):
        """Configuration du logging"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        level = logging.DEBUG if self.config['verbose'] else logging.INFO
        
        # Ensure log file path exists
        log_file = self.results_dir / 'winrecon.log'
        
        logging.basicConfig(
            level=level,
            format=log_format,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def detect_and_update_tools(self):
        """Détecte automatiquement les chemins des outils et met à jour la configuration"""
        print("[*] Auto-detecting tool paths...")
        self.logger.info("Auto-detecting tool paths...")
        
        # Dictionnaire des outils avec leurs noms alternatifs
        tool_alternatives = {
            'crackmapexec': ['cme', 'crackmapexec', 'nxc', 'netexec'],
            'impacket-secretsdump': ['impacket-secretsdump', 'secretsdump.py', 'secretsdump'],
            'impacket-GetNPUsers': ['impacket-GetNPUsers', 'GetNPUsers.py', 'GetNPUsers'],
            'impacket-GetUserSPNs': ['impacket-GetUserSPNs', 'GetUserSPNs.py', 'GetUserSPNs'],
            'bloodhound': ['bloodhound-python', 'bloodhound.py', 'bloodhound'],
            'enum4linux': ['enum4linux'],
            'kerbrute': ['kerbrute'],
            'nmap': ['nmap'],
            'smbclient': ['smbclient'],
            'ldapsearch': ['ldapsearch'],
            'gobuster': ['gobuster'],
            'nikto': ['nikto']
        }
        
        updated_tools = {}
        
        for tool_key, alternatives in tool_alternatives.items():
            detected_path = self._find_tool_path(alternatives)
            if detected_path:
                # Only update if different from current config
                current_path = self.config['tools'].get(tool_key, '')
                if current_path != detected_path:
                    updated_tools[tool_key] = detected_path
                    self.config['tools'][tool_key] = detected_path
                    self.logger.debug(f"Updated {tool_key}: {detected_path}")
        
        # Special case for BloodHound - check if it's available as Python module
        if 'bloodhound' not in updated_tools:
            try:
                import subprocess
                result = subprocess.run(['python3', '-c', 'import bloodhound'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    updated_tools['bloodhound'] = 'python3 -m bloodhound'
                    self.config['tools']['bloodhound'] = 'python3 -m bloodhound'
                    self.logger.debug("BloodHound available as Python module")
            except:
                pass
        
        if updated_tools:
            print(f"[*] Auto-detected and updated {len(updated_tools)} tool paths")
            self.logger.info(f"Auto-detected {len(updated_tools)} tool paths")
            for tool, path in updated_tools.items():
                self.logger.debug(f"  {tool}: {path}")
        else:
            self.logger.debug("No tool path updates needed")
    
    def _find_tool_path(self, tool_names: List[str]) -> Optional[str]:
        """Trouve le chemin d'un outil parmi plusieurs noms possibles"""
        import shutil
        
        for name in tool_names:
            # Check if command is available in PATH
            path = shutil.which(name)
            if path:
                return name  # Return the command name, not full path for flexibility
            
            # Check common installation directories
            common_dirs = [
                '/usr/local/bin',
                '/usr/bin', 
                '/opt',
                f'{Path.home()}/.local/bin'
            ]
            
            for directory in common_dirs:
                full_path = Path(directory) / name
                if full_path.exists() and full_path.is_file():
                    # Check if executable
                    if os.access(full_path, os.X_OK):
                        return str(full_path)
        
        return None
        
    def ensure_tools_available(self):
        """Vérifie que les outils nécessaires sont disponibles"""
        missing_tools = []
        tool_commands = {
            'nmap': 'apt-get install -y nmap',
            'ldapsearch': 'apt-get install -y ldap-utils',
            'smbclient': 'apt-get install -y smbclient',
            'enum4linux': 'apt-get install -y enum4linux',
            'crackmapexec': 'apt-get install -y crackmapexec',
            'impacket-secretsdump': 'apt-get install -y python3-impacket',
            'impacket-GetNPUsers': 'apt-get install -y python3-impacket',
            'impacket-GetUserSPNs': 'apt-get install -y python3-impacket',
            'kerbrute': 'wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute',
            'gobuster': 'apt-get install -y gobuster',
            'nikto': 'apt-get install -y nikto',
            'windapsearch': 'git clone https://github.com/ropnop/windapsearch.git /opt/windapsearch',
            'bloodhound': 'pip3 install bloodhound'
        }
        
        for tool, path in self.config['tools'].items():
            if not self.check_tool_available(path.split()[0]):
                missing_tools.append(tool)
                
        if missing_tools:
            self.logger.warning(f"Missing tools detected: {', '.join(missing_tools)}")
            print("\n" + "="*60)
            print("MISSING TOOLS DETECTED")
            print("="*60)
            print(f"\nThe following tools are missing: {', '.join(missing_tools)}")
            print("\nWinRecon can work with limited functionality, but installing")
            print("these tools will enable all features.")
            
            if self.no_prompt:
                print("\n[*] Skipping installation prompt (--no-prompt flag used)")
                return
                
            install_prompt = input("\nWould you like to see installation instructions? (y/n): ").lower().strip()
            
            if install_prompt == 'y':
                print("\n" + "-"*60)
                print("INSTALLATION INSTRUCTIONS")
                print("-"*60)
                
                # Check if user has sudo
                has_sudo = os.geteuid() == 0 or subprocess.run(['sudo', '-n', 'true'], 
                                                               capture_output=True).returncode == 0
                
                if not has_sudo:
                    print("\n[!] You need sudo/root privileges to install system tools.")
                    print("    Please run WinRecon with sudo or ask your administrator to install:")
                
                print("\nTo install all missing tools at once:")
                all_commands = set()
                impacket_needed = False
                
                for tool in missing_tools:
                    if tool in tool_commands:
                        cmd = tool_commands[tool]
                        if 'impacket' in cmd:
                            impacket_needed = True
                        elif cmd.startswith('apt-get'):
                            pkg = cmd.replace('apt-get install -y ', '')
                            all_commands.add(pkg)
                
                if all_commands or impacket_needed:
                    print(f"\n    sudo apt-get update")
                    if all_commands:
                        print(f"    sudo apt-get install -y {' '.join(all_commands)}")
                    if impacket_needed:
                        print(f"    sudo apt-get install -y python3-impacket")
                
                print("\nIndividual installation commands:")
                for tool in missing_tools:
                    if tool in tool_commands:
                        print(f"\n{tool}:")
                        cmd = tool_commands[tool]
                        if not has_sudo and not cmd.startswith('pip3'):
                            cmd = 'sudo ' + cmd
                        print(f"    {cmd}")
                
                print("\n" + "-"*60)
                
                if has_sudo:
                    auto_install = input("\nAttempt automatic installation? (y/n): ").lower().strip()
                    if auto_install == 'y':
                        self.install_missing_tools(missing_tools, tool_commands)
            
            print("\nContinuing with available tools...\n")
            
    def check_tool_available(self, tool_path: str) -> bool:
        """Vérifie si un outil est disponible"""
        try:
            subprocess.run([tool_path, '--help'], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL, 
                         timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False
    
    def install_missing_tools(self, missing_tools: List[str], tool_commands: Dict[str, str]):
        """Try to install missing tools automatically"""
        print("\nAttempting automatic installation...")
        
        # Fix /tmp permissions if needed
        try:
            # Check if we can write to /tmp
            test_file = '/tmp/winrecon_test'
            Path(test_file).touch()
            Path(test_file).unlink()
        except Exception:
            print("\n[!] /tmp directory has permission issues. Attempting to fix...")
            try:
                subprocess.run(['chmod', '1777', '/tmp'], check=False)
                subprocess.run(['mount', '-o', 'remount,exec', '/tmp'], check=False)
            except:
                pass
        
        # Update package lists with workarounds
        print("\n[*] Updating package lists...")
        update_success = False
        
        # Try different update methods
        update_methods = [
            ['apt-get', 'update'],
            ['apt-get', 'update', '--allow-insecure-repositories'],
            ['apt-get', 'update', '-o', 'Acquire::AllowInsecureRepositories=true'],
            ['apt-get', 'update', '-o', 'Dir::Etc::sourcelist=/dev/null', '-o', 'Dir::Etc::sourceparts=/dev/null']
        ]
        
        for method in update_methods:
            try:
                # Set environment to avoid apt-key issues
                env = os.environ.copy()
                env['APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE'] = '1'
                env['DEBIAN_FRONTEND'] = 'noninteractive'
                
                result = subprocess.run(method, env=env, capture_output=True, text=True)
                if result.returncode == 0:
                    update_success = True
                    break
                elif 'is not signed' in result.stderr:
                    print("[!] Some repositories are unsigned. Trying with --allow-insecure...")
                    continue
            except Exception as e:
                continue
        
        if not update_success:
            print("[!] Failed to update package lists. Continuing anyway...")
        else:
            print("[✓] Package lists updated")
        
        # Install each tool
        env = os.environ.copy()
        env['DEBIAN_FRONTEND'] = 'noninteractive'
        env['APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE'] = '1'
        
        for tool in missing_tools:
            if tool not in tool_commands:
                continue
                
            print(f"\n[*] Installing {tool}...")
            cmd = tool_commands[tool]
            
            try:
                if cmd.startswith('apt-get'):
                    # Try with different options for problematic systems
                    install_cmds = [
                        cmd.split(),
                        cmd.split() + ['--allow-unauthenticated'],
                        cmd.split() + ['-o', 'Acquire::AllowInsecureRepositories=true']
                    ]
                    
                    installed = False
                    for install_cmd in install_cmds:
                        try:
                            subprocess.run(install_cmd, env=env, check=True)
                            installed = True
                            break
                        except subprocess.CalledProcessError:
                            continue
                    
                    if installed:
                        print(f"[✓] {tool} installed successfully")
                    else:
                        print(f"[✗] Failed to install {tool}")
                        
                elif cmd.startswith('wget'):
                    subprocess.run(cmd, shell=True, check=True)
                    print(f"[✓] {tool} installed successfully")
                elif cmd.startswith('git'):
                    subprocess.run(cmd.split(), check=True)
                    print(f"[✓] {tool} installed successfully")
                elif cmd.startswith('pip3'):
                    subprocess.run(cmd.split(), check=True)
                    print(f"[✓] {tool} installed successfully")
            except Exception as e:
                print(f"[✗] Failed to install {tool}: {e}")
        
        print("\n[*] Installation process completed.")
        print("[*] Some tools may require additional configuration.")

    def create_target_structure(self, target: Target):
        """Crée la structure de dossiers pour une cible"""
        target_dir = self.results_dir / target.ip
        dirs_to_create = [
            target_dir,
            target_dir / 'scans',
            target_dir / 'scans' / 'nmap',
            target_dir / 'scans' / 'smb',
            target_dir / 'scans' / 'ldap',
            target_dir / 'scans' / 'web',
            target_dir / 'scans' / 'kerberos',
            target_dir / 'loot',
            target_dir / 'loot' / 'credentials',
            target_dir / 'loot' / 'hashes',
            target_dir / 'loot' / 'bloodhound',
            target_dir / 'exploit',
            target_dir / 'report'
        ]
        
        for directory in dirs_to_create:
            directory.mkdir(parents=True, exist_ok=True)
            
        # Créer les fichiers de rapport par défaut
        (target_dir / 'report' / 'notes.txt').touch()
        (target_dir / 'report' / 'local.txt').touch()
        (target_dir / 'report' / 'proof.txt').touch()
        
        return target_dir

    async def run_command(self, command: str, output_file: Optional[Path] = None, timeout: Optional[int] = None) -> tuple:
        """Exécute une commande de manière asynchrone"""
        try:
            self.logger.debug(f"Executing: {command}")
            
            # Use custom timeout if provided, otherwise use default
            cmd_timeout = timeout if timeout else self.config['timeout']
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=cmd_timeout
            )
            
            result = {
                'command': command,
                'returncode': process.returncode,
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore')
            }
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(result['stdout'])
                    
            return result
            
        except asyncio.TimeoutError:
            self.logger.error(f"Command timeout: {command}")
            return {'command': command, 'error': 'timeout'}
        except Exception as e:
            self.logger.error(f"Command failed: {command} - {e}")
            return {'command': command, 'error': str(e)}

    async def nmap_scan(self, target: Target, target_dir: Path):
        """Scan Nmap initial pour découvrir les services"""
        self.logger.info(f"Starting Nmap scan for {target.ip}")
        
        # Commands for parallel execution
        tcp_command = (f"{self.config['tools']['nmap']} -sC -sV -O -A -Pn "
                      f"-oA {target_dir}/scans/nmap/tcp_full {target.ip}")
        
        # UDP scan with reduced timeout and limited ports
        udp_timeout = self.config.get('udp_timeout', 300)  # 5 minutes default
        udp_command = (f"{self.config['tools']['nmap']} -sU --top-ports 20 "
                      f"--max-retries 1 --version-intensity 0 "
                      f"-oA {target_dir}/scans/nmap/udp_top20 {target.ip}")
        
        # Run TCP and UDP scans in parallel
        self.logger.info(f"Running TCP and UDP scans in parallel for {target.ip}")
        tcp_task = asyncio.create_task(self.run_command(tcp_command))
        udp_task = asyncio.create_task(self.run_command(udp_command, timeout=udp_timeout))
        
        # Wait for both scans to complete
        tcp_result, udp_result = await asyncio.gather(tcp_task, udp_task, return_exceptions=True)
        
        # Handle results
        if isinstance(tcp_result, Exception):
            self.logger.error(f"TCP scan failed: {tcp_result}")
            tcp_result = {'error': str(tcp_result)}
        if isinstance(udp_result, Exception):
            self.logger.error(f"UDP scan failed: {udp_result}")
            udp_result = {'error': str(udp_result)}
        
        # Parser les résultats pour extraire les ports ouverts
        self.parse_nmap_results(target, tcp_result, udp_result)
        
        # Scans spécialisés basés sur les ports découverts
        await self.specialized_nmap_scans(target, target_dir)

    async def specialized_nmap_scans(self, target: Target, target_dir: Path):
        """Scans Nmap spécialisés basés sur les services découverts"""
        scripts_map = {
            53: "dns-zone-transfer,dns-recursion,dns-cache-snoop",
            88: "krb5-enum-users",
            135: "rpc-grind,rpcinfo",
            139: "smb-enum-shares,smb-enum-users,smb-enum-domains,smb-security-mode",
            389: "ldap-rootdse,ldap-search",
            445: "smb-enum-shares,smb-enum-users,smb-enum-domains,smb-security-mode,smb-vuln-*",
            593: "rpc-grind,rpcinfo",
            636: "ldap-rootdse,ldap-search",
            3268: "ldap-rootdse,ldap-search",
            3269: "ldap-rootdse,ldap-search",
            5985: "http-enum,http-methods,http-webdav-scan"
        }
        
        for port in target.open_ports:
            if port in scripts_map:
                command = (f"{self.config['tools']['nmap']} -p {port} "
                          f"--script {scripts_map[port]} "
                          f"-oA {target_dir}/scans/nmap/port_{port}_specialized {target.ip}")
                
                await self.run_command(command)

    def parse_nmap_results(self, target: Target, tcp_result: Dict, udp_result: Dict):
        """Parse les résultats Nmap pour extraire les informations"""
        import re
        
        # Parse TCP results
        if tcp_result and 'stdout' in tcp_result:
            tcp_output = tcp_result['stdout']
            self.logger.debug(f"Parsing TCP nmap output for {target.ip}")
            
            # Extract open TCP ports using regex
            tcp_port_pattern = r'(\d+)/tcp\s+open'
            tcp_matches = re.findall(tcp_port_pattern, tcp_output)
            
            for port_str in tcp_matches:
                port = int(port_str)
                target.open_ports.append(port)
                self.logger.debug(f"Found open TCP port: {port}")
            
            # Extract service information
            service_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
            service_matches = re.findall(service_pattern, tcp_output)
            
            for port_str, service in service_matches:
                port = int(port_str)
                target.services[port] = service
                self.logger.debug(f"Service on port {port}: {service}")
            
            # Extract hostname if available
            hostname_pattern = r'Nmap scan report for (\S+) \('
            hostname_match = re.search(hostname_pattern, tcp_output)
            if hostname_match and hostname_match.group(1) != target.ip:
                target.hostname = hostname_match.group(1)
                self.logger.debug(f"Found hostname: {target.hostname}")
        
        # Parse UDP results
        if udp_result and 'stdout' in udp_result:
            udp_output = udp_result['stdout']
            self.logger.debug(f"Parsing UDP nmap output for {target.ip}")
            
            # Extract open UDP ports
            udp_port_pattern = r'(\d+)/udp\s+open'
            udp_matches = re.findall(udp_port_pattern, udp_output)
            
            for port_str in udp_matches:
                port = int(port_str)
                if port not in target.open_ports:
                    target.open_ports.append(port)
                    self.logger.debug(f"Found open UDP port: {port}")
            
            # Extract UDP service information
            udp_service_pattern = r'(\d+)/udp\s+open\s+(\S+)'
            udp_service_matches = re.findall(udp_service_pattern, udp_output)
            
            for port_str, service in udp_service_matches:
                port = int(port_str)
                if port not in target.services:
                    target.services[port] = f"{service} (UDP)"
                else:
                    target.services[port] += f" / {service} (UDP)"
                self.logger.debug(f"UDP service on port {port}: {service}")
        
        # Sort ports for consistent output
        target.open_ports.sort()
        
        self.logger.info(f"Found {len(target.open_ports)} open ports on {target.ip}: {target.open_ports}")

    async def smb_enumeration(self, target: Target, target_dir: Path):
        """Énumération SMB complète"""
        if 445 not in target.open_ports and 139 not in target.open_ports:
            return
            
        self.logger.info(f"Starting SMB enumeration for {target.ip}")
        
        commands = [
            # enum4linux
            f"{self.config['tools']['enum4linux']} -a {target.ip}",
            
            # smbclient liste des partages
            f"{self.config['tools']['smbclient']} -L //{target.ip}/ -N",
            
            # crackmapexec
            f"{self.config['tools']['crackmapexec']} smb {target.ip}",
            f"{self.config['tools']['crackmapexec']} smb {target.ip} --shares",
            f"{self.config['tools']['crackmapexec']} smb {target.ip} --users",
            f"{self.config['tools']['crackmapexec']} smb {target.ip} --groups",
            f"{self.config['tools']['crackmapexec']} smb {target.ip} --local-auth",
        ]
        
        # Si on a des credentials
        if self.config.get('username') and (self.config.get('password') or self.config.get('hash')):
            if self.config.get('password'):
                auth_commands = [
                    f"{self.config['tools']['crackmapexec']} smb {target.ip} "
                    f"-u {self.config['username']} -p {self.config['password']} --shares",
                    f"{self.config['tools']['crackmapexec']} smb {target.ip} "
                    f"-u {self.config['username']} -p {self.config['password']} --users",
                    f"{self.config['tools']['crackmapexec']} smb {target.ip} "
                    f"-u {self.config['username']} -p {self.config['password']} --groups",
                ]
            else:  # Using hash
                auth_commands = [
                    f"{self.config['tools']['crackmapexec']} smb {target.ip} "
                    f"-u {self.config['username']} -H {self.config['hash']} --shares",
                    f"{self.config['tools']['crackmapexec']} smb {target.ip} "
                    f"-u {self.config['username']} -H {self.config['hash']} --users",
                    f"{self.config['tools']['crackmapexec']} smb {target.ip} "
                    f"-u {self.config['username']} -H {self.config['hash']} --groups",
                ]
            commands.extend(auth_commands)
        else:
            self.logger.info("[*] No credentials provided - skipping authenticated SMB enumeration")
            
        # Exécuter tous les scans SMB
        for i, command in enumerate(commands):
            output_file = target_dir / 'scans' / 'smb' / f'smb_scan_{i+1}.txt'
            await self.run_command(command, output_file)

    async def ldap_enumeration(self, target: Target, target_dir: Path):
        """Énumération LDAP/Active Directory"""
        if 389 not in target.open_ports and 636 not in target.open_ports:
            return
            
        self.logger.info(f"Starting LDAP enumeration for {target.ip}")
        
        commands = []
        
        # ldapsearch anonyme
        commands.extend([
            f"ldapsearch -x -h {target.ip} -s base namingcontexts",
            f"ldapsearch -x -h {target.ip} -s base '(objectClass=*)'",
        ])
        
        # Si on a des credentials et un domaine
        if (self.config.get('username') and (self.config.get('password') or self.config.get('hash')) and 
            self.config.get('domain')):
            
            domain = self.config['domain']
            username = self.config['username']
            password = self.config.get('password')
            hash_val = self.config.get('hash')
            
            # windapsearch - only if password provided (doesn't support hash)
            if password:
                windap_commands = [
                    f"{self.config['tools']['windapsearch']} -d {domain} "
                    f"-u {username} -p {password} --dc-ip {target.ip} -U",
                    f"{self.config['tools']['windapsearch']} -d {domain} "
                    f"-u {username} -p {password} --dc-ip {target.ip} -G",
                    f"{self.config['tools']['windapsearch']} -d {domain} "
                    f"-u {username} -p {password} --dc-ip {target.ip} -C",
                    f"{self.config['tools']['windapsearch']} -d {domain} "
                    f"-u {username} -p {password} --dc-ip {target.ip} --da",
                ]
                commands.extend(windap_commands)
                
                # BloodHound
                bloodhound_cmd = (f"{self.config['tools']['bloodhound']} "
                                f"-u {username} -p {password} -d {domain} "
                                f"-ns {target.ip} -c all")
                commands.append(bloodhound_cmd)
            else:
                self.logger.info("[*] Using hash authentication - skipping tools that require password")
        else:
            self.logger.info("[*] No credentials provided - skipping authenticated LDAP enumeration")
        
        # Exécuter tous les scans LDAP
        for i, command in enumerate(commands):
            output_file = target_dir / 'scans' / 'ldap' / f'ldap_scan_{i+1}.txt'
            await self.run_command(command, output_file)

    async def kerberos_enumeration(self, target: Target, target_dir: Path):
        """Énumération Kerberos"""
        if 88 not in target.open_ports:
            return
            
        self.logger.info(f"Starting Kerberos enumeration for {target.ip}")
        
        if not (self.config.get('domain') and self.config.get('username')):
            self.logger.info("[*] No credentials provided - skipping Kerberos enumeration")
            return
            
        domain = self.config['domain']
        commands = []
        
        # ASREPRoast
        asrep_cmd = (f"{self.config['tools']['impacket-GetNPUsers']} "
                    f"{domain}/ -usersfile /usr/share/seclists/Usernames/Names/names.txt "
                    f"-format hashcat -outputfile {target_dir}/loot/credentials/asrep_hashes.txt "
                    f"-dc-ip {target.ip}")
        commands.append(asrep_cmd)
        
        # Si on a des credentials
        if self.config.get('password') or self.config.get('hash'):
            username = self.config['username']
            password = self.config.get('password')
            hash_val = self.config.get('hash')
            
            # Kerberoasting
            kerberoast_cmd = (f"{self.config['tools']['impacket-GetUserSPNs']} "
                            f"{domain}/{username}:{password} "
                            f"-request -outputfile {target_dir}/loot/credentials/kerberoast_hashes.txt "
                            f"-dc-ip {target.ip}")
            commands.append(kerberoast_cmd)
        
        # Exécuter les scans Kerberos
        for i, command in enumerate(commands):
            output_file = target_dir / 'scans' / 'kerberos' / f'kerberos_scan_{i+1}.txt'
            await self.run_command(command, output_file)

    async def web_enumeration(self, target: Target, target_dir: Path):
        """Énumération des services web"""
        web_ports = [80, 443, 8080, 8443, 5985, 5986]
        found_web_ports = [port for port in web_ports if port in target.open_ports]
        
        if not found_web_ports:
            return
            
        self.logger.info(f"Starting web enumeration for {target.ip}")
        
        for port in found_web_ports:
            protocol = 'https' if port in [443, 8443, 5986] else 'http'
            url = f"{protocol}://{target.ip}:{port}"
            
            commands = [
                # Nikto
                f"{self.config['tools']['nikto']} -h {url}",
                
                # Gobuster
                f"{self.config['tools']['gobuster']} dir -u {url} "
                f"-w /usr/share/seclists/Discovery/Web-Content/common.txt",
            ]
            
            for i, command in enumerate(commands):
                output_file = target_dir / 'scans' / 'web' / f'web_{port}_scan_{i+1}.txt'
                await self.run_command(command, output_file)

    async def scan_target(self, target: Target):
        """Scanne une cible complètement"""
        self.logger.info(f"Starting comprehensive scan of {target.ip}")
        
        # Créer la structure de dossiers
        target_dir = self.create_target_structure(target)
        
        # Scan initial Nmap
        await self.nmap_scan(target, target_dir)
        
        # Énumérations spécialisées en parallèle
        await asyncio.gather(
            self.smb_enumeration(target, target_dir),
            self.ldap_enumeration(target, target_dir),
            self.kerberos_enumeration(target, target_dir),
            self.web_enumeration(target, target_dir),
            return_exceptions=True
        )
        
        self.logger.info(f"Completed scan of {target.ip}")
        
        # Générer le rapport
        await self.generate_report(target, target_dir)

    async def generate_report(self, target: Target, target_dir: Path):
        """Génère des rapports complets"""
        self.logger.info(f"Generating reports for {target.ip}")
        
        # Use only the simple report generator to avoid import issues
        try:
            # Import and use simple report generator
            import sys
            import os
            # Add current directory to Python path to ensure module can be found
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from simple_report import SimpleReportGenerator
            report_gen = SimpleReportGenerator(self.config, self.logger)
            
            # Prepare results data
            results = {
                'target': target.ip,
                'hostname': target.hostname,
                'domain': target.domain,
                'open_ports': list(target.open_ports) if target.open_ports else [],
                'services': target.services if hasattr(target, 'services') else {},
                'scan_dir': str(target_dir)
            }
            
            # Generate reports
            success = report_gen.generate_reports(results, target_dir)
            
            if success:
                self.logger.info(f"Reports generated successfully for {target.ip}")
                print(f"\n[*] Reports generated in: {target_dir}/report/")
                print(f"    - HTML Report: {target_dir}/report/report.html")
                print(f"    - JSON Report: {target_dir}/report/report.json")
                print(f"    - Text Summary: {target_dir}/report/summary.txt")
                return
            else:
                raise Exception("Simple report generation failed")
                
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            self.logger.info("Falling back to basic text report...")
            # Fallback to basic text report
            await self.generate_simple_report(target, target_dir)
    
    async def generate_simple_report(self, target: Target, target_dir: Path):
        """Génère un rapport texte simple en cas d'erreur"""
        report_file = target_dir / 'report' / 'summary.txt'
        
        with open(report_file, 'w') as f:
            f.write(f"WinRecon Report for {target.ip}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Scan completed: {datetime.now()}\n")
            f.write(f"Target: {target.ip}\n")
            if target.hostname:
                f.write(f"Hostname: {target.hostname}\n")
            if target.domain:
                f.write(f"Domain: {target.domain}\n")
            f.write(f"Open ports: {', '.join(map(str, target.open_ports))}\n\n")
            
            # Service analysis
            f.write("Services Analysis:\n")
            f.write("-" * 20 + "\n")
            
            if 445 in target.open_ports or 139 in target.open_ports:
                f.write("✓ SMB service detected\n")
            if 389 in target.open_ports or 636 in target.open_ports:
                f.write("✓ LDAP service detected\n")
            if 88 in target.open_ports:
                f.write("✓ Kerberos service detected\n")
            
            web_ports = [80, 443, 8080, 8443, 5985, 5986]
            if any(port in target.open_ports for port in web_ports):
                f.write("✓ Web services detected\n")
    
    async def generate_global_report(self):
        """Génère un rapport global pour toutes les cibles"""
        try:
            global_report = self.results_dir / "global_summary.txt"
            with open(global_report, 'w') as f:
                f.write("WinRecon Global Summary\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Scan completed: {datetime.now()}\n")
                f.write(f"Total targets scanned: {len(self.targets)}\n\n")
                
                for target in self.targets:
                    f.write(f"\nTarget: {target.ip}\n")
                    f.write("-" * 30 + "\n")
                    if target.hostname:
                        f.write(f"Hostname: {target.hostname}\n")
                    if target.open_ports:
                        f.write(f"Open ports: {', '.join(map(str, sorted(target.open_ports)))}\n")
                    else:
                        f.write("No open ports detected\n")
                    
                    # Link to detailed report
                    target_dir = self.results_dir / target.ip
                    f.write(f"Detailed reports: {target_dir}/report/\n")
            
            self.logger.info(f"Global summary saved to: {global_report}")
        except Exception as e:
            self.logger.error(f"Failed to generate global report: {e}")

    async def run(self, targets: List[str]):
        """Point d'entrée principal"""
        self.logger.info("Starting WinRecon")
        
        # Ensure results directory exists (already created in __init__)
        self.results_dir.mkdir(exist_ok=True)
        
        # Créer les objets Target
        self.targets = [Target(ip=ip) for ip in targets]
        
        # Scanner toutes les cibles
        semaphore = asyncio.Semaphore(self.config['max_concurrent_scans'])
        
        async def scan_with_semaphore(target):
            async with semaphore:
                await self.scan_target(target)
        
        # Track scan results
        scan_results = await asyncio.gather(
            *[scan_with_semaphore(target) for target in self.targets],
            return_exceptions=True
        )
        
        # Generate global summary report
        await self.generate_global_report()
        
        self.logger.info("WinRecon completed")
        print("\n" + "="*60)
        print("SCAN COMPLETED")
        print("="*60)
        print(f"Results saved in: {self.results_dir}")
        print(f"\nTarget summaries:")
        for target in self.targets:
            target_dir = self.results_dir / target.ip
            print(f"  - {target.ip}: {target_dir}/report/")

def parse_targets(target_input: str) -> List[str]:
    """Parse les cibles d'entrée (IP, CIDR, fichier)"""
    targets = []
    
    if os.path.isfile(target_input):
        # Lire depuis un fichier
        with open(target_input, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.extend(parse_targets(line))
    else:
        try:
            # Essayer de parser comme CIDR
            network = ipaddress.ip_network(target_input, strict=False)
            targets.extend([str(ip) for ip in network.hosts()])
        except ValueError:
            # Traiter comme une IP simple
            targets.append(target_input)
    
    return targets

def load_config(config_file: Optional[str] = None) -> Dict:
    """Charge la configuration"""
    config = DEFAULT_CONFIG.copy()
    
    if config_file and os.path.exists(config_file):
        with open(config_file, 'r') as f:
            user_config = yaml.safe_load(f)
            config.update(user_config)
    
    return config

def prompt_for_credentials(config: Dict) -> Dict:
    """Prompt interactively for missing credentials"""
    import getpass
    
    print("\n=== WinRecon Credential Configuration ===")
    print("Note: Press Enter to skip optional fields\n")
    
    # Domain
    if not config.get('domain'):
        domain = input("Domain name (e.g., corp.local): ").strip()
        if domain:
            config['domain'] = domain
    
    # Username
    if not config.get('username'):
        username = input("Username: ").strip()
        if username:
            config['username'] = username
    
    # Password or Hash (only if username provided)
    if config.get('username') and not config.get('password') and not config.get('hash'):
        print("\nAuthentication method:")
        print("1) Password")
        print("2) NTLM Hash")
        print("3) Skip (anonymous/null session)")
        
        choice = input("Select option [1-3]: ").strip()
        
        if choice == '1':
            password = getpass.getpass("Password: ")
            if password:
                config['password'] = password
        elif choice == '2':
            ntlm_hash = getpass.getpass("NTLM Hash (LM:NTLM or just NTLM): ")
            if ntlm_hash:
                config['hash'] = ntlm_hash
    
    # DC IP (optional but recommended)
    if not config.get('dc_ip') and config.get('domain'):
        dc_ip = input("Domain Controller IP (optional, press Enter to skip): ").strip()
        if dc_ip:
            config['dc_ip'] = dc_ip
    
    print("\n" + "=" * 40 + "\n")
    
    return config

def main():
    parser = argparse.ArgumentParser(
        description="WinRecon - Windows/Active Directory Automated Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100
  %(prog)s 192.168.1.0/24
  %(prog)s -t targets.txt -d domain.local -u user -p password
  %(prog)s 192.168.1.100 --dc-ip 192.168.1.10 -u user -H ntlmhash
        """
    )
    
    parser.add_argument('targets', nargs='*', 
                       help='Target IP addresses, CIDR ranges, or hostnames')
    parser.add_argument('-t', '--target-file', 
                       help='File containing target list')
    parser.add_argument('-o', '--output', default='winrecon_results',
                       help='Output directory (default: winrecon_results)')
    parser.add_argument('-c', '--config', 
                       help='Configuration file (YAML format)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--max-scans', type=int, default=10,
                       help='Maximum concurrent scans (default: 10)')
    parser.add_argument('--timeout', type=int, default=3600,
                       help='Timeout per command in seconds (default: 3600)')
    parser.add_argument('--no-prompt', action='store_true',
                       help='Disable interactive credential prompting')
    parser.add_argument('--no-auto-detect', action='store_true',
                       help='Disable automatic tool detection')
    
    # Credentials
    cred_group = parser.add_argument_group('credentials')
    cred_group.add_argument('-d', '--domain', 
                           help='Domain name')
    cred_group.add_argument('-u', '--username', 
                           help='Username for authentication')
    cred_group.add_argument('-p', '--password', 
                           help='Password for authentication')
    cred_group.add_argument('-H', '--hash', 
                           help='NTLM hash for authentication')
    cred_group.add_argument('--dc-ip', 
                           help='Domain Controller IP address')
    
    args = parser.parse_args()
    
    # Valider les arguments
    if not args.targets and not args.target_file:
        parser.error("Must specify targets or target file")
    
    # Charger la configuration
    config = load_config(args.config)
    
    # Mettre à jour avec les arguments CLI
    config.update({
        'output_dir': args.output,
        'verbose': args.verbose,
        'max_concurrent_scans': args.max_scans,
        'timeout': args.timeout,
        'domain': args.domain,
        'username': args.username,
        'password': args.password,
        'hash': args.hash,
        'dc_ip': args.dc_ip
    })
    
    # Interactive credential prompt if not provided and not disabled
    if not args.no_prompt and not (args.username or args.password or args.hash):
        print("\n" + "="*50)
        print("CREDENTIAL CONFIGURATION")
        print("="*50)
        use_creds = input("\nDo you have credentials for authentication? (y/n): ").lower().strip()
        
        if use_creds == 'y':
            print("\nPlease provide authentication details:")
            if not config['domain']:
                config['domain'] = input("Domain name (e.g., CORP.LOCAL): ").strip()
            
            if not config['username']:
                config['username'] = input("Username: ").strip()
            
            # Ask for password or hash
            auth_type = input("Authentication type - (p)assword or (h)ash? [p]: ").lower().strip() or 'p'
            
            if auth_type == 'h':
                if not config['hash']:
                    config['hash'] = getpass.getpass("NTLM Hash (LM:NTLM or :NTLM): ")
            else:
                if not config['password']:
                    config['password'] = getpass.getpass("Password: ")
            
            # Optional DC IP
            if not config['dc_ip']:
                dc_ip = input("Domain Controller IP (optional, press Enter to skip): ").strip()
                if dc_ip:
                    config['dc_ip'] = dc_ip
        else:
            print("\n[*] No credentials provided. Credential-based enumeration will be skipped.")
            print("[*] Only unauthenticated scans will be performed.")
            config['username'] = None
            config['password'] = None
            config['hash'] = None
            config['domain'] = None
    
    # Parser les cibles
    all_targets = []
    if args.targets:
        for target in args.targets:
            all_targets.extend(parse_targets(target))
    if args.target_file:
        all_targets.extend(parse_targets(args.target_file))
    
    if not all_targets:
        parser.error("No valid targets found")
    
    print(f"WinRecon v1.0 - Windows/AD Enumeration Tool")
    print(f"Targets to scan: {len(all_targets)}")
    print(f"Output directory: {config['output_dir']}")
    print("-" * 50)
    
    # Lancer le scanner
    scanner = WinReconScanner(config, no_prompt=args.no_prompt, no_auto_detect=args.no_auto_detect)
    
    try:
        asyncio.run(scanner.run(all_targets))
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
