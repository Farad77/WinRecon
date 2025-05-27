    async def ldap_enumeration(self, target: Target, target_dir: Path):
        """Énumération LDAP/Active Directory"""
        if 389 not in target.open_ports and 636 not in target.open_ports:
            return
            
        # Préparer toutes les commandes LDAP d'abord
        commands = []
        bloodhound_cmd = None
        
        # ldapsearch anonyme (toujours essayer)
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
            
            # ldapsearch authentifié
            if password:
                # Construire le Bind DN pour ldapsearch
                bind_dn = f"{username}@{domain}"
                
                # Construire le base DN à partir du domaine
                base_dn = ','.join([f'dc={part}' for part in domain.split('.')])
                
                # ldapsearch avec authentification
                auth_ldap_commands = [
                    # Récupérer tous les utilisateurs
                    f"ldapsearch -x -h {target.ip} -D '{bind_dn}' -w '{password}' "
                    f"-b '{base_dn}' '(objectClass=user)' sAMAccountName memberOf userPrincipalName",
                    
                    # Récupérer les groupes
                    f"ldapsearch -x -h {target.ip} -D '{bind_dn}' -w '{password}' "
                    f"-b '{base_dn}' '(objectClass=group)' cn member description",
                    
                    # Récupérer les ordinateurs
                    f"ldapsearch -x -h {target.ip} -D '{bind_dn}' -w '{password}' "
                    f"-b '{base_dn}' '(objectClass=computer)' cn operatingSystem dNSHostName",
                    
                    # Récupérer les comptes de service (SPNs)
                    f"ldapsearch -x -h {target.ip} -D '{bind_dn}' -w '{password}' "
                    f"-b '{base_dn}' '(&(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName",
                    
                    # Récupérer les utilisateurs avec des attributs intéressants
                    f"ldapsearch -x -h {target.ip} -D '{bind_dn}' -w '{password}' "
                    f"-b '{base_dn}' '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName",  # DONT_REQ_PREAUTH
                ]
                commands.extend(auth_ldap_commands)
                
                # windapsearch
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
                
                # BloodHound - stocker la commande pour l'afficher
                bloodhound_output_dir = target_dir / 'loot' / 'bloodhound'
                
                # BloodHound-python avec syntaxe correcte
                bloodhound_cmd = (f"cd {bloodhound_output_dir} && "
                                f"{self.config['tools']['bloodhound']} "
                                f"-u {username}@{domain} "
                                f"-p '{password}' "
                                f"-d {domain} "
                                f"-ns {target.ip} "
                                f"-dc {target.ip} "
                                f"-c All "
                                f"--dns-tcp "
                                f"--disable-pooling "
                                f"--zip")
                
            elif hash_val:
                # BloodHound avec hash NTLM
                bloodhound_output_dir = target_dir / 'loot' / 'bloodhound'
                
                # BloodHound-python supporte l'authentification par hash au format LM:NTLM
                # Si seulement NTLM fourni, ajouter des zéros pour LM
                if ':' not in hash_val:
                    formatted_hash = f"00000000000000000000000000000000:{hash_val}"
                else:
                    formatted_hash = hash_val
                
                bloodhound_cmd = (f"cd {bloodhound_output_dir} && "
                                f"{self.config['tools']['bloodhound']} "
                                f"-u {username}@{domain} "
                                f"--hashes {formatted_hash} "
                                f"-d {domain} "
                                f"-ns {target.ip} "
                                f"-dc {target.ip} "
                                f"-c All "
                                f"--dns-tcp "
                                f"--disable-pooling "
                                f"--auth-method ntlm "
                                f"--zip")
        
        # Préparer les informations pour la confirmation
        creds_info = ""
        tools_info = ""
        all_commands = commands.copy()
        
        if self.config.get('username'):
            creds_info = f"Using credentials: {self.config.get('username')}@{self.config.get('domain', 'WORKGROUP')}"
            tools_info = "Tools: ldapsearch, windapsearch, BloodHound"
            if bloodhound_cmd:
                all_commands.append(bloodhound_cmd)
        else:
            creds_info = "Using anonymous queries only"
            tools_info = "Tools: ldapsearch (anonymous)"
        
        # Demander confirmation avec affichage des commandes
        if not self.ask_confirmation(
            "LDAP/Active Directory Enumeration", 
            f"Enumerate AD users, groups, and collect BloodHound data from {target.ip}\n"
            f"{tools_info}\n"
            f"Authentication: {creds_info}",
            commands=all_commands
        ):
            self.logger.info(f"Skipping LDAP enumeration for {target.ip}")
            return
            
        self.update_status(target.ip, "LDAP_ENUM", "Enumerating AD users and groups")
        self.logger.info(f"Starting LDAP enumeration for {target.ip}")
        
        # Exécuter tous les scans LDAP
        for i, command in enumerate(commands):
            output_file = target_dir / 'scans' / 'ldap' / f'ldap_scan_{i+1}.txt'
            await self.run_command(command, output_file)
        
        # Exécuter BloodHound si disponible
        if bloodhound_cmd:
            bloodhound_output_dir.mkdir(parents=True, exist_ok=True)
            
            self.update_status(target.ip, "BLOODHOUND", "Collecting AD data for graph analysis (All methods)")
            self.logger.info(f"Running BloodHound collection against {target.ip}")
            self.logger.debug(f"BloodHound command: {bloodhound_cmd}")
            
            bloodhound_result = await self.run_command(bloodhound_cmd, timeout=900)  # 15 min timeout
            
            if bloodhound_result and 'error' not in bloodhound_result:
                self.logger.info(f"BloodHound collection completed for {target.ip}")
                # Vérifier si des fichiers ont été générés
                json_files = list(bloodhound_output_dir.glob('*.json'))
                zip_files = list(bloodhound_output_dir.glob('*.zip'))
                if json_files or zip_files:
                    self.logger.info(f"BloodHound generated {len(json_files)} JSON files and {len(zip_files)} ZIP files")
                else:
                    self.logger.warning("BloodHound completed but no output files found")
                    self.logger.warning("Check if the domain/username/password are correct")
                    self.logger.warning("Also verify that the target is a domain controller")
            else:
                self.logger.error(f"BloodHound collection failed: {bloodhound_result.get('error', 'Unknown error')}")