# 🛡️ WinRecon - Windows/Active Directory Automated Enumeration Tool

## Vue d'ensemble

WinRecon est un outil d'énumération automatisé spécialisé pour les environnements Windows et Active Directory, inspiré par AutoRecon mais optimisé pour les techniques d'attaque modernes basées sur les mindmaps Orange Cyberdefense.

### ✨ Caractéristiques principales

- **Énumération automatisée complète** des environnements Windows/AD
- **Techniques d'attaque avancées** (Kerberoasting, ASREPRoasting, ADCS, etc.)
- **Rapports HTML interactifs** avec dashboard et visualisations
- **Architecture modulaire** facilement extensible
- **Support multi-cibles** avec traitement parallèle
- **Configuration flexible** via fichiers YAML
- **Intégration d'outils populaires** (Impacket, BloodHound, CrackMapExec, etc.)

## 🚀 Installation rapide

```bash
# Cloner le repository
git clone https://github.com/votre-repo/winrecon.git
cd winrecon

# Rendre le script d'installation exécutable
chmod +x install_winrecon.sh

# Exécuter l'installation (en tant que root)
sudo ./install_winrecon.sh
```

## 📋 Prérequis

### Système d'exploitation
- Kali Linux (recommandé)
- Ubuntu/Debian
- Autres distributions Linux (avec adaptations)

### Outils requis
L'installation automatique installe tous les outils nécessaires :

#### Outils de base
- Python 3.8+
- nmap
- smbclient
- ldap-utils
- crackmapexec
- enum4linux

#### Outils spécialisés
- [windapsearch](https://github.com/ropnop/windapsearch)
- [BloodHound.py](https://github.com/fox-it/BloodHound.py)
- [Impacket suite](https://github.com/SecureAuthCorp/impacket)
- [Certipy](https://github.com/ly4k/Certipy)
- [Coercer](https://github.com/p0dalirius/Coercer)
- [kerbrute](https://github.com/ropnop/kerbrute)

## 🎯 Utilisation

### Exemples de base

```bash
# Scan d'une IP simple
winrecon 192.168.1.100

# Scan d'un réseau CIDR
winrecon 192.168.1.0/24

# Scan avec authentification
winrecon 192.168.1.100 -d domain.local -u user -p password

# Scan avec hash NTLM
winrecon 192.168.1.100 -d domain.local -u user -H LM:NTLM

# Scan depuis un fichier de cibles
winrecon -t targets.txt -d domain.local -u user -p password
```

### Options avancées

```bash
# Utiliser un fichier de configuration personnalisé
winrecon 192.168.1.100 --config /path/to/config.yaml

# Ajuster le nombre de scans concurrent
winrecon 192.168.1.0/24 --max-scans 20

# Mode verbose pour debug
winrecon 192.168.1.100 -v

# Spécifier le DC et répertoire de sortie
winrecon 192.168.1.100 --dc-ip 192.168.1.10 -o /tmp/results
```

## ⚙️ Configuration

### Fichier de configuration principal

Le fichier `~/.config/winrecon/config.yaml` permet de personnaliser :

```yaml
# Paramètres généraux
output_dir: "winrecon_results"
max_concurrent_scans: 10
timeout: 3600
verbose: false

# Credentials par défaut
domain: "domain.local"
username: "user"
password: "password"

# Techniques avancées
advanced_techniques:
  adcs:
    enabled: true
    cert_enum: true
    template_enum: true
    esc1_8: true
  
  coercion:
    enabled: false  # Potentiellement intrusif
    petitpotam: false
    printerbug: false
  
  lateral_movement:
    enabled: false  # Actions intrusives
    secretsdump: false
    bloodhound: true
```

### Wordlists et outils

```yaml
# Chemins des outils
tools:
  nmap: "/usr/bin/nmap"
  bloodhound: "python3 /opt/BloodHound.py/bloodhound.py"
  crackmapexec: "/usr/bin/crackmapexec"
  # ... autres outils

# Wordlists
wordlists:
  usernames: "/usr/share/seclists/Usernames/Names/names.txt"
  passwords: "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
```

## 📊 Structure des résultats

WinRecon organise les résultats dans une structure claire :

```
winrecon_results/
├── 192.168.1.100/
│   ├── scans/
│   │   ├── nmap/           # Scans Nmap
│   │   ├── smb/            # Énumération SMB
│   │   ├── ldap/           # Énumération LDAP/AD
│   │   ├── kerberos/       # Attaques Kerberos
│   │   └── web/            # Énumération web
│   ├── loot/
│   │   ├── credentials/    # Hashes et tickets
│   │   ├── bloodhound/     # Données BloodHound
│   │   └── ldapdomaindump/ # Dumps LDAP
│   ├── exploit/            # Scripts d'exploitation
│   └── report/
│       ├── winrecon_report.html    # Rapport principal
│       ├── executive_summary.txt   # Résumé exécutif
│       ├── winrecon_results.json   # Données JSON
│       └── *.csv                   # Données CSV
```

## 🎨 Rapports générés

### Rapport HTML interactif
- **Dashboard** avec statistiques et graphiques
- **Onglets organisés** par type d'énumération
- **Visualisations** des données découvertes
- **Recommandations de sécurité** automatiques
- **Export** des données en JSON/CSV

### Formats de sortie
- **HTML** : Rapport interactif complet
- **JSON** : Données structurées pour traitement
- **CSV** : Tables pour analyse dans Excel
- **TXT** : Résumé exécutif

## 🔍 Techniques d'énumération

WinRecon implémente les techniques du mindmap Orange Cyberdefense :

### Énumération initiale
- **Nmap** : Découverte de services et versions
- **SMB** : Partages, utilisateurs, politiques
- **LDAP** : Objets Active Directory
- **DNS** : Zone transfers, sous-domaines

### Attaques Kerberos
- **ASREPRoasting** : Utilisateurs sans pré-auth
- **Kerberoasting** : Comptes de service avec SPN
- **Énumération d'utilisateurs** via Kerberos

### Active Directory Certificate Services (ADCS)
- **Énumération des CA** et templates
- **Détection ESC1-ESC8** : Vulnérabilités de certificats
- **Abuse de templates** vulnérables

### Techniques de coercition
- **PetitPotam** : Coercition NTLM
- **PrinterBug** : Coercition via spooler
- **DFSCoerce** : Coercition DFS

### Post-exploitation (optionnel)
- **Secretsdump** : Extraction de secrets
- **BloodHound** : Analyse des chemins d'attaque
- **Délégations** non contraintes

## 🛡️ Considérations de sécurité

### Utilisation éthique
- ⚠️ **Autorisation requise** : N'utilisez que sur des systèmes autorisés
- 📋 **Tests de pénétration** : Respectez les règles d'engagement
- 🚫 **Pas d'exploitation** : Mode énumération par défaut

### Détection et furtivité
- Les scans génèrent du **trafic réseau** détectable
- Utilisation de **techniques légitimes** minimisant les alertes
- **Logs** générés par les outils peuvent être analysés

### Configuration sécurisée
```yaml
# Désactiver les techniques intrusives par défaut
advanced_techniques:
  coercion:
    enabled: false
  lateral_movement:
    enabled: false
  persistence:
    enabled: false
```

## 🔧 Développement et extension

### Architecture modulaire

```python
# Ajouter une nouvelle technique
class CustomTechnique:
    def __init__(self, config, target_dir, logger):
        self.config = config
        self.target_dir = target_dir
        self.logger = logger
    
    async def run_custom_scan(self, target_ip):
        # Implémentation personnalisée
        pass
```

### Contribution
1. Fork le projet
2. Créer une branche feature
3. Implémenter votre technique
4. Tester sur environnement de lab
5. Soumettre une Pull Request

## 📚 Ressources et références

### Documentation officielle
- [Mindmaps Orange Cyberdefense](https://orange-cyberdefense.github.io/ocd-mindmaps/)
- [MITRE ATT&CK for Enterprise](https://attack.mitre.org/)
- [Microsoft AD Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/)

### Outils intégrés
- [AutoRecon](https://github.com/Tib3rius/AutoRecon) - Inspiration originale
- [Impacket](https://github.com/SecureAuthCorp/impacket) - Suite d'outils Python
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Analyse de graphe AD

### Ressources d'apprentissage
- [Active Directory Security Blog](https://adsecurity.org/)
- [SpecterOps Blog](https://posts.specterops.io/)
- [HackTricks - Active Directory](https://book.hacktricks.xyz/windows/active-directory-methodology)

## 🐛 Dépannage

### Problèmes courants

#### Outils manquants
```bash
# Vérifier les outils installés
winrecon --check-tools

# Réinstaller les outils manquants
sudo ./install_winrecon.sh --reinstall
```

#### Problèmes de permissions
```bash
# Donner les permissions appropriées
sudo chown -R $USER:$USER ~/.config/winrecon/
chmod +x /usr/local/bin/winrecon
```

#### Timeout des commandes
```yaml
# Ajuster dans config.yaml
timeout: 7200  # 2 heures
```

### Logs de debug
```bash
# Mode verbose maximum
winrecon 192.168.1.100 -vvv

# Vérifier les logs
tail -f winrecon_results/192.168.1.100/winrecon.log
```

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## ⚖️ Disclaimer

**WinRecon est destiné à des fins éducatives et de tests de pénétration autorisés uniquement.**

L'utilisation de cet outil sur des systèmes sans autorisation explicite est illégale. Les auteurs ne sont pas responsables de l'utilisation malveillante de cet outil. Assurez-vous d'avoir les autorisations appropriées avant d'utiliser WinRecon dans tout environnement.

## 🤝 Support et contribution

### Signaler un bug
- Utiliser les [GitHub Issues](https://github.com/votre-repo/winrecon/issues)
- Inclure les logs et la configuration
- Décrire les étapes de reproduction

### Demander une fonctionnalité
- Ouvrir une [GitHub Issue](https://github.com/votre-repo/winrecon/issues)
- Décrire le cas d'usage
- Proposer une implémentation si possible

### Contact
- **Email** : security@example.com
- **Twitter** : @winrecon_tool
- **Discord** : [Serveur communautaire](https://discord.gg/example)

---

**Développé avec ❤️ pour la communauté de la cybersécurité**

*WinRecon v1.0 - "Automated Windows/AD Enumeration Made Simple"*