# WinRecon Installation Guide

## Quick Start

```bash
# Clone the repository
git clone https://github.com/your-repo/winrecon.git
cd winrecon

# Run the installation script
./install.sh
```

## Installation Methods

### 1. System-wide Installation (Recommended)

Requires root privileges but provides the most complete setup:

```bash
sudo ./install.sh --native
```

This will:
- Install WinRecon to `/opt/winrecon`
- Create a global `winrecon` command
- Set up configuration in `~/.config/winrecon/`
- Check for required system tools

### 2. User Installation

No root required, installs for current user only:

```bash
./install.sh --user
```

This will:
- Install to `~/.local/lib/winrecon`
- Create command in `~/.local/bin/winrecon`
- Set up configuration in `~/.config/winrecon/`

**Note**: Make sure `~/.local/bin` is in your PATH:
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### 3. Docker Installation

For isolated environment with all tools pre-installed:

```bash
./install.sh --docker
```

Then use:
```bash
# Using wrapper script
./winrecon-docker 192.168.1.100

# Using docker-compose
docker-compose run --rm winrecon winrecon 192.168.1.100
```

### 4. Virtual Environment

For development or testing:

```bash
./install.sh --venv
source activate-winrecon.sh
python3 winrecon.py 192.168.1.100
```

## Dependencies

### Python Requirements
- Python 3.8 or higher
- PyYAML (only required third-party package)

### System Tools
Required tools for full functionality:
- `nmap` - Network scanning
- `smbclient` - SMB enumeration  
- `ldapsearch` - LDAP queries

Install on Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install nmap smbclient ldap-utils
```

Install on Kali Linux:
```bash
sudo apt-get update
sudo apt-get install nmap smbclient ldap-utils
```

### Optional Tools
For extended functionality:
- `enum4linux` - Enhanced SMB enumeration
- `crackmapexec` - Network protocol enumeration
- `nikto` - Web vulnerability scanner
- `gobuster` - Directory/file enumeration
- `impacket-scripts` - Windows protocol tools

## Testing Installation

Run the test suite to verify installation:

```bash
./install.sh --test
# or
python3 test_winrecon.py
```

## Manual Installation

If the installer doesn't work for your system:

1. Install Python dependencies:
```bash
pip3 install PyYAML
```

2. Copy files to desired location:
```bash
mkdir -p ~/winrecon
cp winrecon*.py winrecon-config.yaml ~/winrecon/
chmod +x ~/winrecon/winrecon.py
```

3. Create alias or symlink:
```bash
# Alias method
echo 'alias winrecon="python3 ~/winrecon/winrecon.py"' >> ~/.bashrc

# Or symlink method
ln -s ~/winrecon/winrecon.py ~/.local/bin/winrecon
```

4. Set up configuration:
```bash
mkdir -p ~/.config/winrecon
cp winrecon-config.yaml ~/.config/winrecon/config.yaml
```

## Troubleshooting

### Permission Denied
If you get permission errors:
```bash
chmod +x install.sh winrecon.py
```

### Python Module Not Found
Install PyYAML:
```bash
pip3 install PyYAML
# or with --user flag
pip3 install --user PyYAML
```

### Command Not Found
After installation, if `winrecon` command is not found:
1. Restart your terminal
2. Or run: `source ~/.bashrc`
3. Check PATH: `echo $PATH`

### Missing System Tools
The tool will work with limited functionality if system tools are missing. Install them as needed:
```bash
# Check what's missing
./install.sh --test

# Install missing tools
sudo apt-get install nmap smbclient ldap-utils
```

## Uninstallation

### System-wide
```bash
sudo rm -rf /opt/winrecon
sudo rm -f /usr/local/bin/winrecon
rm -rf ~/.config/winrecon
```

### User Installation
```bash
rm -rf ~/.local/lib/winrecon
rm -f ~/.local/bin/winrecon
rm -rf ~/.config/winrecon
```

### Docker
```bash
docker rmi winrecon:latest
rm -f winrecon-docker
```

## Next Steps

After installation:
1. Review the configuration: `~/.config/winrecon/config.yaml`
2. Run a test scan: `winrecon --help`
3. Check the main documentation: `winrecon-readme.md`