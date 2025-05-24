# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WinRecon is an automated enumeration tool for Windows/Active Directory environments, inspired by AutoRecon but specialized for Windows/AD attacks based on Orange Cyberdefense mindmaps. It performs comprehensive scanning and enumeration with minimal user interaction.

## Commands

### Installation
```bash
# Interactive installation (choose method)
./install.sh

# System-wide installation (requires root)
sudo ./install.sh --native

# User installation (no root required)
./install.sh --user

# Docker installation
./install.sh --docker

# Virtual environment installation
./install.sh --venv

# Run tests only
./install.sh --test
```

### Basic Usage
```bash
# Single target scan
python3 winrecon.py 192.168.1.100

# Network scan with authentication
python3 winrecon.py 192.168.1.0/24 -d domain.local -u user -p password

# Using NTLM hash
python3 winrecon.py 192.168.1.100 -d domain.local -u user -H LM:NTLM

# From targets file
python3 winrecon.py -t targets.txt -d domain.local -u user -p password

# Custom configuration
python3 winrecon.py 192.168.1.100 --config custom.yaml -v
```

### Development Commands
```bash
# Run with verbose output for debugging
python3 winrecon.py 192.168.1.100 -v -o test_results

# Check available options
python3 winrecon.py --help

# Verify tool installation
python3 winrecon.py --check-tools
```

## Architecture

### Core Components

1. **winrecon.py** - Main orchestrator
   - Handles CLI arguments and target validation
   - Manages concurrent scanning with asyncio
   - Coordinates all enumeration phases

2. **winrecon-techniques.py** - Advanced AD attack modules
   - `ADEnumerationTechniques`: LDAP/AD enumeration
   - `KerberosTechniques`: ASREPRoasting, Kerberoasting
   - `ADCSTechniques`: Certificate Services vulnerabilities
   - `CoercionTechniques`: NTLM coercion attacks
   - `PostExploitationTechniques`: SecretsDump, BloodHound

3. **winrecon-report.py** - Report generation
   - Creates interactive HTML reports with dashboards
   - Exports to JSON/CSV formats
   - Generates executive summaries

4. **winrecon-config.yaml** - Configuration template
   - Tool paths and timeout settings
   - Scan configurations per service
   - Advanced technique toggles

### Scanning Pipeline

1. **Initialization**: Directory structure, tool validation, logging setup
2. **Phase 1**: Nmap port discovery
3. **Phase 2**: Service enumeration (SMB, LDAP, Kerberos, DNS, Web)
4. **Phase 3**: Advanced techniques (if enabled)
5. **Phase 4**: Report generation

### Key Design Patterns

- **Asyncio**: Concurrent scanning with semaphore control
- **Modular Architecture**: Each technique is a separate class
- **Configuration-Driven**: YAML config controls behavior
- **Safe Defaults**: Intrusive techniques disabled by default

## Important Notes

### Dependencies
- **Python**: Only requires `PyYAML` as third-party dependency
- **System Tools**: Core functionality needs `nmap`, `smbclient`, `ldapsearch`
- All other Python imports are from standard library

### File Structure
```
winrecon/
├── winrecon.py              # Main entry point and orchestrator
├── winrecon-techniques.py   # Advanced AD attack techniques
├── winrecon-report.py       # Report generation (HTML/JSON/CSV)
├── winrecon-config.yaml     # Configuration template
├── requirements.txt         # Python dependencies (just PyYAML)
├── install.sh              # Main installation script
├── test_winrecon.py        # Installation verification
├── INSTALL.md              # Installation documentation
└── winrecon-readme.md      # Main documentation
```

### Installation Methods
1. **System-wide** (`sudo ./install.sh --native`): Installs to `/opt/winrecon`
2. **User-local** (`./install.sh --user`): Installs to `~/.local/`
3. **Docker** (`./install.sh --docker`): Containerized with all tools
4. **Virtual Environment** (`./install.sh --venv`): For development/testing

### Key Design Decisions
- **Minimal Dependencies**: Only PyYAML required, everything else is stdlib
- **Graceful Degradation**: Works with limited functionality if system tools missing
- **Safe Defaults**: Intrusive techniques disabled by default in config
- **Modular Architecture**: Each technique is a separate class for easy extension

### Common Issues and Solutions
1. **Python syntax error in report module**: Fixed by removing stray HTML code
2. **Missing system tools**: Tool provides clear messages about what to install
3. **Permission errors**: Use appropriate installation method (root vs user)

### Testing
Always run `./install.sh --test` or `python3 test_winrecon.py` to verify:
- Python imports (stdlib and PyYAML)
- Module syntax validity
- System tool availability

### Security Considerations
- Tool is designed for authorized penetration testing only
- Configuration file controls which techniques are enabled
- Results may contain sensitive information (hashes, tickets, etc.)
- Proper authorization required before use