#!/bin/bash

# Detect and update tool paths for WinRecon

echo "Detecting installed tools..."

# Function to find tool
find_tool() {
    local tool_names=("$@")
    for name in "${tool_names[@]}"; do
        if command -v "$name" &> /dev/null; then
            echo "$name"
            return 0
        fi
    done
    # Check common locations
    for name in "${tool_names[@]}"; do
        for dir in /usr/local/bin /opt /usr/bin ~/.local/bin; do
            if [ -f "$dir/$name" ] && [ -x "$dir/$name" ]; then
                echo "$dir/$name"
                return 0
            fi
        done
    done
    return 1
}

# Detect each tool
echo ""
echo "Tool Detection Results:"
echo "======================"

# CrackMapExec/NetExec
if cme_path=$(find_tool "cme" "crackmapexec" "nxc" "netexec"); then
    echo "CrackMapExec/NetExec: $cme_path"
    # Update config
    sed -i "s|crackmapexec: .*|crackmapexec: \"$cme_path\"|" winrecon-config.yaml 2>/dev/null
else
    echo "CrackMapExec/NetExec: NOT FOUND"
fi

# Impacket tools
if secretsdump_path=$(find_tool "impacket-secretsdump" "secretsdump.py"); then
    echo "SecretsDump: $secretsdump_path"
    sed -i "s|impacket-secretsdump: .*|impacket-secretsdump: \"$secretsdump_path\"|" winrecon-config.yaml 2>/dev/null
else
    echo "SecretsDump: NOT FOUND"
fi

if getnpusers_path=$(find_tool "impacket-GetNPUsers" "GetNPUsers.py"); then
    echo "GetNPUsers: $getnpusers_path"
    sed -i "s|impacket-GetNPUsers: .*|impacket-GetNPUsers: \"$getnpusers_path\"|" winrecon-config.yaml 2>/dev/null
else
    echo "GetNPUsers: NOT FOUND"
fi

if getuserspns_path=$(find_tool "impacket-GetUserSPNs" "GetUserSPNs.py"); then
    echo "GetUserSPNs: $getuserspns_path"
    sed -i "s|impacket-GetUserSPNs: .*|impacket-GetUserSPNs: \"$getuserspns_path\"|" winrecon-config.yaml 2>/dev/null
else
    echo "GetUserSPNs: NOT FOUND"
fi

# BloodHound
if bloodhound_path=$(find_tool "bloodhound-python" "bloodhound.py"); then
    echo "BloodHound: $bloodhound_path"
    sed -i "s|bloodhound: .*|bloodhound: \"$bloodhound_path\"|" winrecon-config.yaml 2>/dev/null
else
    # Check if it's available as Python module
    if python3 -c "import bloodhound" 2>/dev/null; then
        echo "BloodHound: python3 -m bloodhound"
        sed -i "s|bloodhound: .*|bloodhound: \"python3 -m bloodhound\"|" winrecon-config.yaml 2>/dev/null
    else
        echo "BloodHound: NOT FOUND"
    fi
fi

# Other tools
for tool in nmap smbclient ldapsearch enum4linux kerbrute gobuster nikto; do
    if tool_path=$(find_tool "$tool"); then
        echo "$tool: $tool_path"
    else
        echo "$tool: NOT FOUND"
    fi
done

echo ""
echo "Configuration updated in winrecon-config.yaml"
echo ""
echo "To manually verify/edit paths:"
echo "  nano winrecon-config.yaml"