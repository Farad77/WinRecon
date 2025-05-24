#!/bin/bash

# Script to fix Neo4j repository issues

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[!] This script will help fix Neo4j repository issues${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[✗] This script must be run as root${NC}"
   echo "Please run: sudo $0"
   exit 1
fi

echo -e "${GREEN}[✓]${NC} Checking for Neo4j repository..."

# Find Neo4j source list files
NEO4J_SOURCES=$(grep -l "neo4j" /etc/apt/sources.list.d/*.list 2>/dev/null)

if [ -z "$NEO4J_SOURCES" ]; then
    # Check main sources.list
    if grep -q "neo4j" /etc/apt/sources.list 2>/dev/null; then
        echo -e "${YELLOW}[!]${NC} Found Neo4j repository in /etc/apt/sources.list"
        echo "You can comment out the Neo4j line by adding # at the beginning"
    else
        echo -e "${GREEN}[✓]${NC} No Neo4j repository found in APT sources"
    fi
else
    echo -e "${YELLOW}[!]${NC} Found Neo4j repository files:"
    echo "$NEO4J_SOURCES"
    echo ""
    echo "Options:"
    echo "1) Temporarily disable Neo4j repositories"
    echo "2) Remove Neo4j repositories"
    echo "3) Update with --allow-insecure-repositories (not recommended)"
    echo "4) Exit without changes"
    read -p "Choose option [1-4]: " choice
    
    case $choice in
        1)
            for file in $NEO4J_SOURCES; do
                mv "$file" "$file.disabled"
                echo -e "${GREEN}[✓]${NC} Disabled: $file"
            done
            echo -e "${GREEN}[✓]${NC} Neo4j repositories temporarily disabled"
            echo "To re-enable: rename .disabled files back to .list"
            ;;
        2)
            for file in $NEO4J_SOURCES; do
                rm "$file"
                echo -e "${GREEN}[✓]${NC} Removed: $file"
            done
            echo -e "${GREEN}[✓]${NC} Neo4j repositories removed"
            ;;
        3)
            echo "Adding --allow-insecure-repositories to apt update..."
            apt-get update --allow-insecure-repositories
            ;;
        4)
            echo "Exiting without changes"
            exit 0
            ;;
        *)
            echo -e "${RED}[✗]${NC} Invalid choice"
            exit 1
            ;;
    esac
fi

echo ""
echo -e "${GREEN}[✓]${NC} You can now run the WinRecon installer: ./install.sh"