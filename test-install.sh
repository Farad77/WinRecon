#!/bin/bash

# WinRecon Test Installation Script
# Tests the installation in a controlled environment

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test configuration
TEST_DIR="/tmp/winrecon-test"
VENV_DIR="$TEST_DIR/venv"
INSTALL_LOG="$TEST_DIR/install.log"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    if [ -f "$INSTALL_LOG" ]; then
        echo "[INFO] $1" >> "$INSTALL_LOG"
    fi
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    if [ -f "$INSTALL_LOG" ]; then
        echo "[WARN] $1" >> "$INSTALL_LOG"
    fi
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    if [ -f "$INSTALL_LOG" ]; then
        echo "[ERROR] $1" >> "$INSTALL_LOG"
    fi
}

cleanup() {
    log_info "Cleaning up test environment..."
    if [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
    fi
}

setup_test_env() {
    log_info "Setting up test environment..."
    
    # Clean up any existing test directory
    if [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
    fi
    
    # Create test directory structure
    mkdir -p "$TEST_DIR"
    mkdir -p "$TEST_DIR/logs"
    
    # Copy winrecon files to test directory
    cp -r . "$TEST_DIR/winrecon-src"
    
    # Initialize log file
    echo "WinRecon Test Installation Log - $(date)" > "$INSTALL_LOG"
}

create_venv() {
    log_info "Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    log_info "Virtual environment created at: $VENV_DIR"
}

test_python_dependencies() {
    log_info "Testing Python dependencies..."
    
    # Create requirements.txt based on imports found
    cat > "$TEST_DIR/requirements.txt" << EOF
pyyaml>=6.0
asyncio
aiofiles
jinja2
matplotlib
pandas
EOF
    
    # Install Python dependencies
    pip install -r "$TEST_DIR/requirements.txt"
    
    # Test imports
    python3 -c "
import yaml
import asyncio
import argparse
import ipaddress
import json
import logging
print('✓ All Python standard library imports successful')
"
    
    if [ $? -eq 0 ]; then
        log_info "Python dependencies test passed"
    else
        log_error "Python dependencies test failed"
        return 1
    fi
}

test_winrecon_modules() {
    log_info "Testing WinRecon module imports..."
    
    cd "$TEST_DIR/winrecon-src"
    
    # Test main module
    python3 -c "
import sys
sys.path.insert(0, '.')
try:
    import winrecon
    print('✓ winrecon.py imports successfully')
except Exception as e:
    print(f'✗ Error importing winrecon.py: {e}')
    sys.exit(1)
"
    
    # Test report module
    python3 -c "
import sys
sys.path.insert(0, '.')
try:
    exec(open('winrecon-report.py').read())
    print('✓ winrecon-report.py loads successfully')
except Exception as e:
    print(f'✗ Error loading winrecon-report.py: {e}')
"
    
    # Test techniques module
    python3 -c "
import sys
sys.path.insert(0, '.')
try:
    exec(open('winrecon-techniques.py').read())
    print('✓ winrecon-techniques.py loads successfully')
except Exception as e:
    print(f'✗ Error loading winrecon-techniques.py: {e}')
"
}

test_system_tools() {
    log_info "Testing system tool availability..."
    
    # Define required tools
    REQUIRED_TOOLS=(
        "nmap"
        "smbclient"
        "ldapsearch"
        "dig"
        "curl"
        "wget"
    )
    
    # Define optional tools
    OPTIONAL_TOOLS=(
        "enum4linux"
        "crackmapexec"
        "nikto"
        "gobuster"
        "kerbrute"
    )
    
    # Check required tools
    local missing_required=()
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_info "✓ $tool found"
        else
            log_warn "✗ $tool not found (REQUIRED)"
            missing_required+=("$tool")
        fi
    done
    
    # Check optional tools
    local missing_optional=()
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_info "✓ $tool found"
        else
            log_warn "○ $tool not found (optional)"
            missing_optional+=("$tool")
        fi
    done
    
    # Report results
    if [ ${#missing_required[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_required[*]}"
        log_info "Install with: apt-get install ${missing_required[*]}"
        return 1
    fi
    
    if [ ${#missing_optional[@]} -gt 0 ]; then
        log_warn "Missing optional tools: ${missing_optional[*]}"
        log_info "For full functionality, install with: apt-get install ${missing_optional[*]}"
    fi
    
    return 0
}

test_config_setup() {
    log_info "Testing configuration setup..."
    
    # Test directory creation
    TEST_CONFIG_DIR="$TEST_DIR/test-config"
    mkdir -p "$TEST_CONFIG_DIR/.config/winrecon"
    
    # Copy config file
    cp "$TEST_DIR/winrecon-src/winrecon-config.yaml" "$TEST_CONFIG_DIR/.config/winrecon/config.yaml"
    
    # Test config loading
    cd "$TEST_DIR/winrecon-src"
    python3 -c "
import yaml
import os

config_path = '$TEST_CONFIG_DIR/.config/winrecon/config.yaml'
try:
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    print('✓ Configuration file loads successfully')
    print(f'  - Output directory: {config.get(\"output_dir\", \"Not set\")}')
    print(f'  - Max concurrent scans: {config.get(\"max_concurrent_scans\", \"Not set\")}')
except Exception as e:
    print(f'✗ Error loading config: {e}')
    exit(1)
"
}

test_winrecon_execution() {
    log_info "Testing WinRecon execution..."
    
    cd "$TEST_DIR/winrecon-src"
    
    # Test help command
    python3 winrecon.py --help > "$TEST_DIR/help_output.txt" 2>&1
    if [ $? -eq 0 ]; then
        log_info "✓ WinRecon help command works"
    else
        log_error "✗ WinRecon help command failed"
        cat "$TEST_DIR/help_output.txt"
        return 1
    fi
    
    # Test dry run (without actual scanning)
    # This would need modification in winrecon.py to support --dry-run
    log_info "○ Dry run test skipped (not implemented)"
}

create_test_report() {
    log_info "Creating test report..."
    
    cat > "$TEST_DIR/test-report.txt" << EOF
=================================================
WinRecon Installation Test Report
=================================================
Date: $(date)
Test Directory: $TEST_DIR

Python Version: $(python3 --version)
Virtual Environment: $VENV_DIR

Test Results:
EOF
    
    # Append log highlights
    echo "" >> "$TEST_DIR/test-report.txt"
    echo "Key Findings:" >> "$TEST_DIR/test-report.txt"
    grep -E "(✓|✗|○)" "$INSTALL_LOG" >> "$TEST_DIR/test-report.txt"
    
    echo "" >> "$TEST_DIR/test-report.txt"
    echo "Full log available at: $INSTALL_LOG" >> "$TEST_DIR/test-report.txt"
    
    log_info "Test report created at: $TEST_DIR/test-report.txt"
}

run_full_test() {
    # Setup must come first to create directories
    setup_test_env
    
    log_info "Starting WinRecon installation test..."
    
    # Now we can create venv
    create_venv
    
    # Run tests and track failures
    local failed=0
    
    test_python_dependencies || ((failed++))
    test_winrecon_modules || ((failed++))
    test_system_tools || ((failed++))
    test_config_setup || ((failed++))
    test_winrecon_execution || ((failed++))
    
    # Create report
    create_test_report
    
    # Deactivate virtual environment
    deactivate
    
    # Summary
    echo ""
    if [ $failed -eq 0 ]; then
        log_info "✅ All tests passed!"
        log_info "WinRecon appears to be ready for installation"
    else
        log_error "❌ $failed test(s) failed"
        log_error "Please review the test report and fix issues before installation"
    fi
    
    # Display test report
    echo ""
    cat "$TEST_DIR/test-report.txt"
    
    return $failed
}

# Add option to keep test environment for debugging
if [ "$1" == "--keep" ]; then
    KEEP_ENV=1
else
    KEEP_ENV=0
fi

# Run tests
run_full_test
TEST_RESULT=$?

# Cleanup unless --keep was specified
if [ $KEEP_ENV -eq 0 ]; then
    log_info "Cleaning up test environment..."
    log_info "Use --keep to preserve test environment for debugging"
    cleanup
else
    log_info "Test environment preserved at: $TEST_DIR"
fi

exit $TEST_RESULT