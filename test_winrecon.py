#!/usr/bin/env python3
"""
Simple test script to verify WinRecon installation
"""

import sys
import importlib
import subprocess

def test_imports():
    """Test that all required modules can be imported"""
    print("Testing Python imports...")
    
    # Standard library modules (should always be available)
    stdlib_modules = [
        'asyncio',
        'ipaddress',
        'json',
        'argparse',
        'concurrent.futures',
        'subprocess',
        'logging',
        'dataclasses',
        'datetime',
        'pathlib',
        'typing',
        'base64',
        're'
    ]
    
    # Third-party modules
    third_party_modules = [
        'yaml'  # PyYAML
    ]
    
    # Test standard library
    print("  Standard library:")
    for module in stdlib_modules:
        try:
            importlib.import_module(module)
            print(f"    ✓ {module}")
        except ImportError as e:
            print(f"    ✗ {module}: {e}")
    
    # Test third-party modules
    print("\n  Third-party modules:")
    required_modules = third_party_modules
    
    failed = []
    for module in required_modules:
        try:
            importlib.import_module(module)
            print(f"  ✓ {module}")
        except ImportError as e:
            print(f"  ✗ {module}: {e}")
            failed.append(module)
    
    return len(failed) == 0

def test_winrecon_modules():
    """Test that WinRecon modules can be loaded"""
    print("\nTesting WinRecon modules...")
    
    modules = {
        'winrecon.py': 'Main scanner module',
        'winrecon-report.py': 'Report generator',
        'winrecon-techniques.py': 'Attack techniques'
    }
    
    failed = []
    for module, desc in modules.items():
        try:
            with open(module, 'r') as f:
                compile(f.read(), module, 'exec')
            print(f"  ✓ {module} - {desc}")
        except Exception as e:
            print(f"  ✗ {module}: {e}")
            failed.append(module)
    
    return len(failed) == 0

def test_system_tools():
    """Test for required system tools"""
    print("\nTesting system tools...")
    
    tools = {
        'nmap': 'Network scanner',
        'smbclient': 'SMB enumeration',
        'ldapsearch': 'LDAP queries',
        'dig': 'DNS queries',
        'curl': 'HTTP requests',
        'wget': 'File downloads'
    }
    
    missing = []
    for tool, desc in tools.items():
        try:
            subprocess.run(['which', tool], check=True, capture_output=True)
            print(f"  ✓ {tool} - {desc}")
        except subprocess.CalledProcessError:
            print(f"  ✗ {tool} - {desc} (NOT FOUND)")
            missing.append(tool)
    
    if missing:
        print(f"\nMissing tools: {', '.join(missing)}")
        print("Install with: sudo apt-get install " + ' '.join(missing))
    
    return len(missing) == 0

def main():
    """Run all tests"""
    print("WinRecon Installation Test")
    print("=" * 50)
    
    results = {
        'imports': test_imports(),
        'modules': test_winrecon_modules(),
        'tools': test_system_tools()
    }
    
    print("\nTest Summary:")
    print("-" * 50)
    for test, passed in results.items():
        status = "PASSED" if passed else "FAILED"
        print(f"{test.capitalize()}: {status}")
    
    all_passed = all(results.values())
    if all_passed:
        print("\n✅ All tests passed! WinRecon is ready to use.")
    else:
        print("\n❌ Some tests failed. Please fix the issues above.")
        sys.exit(1)

if __name__ == "__main__":
    main()