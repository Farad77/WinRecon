"""
WinRecon - Windows/Active Directory Enumeration Tool
"""

__version__ = "1.0.0"
__author__ = "WinRecon Team"
__email__ = "security@example.com"

# Import main functionality
try:
    from .winrecon import main, WinReconScanner
except ImportError:
    # Handle case where package structure isn't set up yet
    pass