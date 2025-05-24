# WinRecon Makefile
# Simplifies installation and testing

.PHONY: help install test clean dev-install check-deps

# Default target
help:
	@echo "WinRecon Installation Makefile"
	@echo "=============================="
	@echo ""
	@echo "Available targets:"
	@echo "  make install      - Install WinRecon (requires sudo)"
	@echo "  make dev-install  - Install in development mode"
	@echo "  make test         - Run installation tests"
	@echo "  make check-deps   - Check system dependencies"
	@echo "  make clean        - Clean temporary files"
	@echo ""

# Install WinRecon
install:
	@echo "Installing WinRecon..."
	sudo ./winrecon-install-improved.sh

# Development installation (editable)
dev-install:
	@echo "Installing WinRecon in development mode..."
	pip3 install -e . --user

# Run tests
test:
	@echo "Running WinRecon tests..."
	python3 test_winrecon.py

# Check dependencies only
check-deps:
	@echo "Checking dependencies..."
	@python3 -c "import sys; print(f'Python version: {sys.version}')"
	@echo ""
	@echo "Required system packages:"
	@which nmap >/dev/null 2>&1 && echo "  ✓ nmap" || echo "  ✗ nmap (apt-get install nmap)"
	@which smbclient >/dev/null 2>&1 && echo "  ✓ smbclient" || echo "  ✗ smbclient (apt-get install smbclient)"
	@which ldapsearch >/dev/null 2>&1 && echo "  ✓ ldapsearch" || echo "  ✗ ldapsearch (apt-get install ldap-utils)"
	@which dig >/dev/null 2>&1 && echo "  ✓ dig" || echo "  ✗ dig (apt-get install dnsutils)"
	@echo ""
	@echo "Python packages:"
	@pip3 list | grep -E "PyYAML|Jinja2|matplotlib|pandas" || echo "Run: pip3 install -r requirements.txt"

# Clean temporary files
clean:
	@echo "Cleaning temporary files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/ 2>/dev/null || true
	rm -rf /tmp/winrecon-test/ 2>/dev/null || true