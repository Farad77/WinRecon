# WinRecon Docker Image
# Provides a complete environment with all required tools

FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Update and install base packages
RUN apt-get update && apt-get install -y \
    # Python and pip
    python3 \
    python3-pip \
    python3-venv \
    # Required system tools
    nmap \
    smbclient \
    ldap-utils \
    dnsutils \
    curl \
    wget \
    git \
    # Optional but recommended tools
    enum4linux \
    crackmapexec \
    nikto \
    gobuster \
    impacket-scripts \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /opt/winrecon

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Make scripts executable
RUN chmod +x winrecon.py winrecon-install-improved.sh test-install.sh

# Create symbolic link
RUN ln -s /opt/winrecon/winrecon.py /usr/local/bin/winrecon

# Create volume for results
VOLUME ["/winrecon_results"]

# Set default command
CMD ["python3", "winrecon.py", "--help"]