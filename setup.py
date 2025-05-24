#!/usr/bin/env python3
"""
WinRecon - Windows/Active Directory Enumeration Tool
Setup script for installation
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_long_description():
    try:
        with open("winrecon-readme.md", "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return "WinRecon - Windows/Active Directory Enumeration Tool"

# Read requirements
def read_requirements():
    try:
        with open("requirements.txt", "r") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return [
            "PyYAML>=6.0.1",
            "Jinja2>=3.1.2",
            "matplotlib>=3.7.1",
            "pandas>=2.0.0",
            "aiofiles>=23.1.0",
            "colorama>=0.4.6",
            "rich>=13.3.5",
            "dnspython>=2.3.0",
            "requests>=2.31.0",
            "beautifulsoup4>=4.12.2",
            "lxml>=4.9.2"
        ]

setup(
    name="winrecon",
    version="1.0.0",
    author="WinRecon Team",
    author_email="security@example.com",
    description="Automated Windows/Active Directory enumeration tool",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/winrecon",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "winrecon=winrecon:main",
        ],
    },
    package_data={
        "": ["*.yaml", "*.md"],
    },
    include_package_data=True,
)