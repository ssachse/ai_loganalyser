#!/usr/bin/env python3
"""
Setup-Skript für den macOS Logfile-Analysator
"""

from setuptools import setup, find_packages
import os

# README einlesen
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

setup(
    name="macos-loganalyzer",
    version="1.0.0",
    author="macOS Log Analyzer Team",
    author_email="support@example.com",
    description="Ein intelligenter Logfile-Analysator für macOS mit Ollama-Integration",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/macos-loganalyser",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "psutil>=5.9.6",
        "colorama>=0.4.6",
        "rich>=13.7.0",
        "python-dateutil>=2.8.2",
        "pandas>=2.1.4",
        "numpy>=1.24.3",
    ],
    entry_points={
        "console_scripts": [
            "macos-loganalyzer=log_analyzer:main",
        ],
    },
    keywords="macos, log, analyzer, ollama, ai, system, monitoring, security",
    project_urls={
        "Bug Reports": "https://github.com/your-repo/macos-loganalyser/issues",
        "Source": "https://github.com/your-repo/macos-loganalyser",
        "Documentation": "https://github.com/your-repo/macos-loganalyser#readme",
    },
) 