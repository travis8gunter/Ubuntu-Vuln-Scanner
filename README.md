# Ubuntu Vulnerability Scanner

A lightweight Python command-line tool that scans installed Debian/Ubuntu packages for known vulnerabilities using the [OSV.dev API](https://osv.dev/). It reports CVEs (where available), severity levels, summaries, and suggested fixes (upgrades).

Built as a personal cybersecurity learning project — great for SOC analysts, security engineers, or anyone hardening Ubuntu systems.

## Features
- Scans all installed packages or only upgradable ones (`--only-upgradable`)
- Pulls vulnerability data from OSV.dev (Debian ecosystem)
- Basic severity classification (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN)
- Shows fix versions when available
- Planned: colored output, summary stats, JSON/report export

## Prerequisites
- Python 3.8+
- Ubuntu/Debian-based system (uses `dpkg-query` and `apt`)

## Installation
1. Clone the repo:
   ```bash
   git clone https://github.com/travis8gunter/ubuntu-vuln-scanner.git
   cd ubuntu-vuln-scanner
2. Install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt

## Usage:
  ```bash
  python3 vuln_scan.py
  python3 vuln_scan.py --only-upgradable
