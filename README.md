<p align="center">
  <img alt="SentinelScan logo" src="https://raw.githubusercontent.com/AJulianSec/SentinelScan/main/logo_sentinel_scan.jpg" width="320"/>
</p>

# 🛡️ SentinelScan

**SentinelScan** is an educational Python tool for **network reconnaissance and basic vulnerability correlation** intended for use **only in authorized and controlled environments**.  
It is ideal for learning, Purple Team exercises, lab training and for anyone who wants a hands‑on, ethical view into service discovery and basic vulnerability identification.

> ⚠️ **Legal & Ethical Notice**  
> SentinelScan is strictly for authorized testing (your systems, lab VMs, or explicit, written permission). Misuse against third‑party systems or networks is illegal and unethical. The author accepts no responsibility for misuse.

---

## 📋 Overview

SentinelScan automates network reconnaissance phases — port scanning, banner grabbing and local vulnerability correlation — through a simple CLI. The tool is designed to teach methodology and interpretation of results rather than to act as an offensive exploitation framework.

Use cases:
- Security education (students, Purple/Blue/Red team drills)
- Quick asset discovery in a lab environment
- Learning how banner parsing and version matching works

---

## ⚙️ Key Features

- **Quick TCP & UDP scans** for common ports.  
- **Full TCP scan (1–65535)** (educational; heavy scans may take long).  
- **Banner grabbing** to capture service strings and infer versions.  
- **Local vulnerability correlation** using a pipe‑separated `vuln_db.txt` (offline, strict substring matching).  
- **Asynchronous worker pool** (`asyncio`) for concurrent scanning.  
- **TXT reports** generated per-scan under `reports/<target>_<timestamp>/report.txt`.  
- **Logging** to `logs/scanner.log` (rotating file handler).  
- Optional colored console output / progress bars if [`rich`] is installed.  
- Designed to run on Linux, WSL2 or Windows with Python 3.11+.

---

## 📥 Requirements & Installation

### System requirements
- **Python 3.11+** (recommended)  
- `pip` (Python package manager)  
- Optional: `nmap` (for users who want to extend integration)  
- OS: Linux, macOS, Windows or WSL2

### Quick install

```bash
# Clone the repository (use your fork / upstream as needed)
git clone https://github.com/AJulianSec/SentinelScan.git
cd SentinelScan
```
# Create & activate a virtual environment (recommended)
```bash
python -m venv venv
```
# Windows
```bash
venv\Scripts\activate
```
# Linux / macOS
```bash
source venv/bin/activate
```
# Install Python dependencies
```bash
pip install -r requirements.txt
```

