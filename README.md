# 🛡️ SentinelScan

**SentinelScan** is an educational Python tool designed for **network reconnaissance and basic vulnerability assessment** in **authorized and controlled environments**.  
It is intended for learning purposes, especially for **Purple Team exercises**, combining offensive and defensive techniques in a safe lab setting.

---

## 📋 Overview

SentinelScan automates several phases of network reconnaissance, service identification, and vulnerability correlation through a **user-friendly command-line interface (CLI)**.  
This project is ideal for students or cybersecurity professionals looking to improve their skills in **ethical hacking, defensive monitoring, and threat analysis**.

> ⚠️ **Legal and Ethical Disclaimer:**  
> SentinelScan must only be used on systems you own or in laboratory environments where you have explicit permission.  
> Misuse on unauthorized systems or networks may be illegal.  
> This software is educational and does not include exploits or intrusion mechanisms.

---

## ⚙️ Key Features

-  **Quick TCP Port Scan** — scan common ports rapidly.
-  **Full Port Scan (1–65535)** with optional `nmap` integration.
-  **Banner Grabbing** — identify services and versions.
-  **Educational Vulnerability Analysis** using a local JSON database.
-  **Asynchronous/Concurrent Mode** using `asyncio` for faster scans.
-  **Export Results** in JSON and CSV formats.
-  **Logging** with multiple levels and ethical warnings.
-  **Console interface with colors** (optional via `rich` library).
-  **Automated Tests** (`pytest`) for basic validation against `localhost`.

---

##  Requirements & Installation

###  System Requirements
- Python 3.10 or higher  
- pip (Python package manager)  
- (Optional) `nmap` installed on the system  
- OS: Windows, Linux, or WSL2

###  Installation

#Clone the repository

```bash

git clone https://github.com/yourusername/SentinelScan.git
cd SentinelScan
```

# Create a virtual environment
```bash
python -m venv venv
```
# Activate (Windows)
```bash
venv\Scripts\activate
```
# Activate (Linux/Mac)
```bash
source venv/bin/activate
```

# Install dependencies
```bash 
pip install -r requirements.txt
``````
