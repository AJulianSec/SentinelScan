# SentinelScan

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20WSL2-4B8BBE)
![Status](https://img.shields.io/badge/Status-Prototype-orange)

**SentinelScan** is an educational Python application for network reconnaissance and basic local vulnerability correlation.

It combines TCP and UDP port discovery, service banner collection, an offline vulnerability database and multiple report formats in a simple command-line interface. The project is designed to teach network scanning concepts and safe result interpretation in authorized environments.

> [!WARNING]
> SentinelScan is intended only for systems you own or are authorized to test in writing. Scanning third-party systems without permission may be illegal or disruptive. The author accepts no responsibility for misuse.

## Table of Contents

- [Purpose](#purpose)
- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Report Formats](#report-formats)
- [Vulnerability Database](#vulnerability-database)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Limitations](#limitations)
- [Responsible Use](#responsible-use)
- [Roadmap](#roadmap)

## Purpose

SentinelScan provides a practical environment for learning:

- TCP and UDP port scanning
- IPv4 and IPv6 hostname resolution
- Banner grabbing
- Asynchronous worker pools
- Service and version correlation
- Structured report generation
- Basic authorization workflows
- Responsible network testing

It is not an exploitation framework and does not perform privilege escalation, brute force attacks or payload execution.

## Features

- Interactive terminal menu
- Non-interactive command-line mode
- Quick scan of common TCP and UDP ports
- Full TCP scan from port 1 to 65535
- Selected UDP checks for common services
- Single-port TCP or UDP banner grabbing
- Configurable timeout and concurrency
- Optional Rich console progress
- Separate TCP and UDP result keys
- IPv4 and IPv6 socket support
- Additional confirmation for external targets
- Text, JSON, CSV and HTML reports
- Daily operational logging with rotating log files
- Local vulnerability correlation without external API calls
- `open`, `closed` and `open|filtered` result states

## How It Works

1. The target is validated and resolved to an IP address.
2. The selected TCP and UDP tasks are placed in an asynchronous queue.
3. A limited worker pool executes socket checks.
4. A TCP connection receives a short banner sample when available.
5. UDP checks are reported as `open|filtered` when no response is received.
6. Captured banners are compared with the local vulnerability database.
7. TXT, JSON, CSV and HTML reports are generated, as requested.

UDP scanning is inherently less reliable than TCP scanning. A lack of response is not proof that a UDP port is closed or open.

## Requirements

- Python 3.11 or newer
- Windows, Linux or WSL2
- No external dependency is required for the core program
- Rich is optional for colored output and progress bars

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/AJulianSec/SentinelScan.git
cd SentinelScan
```

### 2. Create a virtual environment

**Windows:**

```powershell
python -m venv venv
venv\Scripts\activate
```

**Linux / macOS / WSL2:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install optional dependencies

```bash
python -m pip install rich
```

The basic interactive mode can run without third-party packages.

## Usage

### Interactive mode

```bash
python SentinelScan.py
```

The program asks for the exact consent message `I AGREE` before opening the menu.

Menu operations include:

1. Quick TCP and UDP scan
2. Full TCP scan from port 1 to 65535
3. Single TCP or UDP banner grab
4. Offline vulnerability analysis
5. Concurrency configuration
6. Last report path
7. Recent log entries
8. Exit

### Quick scan

```bash
python SentinelScan.py --target localhost --quick
```

### Banner grab

```bash
python SentinelScan.py --target localhost --banner --port 22 --protocol tcp
```

Valid port numbers range from 1 to 65535.

### Full scan

```bash
python SentinelScan.py --target localhost --full
```

A full TCP scan can take significant time and should only be used on authorized systems.

### Choose report formats

```bash
python SentinelScan.py --target localhost --quick --format txt
python SentinelScan.py --target localhost --quick --format json
python SentinelScan.py --target localhost --quick --format csv
python SentinelScan.py --target localhost --quick --format html
python SentinelScan.py --target localhost --quick --format all
```

The default format is `all`.

### Available options

```text
--target TARGET
--quick
--full
--banner
--port PORT
--protocol {tcp,udp}
--timeout TIMEOUT
--concurrency CONCURRENT_TASKS
--format {txt,json,csv,html,both,all}
--yes
--debug
-h, --help
```

External targets require explicit confirmation:

```bash
python SentinelScan.py --target example.com --quick --yes
```

Replace `example.com` only after obtaining written authorization to test that system.

## Report Formats

Reports are stored inside timestamped directories under `reports/`.

| Format | File | Main use |
|---|---|---|
| Text | `report.txt` | Human-readable summary and recommendations |
| JSON | `report.json` | Machine-readable automation and integrations |
| CSV | `report.csv` | Spreadsheet analysis |
| HTML | `report.html` | Browser-friendly visual report |

Operational events are appended to `logs/scanner.log`.

## Vulnerability Database

SentinelScan reads local entries from `vuln_db.txt`. Each line uses this format:

```text
service|version_expression|cve_id|cvss|severity|summary|recommendation
```

Example:

```text
openssh|>=6.0,<7.0|CVE-2025-0001|7.5|HIGH|Example entry.|Upgrade the service.
```

A simple substring remains supported for compatibility:

```text
openssh|6.|CVE-2016-0777|7.5|HIGH|OpenSSH 6.x example.|Upgrade OpenSSH.
```

Matching requires a recognized service name and a compatible detected version. Lines beginning with `#` are treated as comments.

> [!IMPORTANT]
> The database included with the project is an offline educational example. It is not a maintained vulnerability feed and must not be interpreted as a definitive security assessment.

## Project Structure

```text
SentinelScan/
├── SentinelScan.py
├── vuln_db.txt
├── test_SentinelScan.py
├── pyproject.toml
├── README.md
├── .github/
│   └── workflows/
│       └── tests.yml
├── logs/
└── reports/
```

Generated reports and logs are created next to the script when the program runs.

## Testing

Run the unit test suite with:

```bash
python -m unittest test_SentinelScan.py
```

The tests cover:

- Valid and invalid port numbers
- Banner service and version parsing
- Numeric version ranges
- Service and version vulnerability matching
- JSON report generation
- CSV result generation
- HTML output and character escaping

GitHub Actions runs the test suite on Windows for pushes and pull requests.

## Limitations

- Banner grabbing cannot always identify the software or exact version.
- UDP responses are difficult to interpret reliably.
- An offline example database cannot replace current vulnerability intelligence.
- Version correlation may produce false positives or false negatives.
- A full scan is resource-intensive and can take a long time.
- The additional authorization prompt is a user safeguard, not an access-control system.
- The current result format is primarily educational and should not replace a professional security assessment.

## Responsible Use

Use SentinelScan only in these situations:

- On localhost
- On virtual machines you control
- Inside an isolated laboratory
- On systems covered by explicit written authorization
- Within an organization where network scanning is approved

Do not use SentinelScan to assess production systems or third-party networks without consent.

## Roadmap

Potential future improvements include:

- Modular package structure
- SQLite or JSON vulnerability database
- CVSS and CVE reference links
- JSON configuration profiles
- Port exclusion and custom port lists
- More precise TCP state handling
- Unit tests with mocked network sockets
- HTML dashboard enhancements
- Optional local web interface
- Professional CI configuration and packaging

## Author

Developed by **Adrià Julián** as an educational cybersecurity project.
