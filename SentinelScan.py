#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SentinelScan

Small educational scanner for local or explicitly authorized targets.
It checks TCP and UDP ports, tries to collect service banners and compares
them with a local text database of example vulnerability entries.

The program requires the exact consent message "I AGREE" in interactive mode.
Use it only for systems you own or have permission to test.

Reports:
    reports/<target>_<timestamp>/report.txt
    reports/<target>_<timestamp>/report.json
    reports/<target>_<timestamp>/report.csv
    reports/<target>_<timestamp>/report.html

Log file:
    logs/scanner.log

The application uses an asynchronous worker pool and can show progress with
Rich when that optional package is installed. Python 3.11 or newer is
recommended.
"""
from __future__ import annotations

import asyncio
import argparse
import csv
import html
import ipaddress
import json
import logging
import logging.handlers
import math
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Rich is optional, so the program can also run in a plain terminal.
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.panel import Panel

    RICH_AVAILABLE = True
    console = Console()
except Exception:
    RICH_AVAILABLE = False
    console = None

# Configuration
AUTHOR = "Adria Julian"
DEFAULT_TIMEOUT = 1.0
DEFAULT_CONCURRENCY = 200
COMMON_TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]
COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 161, 500, 520]
MAX_CONCURRENCY = 1000

BASE_DIR = Path(__file__).resolve().parent


def _runtime_data_dir() -> Path:
    configured = os.environ.get("SENTINELSCAN_DATA_DIR")
    if configured:
        return Path(configured).expanduser().resolve()

    if (BASE_DIR / "vuln_db.txt").exists():
        try:
            (BASE_DIR / "logs").mkdir(parents=True, exist_ok=True)
            (BASE_DIR / "reports").mkdir(parents=True, exist_ok=True)
            return BASE_DIR
        except OSError:
            pass

    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "SentinelScan"


RUNTIME_DATA_DIR = _runtime_data_dir()
LOG_DIR = RUNTIME_DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "scanner.log"

VULN_DB_FILE = BASE_DIR / "vuln_db.txt"
if not VULN_DB_FILE.exists():
    VULN_DB_FILE = RUNTIME_DATA_DIR / "vuln_db.txt"

REPORTS_DIR = RUNTIME_DATA_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Logging
logger = logging.getLogger("sentinelscan")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    rh = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    rh.setFormatter(fmt)
    logger.addHandler(rh)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

# Terminal output helpers


def _print(msg: str, style: Optional[str] = None) -> None:
    if RICH_AVAILABLE and console:
        console.print(msg, style=style)
    else:
        print(msg)


def _panel(text: str, title: str = "") -> None:
    if RICH_AVAILABLE and console:
        console.print(Panel(text, title=title))
    else:
        print(f"--- {title} ---\n{text}\n")


# Network helpers


def resolve_host(target: str) -> Optional[str]:
    """Resolve a hostname and return the first IPv4 address, or an IPv6 address."""
    try:
        # This call can return several network addresses, especially when the
        # target is a domain with both IPv4 and IPv6 records.
        infos = socket.getaddrinfo(target, None)
        ipv4 = [i for i in infos if i[0] == socket.AF_INET]
        if ipv4:
            return ipv4[0][4][0]
        ipv6 = [i for i in infos if i[0] == socket.AF_INET6]
        if ipv6:
            return ipv6[0][4][0]
        return None
    except socket.gaierror:
        return None


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def _safe_decode(b: bytes) -> str:
    try:
        return b.decode(errors="ignore")
    except Exception:
        return repr(b)


def validate_port(port: int) -> bool:
    # Port numbers start at 1 for normal use. Zero and values above 65535
    # cannot represent valid TCP or UDP ports and must be rejected here.
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


# TCP and UDP checks


def _blocking_tcp_check(ip: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str]]:
    if not validate_port(port):
        return port, False, None
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((ip, port))
            if res != 0:
                return port, False, None
            try:
                # If the connection succeeds, waiting briefly for an initial
                # message allows SentinelScan to collect the most useful banner.
                s.settimeout(min(1.0, timeout))
                data = s.recv(4096)
                if data:
                    return port, True, _safe_decode(data).strip()
                return port, True, None
            except socket.timeout:
                return port, True, None
            except Exception:
                return port, True, None
    except Exception:
        return port, False, None


def _blocking_udp_check(ip: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str]]:
    """Return open|filtered when the port does not respond."""
    if not validate_port(port):
        return port, False, None
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                # The line sent is only a small test packet. It should not be
                # interpreted as a complete request for any UDP application.
                s.sendto(b"\n", (ip, port))
            except Exception:
                return port, False, None
            try:
                data, addr = s.recvfrom(4096)
                if data:
                    return port, True, _safe_decode(data).strip()
                return port, True, None
            except socket.timeout:
                # UDP does not confirm a port as closed by design. Waiting for
                # a response cannot distinguish open ports from filtered ones.
                return port, False, "open|filtered"
            except Exception:
                return port, False, None
    except Exception:
        return port, False, None


# Local vulnerability database
# Format:
# service|version_expression|cve_id|cvss|severity|summary|recommendation


def ensure_vuln_db_exists() -> None:
    if VULN_DB_FILE.exists():
        return
    sample_lines = [
        "openssh|6.|CVE-2016-0777|7.5|HIGH|OpenSSH 6.x example vulnerability (educational).|Upgrade OpenSSH.",
        "nginx|1.14|CVE-2019-20372|7.5|HIGH|nginx 1.14.x example.|Upgrade nginx to a supported version.",
        "apache|2.2|CVE-2017-3169|5.3|MEDIUM|Apache 2.2 end-of-life example.|Migrate to Apache 2.4."
    ]
    try:
        VULN_DB_FILE.write_text('\n'.join(sample_lines), encoding='utf-8')
        logger.info("Created example offline vuln DB (TXT): %s", VULN_DB_FILE)
    except Exception as e:
        logger.error("Failed to create vuln DB: %s", e)


def load_vuln_db_txt() -> List[Dict[str, Any]]:
    ensure_vuln_db_exists()
    results: List[Dict[str, Any]] = []
    try:
        text = VULN_DB_FILE.read_text(encoding='utf-8')
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith('#'):
                continue
            parts = ln.split('|')
            if len(parts) < 7:
                continue
            svc, ver_sub, cve, cvss, severity, summary, reco = [p.strip() for p in parts[:7]]
            try:
                cvss_f = float(cvss)
            except Exception:
                cvss_f = 0.0
            results.append({
                'service': svc,
                'version_contains': ver_sub,
                'cve_id': cve,
                'cvss': cvss_f,
                'severity': severity,
                'summary': summary,
                'recommendation': reco
            })
    except Exception as e:
        logger.error("Failed to load vuln DB: %s", e)
    return results


# Banner parsing
BANNER_SERVICE_VERSION_REGEXES = [
    re.compile(r"(?P<service>openssh)[\s_/\-]?_?v?(?P<version>\d+(?:\.\d+)*)", re.IGNORECASE),
    re.compile(r"(?P<service>apache)[/ _\-]?v?(?P<version>\d+(?:\.\d+)*)", re.IGNORECASE),
    re.compile(r"(?P<service>nginx)[/ _\-]?v?(?P<version>\d+(?:\.\d+)*)", re.IGNORECASE),
    re.compile(r"(?P<service>[A-Za-z0-9_\-]+)[/ _\-]?v?(?P<version>\d+(?:\.\d+){0,3})", re.IGNORECASE),
]


def parse_banner_service_version(banner: str) -> Tuple[Optional[str], Optional[str]]:
    # This parser tries the most recognizable formats first. If no complete
    # service and version pair is found, it checks known service names in the
    # beginning of the banner before returning an unknown result.
    if not banner:
        return None, None
    for rx in BANNER_SERVICE_VERSION_REGEXES:
        m = rx.search(banner)
        if m:
            svc = m.groupdict().get('service')
            ver = m.groupdict().get('version')
            if svc:
                return svc.lower(), ver
    tokens = banner.split()
    for t in tokens[:6]:
        t_clean = re.sub(r"[^A-Za-z0-9_\-./]", "", t)
        if len(t_clean) > 2 and any(k in t_clean.lower() for k in ("nginx", "apache", "openssh", "ssh", "postgres", "mysql", "mariadb", "iis")):
            m = re.search(r"(\d+(?:\.\d+)*)", t_clean)
            return t_clean.split('/')[0].lower(), (m.group(1) if m else None)
    return None, None


# Vulnerability analysis


def severity_suggested_actions(severity: str) -> List[str]:
    sev = (severity or '').upper()
    if sev == 'CRITICAL':
        return [
            "Immediate action required: isolate affected systems if possible.",
            "Apply vendor patch or mitigation immediately.",
            "Engage incident response if exploitation is suspected."
        ]
    if sev == 'HIGH':
        return [
            "High priority patching recommended.",
            "Apply mitigations (restrict access, firewall rules) while patching."
        ]
    if sev == 'MEDIUM':
        return [
            "Investigate and schedule patching.",
            "Review configuration and compensating controls."
        ]
    if sev == 'LOW':
        return [
            "Monitor and schedule patching as appropriate.",
            "Assess real exploitability in your environment."
        ]
    return ["No automated recommendation available."]


def version_matches(detected: Optional[str], version_expression: str) -> bool:
    """Compare a detected version with a substring or a simple numeric range."""
    if not detected or not version_expression:
        return False
    expression = version_expression.strip()
    if re.match(r"^\s*(?:>=|<=|==|!=|>|<)\s*\d", expression):
        # Numeric ranges are safer than loose text matching. Splitting the
        # version at each dot lets the function compare 6.10 correctly as
        # newer than 6.9 rather than comparing the text from left to right.
        try:
            detected_parts = tuple(int(part) for part in detected.split('.'))
        except (TypeError, ValueError):
            return False
        for rule in expression.split(','):
            rule = rule.strip()
            match = re.fullmatch(r"(>=|<=|==|!=|>|<)\s*(\d+(?:\.\d+)*)", rule)
            if not match:
                return False
            operator, required_text = match.groups()
            required_parts = tuple(int(part) for part in required_text.split('.'))
            width = max(len(detected_parts), len(required_parts))
            left = detected_parts + (0,) * (width - len(detected_parts))
            right = required_parts + (0,) * (width - len(required_parts))
            if operator == ">=" and not left >= right:
                return False
            if operator == "<=" and not left <= right:
                return False
            if operator == "==" and not left == right:
                return False
            if operator == "!=" and not left != right:
                return False
            if operator == ">" and not left > right:
                return False
            if operator == "<" and not left < right:
                return False
        return True
    return expression.lower() in detected.lower()


def vuln_analysis_from_banners_txt(banners: Dict[Any, Optional[str]]) -> List[Dict[str, Any]]:
    db = load_vuln_db_txt()
    matches: List[Dict[str, Any]] = []
    for port_key, banner in banners.items():
        if not banner:
            continue
        try:
            # Port keys may include a protocol, such as tcp/22, or may simply
            # contain the number. The report stores the numeric port separately.
            port_label = str(port_key)
            port = int(port_label.split('/', 1)[1]) if '/' in port_label else int(port_label)
        except (TypeError, ValueError):
            continue
        svc, ver = parse_banner_service_version(banner)
        banner_lower = banner.lower()
        for entry in db:
            svc_entry = (entry.get('service') or '').lower()
            ver_sub = (entry.get('version_contains') or '').lower()
            matched = False
            matched_string = None
            if svc_entry and ver_sub:
                if svc and svc_entry in svc and ver and version_matches(ver, ver_sub):
                    matched = True
                    matched_string = ver
            if not matched and svc_entry and ver_sub and svc_entry in banner_lower:
                detected_banner_ver = ver or re.search(r"(\d+(?:\.\d+)*)", banner_lower)
                if isinstance(detected_banner_ver, re.Match):
                    detected_banner_ver = detected_banner_ver.group(1)
                if detected_banner_ver and version_matches(detected_banner_ver, ver_sub):
                    matched = True
                    matched_string = detected_banner_ver
            if matched:
                matches.append({
                    'port': port,
                    'banner': banner,
                    'service_detected': svc,
                    'version_detected': ver,
                    'matched_string': matched_string,
                    'service': entry.get('service'),
                    'version_contains': entry.get('version_contains'),
                    'cve_id': entry.get('cve_id'),
                    'cvss': entry.get('cvss'),
                    'severity': entry.get('severity'),
                    'summary': entry.get('summary'),
                    'recommendation': entry.get('recommendation')
                })
    return matches


# Asynchronous network operations


async def _attempt_connect_in_thread(ip: str, port: int, timeout: float, proto: str = 'tcp') -> Tuple[int, bool, Optional[str]]:
    loop = asyncio.get_running_loop()
    try:
        if hasattr(asyncio, 'to_thread'):
            if proto == 'tcp':
                return await asyncio.to_thread(_blocking_tcp_check, ip, port, timeout)
            else:
                return await asyncio.to_thread(_blocking_udp_check, ip, port, timeout)
        else:
            if proto == 'tcp':
                fut = loop.run_in_executor(None, _blocking_tcp_check, ip, port, timeout)
            else:
                fut = loop.run_in_executor(None, _blocking_udp_check, ip, port, timeout)
            return await fut
    except Exception:
        return port, False, None


async def _worker(queue: asyncio.Queue, results: Dict[str, Dict[str, Optional[str]]], sem: asyncio.Semaphore, timeout: float, progress_cb=None):
    while True:
        try:
            port, ip, proto = await queue.get()
            async with sem:
                # The semaphore keeps network usage under control even when there
                # are thousands of queued ports. Each result is stored under the
                # protocol and port so TCP and UDP cannot overwrite each other.
                p, is_open, banner = await _attempt_connect_in_thread(ip, port, timeout, proto)
                key = f"{proto}/{p}"
                results[key] = {"open": is_open, "banner": banner}
                if progress_cb:
                    progress_cb()
        except asyncio.CancelledError:
            break
        except Exception:
            key = f"{proto}/{port}"
            results[key] = {"open": False, "banner": None}
        finally:
            queue.task_done()


async def _run_port_pool(ip: str, tasks: List[Tuple[int, str]], timeout: float, concurrency: int, progress_cb=None) -> Dict[str, Dict[str, Optional[str]]]:
    results: Dict[str, Dict[str, Optional[str]]] = {}
    q: asyncio.Queue = asyncio.Queue()
    for p, proto in tasks:
        q.put_nowait((p, ip, proto))
    sem = asyncio.Semaphore(concurrency)
    workers = [asyncio.create_task(_worker(q, results, sem, timeout, progress_cb)) for _ in range(min(len(tasks), concurrency))]
    try:
        await q.join()
    finally:
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
    return results


async def scan_ports_async_with_progress(ip: str, tasks: List[Tuple[int, str]], timeout: float, concurrency: int, show_rich: bool = True) -> Dict[str, Dict[str, Optional[str]]]:
    total = len(tasks)
    completed = 0

    def progress_cb():
        nonlocal completed
        completed += 1

    use_rich = RICH_AVAILABLE and show_rich
    progress = None
    task_id = None
    if use_rich:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total} tasks"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        )
        task_id = progress.add_task("Scanning ports", total=total)
        progress.start()
    else:
        _print(f"[*] Scanning {total} ports... (text progress)")

    pool_task = asyncio.create_task(_run_port_pool(ip, tasks, timeout, concurrency, progress_cb))
    try:
        while not pool_task.done():
            await asyncio.sleep(0.25)
            if use_rich and progress and task_id is not None:
                progress.update(task_id, completed=completed)
            else:
                if total > 0 and (completed % max(1, total // 40) == 0):
                    pct = (completed / total) * 100
                    print(f"[*] Progress: {completed}/{total} tasks scanned ({pct:.1f}%)")
        results = await pool_task
    finally:
        if use_rich and progress:
            progress.stop()
    return results


# Report writing


def create_scan_paths(target: str, ts: Optional[datetime] = None) -> Tuple[Path, Path]:
    if ts is None:
        ts = datetime.now(timezone.utc)
    stamp = ts.strftime("%Y%m%d_%H%M%S_%f")
    safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    dir_path = REPORTS_DIR / f"{safe_target}_{stamp}"
    dir_path.mkdir(parents=True, exist_ok=True)
    report_path = dir_path / "report.txt"
    return report_path, dir_path


def write_txt_report(payload: Dict[str, Any], report_path: Path) -> Path:
    try:
        lines: List[str] = []
        # The text report follows a fixed structure: summary, open ports,
        # vulnerability matches and a final section explaining limitations.
        lines.append("Scan Report")
        lines.append("=" * 80)
        lines.append(f"Author : {AUTHOR}")
        lines.append(f"Date : {datetime.now(timezone.utc).isoformat()}")
        lines.append(f"Target : {payload.get('target')} ({payload.get('ip')})")
        lines.append(f"Duration: {payload.get('duration', 0.0):.2f}s")
        lines.append("")
        ports_dict = payload.get('ports', {}) or {}
        port_items = sorted([(k, v) for k, v in ports_dict.items()], key=lambda x: x[0]) if ports_dict else []
        total_scanned = len(port_items)
        open_ports = [k for k, info in port_items if info.get('open')]
        lines.append("Summary:")
        lines.append(f" - Scanned ports/tasks: {total_scanned}")
        lines.append(f" - Open ports: {len(open_ports)}")
        lines.append("")
        lines.append("Open Ports (detailed):")
        if open_ports:
            for k, info in port_items:
                if info.get('open'):
                    banner = info.get('banner') or '-'
                    lines.append(f" - {k} OPEN banner: {banner}")
        else:
            lines.append(" - None found among scanned ports.")

        udp_unknown = [k for k, info in port_items if info.get('banner') == 'open|filtered']
        if udp_unknown:
            lines.append("")
            lines.append("UDP observations (not confirmed open):")
            for k in udp_unknown:
                lines.append(f" - {k} OPEN|FILTERED (no response received)")

        lines.append("")
        lines.append("Vulnerability Analysis (LOCAL TXT DB - strict match):")
        vmatches = payload.get('vuln_matches') or []
        if not vmatches:
            lines.append(" - No vulnerabilities matched in the local offline TXT DB using strict version substring matching.")
        else:
            for m in vmatches:
                lines.append(f" - {m['port']} Service (db): {m.get('service')} Detected service: {m.get('service_detected')} Detected version: {m.get('version_detected') or '-'}")
                lines.append(f"   Matched substring: {m.get('matched_string')}")
                lines.append(f"   CVE: {m.get('cve_id')}")
                lines.append(f"   Severity: {m.get('severity')} CVSS: {m.get('cvss')}")
                lines.append(f"   Summary: {m.get('summary')}")
                lines.append(f"   Recommendation: {m.get('recommendation')}")
                lines.append(f"   Suggested next steps:")
                for step in severity_suggested_actions(m.get('severity')):
                    lines.append(f"    - {step}")
                lines.append("")

        lines.append("Methodology / Caveats:")
        lines.append(" - This analysis uses a local offline example database (vuln_db.txt).")
        lines.append(" - Matching requires both a recognized service name and a version substring (case-insensitive).")
        lines.append(" - UDP open|filtered means no response was received; this is not confirmation that the port is open.")
        lines.append(" - Use authorized scopes only. The tool logs consent and operations.")
        lines.append("")

        report_path.write_text('\n'.join(lines), encoding='utf-8')
        logger.info("TXT report written -> %s", report_path)
        return report_path
    except Exception as e:
        logger.exception("Failed to write TXT report: %s", e)
        raise


def write_json_report(payload: Dict[str, Any], report_path: Path) -> Path:
    json_path = report_path.with_suffix(".json")
    try:
        # A shallow copy keeps the original scan payload available while adding
        # file metadata that is useful when the JSON is opened later.
        json_payload = dict(payload)
        json_payload["generated_at"] = datetime.now(timezone.utc).isoformat()
        json_payload["author"] = AUTHOR
        json_path.write_text(json.dumps(json_payload, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("JSON report written -> %s", json_path)
        return json_path
    except Exception as e:
        logger.exception("Failed to write JSON report: %s", e)
        raise


def _csv_safe(value: Any) -> str:
    text = "-" if value is None else str(value)
    stripped = text.lstrip(" \t\r\n")
    if stripped.startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def write_csv_report(payload: Dict[str, Any], report_path: Path) -> Path:
    csv_path = report_path.with_suffix(".csv")
    try:
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["protocol", "port", "status", "banner"])
            for result_key, info in sorted(payload.get("ports", {}).items()):
                parts = result_key.split("/", 1)
                protocol = parts[0] if len(parts) == 2 else ""
                port = parts[1] if len(parts) == 2 else result_key
                banner = info.get("banner")
                if banner == "open|filtered":
                    status = "open|filtered"
                elif info.get("open"):
                    status = "open"
                else:
                    status = "closed"
                writer.writerow([
                    _csv_safe(protocol),
                    _csv_safe(port),
                    _csv_safe(status),
                    _csv_safe(banner),
                ])
        logger.info("CSV report written -> %s", csv_path)
        return csv_path
    except Exception as e:
        logger.exception("Failed to write CSV report: %s", e)
        raise


def write_html_report(payload: Dict[str, Any], report_path: Path) -> Path:
    html_path = report_path.with_suffix(".html")
    try:
        rows: List[str] = []
        for result_key, info in sorted(payload.get("ports", {}).items()):
            parts = result_key.split("/", 1)
            protocol = parts[0] if len(parts) == 2 else ""
            port = parts[1] if len(parts) == 2 else result_key
            banner = info.get("banner")
            if banner == "open|filtered":
                status, css_class = "open|filtered", "filtered"
            elif info.get("open"):
                status, css_class = "open", "open"
            else:
                status, css_class = "closed", "closed"
            rows.append(
                "<tr>"
                f"<td>{html.escape(protocol)}</td>"
                f"<td>{html.escape(str(port))}</td>"
                f"<td class=\"{css_class}\">{status}</td>"
                f"<td>{html.escape(str(banner or '-'))}</td>"
                "</tr>"
            )

        vuln_rows: List[str] = []
        for match in payload.get("vuln_matches") or []:
            vuln_rows.append(
                "<tr>"
                f"<td>{html.escape(str(match.get('port')))}</td>"
                f"<td>{html.escape(str(match.get('service') or '-'))}</td>"
                f"<td>{html.escape(str(match.get('cve_id') or '-'))}</td>"
                f"<td>{html.escape(str(match.get('severity') or '-'))}</td>"
                f"<td>{html.escape(str(match.get('summary') or '-'))}</td>"
                "</tr>"
            )

        document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SentinelScan report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #202124; }}
    h1, h2 {{ color: #182b49; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
    th, td {{ border: 1px solid #d7dce2; padding: .55rem; text-align: left; }}
    th {{ background: #eef3f8; }}
    .open {{ color: #18794e; font-weight: bold; }}
    .filtered {{ color: #9a6700; font-weight: bold; }}
    .closed {{ color: #656a70; }}
    .notice {{ background: #fff7d6; border-left: 4px solid #d4a72c; padding: .75rem; }}
  </style>
</head>
<body>
  <h1>SentinelScan Report</h1>
  <p><strong>Target:</strong> {html.escape(str(payload.get('target')))} ({html.escape(str(payload.get('ip')))})</p>
  <p><strong>Duration:</strong> {float(payload.get('duration', 0.0)):.2f}s</p>
  <p class="notice">UDP open|filtered means no response was received. It is not a confirmed open port.</p>
  <h2>Port results</h2>
  <table>
    <thead><tr><th>Protocol</th><th>Port</th><th>Status</th><th>Banner</th></tr></thead>
    <tbody>{''.join(rows) or '<tr><td colspan="4">No port results</td></tr>'}</tbody>
  </table>
  <h2>Vulnerability matches</h2>
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>CVE</th><th>Severity</th><th>Summary</th></tr></thead>
    <tbody>{''.join(vuln_rows) or '<tr><td colspan="5">No matches in the local database</td></tr>'}</tbody>
  </table>
</body>
</html>
"""
        html_path.write_text(document, encoding="utf-8")
        logger.info("HTML report written -> %s", html_path)
        return html_path
    except Exception as e:
        logger.exception("Failed to write HTML report: %s", e)
        raise


# Report and log helpers


def find_latest_report(target: Optional[str] = None) -> Optional[Path]:
    """Find the newest report.txt for a target, or for all targets if no target is given."""
    try:
        candidates = []
        for d in REPORTS_DIR.iterdir():
            if not d.is_dir():
                continue
            if target:
                safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", target)
                if not d.name.startswith(safe_target + "_"):
                    continue
            rpt = d / "report.txt"
            if rpt.exists():
                candidates.append(rpt)
        if not candidates:
            return None
        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return candidates[0]
    except Exception:
        return None


def tail_log(lines: int = 50) -> None:
    """Print the last `lines` lines from the primary log file or the newest rotated log in logs/."""
    try:
        if LOG_FILE.exists():
            path = LOG_FILE
        else:
            # There is no active log file, so use the newest rotated file.
            files = [p for p in LOG_DIR.iterdir() if p.is_file()]
            if not files:
                _print("No log file available.")
                return
            files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            path = files[0]
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            data = fh.readlines()
            for l in data[-lines:]:
                _print(l.rstrip())
    except Exception as e:
        _print(f"Failed to read log file: {e}")


# Scan actions


async def action_quick_scan(target: str, timeout: float, concurrency: int) -> Dict[str, Any]:
    ip = resolve_host(target) or target
    start = time.time()
    tasks: List[Tuple[int, str]] = []
    tasks.extend([(p, 'tcp') for p in COMMON_TCP_PORTS])
    tasks.extend([(p, 'udp') for p in COMMON_UDP_PORTS])
    ports_res = await scan_ports_async_with_progress(ip, tasks, timeout, concurrency, show_rich=True)
    duration = time.time() - start
    payload_ports = {str(k): v for k, v in ports_res.items()}
    banners = {k: v.get('banner') for k, v in ports_res.items()}
    vuln_matches = vuln_analysis_from_banners_txt(banners)
    return {"target": target, "ip": ip, "duration": duration, "ports": payload_ports, "vuln_matches": vuln_matches}


async def action_full_scan(target: str, timeout: float, concurrency: int) -> Dict[str, Any]:
    ip = resolve_host(target) or target
    ports = list(range(1, 65536))
    # A full TCP scan reaches every port, while UDP is limited to a small
    # selection because sending every UDP packet would be too slow and noisy.
    tasks = [(p, 'tcp') for p in ports] + [(p, 'udp') for p in (1, 53, 67, 68, 69, 123, 161, 500, 520)]
    start = time.time()
    ports_res = await scan_ports_async_with_progress(ip, tasks, timeout, concurrency, show_rich=True)
    duration = time.time() - start
    payload_ports = {str(k): v for k, v in ports_res.items()}
    banners = {k: v.get('banner') for k, v in ports_res.items()}
    vuln_matches = vuln_analysis_from_banners_txt(banners)
    return {"target": target, "ip": ip, "duration": duration, "ports": payload_ports, "vuln_matches": vuln_matches}

# Single-port banner grab


def action_banner_grab(target: str, port: int, proto: str, timeout: float) -> Dict[str, Any]:
    ip = resolve_host(target) or target
    if proto == 'tcp':
        p, is_open, banner = _blocking_tcp_check(ip, port, timeout)
    else:
        p, is_open, banner = _blocking_udp_check(ip, port, timeout)
    return {"target": target, "ip": ip, "port": port, "proto": proto, "banner": banner, "open": is_open}

# Interactive menu


def print_menu() -> None:
    _print("\nSentinelScan - Menu")
    _print(" 1) Quick TCP+UDP scan (common ports)")
    _print(" 2) Full TCP scan (1-65535) + selected UDP (educational) <-- shows progress")
    _print(" 3) Banner grabbing (single TCP/UDP port)")
    _print(" 4) Vulnerability analysis (offline TXT, strict)")
    _print(" 5) Configure concurrency")
    _print(" 6) Show last report path")
    _print(" 7) View logs (tail)")
    _print(" 8) Exit")


async def main_cli_loop() -> None:
    _print("=== SentinelScan ===", style="bold cyan" if RICH_AVAILABLE else None)
    _print("Educational tool: use only on authorized systems. UNETHICAL use is PROHIBITED.")
    _print('Type exactly: I AGREE to accept the legal notice and continue.')
    # This first confirmation is mandatory. It is deliberately simple and
    # recorded in the log, but it does not replace explicit authorization for
    # a real system or network that belongs to another person or organization.
    consent = input("Consent (type I AGREE to continue): ").strip()
    logger.info("User consent: %s", consent)
    if consent != "I AGREE":
        _print("Consent not provided. Exiting.")
        return

    ensure_vuln_db_exists()
    last_target = "localhost"
    last_payload: Optional[Dict[str, Any]] = None
    last_report_path: Optional[Path] = None
    timeout = DEFAULT_TIMEOUT
    concurrency = DEFAULT_CONCURRENCY

    while True:
        print_menu()
        choice = input("Select option (1-8): ").strip()
        if choice == "1":
            target = input(f"Target [{last_target}]: ").strip() or last_target
            ip = resolve_host(target)
            if ip is None:
                _print("Could not resolve the target. Enter a valid hostname or IP.")
                continue
            if not (target in ("localhost", "127.0.0.1", "::1") or is_private_ip(ip)):
                # Public targets receive an additional confirmation before any
                # packet is sent. The second message includes the exact target
                # name so that accidental confirmation is less likely.
                _print(f"Target {target} resolves to {ip}, it appears to be external.")
                confirm = input(f"Type '{target} PERMISSION' to confirm authorization: ").strip()
                logger.info("External confirm: %s", confirm)
                if confirm != f"{target} PERMISSION":
                    _print("External permission not granted. Returning to menu.")
                    continue
            _print(f"[*] Performing quick scan on {target} ({ip}) ...")
            payload = await action_quick_scan(target, timeout, concurrency)
            last_payload = payload
            last_target = target
            report_path, _ = create_scan_paths(target)
            last_report_path = Path(report_path)
            try:
                write_txt_report(payload, last_report_path)
                write_json_report(payload, last_report_path)
                write_csv_report(payload, last_report_path)
                write_html_report(payload, last_report_path)
                open_ports = [p for p, info in payload.get('ports', {}).items() if info.get('open')]
                _print("[+] Quick scan completed.")
                _print(f" Open ports found: {len(open_ports)}")
                _print(f" TXT report: {last_report_path}")
            except Exception as e:
                _print(f"[!] Failed to write report: {e}")

        elif choice == "2":
            target = input(f"Target [{last_target}]: ").strip() or last_target
            ip = resolve_host(target)
            if ip is None:
                _print("Could not resolve the target.")
                continue
            if not (target in ("localhost", "127.0.0.1", "::1") or is_private_ip(ip)):
                _print(f"Target {target} resolves to {ip}, it appears to be external.")
                confirm = input(f"Type '{target} PERMISSION' to confirm authorization: ").strip()
                logger.info("External confirm: %s", confirm)
                if confirm != f"{target} PERMISSION":
                    _print("External permission not granted.")
                    continue
            _print("Full scan may take a long time and consume resources.")
            ok = input("Type 'y' to continue, any other key to cancel: ").strip().lower()
            if ok != "y":
                _print("Full scan canceled.")
                continue
            report_path, _ = create_scan_paths(target)
            last_report_path = Path(report_path)
            _print(f"[*] Starting full scan on {target} ({ip}) ...")
            start_t = time.time()
            try:
                payload = await action_full_scan(target, timeout, concurrency)
            except KeyboardInterrupt:
                _print("\nScan interrupted by user.")
                logger.info("Full scan interrupted.")
                continue
            elapsed = time.time() - start_t
            last_payload = payload
            payload["duration"] = elapsed
            try:
                write_txt_report(payload, last_report_path)
                write_json_report(payload, last_report_path)
                write_csv_report(payload, last_report_path)
                write_html_report(payload, last_report_path)
                open_ports = [p for p, info in payload.get('ports', {}).items() if info.get('open')]
                vuln_matches = payload.get('vuln_matches') or []
                _print("[+] Full scan completed.")
                _print(f" Duration: {elapsed:.2f}s")
                _print(f" Open ports found: {len(open_ports)}")
                _print(f" Vulnerability matches: {len(vuln_matches)}")
                _print(f" TXT report: {last_report_path}")
            except Exception as e:
                _print(f"[!] Failed to write report: {e}")

        elif choice == "3":
            target = input(f"Target [{last_target}]: ").strip() or last_target
            ip = resolve_host(target)
            if ip is None:
                _print("Could not resolve target.")
                continue
            if not (target in ("localhost", "127.0.0.1", "::1") or is_private_ip(ip)):
                _print(f"Target {target} resolves to {ip}, it appears to be external.")
                confirm = input(f"Type '{target} PERMISSION' to confirm authorization: ").strip()
                logger.info("Banner external confirm: %s", confirm)
                if confirm != f"{target} PERMISSION":
                    _print("External permission not granted.")
                    continue
            port_s = input("Port for banner grab (e.g. 22): ").strip()
            proto = input("Protocol (tcp/udp) [tcp]: ").strip().lower() or 'tcp'
            try:
                port = int(port_s)
            except Exception:
                _print("Invalid port.")
                continue
            if not validate_port(port):
                _print("Invalid port. Choose a value from 1 to 65535.")
                continue
            if proto not in ('tcp', 'udp'):
                _print("Invalid protocol. Use tcp or udp.")
                continue
            res = action_banner_grab(target, port, proto, timeout)
            banner = res.get('banner')
            is_open = res.get('open')
            _print(f"Banner {target}:{port}/{proto} -> {banner or '<no banner>'} Open: {is_open}")
            if last_payload is None:
                last_payload = {"target": target, "ip": ip, "duration": 0.0, "ports": {}, "vuln_matches": []}
            last_payload['ports'][f"{proto}/{port}"] = {"open": bool(is_open), "banner": banner}
            last_target = target

        elif choice == "4":
            if last_payload is None:
                _print("No scan data available. Run a quick/full scan or a banner grab first.")
                continue
            banners = {}
            for p_str, info in last_payload.get('ports', {}).items():
                try:
                    proto, port_s = p_str.split('/', 1)
                    p_int = int(port_s)
                except Exception:
                    continue
                banners[p_int] = info.get('banner')
            vmatches = vuln_analysis_from_banners_txt(banners)
            last_payload['vuln_matches'] = vmatches
            if last_report_path is None:
                report_path, _ = create_scan_paths(last_payload.get('target', 'unknown'))
                last_report_path = Path(report_path)
            try:
                write_txt_report(last_payload, last_report_path)
                write_json_report(last_payload, last_report_path)
                write_csv_report(last_payload, last_report_path)
                write_html_report(last_payload, last_report_path)
                _print(f"[+] Vulnerability analysis complete. TXT report: {last_report_path}")
                _print(f" Vulnerability matches found: {len(vmatches)}")
            except Exception as e:
                _print(f"[!] Failed to write report: {e}")

        elif choice == "5":
            try:
                c = int(input(f"Concurrency [{concurrency}]: ").strip() or concurrency)
                concurrency = max(1, min(MAX_CONCURRENCY, c))
            except Exception:
                _print("Invalid concurrency. Using previous value.")

        elif choice == "6":
            # Find the report in memory first, and search the reports folder as a fallback.
            if last_report_path and last_report_path.exists():
                _print(f"Last report: {last_report_path}")
                _print("You can view it with: less " + str(last_report_path))
            else:
                # Check the last target first, then look for any report.
                found = find_latest_report(last_target) or find_latest_report(None)
                if found:
                    last_report_path = found
                    _print(f"Last report (found): {last_report_path}")
                    _print("You can view it with: less " + str(last_report_path))
                else:
                    _print("No report generated yet or report file not found on disk.")

        elif choice == "7":
            # Show the latest log entries, including rotated logs if needed.
            tail_log(80)

        elif choice == "8":
            _print("Exiting. Stay ethical and authorized.")
            break

        else:
            _print("Invalid selection. Choose an option 1-8.")

# Command-line entry point


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SentinelScan - authorized educational port scanner")
    parser.add_argument("--target", help="Hostname or IP address")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="Scan common TCP/UDP ports")
    mode.add_argument("--full", action="store_true", help="Scan all TCP ports and selected UDP ports")
    mode.add_argument("--banner", action="store_true", help="Grab a single service banner")
    parser.add_argument("--port", type=int, help="Port for --banner")
    parser.add_argument("--protocol", choices=("tcp", "udp"), default="tcp", help="Protocol for --banner")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--format", choices=("txt", "json", "csv", "html", "both", "all"), default="all")
    parser.add_argument("--yes", action="store_true", help="Confirm authorization for an external target")
    parser.add_argument("--debug", "-d", action="store_true")
    return parser


async def run_headless(args: argparse.Namespace) -> int:
    if not args.target:
        _print("The --target argument is required in non-interactive mode.")
        return 2
    ip = resolve_host(args.target)
    if ip is None:
        _print("Could not resolve the target.")
        return 2
    if not (args.target in ("localhost", "127.0.0.1", "::1") or is_private_ip(ip)):
        if not args.yes:
            _print("External target blocked. Use --yes only if you are explicitly authorized.")
            return 2
        logger.info("External target authorized via --yes: %s (%s)", args.target, ip)

    timeout = args.timeout
    if not math.isfinite(timeout) or timeout < 0.1:
        _print("Invalid timeout. Use a finite value of at least 0.1 seconds.")
        return 2
    concurrency = max(1, min(MAX_CONCURRENCY, args.concurrency))

    if args.banner:
        if args.port is None or not validate_port(args.port):
            _print("Invalid banner port. Choose a value from 1 to 65535.")
            return 2
        result = action_banner_grab(args.target, args.port, args.protocol, timeout)
        payload = {
            "target": args.target,
            "ip": ip,
            "duration": 0.0,
            "ports": {f"{args.protocol}/{args.port}": {"open": result["open"], "banner": result["banner"]}},
            "vuln_matches": [],
        }
        payload["vuln_matches"] = vuln_analysis_from_banners_txt(
            {f"{args.protocol}/{args.port}": result["banner"]}
        )
    elif args.full:
        payload = await action_full_scan(args.target, timeout, concurrency)
    else:
        payload = await action_quick_scan(args.target, timeout, concurrency)

    report_path, _ = create_scan_paths(args.target)
    if args.format in ("txt", "both", "all"):
        write_txt_report(payload, report_path)
    if args.format in ("json", "both", "all"):
        write_json_report(payload, report_path)
    if args.format in ("csv", "all"):
        write_csv_report(payload, report_path)
    if args.format in ("html", "all"):
        write_html_report(payload, report_path)
    _print(f"Scan report: {report_path.parent}")
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled.")
    logger.info("Starting SentinelScan — Author: %s", AUTHOR)
    try:
        if args.target or args.quick or args.full or args.banner:
            exit_code = asyncio.run(run_headless(args))
            raise SystemExit(exit_code)
        asyncio.run(main_cli_loop())
    except KeyboardInterrupt:
        _print("\nInterrupted by user.")
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        _print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()

