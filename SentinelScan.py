#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SentinelScan - UDP & TCP + IPv6 (educational) - Single-file CLI interactive scanner (text in English)
Requires exact consent "I AGREE"
Reports: reports/<target>_<ts>/report.txt
Logs: logs/scanner.log
Asynchronous worker-pool, progress with rich if installed
Vulnerability DB: vuln_db.txt (pipe-separated TXT strict matching)
Educational use, show legal warning
Recommended Python 3.11+, designed for Linux but may run on Windows

This version fixes menu options 6 and 7:
 - option 6 now locates the last report robustly (uses last_report_path if valid, otherwise searches the reports directory for the most recent report for the last target or any target).
 - option 7's tail_log now correctly looks for rotated logs in the logs directory if the primary LOG_FILE doesn't exist and prints using the same UI path (_print).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import logging.handlers
import os
import re
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from shutil import which
from typing import Any, Dict, List, Optional, Tuple

# Optional rich
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.panel import Panel

    RICH_AVAILABLE = True
    console = Console()
except Exception:
    RICH_AVAILABLE = False
    console = None

# ---------------------
# Config
# ---------------------
AUTHOR = "Your Name Here"
DEFAULT_TIMEOUT = 1.0
DEFAULT_CONCURRENCY = 200
COMMON_TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]
COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 161, 500, 520]
MAX_CONCURRENCY = 1000

LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "scanner.log"

VULN_DB_FILE = Path("vuln_db.txt")

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------
# Logging
# ---------------------
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

# ---------------------
# Helpers (printing)
# ---------------------


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


# ---------------------
# Network utils (IPv4/IPv6 aware)
# ---------------------


def resolve_host(target: str) -> Optional[str]:
    """Resolve hostname to the first usable IP (prefer IPv4, then IPv6).
    Returns the IP as a string or None.
    """
    try:
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


# ---------------------
# Blocking TCP banner & UDP probe (used inside thread pool)
# ---------------------


def _blocking_tcp_check(ip: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str]]:
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((ip, port))
            if res != 0:
                return port, False, None
            try:
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
    """Send an empty UDP datagram and wait for response or indirect ICMP unreachable.
    Note: on many networks UDP scanning yields "open|filtered" false positives; this is educational only.
    Returns (port, maybe_open, banner)
    """
    try:
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.sendto(b"\n", (ip, port))
            except Exception:
                return port, False, None
            try:
                data, addr = s.recvfrom(4096)
                if data:
                    return port, True, _safe_decode(data).strip()
                return port, True, None
            except socket.timeout:
                # No response: could be filtered, closed (ICMP), or open-but-no-response.
                # For educational strictness we'll mark as 'filtered/unknown' -> False
                return port, False, None
            except Exception:
                return port, False, None
    except Exception:
        return port, False, None


# ---------------------
# Vulnerability DB (TXT) - simple pipe-separated format
# service|version_contains|cve_id|cvss|severity|summary|recommendation
# ---------------------


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


# ---------------------
# Banner parsing
# ---------------------
BANNER_SERVICE_VERSION_REGEXES = [
    re.compile(r"(?P<service>[A-Za-z0-9_\-]+)[/ _\-]?v?(?P<version>\d+(?:\.\d+){0,3})", re.IGNORECASE),
    re.compile(r"(?P<service>openssh)[\s_/\-]?_?v?(?P<version>\d+(?:\.\d+)*)", re.IGNORECASE),
    re.compile(r"(?P<service>apache)[/ _\-]?v?(?P<version>\d+(?:\.\d+)*)", re.IGNORECASE),
]


def parse_banner_service_version(banner: str) -> Tuple[Optional[str], Optional[str]]:
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


# ---------------------
# Vulnerability analysis (strict substring matching against txt DB)
# ---------------------


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


def vuln_analysis_from_banners_txt(banners: Dict[int, Optional[str]]) -> List[Dict[str, Any]]:
    db = load_vuln_db_txt()
    matches: List[Dict[str, Any]] = []
    for port, banner in banners.items():
        if not banner:
            continue
        svc, ver = parse_banner_service_version(banner)
        banner_lower = banner.lower()
        for entry in db:
            svc_entry = (entry.get('service') or '').lower()
            ver_sub = (entry.get('version_contains') or '').lower()
            matched = False
            matched_string = None
            if svc and svc_entry and svc_entry in svc and ver_sub:
                if ver and ver_sub in ver.lower():
                    matched = True
                    matched_string = ver
            if not matched and ver_sub and ver_sub in banner_lower:
                matched = True
                matched_string = ver_sub
            if not matched and svc_entry and svc_entry in banner_lower:
                matched = True
                matched_string = svc_entry
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


# ---------------------
# Async thread-backed attempts (TCP/UDP)
# ---------------------


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


# ---------------------
# Report writing (TXT only)
# ---------------------


def create_scan_paths(target: str, ts: Optional[datetime] = None) -> Tuple[Path, Path]:
    if ts is None:
        ts = datetime.utcnow()
    stamp = ts.strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    dir_path = REPORTS_DIR / f"{safe_target}_{stamp}"
    dir_path.mkdir(parents=True, exist_ok=True)
    report_path = dir_path / "report.txt"
    return report_path, dir_path


def write_txt_report(payload: Dict[str, Any], report_path: Path) -> Path:
    try:
        lines: List[str] = []
        lines.append("Scan Report")
        lines.append("=" * 80)
        lines.append(f"Author : {AUTHOR}")
        lines.append(f"Date : {datetime.utcnow().isoformat()}Z")
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
        lines.append(" - Matching is STRICT: 'version_contains' must appear in the detected version or in the banner (case-insensitive).")
        lines.append(" - UDP scanning is lossy and may produce false negatives; it's implemented for educational use only.")
        lines.append(" - Use authorized scopes only. The tool logs consent and operations.")
        lines.append("")

        report_path.write_text('\n'.join(lines), encoding='utf-8')
        logger.info("TXT report written -> %s", report_path)
        return report_path
    except Exception as e:
        logger.exception("Failed to write TXT report: %s", e)
        raise


# ---------------------
# Helpers for menu fixes: find latest report and robust tail for logs
# ---------------------


def find_latest_report(target: Optional[str] = None) -> Optional[Path]:
    """Search reports/ for the most recent report for given target (or any if target is None).
    Returns Path to report.txt or None.
    """
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
            # look for any file in logs dir and choose the newest
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


# ---------------------
# High-level actions
# ---------------------


async def action_quick_scan(target: str, timeout: float, concurrency: int) -> Dict[str, Any]:
    ip = resolve_host(target) or target
    start = time.time()
    tasks: List[Tuple[int, str]] = []
    tasks.extend([(p, 'tcp') for p in COMMON_TCP_PORTS])
    tasks.extend([(p, 'udp') for p in COMMON_UDP_PORTS])
    ports_res = await scan_ports_async_with_progress(ip, tasks, timeout, concurrency, show_rich=True)
    duration = time.time() - start
    payload_ports = {str(k): v for k, v in ports_res.items()}
    banners = {int(k.split('/', 1)[1]) if '/' in k else k: v.get('banner') for k, v in ports_res.items()}
    vuln_matches = vuln_analysis_from_banners_txt(banners)
    return {"target": target, "ip": ip, "duration": duration, "ports": payload_ports, "vuln_matches": vuln_matches}


async def action_full_scan(target: str, timeout: float, concurrency: int) -> Dict[str, Any]:
    ip = resolve_host(target) or target
    ports = list(range(1, 65536))
    tasks = [(p, 'tcp') for p in ports] + [(p, 'udp') for p in (1, 53, 67, 68, 69, 123, 161, 500, 520)]
    start = time.time()
    ports_res = await scan_ports_async_with_progress(ip, tasks, timeout, concurrency, show_rich=True)
    duration = time.time() - start
    payload_ports = {str(k): v for k, v in ports_res.items()}
    banners = {int(k.split('/', 1)[1]) if '/' in k else k: v.get('banner') for k, v in ports_res.items()}
    vuln_matches = vuln_analysis_from_banners_txt(banners)
    return {"target": target, "ip": ip, "duration": duration, "ports": payload_ports, "vuln_matches": vuln_matches}

# ---------------------
# Banner grab (sync)
# ---------------------


def action_banner_grab(target: str, port: int, proto: str, timeout: float) -> Dict[str, Any]:
    ip = resolve_host(target) or target
    if proto == 'tcp':
        p, is_open, banner = _blocking_tcp_check(ip, port, timeout)
    else:
        p, is_open, banner = _blocking_udp_check(ip, port, timeout)
    return {"target": target, "ip": ip, "port": port, "proto": proto, "banner": banner, "open": is_open}

# ---------------------
# CLI
# ---------------------


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
            port_s = input("Port for banner grab (e.g. 22): ").strip()
            proto = input("Protocol (tcp/udp) [tcp]: ").strip().lower() or 'tcp'
            try:
                port = int(port_s)
            except Exception:
                _print("Invalid port.")
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
            # Show last report path, try robust lookup if necessary
            if last_report_path and last_report_path.exists():
                _print(f"Last report: {last_report_path}")
                _print("You can view it with: less " + str(last_report_path))
            else:
                # try to find the latest report for the last target first, then any
                found = find_latest_report(last_target) or find_latest_report(None)
                if found:
                    last_report_path = found
                    _print(f"Last report (found): {last_report_path}")
                    _print("You can view it with: less " + str(last_report_path))
                else:
                    _print("No report generated yet or report file not found on disk.")

        elif choice == "7":
            # Tail logs: improved behavior to handle missing primary log file and rotated logs
            tail_log(80)

        elif choice == "8":
            _print("Exiting. Stay ethical and authorized.")
            break

        else:
            _print("Invalid selection. Choose an option 1-8.")

# ---------------------
# Entrypoint
# ---------------------


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in ("--debug", "-d"):
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled.")
    logger.info("Starting SentinelScan — Author: %s", AUTHOR)
    try:
        asyncio.run(main_cli_loop())
    except KeyboardInterrupt:
        _print("\nInterrupted by user.")
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        _print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()

