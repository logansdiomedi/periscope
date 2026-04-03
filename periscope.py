#!/usr/bin/env python3
"""
Periscope - Automated Reconnaissance & Discovery Tool
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

import requests

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
\033[36m
  ██████╗ ███████╗██████╗ ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ██╔══██╗██╔════╝██╔══██╗██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██████╔╝█████╗  ██████╔╝██║███████╗██║     ██║   ██║██████╔╝█████╗
  ██╔═══╝ ██╔══╝  ██╔══██╗██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
  ██║     ███████╗██║  ██║██║███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
\033[0m\033[90m
              surface everything. miss nothing.
              DNS recon → port scan → screenshots → API
\033[0m
"""

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

HTTPS_PORTS = {443, 8443, 444}
HTTP_PORTS  = {80, 8080, 8000, 8888, 81, 7001, 7002}
ALL_WEB_PORTS = HTTPS_PORTS | HTTP_PORTS

GOWITNESS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
BURP_UA      = GOWITNESS_UA

GOBUSTER_WORDLIST  = "/opt/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt"
GOBUSTER_EXTENSIONS = "php,asp,aspx,jsp,html,txt,json"

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def info(msg):  print(f"\033[34m[*]\033[0m {msg}")
def good(msg):  print(f"\033[32m[+]\033[0m {msg}")
def warn(msg):  print(f"\033[33m[!]\033[0m {msg}")
def err(msg):   print(f"\033[31m[-]\033[0m {msg}")
def section(msg): print(f"\n\033[35m{'─'*60}\033[0m\n\033[35m  {msg}\033[0m\n\033[35m{'─'*60}\033[0m")

# ─────────────────────────────────────────────────────────────────────────────
# DNS RECON — THC.ORG (integrated from thc.py)
# ─────────────────────────────────────────────────────────────────────────────

def _thc_fetch_page(url: str) -> Tuple[List[str], Optional[str]]:
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        lines = response.text.strip().split('\n')
        subdomains = []
        next_page = None
        for line in lines:
            if line.startswith(';;Next Page:'):
                next_page = ANSI_ESCAPE.sub('', line.split(';;Next Page:', 1)[1].strip())
            elif not line.startswith(';;') and line.strip():
                subdomains.append(ANSI_ESCAPE.sub('', line.strip()))
        return subdomains, next_page
    except Exception as e:
        warn(f"THC fetch error ({url}): {e}")
        return [], None


def enumerate_thc(domain: str) -> Set[str]:
    info(f"Querying ip.thc.org for {domain} ...")
    found: Set[str] = set()
    current_url = f"https://ip.thc.org/{domain}"
    page = 0
    while current_url:
        page += 1
        subs, next_url = _thc_fetch_page(current_url)
        found.update(subs)
        info(f"  THC page {page}: +{len(subs)} (total {len(found)})")
        current_url = next_url
    good(f"THC complete: {len(found)} subdomains for {domain}")
    return found

# ─────────────────────────────────────────────────────────────────────────────
# DNS RECON — SUBFINDER
# ─────────────────────────────────────────────────────────────────────────────

def enumerate_subfinder(domain: str) -> Set[str]:
    info(f"Running subfinder for {domain} ...")
    found: Set[str] = set()
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=300
        )
        for line in result.stdout.strip().splitlines():
            h = line.strip()
            if h:
                found.add(h)
        good(f"subfinder: {len(found)} subdomains for {domain}")
    except FileNotFoundError:
        warn("subfinder not found in PATH — skipping")
    except subprocess.TimeoutExpired:
        warn("subfinder timed out")
    except Exception as e:
        warn(f"subfinder error: {e}")
    return found

# ─────────────────────────────────────────────────────────────────────────────
# DNS RECON — CRT.SH
# ─────────────────────────────────────────────────────────────────────────────

def enumerate_crtsh(domain: str) -> Set[str]:
    info(f"Querying crt.sh for {domain} ...")
    found: Set[str] = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30,
            headers={"Accept": "application/json"}
        )
        resp.raise_for_status()
        data = resp.json()
        for entry in data:
            name = entry.get("name_value", "")
            for h in name.splitlines():
                h = h.strip().lstrip("*.")
                if h and domain in h:
                    found.add(h)
        good(f"crt.sh: {len(found)} subdomains for {domain}")
    except Exception as e:
        warn(f"crt.sh error: {e}")
    return found

# ─────────────────────────────────────────────────────────────────────────────
# DNS RESOLUTION
# ─────────────────────────────────────────────────────────────────────────────

def resolve_host(hostname: str) -> Tuple[str, Optional[str]]:
    try:
        ip = socket.gethostbyname(hostname)
        return hostname, ip
    except socket.gaierror:
        return hostname, None


def resolve_all(hostnames: Set[str], threads: int = 50) -> Tuple[Dict[str, str], Set[str]]:
    """Returns (resolved {host: ip}, unresolved set)."""
    resolved: Dict[str, str] = {}
    unresolved: Set[str] = set()
    info(f"Resolving {len(hostnames)} hostnames ({threads} threads) ...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve_host, h): h for h in hostnames}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            host, ip = fut.result()
            done += 1
            if ip:
                resolved[host] = ip
            else:
                unresolved.add(host)
            if done % 200 == 0:
                info(f"  Resolved {done}/{len(hostnames)}")
    good(f"Resolution done: {len(resolved)} live, {len(unresolved)} unresolved")
    return resolved, unresolved

# ─────────────────────────────────────────────────────────────────────────────
# NMAP
# ─────────────────────────────────────────────────────────────────────────────

def run_nmap(targets_file: str, output_file: str) -> Dict[str, Set[int]]:
    """Scan targets_file, return {ip: set(open_ports)}."""
    section("Port Scan (nmap)")
    port_list = ",".join(str(p) for p in sorted(ALL_WEB_PORTS))
    cmd = [
        "nmap", "-iL", targets_file,
        "--open", "-v",
        "-p", port_list,
        "-Pn", "--min-rate=5000",
        "-oN", output_file
    ]
    info(f"Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        err("nmap not found — cannot continue port scanning")
        return {}
    except subprocess.CalledProcessError as e:
        warn(f"nmap exited with code {e.returncode}")

    return _parse_nmap_output(output_file)


def _parse_nmap_output(nmap_file: str) -> Dict[str, Set[int]]:
    """Parse nmap normal output → {ip/host: set(open_ports)}."""
    results: Dict[str, Set[int]] = {}
    current_host = None
    try:
        with open(nmap_file) as f:
            for line in f:
                line = line.strip()
                # Match "Nmap scan report for hostname (ip)" or "Nmap scan report for ip"
                m = re.match(r"Nmap scan report for (.+)", line)
                if m:
                    target = m.group(1).strip()
                    # If format is "hostname (ip)" extract ip
                    ip_match = re.match(r".+\((\d+\.\d+\.\d+\.\d+)\)", target)
                    if ip_match:
                        current_host = ip_match.group(1)
                    else:
                        current_host = target
                    results.setdefault(current_host, set())
                    continue
                # Match open port lines: "80/tcp   open  http"
                port_match = re.match(r"(\d+)/tcp\s+open", line)
                if port_match and current_host:
                    results[current_host].add(int(port_match.group(1)))
    except FileNotFoundError:
        warn(f"nmap output file not found: {nmap_file}")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# URL BUILDING
# ─────────────────────────────────────────────────────────────────────────────

def port_to_url(host: str, port: int) -> str:
    if port in HTTPS_PORTS:
        scheme = "https"
        default = 443
    else:
        scheme = "http"
        default = 80
    if port == default:
        return f"{scheme}://{host}/"
    return f"{scheme}://{host}:{port}/"


def build_live_urls(
    resolved: Dict[str, str],
    nmap_results: Dict[str, Set[int]]
) -> Tuple[List[str], List[Dict]]:
    """
    Returns (url_list, enriched_records).
    enriched_records: [{url, hostname, ip, port, scheme}]
    """
    # Build reverse map ip → [hostnames]
    ip_to_hosts: Dict[str, List[str]] = {}
    for host, ip in resolved.items():
        ip_to_hosts.setdefault(ip, []).append(host)

    urls: List[str] = []
    records: List[Dict] = []
    seen_urls: Set[str] = set()

    for ip, open_ports in nmap_results.items():
        for port in sorted(open_ports):
            # Prefer hostnames; fall back to raw IP
            hostnames = ip_to_hosts.get(ip, [ip])
            for hostname in hostnames:
                url = port_to_url(hostname, port)
                if url not in seen_urls:
                    seen_urls.add(url)
                    urls.append(url)
                    scheme = "https" if port in HTTPS_PORTS else "http"
                    records.append({
                        "url": url,
                        "hostname": hostname,
                        "ip": ip,
                        "port": port,
                        "scheme": scheme
                    })

    return urls, records

# ─────────────────────────────────────────────────────────────────────────────
# GOWITNESS
# ─────────────────────────────────────────────────────────────────────────────

def run_gowitness(url_list_file: str, screenshot_dir: str):
    section("Screenshots (gowitness)")
    os.makedirs(screenshot_dir, exist_ok=True)

    # Try gowitness v3 syntax first, fall back to v2
    cmd_v3 = [
        "gowitness", "scan", "file",
        "-f", url_list_file,
        "--screenshot-path", screenshot_dir,
        "--user-agent", GOWITNESS_UA,
        "--disable-db"
    ]
    cmd_v2 = [
        "gowitness", "file",
        "-f", url_list_file,
        "--destination", screenshot_dir,
        "--user-agent", GOWITNESS_UA
    ]

    try:
        result = subprocess.run(["gowitness", "version"], capture_output=True, text=True, timeout=5)
        version_out = result.stdout + result.stderr
        if "v3" in version_out or "3." in version_out:
            cmd = cmd_v3
            info("Using gowitness v3 syntax")
        else:
            cmd = cmd_v2
            info("Using gowitness v2 syntax")
    except Exception:
        cmd = cmd_v2
        info("Could not detect gowitness version, using v2 syntax")

    info(f"Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
        good("gowitness complete")
    except FileNotFoundError:
        warn("gowitness not found — skipping screenshots")
    except subprocess.CalledProcessError as e:
        warn(f"gowitness exited with code {e.returncode}")

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT FILE GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def write_gobuster_commands(urls: List[str], out_file: str):
    lines = []
    for url in urls:
        lines.append(
            f"gobuster dir -u {url} -w {GOBUSTER_WORDLIST} "
            f"-t 10 --random-agent -k -x {GOBUSTER_EXTENSIONS}"
        )
    with open(out_file, "w") as f:
        f.write("\n".join(lines) + "\n")
    good(f"GoBuster commands → {out_file}")


def write_plain_results(
    domains: List[str],
    resolved: Dict[str, str],
    unresolved: Set[str],
    nmap_results: Dict[str, Set[int]],
    records: List[Dict],
    out_file: str
):
    sep = "=" * 70
    thin = "-" * 70

    lines = [
        sep,
        "  PERISCOPE RESULTS",
        f"  Targets: {', '.join(domains)}",
        sep,
        "",
        "[ LIVE TARGETS ]",
        thin,
    ]

    for rec in records:
        lines.append(f"  {rec['url']}")
        lines.append(f"    Hostname : {rec['hostname']}")
        lines.append(f"    IP       : {rec['ip']}")
        lines.append(f"    Port     : {rec['port']}")
        lines.append("")

    lines += [
        "[ RESOLVED HOSTS ]",
        thin,
    ]
    for host, ip in sorted(resolved.items()):
        lines.append(f"  {host:<50} {ip}")

    lines += [
        "",
        "[ POTENTIAL VHOSTS (unresolved) ]",
        thin,
    ]
    for h in sorted(unresolved):
        lines.append(f"  {h}")

    lines += [
        "",
        "[ OPEN PORTS BY IP ]",
        thin,
    ]
    for ip, ports in sorted(nmap_results.items()):
        lines.append(f"  {ip:<20} {', '.join(str(p) for p in sorted(ports))}")

    lines.append("")
    lines.append(sep)

    with open(out_file, "w") as f:
        f.write("\n".join(lines) + "\n")
    good(f"Plain results → {out_file}")

# ─────────────────────────────────────────────────────────────────────────────
# API SERVER
# ─────────────────────────────────────────────────────────────────────────────

# Shared state for the API — populated before server starts
_API_STATE: Dict = {
    "records": [],
    "vhosts": [],
    "resolved": {},
    "nmap": {},
    "domains": [],
}


def start_api(port: int):
    """Start Flask API server on localhost only."""
    try:
        from flask import Flask, jsonify, Response
    except ImportError:
        err("Flask not installed. Run: pip install flask")
        err("API will not be started.")
        return

    app = Flask(__name__)

    @app.route("/api/targets", methods=["GET"])
    def api_targets():
        return jsonify({
            "count": len(_API_STATE["records"]),
            "targets": _API_STATE["records"]
        })

    @app.route("/api/targets/plain", methods=["GET"])
    def api_targets_plain():
        urls = [r["url"] for r in _API_STATE["records"]]
        return Response("\n".join(urls) + "\n", mimetype="text/plain")

    @app.route("/api/targets/ips", methods=["GET"])
    def api_targets_ips():
        """Return targets by IP address only (no hostname)."""
        seen = set()
        ip_records = []
        for rec in _API_STATE["records"]:
            url = port_to_url(rec["ip"], rec["port"])
            if url not in seen:
                seen.add(url)
                ip_records.append({**rec, "url": url})
        return jsonify({"count": len(ip_records), "targets": ip_records})

    @app.route("/api/targets/hostnames", methods=["GET"])
    def api_targets_hostnames():
        """Return targets by hostname only."""
        hostname_records = [r for r in _API_STATE["records"] if r["hostname"] != r["ip"]]
        return jsonify({"count": len(hostname_records), "targets": hostname_records})

    @app.route("/api/vhosts", methods=["GET"])
    def api_vhosts():
        return jsonify({
            "count": len(_API_STATE["vhosts"]),
            "vhosts": _API_STATE["vhosts"]
        })

    @app.route("/api/status", methods=["GET"])
    def api_status():
        return jsonify({
            "domains": _API_STATE["domains"],
            "resolved_count": len(_API_STATE["resolved"]),
            "live_target_count": len(_API_STATE["records"]),
            "vhost_count": len(_API_STATE["vhosts"]),
            "ready": True
        })

    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)

    good(f"Periscope API listening on http://127.0.0.1:{port}")
    info("Press Ctrl+C to stop.")
    app.run(host="127.0.0.1", port=port, threaded=True)

# ─────────────────────────────────────────────────────────────────────────────
# LOAD PREVIOUS OUTPUT (--api-only)
# ─────────────────────────────────────────────────────────────────────────────

def load_previous_output(folder: str):
    """Load results from a previous Periscope run and populate _API_STATE."""
    info(f"Loading previous output from {folder} ...")

    live_urls_file = os.path.join(folder, "live-target-urls.txt")
    vhosts_file    = os.path.join(folder, "potential-vhosts.txt")
    resolved_file  = os.path.join(folder, "dns", "resolved-hosts.txt")
    nmap_file      = os.path.join(folder, "nmap", "nmap-results.txt")

    records = []
    if os.path.exists(live_urls_file):
        with open(live_urls_file) as f:
            for line in f:
                url = line.strip()
                if not url:
                    continue
                # Parse url back into components
                m = re.match(r"(https?)://([^/:]+)(?::(\d+))?/", url)
                if m:
                    scheme, hostname, port_str = m.group(1), m.group(2), m.group(3)
                    if port_str:
                        port = int(port_str)
                    else:
                        port = 443 if scheme == "https" else 80
                    try:
                        ip = socket.gethostbyname(hostname)
                    except Exception:
                        ip = hostname
                    records.append({
                        "url": url,
                        "hostname": hostname,
                        "ip": ip,
                        "port": port,
                        "scheme": scheme
                    })
    _API_STATE["records"] = records
    good(f"Loaded {len(records)} live targets")

    vhosts = []
    if os.path.exists(vhosts_file):
        with open(vhosts_file) as f:
            vhosts = [l.strip() for l in f if l.strip()]
    _API_STATE["vhosts"] = vhosts
    good(f"Loaded {len(vhosts)} potential vhosts")

    resolved = {}
    if os.path.exists(resolved_file):
        with open(resolved_file) as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    parts = line.rsplit(":", 1)
                    resolved[parts[0]] = parts[1]
    _API_STATE["resolved"] = resolved

    nmap = {}
    if os.path.exists(nmap_file):
        nmap = _parse_nmap_output(nmap_file)
    _API_STATE["nmap"] = nmap

    # Best-effort domain detection
    _API_STATE["domains"] = ["(loaded from previous run)"]

# ─────────────────────────────────────────────────────────────────────────────
# MAIN RECON PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def run_recon(domains: List[str], output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    dns_dir        = os.path.join(output_dir, "dns")
    nmap_dir       = os.path.join(output_dir, "nmap")
    screenshot_dir = os.path.join(output_dir, "screenshots")
    for d in [dns_dir, nmap_dir, screenshot_dir]:
        os.makedirs(d, exist_ok=True)

    # ── DNS RECON ───────────────────────────────────────────────────────────
    section("DNS Enumeration")
    all_hosts: Set[str] = set()

    for domain in domains:
        thc_hosts = enumerate_thc(domain)
        sf_hosts  = enumerate_subfinder(domain)
        crt_hosts = enumerate_crtsh(domain)

        # Save per-source for reference
        for name, hosts in [("thc", thc_hosts), ("subfinder", sf_hosts), ("crtsh", crt_hosts)]:
            src_file = os.path.join(dns_dir, f"{name}-{domain}.txt")
            with open(src_file, "w") as f:
                f.write("\n".join(sorted(hosts)) + "\n")

        combined = thc_hosts | sf_hosts | crt_hosts
        # Always include the root domain itself
        combined.add(domain)
        all_hosts.update(combined)

    good(f"Total unique hostnames across all sources: {len(all_hosts)}")
    with open(os.path.join(dns_dir, "all-subdomains.txt"), "w") as f:
        f.write("\n".join(sorted(all_hosts)) + "\n")

    # ── RESOLUTION ──────────────────────────────────────────────────────────
    section("Host Resolution")
    resolved, unresolved = resolve_all(all_hosts)

    resolved_file = os.path.join(dns_dir, "resolved-hosts.txt")
    with open(resolved_file, "w") as f:
        for host, ip in sorted(resolved.items()):
            f.write(f"{host}:{ip}\n")
    good(f"Resolved hosts → {resolved_file}")

    vhosts_file = os.path.join(output_dir, "potential-vhosts.txt")
    with open(vhosts_file, "w") as f:
        f.write("\n".join(sorted(unresolved)) + "\n")
    good(f"Potential vhosts (unresolved) → {vhosts_file}")

    # ── NMAP ────────────────────────────────────────────────────────────────
    # Write unique IPs to scan file
    unique_ips = sorted(set(resolved.values()))
    targets_file = os.path.join(output_dir, "generated-targets-list.txt")
    with open(targets_file, "w") as f:
        f.write("\n".join(unique_ips) + "\n")
    good(f"Nmap targets ({len(unique_ips)} IPs) → {targets_file}")

    nmap_output = os.path.join(nmap_dir, "nmap-results.txt")
    nmap_results = run_nmap(targets_file, nmap_output)

    if not nmap_results:
        warn("No nmap results — live URL list will be empty")

    # ── LIVE URLS ───────────────────────────────────────────────────────────
    section("Building Live Target List")
    urls, records = build_live_urls(resolved, nmap_results)

    live_urls_file = os.path.join(output_dir, "live-target-urls.txt")
    with open(live_urls_file, "w") as f:
        f.write("\n".join(urls) + "\n")
    good(f"Live URLs ({len(urls)}) → {live_urls_file}")

    # ── GOWITNESS ───────────────────────────────────────────────────────────
    if urls:
        run_gowitness(live_urls_file, screenshot_dir)
    else:
        warn("No live URLs found — skipping gowitness")

    # ── GOBUSTER COMMANDS ───────────────────────────────────────────────────
    dirbusting_file = os.path.join(output_dir, "dirbusting.txt")
    write_gobuster_commands(urls, dirbusting_file)

    # ── PLAIN TEXT RESULTS ──────────────────────────────────────────────────
    results_file = os.path.join(output_dir, "periscope-results.txt")
    write_plain_results(domains, resolved, unresolved, nmap_results, records, results_file)

    # ── POPULATE API STATE ──────────────────────────────────────────────────
    _API_STATE["records"]  = records
    _API_STATE["vhosts"]   = sorted(unresolved)
    _API_STATE["resolved"] = resolved
    _API_STATE["nmap"]     = nmap_results
    _API_STATE["domains"]  = domains

    section("Recon Complete")
    good(f"Output folder : {output_dir}")
    good(f"Live targets  : {len(urls)}")
    good(f"Vhosts (pot.) : {len(unresolved)}")
    good(f"Screenshots   : {screenshot_dir}")

    return records, unresolved

# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_domains(raw: str) -> List[str]:
    """Accept: single domain, comma-separated list, or path to a file."""
    if os.path.isfile(raw):
        with open(raw) as f:
            return [l.strip() for l in f if l.strip()]
    return [d.strip() for d in raw.split(",") if d.strip()]


def parse_args():
    p = argparse.ArgumentParser(
        description="Periscope — automated recon & Burp integration",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("-d", "--domains",
                   help="Domain(s): single, comma-separated, or path to file")
    p.add_argument("-o", "--output",
                   help="Output folder")
    p.add_argument("--burp-api", action="store_true",
                   help="Start the Periscope API after recon")
    p.add_argument("--api-port", type=int, default=13337,
                   help="API port (default: 13337)")
    p.add_argument("--api-only", metavar="PREV_OUTPUT_DIR",
                   help="Skip recon, only expose the API from a previous run")
    return p.parse_args()

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(BANNER.replace("\\033", "\033"))

    args = parse_args()

    # ── API-ONLY MODE ────────────────────────────────────────────────────────
    if args.api_only:
        if not os.path.isdir(args.api_only):
            err(f"Directory not found: {args.api_only}")
            sys.exit(1)
        load_previous_output(args.api_only)
        start_api(args.api_port)
        return

    # ── NORMAL MODE ──────────────────────────────────────────────────────────
    if not args.domains:
        err("-d / --domains is required unless using --api-only")
        sys.exit(1)
    if not args.output:
        err("-o / --output is required unless using --api-only")
        sys.exit(1)

    domains = parse_domains(args.domains)
    if not domains:
        err("No domains parsed from input")
        sys.exit(1)

    info(f"Targets: {', '.join(domains)}")
    info(f"Output : {args.output}")

    run_recon(domains, args.output)

    if args.burp_api:
        start_api(args.api_port)
    else:
        info("Tip: re-run with --burp-api to expose the API for Burp extension")
        info(f"  or: python3 periscope.py --api-only {args.output} --burp-api")


if __name__ == "__main__":
    main()
