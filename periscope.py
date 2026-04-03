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
import socket
import subprocess
import sys
import threading
from typing import Dict, List, Optional, Set, Tuple

import requests

# -----------------------------------------------------------------------------
# BANNER
# -----------------------------------------------------------------------------

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
\033[36mv1.0 - By \033[31mLogan Diomedi\033[36m - Depth Security (www.depthsecurity.com)\033[0m
"""

# -----------------------------------------------------------------------------
# CONSTANTS
# -----------------------------------------------------------------------------

HTTPS_PORTS  = {443, 8443, 444, 4443, 9443}
HTTP_PORTS   = {80, 8080, 8000, 8888, 81, 7001, 7002}
ALL_WEB_PORTS = HTTPS_PORTS | HTTP_PORTS

DEFAULT_PORTS_STR = "80,443,8443,8080,8888,444,81,8000,7001,7002"

GOWITNESS_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

GOBUSTER_WORDLIST   = "/opt/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt"
GOBUSTER_EXTENSIONS = "php,asp,aspx,jsp,html,txt,json"

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# -----------------------------------------------------------------------------
# LOGGING HELPERS
# -----------------------------------------------------------------------------

def info(msg):    print(f"\033[34m[*]\033[0m {msg}")
def good(msg):    print(f"\033[32m[+]\033[0m {msg}")
def warn(msg):    print(f"\033[33m[!]\033[0m {msg}")
def err(msg):     print(f"\033[31m[-]\033[0m {msg}")
def section(msg): print(f"\n\033[35m{'='*60}\033[0m\n\033[35m  {msg}\033[0m\n\033[35m{'='*60}\033[0m")

# -----------------------------------------------------------------------------
# DNS RECON — THC.ORG (integrated from thc.py)
# -----------------------------------------------------------------------------

def _thc_fetch_page(url: str) -> Tuple[List[str], Optional[str]]:
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        lines = response.text.strip().split('\n')
        subdomains, next_page = [], None
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

# -----------------------------------------------------------------------------
# DNS RECON — SUBFINDER
# -----------------------------------------------------------------------------

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

# -----------------------------------------------------------------------------
# DNS RECON — CRT.SH
# -----------------------------------------------------------------------------

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

# -----------------------------------------------------------------------------
# DNS RESOLUTION
# -----------------------------------------------------------------------------

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

# -----------------------------------------------------------------------------
# IP RANGE INGESTION
# -----------------------------------------------------------------------------

def parse_ip_file(filepath: str) -> Tuple[List[ipaddress.IPv4Network], Set[str], List[str]]:
    """
    Parse a file containing IP ranges. Accepted formats:
      - CIDR:       10.0.0.0/24
      - Dash range: 10.0.0.1-254   (last-octet shorthand)
                    10.0.0.1-10.0.0.254  (full range)
      - Single IP:  10.0.0.1

    Returns:
      networks       - IPv4Network list (CIDR entries)
      individual_ips - Set of expanded individual IP strings
      nmap_targets   - Lines to write to the nmap targets file
    """
    networks: List[ipaddress.IPv4Network] = []
    individual_ips: Set[str] = set()
    nmap_targets: List[str] = []

    with open(filepath) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue

            if '/' in line:
                try:
                    net = ipaddress.IPv4Network(line, strict=False)
                    networks.append(net)
                    nmap_targets.append(str(net))
                except ValueError:
                    warn(f"Invalid CIDR: {line}")

            elif '-' in line:
                parts = line.split('-', 1)
                start_str = parts[0].strip()
                end_str   = parts[1].strip()
                if '.' not in end_str:
                    prefix  = '.'.join(start_str.split('.')[:3])
                    end_str = f"{prefix}.{end_str}"
                try:
                    start_int = int(ipaddress.IPv4Address(start_str))
                    end_int   = int(ipaddress.IPv4Address(end_str))
                    count = end_int - start_int + 1
                    if count > 65536:
                        warn(f"Range too large to expand ({count} IPs): {line} — add as CIDR block instead")
                        nmap_targets.append(line)
                    else:
                        for ip_int in range(start_int, end_int + 1):
                            individual_ips.add(str(ipaddress.IPv4Address(ip_int)))
                        nmap_targets.append(line)  # nmap understands dash ranges
                except ValueError as e:
                    warn(f"Invalid IP range '{line}': {e}")

            else:
                try:
                    ipaddress.IPv4Address(line)
                    individual_ips.add(line)
                    nmap_targets.append(line)
                except ValueError:
                    warn(f"Invalid IP: {line}")

    good(f"Parsed {len(networks)} CIDR networks, {len(individual_ips)} individual IPs from {filepath}")
    return networks, individual_ips, nmap_targets


def ip_in_networks(
    ip: str,
    networks: List[ipaddress.IPv4Network],
    individual_ips: Set[str]
) -> bool:
    """Return True if ip falls within any of the provided networks or individual IPs."""
    if ip in individual_ips:
        return True
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False

# -----------------------------------------------------------------------------
# PORT PROBING (--no-nmap fallback)
# -----------------------------------------------------------------------------

def probe_ports(
    targets: Set[str],
    scan_ports: Set[int],
    threads: int = 100,
    timeout: float = 2.0
) -> Dict[str, Set[int]]:
    """
    Socket-based port prober used when --no-nmap is set.
    Tries every (target, port) combination with a 2-second TCP connect timeout.
    Returns {ip_or_host: set(open_ports)}.
    """
    section("Port Probe (no-nmap mode)")
    results: Dict[str, Set[int]] = {}
    work = [(t, p) for t in targets for p in scan_ports]
    info(f"Probing {len(targets)} targets x {len(scan_ports)} ports "
         f"= {len(work)} checks ({threads} threads, {timeout}s timeout)")

    def check(target: str, port: int) -> tuple:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            connected = sock.connect_ex((target, port)) == 0
            sock.close()
            return target, port, connected
        except Exception:
            return target, port, False

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check, t, p): (t, p) for t, p in work}
        for fut in concurrent.futures.as_completed(futures):
            target, port, is_open = fut.result()
            done += 1
            if is_open:
                results.setdefault(target, set()).add(port)
            if done % 500 == 0:
                info(f"  Probed {done}/{len(work)}, {len(results)} hosts with open ports so far")

    live = sum(len(v) for v in results.values())
    good(f"Probe complete: {live} open port(s) across {len(results)} host(s)")
    return results


# -----------------------------------------------------------------------------
# NMAP
# -----------------------------------------------------------------------------

def run_nmap(targets_file: str, output_file: str, scan_ports: Set[int]) -> Dict[str, Set[int]]:
    """Scan targets_file, return {ip: set(open_ports)}."""
    section("Port Scan (nmap)")
    port_list = ",".join(str(p) for p in sorted(scan_ports))
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
    """Parse nmap normal output → {ip: set(open_ports)}."""
    results: Dict[str, Set[int]] = {}
    current_host = None
    try:
        with open(nmap_file) as f:
            for line in f:
                line = line.strip()
                m = re.match(r"Nmap scan report for (.+)", line)
                if m:
                    target = m.group(1).strip()
                    ip_match = re.match(r".+\((\d+\.\d+\.\d+\.\d+)\)", target)
                    current_host = ip_match.group(1) if ip_match else target
                    results.setdefault(current_host, set())
                    continue
                port_match = re.match(r"(\d+)/tcp\s+open", line)
                if port_match and current_host:
                    results[current_host].add(int(port_match.group(1)))
    except FileNotFoundError:
        warn(f"nmap output file not found: {nmap_file}")
    return results

# -----------------------------------------------------------------------------
# URL BUILDING
# -----------------------------------------------------------------------------

def port_to_url(host: str, port: int) -> str:
    if port in HTTPS_PORTS:
        scheme, default = "https", 443
    else:
        scheme, default = "http", 80
    if port == default:
        return f"{scheme}://{host}/"
    return f"{scheme}://{host}:{port}/"


def build_live_urls(
    resolved: Dict[str, str],
    nmap_results: Dict[str, Set[int]],
) -> Tuple[List[str], List[Dict]]:
    """
    Returns (url_list, enriched_records).
    For IPs that have DNS hostnames, one record per hostname per port.
    For IP-only entries (no DNS hostname), one record per IP per port.
    """
    ip_to_hosts: Dict[str, List[str]] = {}
    for host, ip in resolved.items():
        ip_to_hosts.setdefault(ip, []).append(host)

    urls: List[str] = []
    records: List[Dict] = []
    seen_urls: Set[str] = set()

    for ip, open_ports in nmap_results.items():
        for port in sorted(open_ports):
            hostnames = ip_to_hosts.get(ip)
            if hostnames:
                # Prefer DNS hostnames
                for hostname in sorted(hostnames):
                    url = port_to_url(hostname, port)
                    if url not in seen_urls:
                        seen_urls.add(url)
                        urls.append(url)
                        records.append({
                            "url":      url,
                            "hostname": hostname,
                            "ip":       ip,
                            "port":     port,
                            "scheme":   "https" if port in HTTPS_PORTS else "http"
                        })
            else:
                # IP-only (ingested directly, no DNS resolution)
                url = port_to_url(ip, port)
                if url not in seen_urls:
                    seen_urls.add(url)
                    urls.append(url)
                    records.append({
                        "url":      url,
                        "hostname": ip,
                        "ip":       ip,
                        "port":     port,
                        "scheme":   "https" if port in HTTPS_PORTS else "http"
                    })

    return urls, records

# -----------------------------------------------------------------------------
# GOWITNESS
# -----------------------------------------------------------------------------

def run_gowitness(url_list_file: str, screenshot_dir: str):
    section("Screenshots (gowitness)")
    os.makedirs(screenshot_dir, exist_ok=True)

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
        cmd = cmd_v3 if ("v3" in version_out or "3." in version_out) else cmd_v2
        info(f"Using gowitness {'v3' if cmd is cmd_v3 else 'v2'} syntax")
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

# -----------------------------------------------------------------------------
# BURP SCOPE FILE GENERATION
# -----------------------------------------------------------------------------

def generate_burp_scope(
    input_domains: List[str],
    resolved: Dict[str, str],
    user_networks: List[ipaddress.IPv4Network],
    user_range_ips: Set[str],
    user_nmap_targets: List[str],
    scope_flags: Optional[str],
    has_domains: bool,
    has_user_ips: bool,
    out_file: str
):
    """
    Generate a plain-text Burp Suite scope file for import via
    Target > Scope > Load (with "Use advanced scope control" enabled).

    Each line is a host pattern loaded into the Host/IP range field:
      - Domain wildcards use regex:  ^(.+\\.)?example\\.com$
      - Individual IPs:              10.0.0.1
      - CIDR ranges:                 10.0.0.0/24

    Scoping logic:
      only_domains  -> wildcard regex per input domain + all IPs from DNS resolution
      both          -> wildcard regex per input domain + user-supplied CIDR/IP ranges
      only_ips      -> user CIDR/IP ranges + DNS hostnames resolving INTO those ranges
      lax-scoping   -> adds all discovered hostnames regardless of source
    """
    lax          = scope_flags is not None and "lax-scoping" in scope_flags
    only_domains = has_domains and not has_user_ips
    only_ips     = has_user_ips and not has_domains

    seen: Set[str] = set()
    items: List[str] = []

    def add(entry: str):
        if entry not in seen:
            seen.add(entry)
            items.append(entry)

    def domain_regex(domain: str) -> str:
        return "^(.+\\.)?{}$".format(re.escape(domain))

    if only_domains or (lax and not has_user_ips):
        for d in input_domains:
            add(domain_regex(d))
        for ip in sorted(set(resolved.values())):
            add(ip)

    elif has_domains and has_user_ips:
        for d in input_domains:
            add(domain_regex(d))
        for t in user_nmap_targets:
            add(t)

    elif only_ips:
        for t in user_nmap_targets:
            add(t)
        for hostname, ip in sorted(resolved.items()):
            if lax or ip_in_networks(ip, user_networks, user_range_ips):
                add(domain_regex(hostname))

    with open(out_file, 'w') as f:
        f.write('\n'.join(items) + '\n')

    good(f"Burp scope file ({len(items)} entries) -> {out_file}")
    info("Import via: Target > Scope > Load  (advanced scope control must be enabled)")

# -----------------------------------------------------------------------------
# OUTPUT FILE GENERATION
# -----------------------------------------------------------------------------

def write_gobuster_commands(urls: List[str], out_file: str):
    lines = [
        f"gobuster dir -u {url} -w {GOBUSTER_WORDLIST} "
        f"-t 10 --random-agent -k -x {GOBUSTER_EXTENSIONS}"
        for url in urls
    ]
    with open(out_file, "w") as f:
        f.write("\n".join(lines) + "\n")
    good(f"GoBuster commands -> {out_file}")


def write_plain_results(
    domains: List[str],
    resolved: Dict[str, str],
    unresolved: Set[str],
    nmap_results: Dict[str, Set[int]],
    records: List[Dict],
    out_file: str
):
    sep  = "=" * 70
    thin = "-" * 70

    lines = [
        sep,
        "  PERISCOPE RESULTS",
        f"  Targets: {', '.join(domains)}",
        sep, "",
        "[ LIVE TARGETS ]", thin,
    ]
    for rec in records:
        lines += [
            f"  {rec['url']}",
            f"    Hostname : {rec['hostname']}",
            f"    IP       : {rec['ip']}",
            f"    Port     : {rec['port']}",
            "",
        ]

    lines += ["[ RESOLVED HOSTS ]", thin]
    for host, ip in sorted(resolved.items()):
        lines.append(f"  {host:<50} {ip}")

    lines += ["", "[ POTENTIAL VHOSTS (unresolved) ]", thin]
    for h in sorted(unresolved):
        lines.append(f"  {h}")

    lines += ["", "[ OPEN PORTS BY IP ]", thin]
    for ip, ports in sorted(nmap_results.items()):
        lines.append(f"  {ip:<20} {', '.join(str(p) for p in sorted(ports))}")

    lines += ["", sep]

    with open(out_file, "w") as f:
        f.write("\n".join(lines) + "\n")
    good(f"Plain results -> {out_file}")

# -----------------------------------------------------------------------------
# API SERVER
# -----------------------------------------------------------------------------

_API_STATE: Dict = {
    "records":  [],
    "vhosts":   [],
    "resolved": {},
    "nmap":     {},
    "domains":  [],
}


def start_api(port: int):
    """Start Flask API server on localhost only."""
    try:
        from flask import Flask, jsonify, Response
    except ImportError:
        err("Flask not installed. Run: pip install flask")
        return

    app = Flask(__name__)

    @app.route("/api/targets", methods=["GET"])
    def api_targets():
        return jsonify({"count": len(_API_STATE["records"]), "targets": _API_STATE["records"]})

    @app.route("/api/targets/plain", methods=["GET"])
    def api_targets_plain():
        urls = [r["url"] for r in _API_STATE["records"]]
        return Response("\n".join(urls) + "\n", mimetype="text/plain")

    @app.route("/api/targets/ips", methods=["GET"])
    def api_targets_ips():
        seen, ip_records = set(), []
        for rec in _API_STATE["records"]:
            url = port_to_url(rec["ip"], rec["port"])
            if url not in seen:
                seen.add(url)
                ip_records.append({**rec, "url": url})
        return jsonify({"count": len(ip_records), "targets": ip_records})

    @app.route("/api/targets/hostnames", methods=["GET"])
    def api_targets_hostnames():
        hostname_records = [r for r in _API_STATE["records"] if r["hostname"] != r["ip"]]
        return jsonify({"count": len(hostname_records), "targets": hostname_records})

    @app.route("/api/vhosts", methods=["GET"])
    def api_vhosts():
        return jsonify({"count": len(_API_STATE["vhosts"]), "vhosts": _API_STATE["vhosts"]})

    @app.route("/api/status", methods=["GET"])
    def api_status():
        return jsonify({
            "domains":           _API_STATE["domains"],
            "resolved_count":    len(_API_STATE["resolved"]),
            "live_target_count": len(_API_STATE["records"]),
            "vhost_count":       len(_API_STATE["vhosts"]),
            "ready":             True
        })

    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    good(f"Periscope API listening on http://127.0.0.1:{port}")
    info("Press Ctrl+C to stop.")
    app.run(host="127.0.0.1", port=port, threaded=True)

# -----------------------------------------------------------------------------
# LOAD PREVIOUS OUTPUT (--api-only)
# -----------------------------------------------------------------------------

def load_previous_output(folder: str):
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
                m = re.match(r"(https?)://([^/:]+)(?::(\d+))?/", url)
                if m:
                    scheme, hostname, port_str = m.group(1), m.group(2), m.group(3)
                    port = int(port_str) if port_str else (443 if scheme == "https" else 80)
                    try:
                        ip = socket.gethostbyname(hostname)
                    except Exception:
                        ip = hostname
                    records.append({
                        "url": url, "hostname": hostname,
                        "ip": ip, "port": port, "scheme": scheme
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

    _API_STATE["domains"] = ["(loaded from previous run)"]
    return resolved

# -----------------------------------------------------------------------------
# MAIN RECON PIPELINE
# -----------------------------------------------------------------------------

def run_recon(
    domains: List[str],
    output_dir: str,
    scan_ports: Set[int],
    ingest_ips_file: Optional[str]   = None,
    ingest_only_by_ip: Optional[str] = None,
    generate_scope: Optional[str]    = None,
    no_nmap: bool                    = False,
):
    os.makedirs(output_dir, exist_ok=True)
    dns_dir        = os.path.join(output_dir, "dns")
    nmap_dir       = os.path.join(output_dir, "nmap")
    screenshot_dir = os.path.join(output_dir, "screenshots")
    for d in [dns_dir, nmap_dir, screenshot_dir]:
        os.makedirs(d, exist_ok=True)

    # -- Parse user-supplied IP ranges ----------------------------------------
    user_networks:      List[ipaddress.IPv4Network] = []
    user_range_ips:     Set[str]  = set()
    user_nmap_targets:  List[str] = []
    has_user_ips = False

    ip_file = ingest_only_by_ip or ingest_ips_file
    if ip_file:
        if not os.path.isfile(ip_file):
            err(f"IP file not found: {ip_file}")
            sys.exit(1)
        user_networks, user_range_ips, user_nmap_targets = parse_ip_file(ip_file)
        has_user_ips = True

    # -- DNS RECON (skipped if --ingest-only-by-ip) ---------------------------
    resolved: Dict[str, str] = {}
    unresolved: Set[str]     = set()
    has_domains = bool(domains)

    if not ingest_only_by_ip and domains:
        section("DNS Enumeration")
        all_hosts: Set[str] = set()

        for domain in domains:
            thc_hosts = enumerate_thc(domain)
            sf_hosts  = enumerate_subfinder(domain)
            crt_hosts = enumerate_crtsh(domain)

            for name, hosts in [("thc", thc_hosts), ("subfinder", sf_hosts), ("crtsh", crt_hosts)]:
                src_file = os.path.join(dns_dir, f"{name}-{domain}.txt")
                with open(src_file, "w") as f:
                    f.write("\n".join(sorted(hosts)) + "\n")

            combined = thc_hosts | sf_hosts | crt_hosts
            combined.add(domain)
            all_hosts.update(combined)

        good(f"Total unique hostnames across all sources: {len(all_hosts)}")
        with open(os.path.join(dns_dir, "all-subdomains.txt"), "w") as f:
            f.write("\n".join(sorted(all_hosts)) + "\n")

        section("Host Resolution")
        resolved, unresolved = resolve_all(all_hosts)

        resolved_file = os.path.join(dns_dir, "resolved-hosts.txt")
        with open(resolved_file, "w") as f:
            for host, ip in sorted(resolved.items()):
                f.write(f"{host}:{ip}\n")
        good(f"Resolved hosts -> {resolved_file}")

        vhosts_file = os.path.join(output_dir, "potential-vhosts.txt")
        with open(vhosts_file, "w") as f:
            f.write("\n".join(sorted(unresolved)) + "\n")
        good(f"Potential vhosts (unresolved) -> {vhosts_file}")

    # -- Build nmap targets file ----------------------------------------------
    # DNS IPs + user-supplied IPs/CIDRs, deduplicated
    dns_ips = sorted(set(resolved.values()))

    targets_lines: List[str] = []
    seen_nmap: Set[str] = set()

    for ip in dns_ips:
        if ip not in seen_nmap:
            seen_nmap.add(ip)
            targets_lines.append(ip)

    for t in user_nmap_targets:
        if t not in seen_nmap:
            seen_nmap.add(t)
            targets_lines.append(t)

    targets_file = os.path.join(output_dir, "generated-targets-list.txt")
    with open(targets_file, "w") as f:
        f.write("\n".join(targets_lines) + "\n")
    good(f"Nmap targets ({len(targets_lines)} entries) -> {targets_file}")

    if not targets_lines:
        warn("No targets to scan — check your inputs")
        return [], set()

    # -- PORT DISCOVERY -------------------------------------------------------
    if no_nmap:
        # Expand any CIDR/range targets down to individual IPs for socket probing
        probe_targets: Set[str] = set()
        for t in targets_lines:
            if '/' in t:
                try:
                    net = ipaddress.IPv4Network(t, strict=False)
                    if net.num_addresses <= 65536:
                        for addr in net.hosts():
                            probe_targets.add(str(addr))
                    else:
                        warn(f"Range {t} too large to socket-probe — skipping in no-nmap mode")
                except ValueError:
                    probe_targets.add(t)
            elif '-' in t:
                # nmap-style dash range — already expanded into individual_ips above,
                # but user_nmap_targets may still hold the raw string; skip it here
                # since individual_ips was already merged into targets_lines via dns_ips
                probe_targets.add(t)
            else:
                probe_targets.add(t)
        nmap_results = probe_ports(probe_targets, scan_ports)
    else:
        nmap_output  = os.path.join(nmap_dir, "nmap-results.txt")
        nmap_results = run_nmap(targets_file, nmap_output, scan_ports)

    if not nmap_results:
        warn("No open ports found — live URL list will be empty")

    # -- LIVE URLS ------------------------------------------------------------
    section("Building Live Target List")
    urls, records = build_live_urls(resolved, nmap_results)

    live_urls_file = os.path.join(output_dir, "live-target-urls.txt")
    with open(live_urls_file, "w") as f:
        f.write("\n".join(urls) + "\n")
    good(f"Live URLs ({len(urls)}) -> {live_urls_file}")

    # -- GOWITNESS ------------------------------------------------------------
    if urls:
        run_gowitness(live_urls_file, screenshot_dir)
    else:
        warn("No live URLs found — skipping gowitness")

    # -- GOBUSTER COMMANDS ----------------------------------------------------
    dirbusting_file = os.path.join(output_dir, "dirbusting.txt")
    write_gobuster_commands(urls, dirbusting_file)

    # -- PLAIN TEXT RESULTS ---------------------------------------------------
    results_file = os.path.join(output_dir, "periscope-results.txt")
    write_plain_results(domains, resolved, unresolved, nmap_results, records, results_file)

    # -- BURP SCOPE XML -------------------------------------------------------
    if generate_scope is not None:
        scope_file = os.path.join(output_dir, "burp-scope.txt")
        generate_burp_scope(
            input_domains    = domains,
            resolved         = resolved,
            user_networks    = user_networks,
            user_range_ips   = user_range_ips,
            user_nmap_targets= user_nmap_targets,
            scope_flags      = generate_scope,
            has_domains      = has_domains,
            has_user_ips     = has_user_ips,
            out_file         = scope_file,
        )

    # -- POPULATE API STATE ---------------------------------------------------
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

# -----------------------------------------------------------------------------
# ARGUMENT PARSING
# -----------------------------------------------------------------------------

def parse_domains(raw: str) -> List[str]:
    if os.path.isfile(raw):
        with open(raw) as f:
            return [l.strip() for l in f if l.strip()]
    return [d.strip() for d in raw.split(",") if d.strip()]


def parse_ports(raw: str) -> Set[int]:
    try:
        return {int(p.strip()) for p in raw.split(",") if p.strip()}
    except ValueError as e:
        err(f"Invalid port specification '{raw}': {e}")
        sys.exit(1)


def parse_args():
    p = argparse.ArgumentParser(
        description="Periscope — automated recon & Burp integration",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("-d", "--domains",
                   help="Domain(s): single, comma-separated, or path to a plaintext file")
    p.add_argument("-o", "--output",
                   help="Output folder")
    p.add_argument("--burp-api", action="store_true",
                   help="Start the Periscope API after recon completes")
    p.add_argument("--api-port", type=int, default=13337,
                   help="API port (default: 13337)")
    p.add_argument("--api-only", metavar="PREV_OUTPUT_DIR",
                   help="Skip recon, expose API from a previous output folder")
    p.add_argument("--nmap-ports", default=DEFAULT_PORTS_STR,
                   help=f"Comma-separated port list for nmap (default: {DEFAULT_PORTS_STR})")
    p.add_argument("--ingest-ips", metavar="IP_FILE",
                   help="File of IP ranges/CIDRs to scan ALONGSIDE DNS enumeration")
    p.add_argument("--ingest-only-by-ip", metavar="IP_FILE",
                   help="File of IP ranges/CIDRs to scan ONLY — skips DNS enumeration entirely")
    p.add_argument("--no-nmap", action="store_true",
                   help=(
                       "Skip nmap entirely. Use direct TCP socket probing instead "
                       "(2-second timeout per port). Faster for quick checks, "
                       "less reliable than nmap for fingerprinting."
                   ))
    p.add_argument("--generate-burp-scope", nargs="?", const="default", default=None,
                   metavar="FLAGS",
                   help=(
                       "Generate a plain-text Burp scope file (Target > Scope > Load). "
                       "Optional flags: lax-scoping. Use bare flag for default behavior."
                   ))
    return p.parse_args()

# -----------------------------------------------------------------------------
# ENTRY POINT
# -----------------------------------------------------------------------------

def main():
    print(BANNER.replace("\\033", "\033"))

    args = parse_args()

    # -- Validate mutually exclusive IP flags ---------------------------------
    if args.ingest_ips and args.ingest_only_by_ip:
        err("--ingest-ips and --ingest-only-by-ip are mutually exclusive")
        sys.exit(1)

    # -- API-ONLY MODE --------------------------------------------------------
    if args.api_only:
        if not os.path.isdir(args.api_only):
            err(f"Directory not found: {args.api_only}")
            sys.exit(1)
        resolved = load_previous_output(args.api_only)

        if args.generate_burp_scope is not None:
            scope_file = os.path.join(args.api_only, "burp-scope.txt")
            ip_file = args.ingest_ips or args.ingest_only_by_ip
            nets, rips, ntargets = parse_ip_file(ip_file) if ip_file else ([], set(), [])
            generate_burp_scope(
                input_domains    = parse_domains(args.domains) if args.domains else [],
                resolved         = resolved,
                user_networks    = nets,
                user_range_ips   = rips,
                user_nmap_targets= ntargets,
                scope_flags      = args.generate_burp_scope,
                has_domains      = bool(args.domains),
                has_user_ips     = bool(ip_file),
                out_file         = scope_file,
            )

        if args.burp_api:
            start_api(args.api_port)
        return

    # -- NORMAL MODE ----------------------------------------------------------
    if not args.domains and not (args.ingest_ips or args.ingest_only_by_ip):
        err("Provide -d (domains) and/or --ingest-ips / --ingest-only-by-ip")
        sys.exit(1)
    if not args.output:
        err("-o / --output is required unless using --api-only")
        sys.exit(1)

    domains    = parse_domains(args.domains) if args.domains else []
    scan_ports = parse_ports(args.nmap_ports)

    info(f"Targets   : {', '.join(domains) if domains else '(none — IP-only mode)'}")
    info(f"Output    : {args.output}")
    info(f"Ports     : {', '.join(str(p) for p in sorted(scan_ports))}")
    if args.no_nmap:
        info("Port scan : socket probe mode (--no-nmap)")

    run_recon(
        domains           = domains,
        output_dir        = args.output,
        scan_ports        = scan_ports,
        ingest_ips_file   = args.ingest_ips,
        ingest_only_by_ip = args.ingest_only_by_ip,
        generate_scope    = args.generate_burp_scope,
        no_nmap           = args.no_nmap,
    )

    if args.burp_api:
        start_api(args.api_port)
    else:
        info("Tip: re-run with --burp-api to expose the API for Burp extension")
        info(f"  or: python3 periscope.py --api-only {args.output} --burp-api")


if __name__ == "__main__":
    main()
