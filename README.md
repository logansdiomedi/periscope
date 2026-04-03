# Periscope

Automated recon and discovery tool with a companion Burp Suite extension. Takes one or more domains, runs full DNS enumeration, resolves live hosts, scans common web ports, takes screenshots, and exposes a local API for Burp to populate the sitemap.

---

## Requirements

**Python (periscope.py)**
- Python 3.8+
- `pip install requests flask`
- `subfinder` in PATH
- `nmap` in PATH
- `gowitness` in PATH (v2 or v3, auto-detected)

**Burp Extension (periscope_burp.py)**
- Burp Suite Professional
- Jython 2.7.2 standalone JAR configured under Extender > Options

---

## Installation

```
git clone <repo>
cd periscope
pip install requests flask
```

Load `periscope_burp.py` in Burp via Extender > Extensions > Add > Python.

---

## Usage

```
python3 periscope.py -d <target(s)> -o <output-folder> [options]
```

**Arguments**

| Flag | Description |
|---|---|
| `-d` | Target domain(s). Single domain, comma-separated list, or path to a plaintext file (one domain per line). |
| `-o` | Output folder. Created if it does not exist. |
| `--burp-api` | Start the Periscope API after recon completes. Killed with Ctrl+C. |
| `--api-port` | Port for the API to listen on (default: 13337). |
| `--api-only` | Skip all recon. Load results from a previous output folder and expose the API only. |

**Examples**

Single target, run full recon then expose API:
```
python3 periscope.py -d example.com -o ./out --burp-api
```

Multiple targets via comma-separated list:
```
python3 periscope.py -d example.com,corp.com,dev.example.com -o ./out --burp-api
```

Targets from a file:
```
python3 periscope.py -d domains.txt -o ./out --burp-api
```

Custom API port:
```
python3 periscope.py -d example.com -o ./out --burp-api --api-port 8080
```

Expose API from a previous run without re-running recon:
```
python3 periscope.py --api-only ./out --burp-api
```

---

## Output Structure

```
<output-folder>/
    dns/
        thc-<domain>.txt          # Raw results from ip.thc.org
        subfinder-<domain>.txt    # Raw results from subfinder
        crtsh-<domain>.txt        # Raw results from crt.sh
        all-subdomains.txt        # All sources combined and deduplicated
        resolved-hosts.txt        # hostname:ip for all resolved hosts
    nmap/
        nmap-results.txt          # Full nmap output
    screenshots/                  # GoWitness screenshots
    generated-targets-list.txt    # Unique IPs passed to nmap
    live-target-urls.txt          # Final list of live URLs with correct scheme/port
    potential-vhosts.txt          # Hostnames that did not resolve to an IP
    dirbusting.txt                # Pre-formatted gobuster commands for each live URL
    periscope-results.txt         # Human-readable summary of all findings
```

---

## What It Does

**DNS Enumeration**

Queries three sources per domain and deduplicates across all of them:
- `ip.thc.org` — passive DNS via the THC API
- `subfinder` — multi-source passive subdomain enumeration
- `crt.sh` — certificate transparency log search

Hosts that resolve to an IP go into the live pipeline. Hosts that do not resolve are written to `potential-vhosts.txt` for use in VHost Blast later.

**Port Scanning**

Scans all resolved IPs with nmap across the 11 most common web ports:
`80, 443, 444, 81, 8080, 8443, 8000, 8888, 7001, 7002`

**Screenshot Capture**

Runs GoWitness against all live URLs by hostname wherever possible, falling back to IP only when no hostname is available. Uses the Windows 10 Chrome user agent.

**Live URL List**

Automatically assigns the correct scheme (`http`/`https`) per port and omits default ports from URLs. Example output:
```
http://example.com/
https://example.com/
https://app.example.com:8443/
http://dev.example.com:8080/
```

**GoBuster Commands**

Generates a ready-to-run gobuster command for every live URL targeting `/opt/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt`.

---

## API Reference

The API only ever binds to `127.0.0.1`. It is never exposed on any external interface.

| Endpoint | Description |
|---|---|
| `GET /api/targets` | All live targets as JSON |
| `GET /api/targets/plain` | All live URLs, newline-delimited plaintext |
| `GET /api/targets/ips` | Live targets with URLs rewritten to IP address only |
| `GET /api/targets/hostnames` | Live targets by hostname only |
| `GET /api/vhosts` | Contents of potential-vhosts.txt as JSON |
| `GET /api/status` | Summary counts and ready status |

---

## Burp Extension

Load `periscope_burp.py` via Extender. A **Periscope** tab will appear. Start `periscope.py` with `--burp-api` first, then use the extension.

**Sitemap Population**

| Button | Behavior |
|---|---|
| Populate Sitemap | Sends a request to every discovered live URL and adds results to the Burp sitemap. |
| Populate Sitemap (In-Scope) | Same, but only for URLs that fall within Burp's active scope. |
| Populate via IP Address | Forces all requests to use the raw IP address, no hostnames. |
| Populate via Hostname/VHost | Forces all requests to use hostnames only. |

All sitemap population requests use the Windows 10 Chrome user agent by default. Override it in the User-Agent field.

**VHost Blast**

Iterates every discovered IP and open port combination, sending a request for each candidate hostname (discovered subdomains plus everything in `potential-vhosts.txt`) as the `Host` header. Responses matching the configured status codes are flagged as new vhosts and added to the sitemap.

Default valid response codes: `200, 301, 302, 401`. Configurable in the extension UI.

**Configuration Fields**

| Field | Default | Description |
|---|---|---|
| API Port | 13337 | Port where periscope.py is listening. |
| User-Agent | Windows 10 Chrome | Applied to all sitemap population requests. |
| VHost Blast Resp Codes | 200,301,302,401 | Comma-separated list of codes that indicate a valid vhost. |
