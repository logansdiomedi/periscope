# Periscope

Automated recon and discovery tool with a companion Burp Suite extension. Takes one or more domains and/or IP ranges, runs full DNS enumeration, resolves live hosts, scans common web ports, takes screenshots, and exposes a local API for Burp to populate the sitemap.

---

## Requirements

**Python (periscope.py)**
- Python 3.8+
- `pip install requests flask`
- `subfinder` in PATH
- `nmap` in PATH (not required if using `--no-nmap`)
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
| `--nmap-ports` | Custom comma-separated port list for scanning (default: `80,443,8443,8080,8888,444,81,8000,7001,7002`). |
| `--no-nmap` | Skip nmap entirely. Uses direct TCP socket probing with a 2-second timeout instead. Faster for quick checks. |
| `--ingest-ips` | File of IP ranges/CIDRs to scan alongside DNS enumeration. |
| `--ingest-only-by-ip` | File of IP ranges/CIDRs to scan only. Skips DNS enumeration entirely. Mutually exclusive with `--ingest-ips`. |
| `--generate-burp-scope` | Generate a plain-text Burp scope file. Optional flag: `lax-scoping`. See details below. |

**Examples**

Single target, full recon, then expose API:
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

Custom port list:
```
python3 periscope.py -d example.com -o ./out --nmap-ports 80,443,8080,9443
```

Skip nmap, use socket probing instead:
```
python3 periscope.py -d example.com -o ./out --no-nmap
```

DNS enumeration plus an additional IP range:
```
python3 periscope.py -d example.com -o ./out --ingest-ips ranges.txt
```

IP ranges only, no DNS:
```
python3 periscope.py --ingest-only-by-ip ranges.txt -o ./out --burp-api
```

Generate a Burp scope file alongside recon:
```
python3 periscope.py -d example.com -o ./out --generate-burp-scope
python3 periscope.py -d example.com --ingest-ips ranges.txt -o ./out --generate-burp-scope lax-scoping
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
        nmap-results.txt          # Full nmap output (omitted with --no-nmap)
    screenshots/                  # GoWitness screenshots
    generated-targets-list.txt    # Targets passed to nmap or socket prober
    live-target-urls.txt          # Final list of live URLs with correct scheme/port
    potential-vhosts.txt          # Hostnames that did not resolve to an IP
    dirbusting.txt                # Pre-formatted gobuster commands for each live URL
    periscope-results.txt         # Human-readable summary of all findings
    burp-scope.txt                # Burp scope file (only with --generate-burp-scope)
```

---

## What It Does

**DNS Enumeration**

Queries three sources per domain and deduplicates across all of them:
- `ip.thc.org` — passive DNS via the THC API
- `subfinder` — multi-source passive subdomain enumeration
- `crt.sh` — certificate transparency log search

Hosts that resolve to an IP go into the live pipeline. Hosts that do not resolve are written to `potential-vhosts.txt` for use in VHost Blast later.

**IP Range Ingestion**

`--ingest-ips` and `--ingest-only-by-ip` accept a plaintext file with one entry per line. Supported formats:

```
10.0.0.0/24          # CIDR
10.0.0.1-254         # Dash range, last-octet shorthand
10.0.0.1-10.0.0.254  # Dash range, full notation
10.0.0.1             # Single IP
```

When using `--ingest-ips`, the IP ranges are merged with DNS results. Any IP already discovered via DNS is deduplicated at scan time. For IPs that have no corresponding DNS hostname, the IP itself is used as the hostname in generated URLs.

When using `--ingest-only-by-ip`, DNS enumeration is skipped entirely. All URLs are built from the provided IPs directly.

**Port Scanning**

By default, scans all resolved IPs with nmap across the 10 most common web ports:
`80, 443, 444, 81, 8080, 8443, 8000, 8888, 7001, 7002`

Use `--nmap-ports` to override the port list with any comma-separated set.

Use `--no-nmap` to skip nmap entirely and fall back to direct TCP socket probing. Each host/port combination is probed with a 2-second connection timeout using 100 concurrent threads. This is faster and requires no external tools, but does not produce an nmap output file and is less thorough than a full nmap scan.

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

**Burp Scope File**

`--generate-burp-scope` writes a plain-text file (`burp-scope.txt`) that can be loaded directly into Burp via Target > Scope > Load. Requires "Use advanced scope control" to be enabled in Burp. Each line is a host pattern for the Host/IP range field.

Scoping behavior depends on what inputs were provided:

| Inputs | Scope file contains |
|---|---|
| Domains only | Wildcard regex per input domain + all IPs discovered via DNS |
| Domains + IP ranges | Wildcard regex per input domain + user-supplied CIDR/IP ranges |
| IP ranges only | User-supplied CIDR/IP ranges + DNS hostnames that resolve into those ranges |
| Any + `lax-scoping` | Everything above, plus all discovered hostnames regardless of which range they resolve to |

Domain entries use regex for advanced scope wildcard matching:
```
^(.+\.)?example\.com$
^(.+\.)?corp\.com$
10.0.0.0/24
192.168.1.50
```

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

Iterates every discovered IP and open port combination, sending a request for each candidate hostname (discovered subdomains plus everything in `potential-vhosts.txt`) as the `Host` header. Responses matching the configured status codes are flagged as new vhosts and added to the sitemap under both the IP and the hostname.

- Runs in a configurable thread pool (default: 10 threads).
- Can be cancelled mid-run with the Cancel Blast button. In-flight requests finish before the blast stops.
- Follows redirects automatically, up to the configured Max Redirects limit (default: 3). The final status code at the end of the redirect chain is what gets evaluated — not the initial response code.
- Redirect targets are resolved by connecting to their IP directly, so candidates from `potential-vhosts.txt` that do not resolve in DNS can still be followed through redirects.
- Response body lengths can be filtered with the Ignore Response Lengths field. Any hit whose final response body size matches a configured exact value or range is discarded as a false positive.
- When a valid vhost is confirmed, the entry is added to the sitemap tree under the hostname (not the raw IP).

Default valid response codes: `200, 301, 302, 401`. Configurable in the extension UI.

**Configuration Fields**

| Field | Default | Description |
|---|---|---|
| API Port | 13337 | Port where periscope.py is listening. |
| User-Agent | Windows 10 Chrome | Applied to all sitemap population requests. |
| VHost Blast Valid Codes | 200,301,302,401 | Comma-separated response codes considered a valid vhost hit. |
| VHost Blast Threads | 10 | Number of concurrent threads for the vhost blast. |
| Max Redirects | 3 | Maximum number of redirects to follow per probe during the VHost Blast. The final response code after the full redirect chain is what gets evaluated against Valid Codes. Set to 0 to disable redirect following entirely. |
| Ignore Response Lengths | 0 | Comma-separated list of response body lengths (in bytes) to ignore as false positives. Accepts exact values and ranges (e.g. `0, 100-200, 512`). Hits whose final response body length matches are silently discarded. |
