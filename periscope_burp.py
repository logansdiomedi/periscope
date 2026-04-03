# Periscope Burp Suite Extension
# Compatible with Jython 2.7.2
# Load via Extender > Extensions > Add (Python)

from burp import IBurpExtender, ITab, IHttpRequestResponse
from java.awt import BorderLayout, FlowLayout, Color, Font
from java.awt.event import ActionListener
from javax.swing import (
    JPanel, JButton, JLabel, JTextField, JTextArea, JScrollPane,
    BorderFactory, JSeparator, SwingConstants, SwingUtilities,
    BoxLayout, Box
)
from javax.swing.border import EmptyBorder
import threading
import Queue
import urllib2
import json
import traceback
import sys
import socket
import re

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

DEFAULT_API_PORT      = "13337"
DEFAULT_UA            = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/120.0.0.0 Safari/537.36")
DEFAULT_VHOST_CODES   = "200,301,302,401"
DEFAULT_VHOST_THREADS = "10"
DEFAULT_MAX_REDIRECTS = "3"
DEFAULT_IGNORE_LENS   = "0"

EXT_NAME = "Periscope"

HTTPS_PORTS    = (443, 8443, 444, 4443, 9443)
REDIRECT_CODES = (301, 302, 303, 307, 308)


# -----------------------------------------------------------------------------
# IHttpRequestResponse implementation used to add vhost hits to the sitemap
# under the discovered hostname rather than the raw IP address.
# -----------------------------------------------------------------------------

class _FakeRR(IHttpRequestResponse):
    """Wraps existing request/response bytes with a custom IHttpService so that
    addToSiteMap() files the entry under the hostname, not the IP."""

    def __init__(self, service, request_bytes, response_bytes):
        self._svc  = service
        self._req  = request_bytes
        self._resp = response_bytes

    def getHttpService(self):  return self._svc
    def getRequest(self):      return self._req
    def getResponse(self):     return self._resp
    def setHttpService(self, s): pass
    def setRequest(self, r):     pass
    def setResponse(self, r):    pass
    def getHighlight(self):    return None
    def setHighlight(self, h): pass
    def getComment(self):      return None
    def setComment(self, c):   pass

# -----------------------------------------------------------------------------
# Extension Entry Point
# -----------------------------------------------------------------------------

class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)

        # VHost blast cancel signal
        self._vhost_cancel = threading.Event()

        self._panel = self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.printOutput("[Periscope] Extension loaded successfully.")

    # -- ITab -----------------------------------------------------------------

    def getTabCaption(self):
        return EXT_NAME

    def getUiComponent(self):
        return self._panel

    # -- UI Construction ------------------------------------------------------

    def _build_ui(self):
        outer = JPanel(BorderLayout())
        outer.setBorder(EmptyBorder(12, 14, 12, 14))

        # -- Header -----------------------------------------------------------
        header = JPanel()
        header.setLayout(BoxLayout(header, BoxLayout.Y_AXIS))

        title = JLabel("PERISCOPE")
        title.setFont(Font("Monospaced", Font.BOLD, 22))
        title.setForeground(Color(0x00, 0xBF, 0xFF))

        subtitle = JLabel("  surface everything. miss nothing.")
        subtitle.setFont(Font("Monospaced", Font.PLAIN, 11))
        subtitle.setForeground(Color(0x88, 0x88, 0x88))

        credit_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        credit_panel.setOpaque(False)

        c1 = JLabel("v1.0 - By ")
        c1.setFont(Font("Monospaced", Font.PLAIN, 11))
        c1.setForeground(Color(0x00, 0xBF, 0xFF))

        c2 = JLabel("Logan Diomedi")
        c2.setFont(Font("Monospaced", Font.BOLD, 11))
        c2.setForeground(Color(0xFF, 0x44, 0x44))

        c3 = JLabel(" - Depth Security (www.depthsecurity.com)")
        c3.setFont(Font("Monospaced", Font.PLAIN, 11))
        c3.setForeground(Color(0x00, 0xBF, 0xFF))

        credit_panel.add(c1)
        credit_panel.add(c2)
        credit_panel.add(c3)

        header.add(title)
        header.add(subtitle)
        header.add(credit_panel)
        header.add(Box.createVerticalStrut(8))
        header.add(JSeparator(SwingConstants.HORIZONTAL))
        header.add(Box.createVerticalStrut(8))

        # -- Global config row ------------------------------------------------
        cfg = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))

        cfg.add(JLabel("API Port:"))
        self._port_field = JTextField(DEFAULT_API_PORT, 6)
        cfg.add(self._port_field)

        cfg.add(Box.createHorizontalStrut(10))
        cfg.add(JLabel("User-Agent:"))
        self._ua_field = JTextField(DEFAULT_UA, 48)
        cfg.add(self._ua_field)

        header.add(cfg)
        header.add(Box.createVerticalStrut(4))

        # -- Sitemap Population -----------------------------------------------
        sitemap_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        sitemap_panel.setBorder(BorderFactory.createTitledBorder("Sitemap Population"))

        self._btn_populate       = self._btn("Populate Sitemap",              self._do_populate)
        self._btn_populate_scope = self._btn("Populate Sitemap (In-Scope)",   self._do_populate_scope)
        self._btn_by_ip          = self._btn("Populate via IP Address",        self._do_populate_ip)
        self._btn_by_host        = self._btn("Populate via Hostname/VHost",    self._do_populate_hostname)

        for b in [self._btn_populate, self._btn_populate_scope,
                  self._btn_by_ip, self._btn_by_host]:
            sitemap_panel.add(b)

        # -- VHost Blast ------------------------------------------------------
        vhost_panel = JPanel()
        vhost_panel.setLayout(BoxLayout(vhost_panel, BoxLayout.Y_AXIS))
        vhost_panel.setBorder(BorderFactory.createTitledBorder("VHost Discovery"))

        # Row 1: codes / threads / redirects / buttons
        vhost_row1 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))

        vhost_row1.add(JLabel("Valid Codes:"))
        self._vhost_codes_field = JTextField(DEFAULT_VHOST_CODES, 16)
        vhost_row1.add(self._vhost_codes_field)

        vhost_row1.add(Box.createHorizontalStrut(4))
        vhost_row1.add(JLabel("Threads:"))
        self._vhost_threads_field = JTextField(DEFAULT_VHOST_THREADS, 4)
        vhost_row1.add(self._vhost_threads_field)

        vhost_row1.add(Box.createHorizontalStrut(4))
        vhost_row1.add(JLabel("Max Redirects:"))
        self._vhost_redirects_field = JTextField(DEFAULT_MAX_REDIRECTS, 3)
        vhost_row1.add(self._vhost_redirects_field)

        vhost_row1.add(Box.createHorizontalStrut(6))
        self._btn_vhost_blast  = self._btn("VHost Blast",  self._do_vhost_blast)
        self._btn_vhost_cancel = self._btn("Cancel Blast",  self._do_cancel_vhost)
        self._btn_vhost_cancel.setEnabled(False)
        self._btn_vhost_cancel.setForeground(Color(0xCC, 0x44, 0x44))
        vhost_row1.add(self._btn_vhost_blast)
        vhost_row1.add(self._btn_vhost_cancel)

        # Row 2: ignore lengths
        vhost_row2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        vhost_row2.add(JLabel("Ignore Response Lengths (e.g. 0, 100-200, 512):"))
        self._vhost_ignore_lens_field = JTextField(DEFAULT_IGNORE_LENS, 36)
        vhost_row2.add(self._vhost_ignore_lens_field)

        vhost_panel.add(vhost_row1)
        vhost_panel.add(vhost_row2)

        # -- Log Area ---------------------------------------------------------
        self._log_area = JTextArea(18, 80)
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._log_area.setBackground(Color(0x1e, 0x1e, 0x1e))
        self._log_area.setForeground(Color(0xcc, 0xcc, 0xcc))
        scroll = JScrollPane(self._log_area)
        scroll.setBorder(BorderFactory.createTitledBorder("Log"))

        # -- Status Bar -------------------------------------------------------
        self._status_label = JLabel("Ready.")
        self._status_label.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._status_label.setForeground(Color(0x44, 0xcc, 0x44))

        # -- Assemble ---------------------------------------------------------
        center = JPanel()
        center.setLayout(BoxLayout(center, BoxLayout.Y_AXIS))
        center.add(sitemap_panel)
        center.add(Box.createVerticalStrut(4))
        center.add(vhost_panel)
        center.add(Box.createVerticalStrut(4))
        center.add(scroll)

        outer.add(header, BorderLayout.NORTH)
        outer.add(center, BorderLayout.CENTER)
        outer.add(self._status_label, BorderLayout.SOUTH)

        return outer

    def _btn(self, label, handler):
        b = JButton(label)
        b.addActionListener(_ClickHandler(handler))
        return b

    # -- Logging --------------------------------------------------------------

    def _log(self, msg):
        def _go():
            self._log_area.append(msg + "\n")
            self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        SwingUtilities.invokeLater(_go)
        self._callbacks.printOutput(msg)

    def _set_status(self, msg):
        SwingUtilities.invokeLater(lambda: self._status_label.setText(msg))

    def _set_sitemap_buttons_enabled(self, enabled):
        def _go():
            for b in [self._btn_populate, self._btn_populate_scope,
                      self._btn_by_ip, self._btn_by_host,
                      self._btn_vhost_blast]:
                b.setEnabled(enabled)
        SwingUtilities.invokeLater(_go)

    def _set_vhost_running(self, running):
        """Toggle button states between idle and active vhost blast."""
        def _go():
            self._btn_vhost_blast.setEnabled(not running)
            self._btn_vhost_cancel.setEnabled(running)
            for b in [self._btn_populate, self._btn_populate_scope,
                      self._btn_by_ip, self._btn_by_host]:
                b.setEnabled(not running)
        SwingUtilities.invokeLater(_go)

    # -- API helpers ----------------------------------------------------------

    def _api_port(self):
        try:
            return int(self._port_field.getText().strip())
        except ValueError:
            return int(DEFAULT_API_PORT)

    def _api_get(self, path):
        port = self._api_port()
        url  = "http://127.0.0.1:{}/{}".format(port, path.lstrip("/"))
        resp = urllib2.urlopen(urllib2.Request(url), timeout=10)
        return json.loads(resp.read())

    def _ua(self):
        v = self._ua_field.getText().strip()
        return v if v else DEFAULT_UA

    # -- HTTP helpers (through Burp) ------------------------------------------

    def _url_to_service(self, url):
        """Returns (host, port, useHttps)."""
        m = re.match(r"(https?)://([^/:]+)(?::(\d+))?", url)
        if not m:
            raise ValueError("Cannot parse URL: " + url)
        scheme, host, port_str = m.group(1), m.group(2), m.group(3)
        use_https = (scheme == "https")
        port = int(port_str) if port_str else (443 if use_https else 80)
        return host, port, use_https

    def _build_raw_request(self, url, ua, host_override=None):
        """Build a minimal HTTP GET request string."""
        m = re.match(r"https?://[^/]+(/.*)$", url)
        path = m.group(1) if m else "/"
        m2 = re.match(r"https?://([^/]+)", url)
        host_header = host_override if host_override else (m2.group(1) if m2 else "")
        return (
            "GET {} HTTP/1.1\r\n"
            "Host: {}\r\n"
            "User-Agent: {}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).format(path, host_header, ua)

    def _send_request(self, url, ua, host_override=None):
        """Send a request through Burp and add the result to the sitemap."""
        try:
            service = self._helpers.buildHttpService(*self._url_to_service(url))
            raw_req = self._helpers.stringToBytes(
                self._build_raw_request(url, ua, host_override=host_override))
            resp = self._callbacks.makeHttpRequest(service, raw_req)
            if resp is not None:
                self._callbacks.addToSiteMap(resp)
            return resp
        except:
            # Bare except required: Jython 2.7 does not catch Java RuntimeExceptions
            # (e.g. UnknownHostException) with 'except Exception'.
            err = sys.exc_info()[1]
            self._log("  [!] Request error for {}: {}".format(url, err))
            return None

    def _is_in_scope(self, url):
        try:
            from java.net import URL as JavaURL
            return self._callbacks.isInScope(JavaURL(url))
        except Exception:
            return False

    # -- Threaded runner for sitemap population -------------------------------

    def _threaded(self, fn, *args, **kwargs):
        def run():
            self._set_sitemap_buttons_enabled(False)
            try:
                fn(*args, **kwargs)
            except Exception:
                self._log("[!] Error: " + traceback.format_exc())
            finally:
                self._set_sitemap_buttons_enabled(True)
                self._set_status("Done.")
        threading.Thread(target=run).start()

    # -- Sitemap population actions -------------------------------------------

    def _do_populate(self):
        self._threaded(self._populate_targets)

    def _do_populate_scope(self):
        self._threaded(self._populate_targets, scope_only=True)

    def _do_populate_ip(self):
        self._threaded(self._populate_targets, by_ip=True)

    def _do_populate_hostname(self):
        self._threaded(self._populate_targets, by_host=True)

    def _populate_targets(self, scope_only=False, by_ip=False, by_host=False):
        self._set_status("Fetching targets from API...")
        self._log("\n[*] Fetching targets from Periscope API...")

        try:
            if by_ip:
                data = self._api_get("/api/targets/ips")
            elif by_host:
                data = self._api_get("/api/targets/hostnames")
            else:
                data = self._api_get("/api/targets")
        except Exception as e:
            self._log("[!] Cannot reach Periscope API: " + str(e))
            self._log("    Is periscope.py running with --burp-api?")
            self._set_status("API unreachable.")
            return

        targets = data.get("targets", [])
        self._log("[+] {} targets received".format(len(targets)))

        ua = self._ua()
        sent = skipped = 0

        for rec in targets:
            url = rec.get("url", "")
            if not url:
                continue
            if scope_only and not self._is_in_scope(url):
                skipped += 1
                continue
            self._log("  -> {}".format(url))
            self._set_status("Requesting {} ...".format(url))
            self._send_request(url, ua)
            sent += 1

        self._log("[+] Sitemap populated: {} sent, {} skipped (scope filter)".format(sent, skipped))

    # -- VHost Blast ----------------------------------------------------------

    def _do_cancel_vhost(self):
        self._vhost_cancel.set()
        self._log("[!] Cancel requested - finishing in-flight requests...")
        self._set_status("Cancelling VHost Blast...")

    def _do_vhost_blast(self):
        self._vhost_cancel.clear()
        self._set_vhost_running(True)

        def run():
            try:
                self._vhost_blast()
            except Exception:
                self._log("[!] Error: " + traceback.format_exc())
            finally:
                self._set_vhost_running(False)
                self._set_status("VHost Blast done.")

        threading.Thread(target=run).start()

    def _parse_ignored_lengths(self, text):
        """Parse '0, 100-200, 512' into a callable is_ignored(length) -> bool."""
        exact  = set()
        ranges = []
        for part in text.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                sides = part.split("-", 1)
                try:
                    lo, hi = int(sides[0].strip()), int(sides[1].strip())
                    ranges.append((lo, hi))
                except ValueError:
                    pass
            else:
                try:
                    exact.add(int(part))
                except ValueError:
                    pass

        def is_ignored(length):
            if length in exact:
                return True
            for lo, hi in ranges:
                if lo <= length <= hi:
                    return True
            return False

        return is_ignored

    def _probe_with_redirects(self, ip, port, scheme, candidate, ua, max_redirects):
        """
        Probe ip:port with Host: candidate, following redirects up to max_redirects.
        Returns (final_resp_obj, final_status, body_length).

        Redirects are followed by connecting directly to the resolved IP of the
        redirect target (or the same IP for relative/same-host redirects) so we
        never rely on the candidate hostname resolving in DNS.
        """
        cur_ip     = ip
        cur_port   = port
        cur_scheme = scheme
        cur_path   = "/"
        cur_host   = candidate
        last_resp  = None

        for attempt in range(max_redirects + 1):
            try:
                svc = self._helpers.buildHttpService(cur_ip, cur_port, cur_scheme == "https")
                raw = (
                    "GET {} HTTP/1.1\r\n"
                    "Host: {}\r\n"
                    "User-Agent: {}\r\n"
                    "Accept: */*\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).format(cur_path, cur_host, ua)

                resp_obj = self._callbacks.makeHttpRequest(svc, self._helpers.stringToBytes(raw))
                if not resp_obj or not resp_obj.getResponse():
                    return last_resp, 0, 0

                last_resp  = resp_obj
                resp_info  = self._helpers.analyzeResponse(resp_obj.getResponse())
                status     = resp_info.getStatusCode()
                body_len   = len(resp_obj.getResponse()) - resp_info.getBodyOffset()

                if status in REDIRECT_CODES and attempt < max_redirects:
                    location = None
                    for hdr in resp_info.getHeaders():
                        if hdr.lower().startswith("location:"):
                            location = hdr[9:].strip()
                            break
                    if not location:
                        return resp_obj, status, body_len

                    abs_m = re.match(r"(https?)://([^/:]+)(?::(\d+))?(.*)", location)
                    if abs_m:
                        cur_scheme  = abs_m.group(1)
                        redir_host  = abs_m.group(2)
                        port_str    = abs_m.group(3)
                        cur_path    = abs_m.group(4) or "/"
                        cur_port    = int(port_str) if port_str else (443 if cur_scheme == "https" else 80)
                        cur_host    = redir_host
                        # Resolve redirect target to IP; fall back to hostname literal
                        try:
                            cur_ip = socket.gethostbyname(redir_host)
                        except:
                            cur_ip = redir_host
                    else:
                        # Relative redirect - same IP/port/scheme/host, new path
                        cur_path = location if location.startswith("/") else "/" + location

                    continue

                return resp_obj, status, body_len

            except:
                return last_resp, 0, 0

        return last_resp, 0, 0

    def _vhost_blast(self):
        self._set_status("Starting VHost Blast...")
        self._log("\n[*] Starting VHost Blast...")

        # Parse config fields
        try:
            valid_codes = set(
                int(c.strip()) for c in self._vhost_codes_field.getText().split(",") if c.strip()
            )
        except ValueError:
            valid_codes = {200, 301, 302, 401}

        try:
            num_threads = max(1, int(self._vhost_threads_field.getText().strip()))
        except ValueError:
            num_threads = 10

        try:
            max_redirects = max(0, int(self._vhost_redirects_field.getText().strip()))
        except ValueError:
            max_redirects = 3

        is_ignored_len = self._parse_ignored_lengths(self._vhost_ignore_lens_field.getText())

        self._log("[*] Valid codes: {}  |  Threads: {}".format(sorted(valid_codes), num_threads))

        # Pull data from API
        try:
            targets_data = self._api_get("/api/targets")
            vhosts_data  = self._api_get("/api/vhosts")
        except Exception as e:
            self._log("[!] Cannot reach Periscope API: " + str(e))
            self._set_status("API unreachable.")
            return

        targets = targets_data.get("targets", [])
        vhosts  = vhosts_data.get("vhosts", [])

        # Build ip -> [(port, scheme)] and a per-IP set of already-known hostnames.
        # Known hostnames are excluded per-IP when building the work queue.
        # Testing www.example.com against the IP it already resolves to is not
        # a discovery, it will always match and pollutes results.
        ip_services       = {}   # ip -> [(port, scheme)]
        ip_known_hosts    = {}   # ip -> set of hostnames already confirmed on that IP
        all_known_hosts   = set()

        for rec in targets:
            ip     = rec.get("ip", "")
            port   = rec.get("port", 80)
            scheme = rec.get("scheme", "http")
            host   = rec.get("hostname", "")

            if ip:
                svc = (port, scheme)
                if ip not in ip_services:
                    ip_services[ip] = []
                    ip_known_hosts[ip] = set()
                if svc not in ip_services[ip]:
                    ip_services[ip].append(svc)
                # Track which hostnames are already confirmed on this specific IP
                if host and host != ip:
                    ip_known_hosts[ip].add(host)

            if host and host != ip:
                all_known_hosts.add(host)

        # Candidates = potential vhosts (unresolved) + known hostnames from OTHER IPs.
        # Each IP's own known hostnames are filtered out at queue-build time below.
        all_candidates = list(set(vhosts) | all_known_hosts)

        self._log("[*] IPs: {}  |  Candidate pool: {} hostnames".format(
            len(ip_services), len(all_candidates)))

        # Build work queue - skip candidates already confirmed on the target IP
        work_q = Queue.Queue()
        skipped_known = 0
        for ip, services in ip_services.items():
            already_known = ip_known_hosts.get(ip, set())
            for candidate in all_candidates:
                if candidate == ip:
                    continue
                if candidate in already_known:
                    skipped_known += 1
                    continue
                for (port, scheme) in services:
                    work_q.put((ip, port, scheme, candidate))

        total_work = work_q.qsize()
        self._log("[*] Probes queued: {}  ({} skipped - already known on that IP)".format(
            total_work, skipped_known))

        found_new    = []
        results_lock = threading.Lock()
        completed_count = [0]

        ua = self._ua()

        def worker():
            # Wrap the entire worker in a broad try/except so that any uncaught
            # Java-level exception (e.g. from makeHttpRequest) doesn't silently
            # kill the thread and leave queue items unprocessed.
            while not self._vhost_cancel.is_set():
                item = None
                try:
                    item = work_q.get(timeout=0.5)
                except Queue.Empty:
                    break

                ip, port, scheme, candidate = item
                try:
                    # Probe with redirect following - final_resp is the last
                    # response in the chain; final_status is what we evaluate.
                    final_resp, final_status, body_len = self._probe_with_redirects(
                        ip, port, scheme, candidate, ua, max_redirects)

                    if final_resp is None:
                        pass  # connection failed entirely, logged inside probe
                    elif final_status in valid_codes:
                        if is_ignored_len(body_len):
                            pass  # filtered by response length
                        else:
                            # Build the initial probe request bytes for the sitemap entry
                            probe_req_bytes = self._helpers.stringToBytes(
                                (
                                    "GET / HTTP/1.1\r\n"
                                    "Host: {}\r\n"
                                    "User-Agent: {}\r\n"
                                    "Accept: */*\r\n"
                                    "Connection: close\r\n"
                                    "\r\n"
                                ).format(candidate, ua)
                            )

                            # File sitemap entry under the HOSTNAME (not the IP) so
                            # it appears correctly in Burp's site tree. We use _FakeRR
                            # to attach the hostname service to the real response bytes
                            # without making a new DNS-resolved connection.
                            hostname_svc = self._helpers.buildHttpService(
                                candidate, port, scheme == "https")
                            sitemap_entry = _FakeRR(
                                hostname_svc,
                                probe_req_bytes,
                                final_resp.getResponse()
                            )
                            self._callbacks.addToSiteMap(sitemap_entry)

                            entry = "{}://{}:{}/  [Host: {}]  -> HTTP {} ({} bytes)".format(
                                scheme, ip, port, candidate, final_status, body_len)
                            with results_lock:
                                found_new.append(entry)
                            self._log("[+] NEW VHOST: " + entry)

                except:
                    # Bare except: Java RuntimeExceptions are not caught by
                    # 'except Exception' in Jython 2.7.
                    err = sys.exc_info()[1]
                    self._log("  [!] {}:{} Host:{} -> {}".format(ip, port, candidate, err))

                finally:
                    with results_lock:
                        completed_count[0] += 1
                        done = completed_count[0]
                    if done % 50 == 0:
                        self._set_status("VHost Blast: {}/{} probes, {} hits".format(
                            done, total_work, len(found_new)))
                    work_q.task_done()

        # Spin up thread pool
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        if self._vhost_cancel.is_set():
            self._log("[!] VHost Blast cancelled after {}/{} probes.".format(
                completed_count[0], total_work))
        else:
            self._log("\n[+] VHost Blast complete. {}/{} probes. {} hits.".format(
                completed_count[0], total_work, len(found_new)))

        if found_new:
            self._log("\n--- Confirmed VHosts ---")
            for entry in found_new:
                self._log("  " + entry)


# -----------------------------------------------------------------------------
# Helper: ActionListener wrapper
# -----------------------------------------------------------------------------

class _ClickHandler(ActionListener):
    def __init__(self, fn):
        self._fn = fn

    def actionPerformed(self, event):
        self._fn()
