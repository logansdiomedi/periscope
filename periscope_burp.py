# Periscope Burp Suite Extension
# Compatible with Jython 2.7.2
# Load via Extender > Extensions > Add (Python)

from burp import IBurpExtender, ITab
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Color, Font
from java.awt.event import ActionListener
from javax.swing import (
    JPanel, JButton, JLabel, JTextField, JTextArea, JScrollPane,
    JFrame, BorderFactory, JSeparator, SwingConstants, SwingUtilities,
    JOptionPane, BoxLayout, Box
)
from javax.swing.border import EmptyBorder
import threading
import urllib2
import json
import traceback
import re

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

DEFAULT_API_PORT  = "13337"
DEFAULT_UA        = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                     "AppleWebKit/537.36 (KHTML, like Gecko) "
                     "Chrome/120.0.0.0 Safari/537.36")
DEFAULT_VHOST_CODES = "200,301,302,401"

EXT_NAME = "Periscope"


# -----------------------------------------------------------------------------
# Extension Entry Point
# -----------------------------------------------------------------------------

class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)

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

        # -- Header ----------------------------------------------------------
        header_panel = JPanel()
        header_panel.setLayout(BoxLayout(header_panel, BoxLayout.Y_AXIS))

        title = JLabel("PERISCOPE")
        title.setFont(Font("Monospaced", Font.BOLD, 22))
        title.setForeground(Color(0x00, 0xBF, 0xFF))

        subtitle = JLabel("  surface everything. miss nothing.")
        subtitle.setFont(Font("Monospaced", Font.PLAIN, 11))
        subtitle.setForeground(Color(0x88, 0x88, 0x88))

        header_panel.add(title)
        header_panel.add(subtitle)
        header_panel.add(Box.createVerticalStrut(8))
        header_panel.add(JSeparator(SwingConstants.HORIZONTAL))
        header_panel.add(Box.createVerticalStrut(10))

        # -- Config Row -------------------------------------------------------
        config_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))

        config_panel.add(JLabel("API Port:"))
        self._port_field = JTextField(DEFAULT_API_PORT, 6)
        config_panel.add(self._port_field)

        config_panel.add(Box.createHorizontalStrut(12))
        config_panel.add(JLabel("User-Agent:"))
        self._ua_field = JTextField(DEFAULT_UA, 42)
        config_panel.add(self._ua_field)

        header_panel.add(config_panel)
        header_panel.add(Box.createVerticalStrut(4))

        # -- Sitemap Buttons --------------------------------------------------
        sitemap_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        sitemap_panel.setBorder(BorderFactory.createTitledBorder("Sitemap Population"))

        self._btn_populate     = self._make_button("Populate Sitemap",              self._do_populate)
        self._btn_populate_scope = self._make_button("Populate Sitemap (In-Scope)", self._do_populate_scope)
        self._btn_by_ip        = self._make_button("Populate via IP Address",       self._do_populate_ip)
        self._btn_by_host      = self._make_button("Populate via Hostname/VHost",   self._do_populate_hostname)

        for btn in [self._btn_populate, self._btn_populate_scope,
                    self._btn_by_ip, self._btn_by_host]:
            sitemap_panel.add(btn)

        # -- VHost Blast ------------------------------------------------------
        vhost_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        vhost_panel.setBorder(BorderFactory.createTitledBorder("VHost Discovery"))

        vhost_panel.add(JLabel("Valid Response Codes:"))
        self._vhost_codes_field = JTextField(DEFAULT_VHOST_CODES, 18)
        vhost_panel.add(self._vhost_codes_field)

        self._btn_vhost_blast = self._make_button("VHost Blast", self._do_vhost_blast)
        vhost_panel.add(self._btn_vhost_blast)

        # -- Log Area ---------------------------------------------------------
        self._log_area = JTextArea(16, 80)
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
        center_panel = JPanel()
        center_panel.setLayout(BoxLayout(center_panel, BoxLayout.Y_AXIS))
        center_panel.add(sitemap_panel)
        center_panel.add(Box.createVerticalStrut(6))
        center_panel.add(vhost_panel)
        center_panel.add(Box.createVerticalStrut(6))
        center_panel.add(scroll)

        outer.add(header_panel, BorderLayout.NORTH)
        outer.add(center_panel, BorderLayout.CENTER)
        outer.add(self._status_label, BorderLayout.SOUTH)

        return outer

    def _make_button(self, label, handler):
        btn = JButton(label)
        btn.addActionListener(_ClickHandler(handler))
        return btn

    # -- Logging --------------------------------------------------------------

    def _log(self, msg):
        def _append():
            self._log_area.append(msg + "\n")
            self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        SwingUtilities.invokeLater(_append)
        self._callbacks.printOutput(msg)

    def _set_status(self, msg):
        def _upd():
            self._status_label.setText(msg)
        SwingUtilities.invokeLater(_upd)

    def _set_buttons_enabled(self, enabled):
        def _upd():
            for btn in [self._btn_populate, self._btn_populate_scope,
                        self._btn_by_ip, self._btn_by_host,
                        self._btn_vhost_blast]:
                btn.setEnabled(enabled)
        SwingUtilities.invokeLater(_upd)

    # -- API Helpers -----------------------------------------------------------

    def _api_port(self):
        try:
            return int(self._port_field.getText().strip())
        except ValueError:
            return int(DEFAULT_API_PORT)

    def _api_get(self, path):
        port = self._api_port()
        url  = "http://127.0.0.1:{}/{}".format(port, path.lstrip("/"))
        req  = urllib2.Request(url)
        resp = urllib2.urlopen(req, timeout=10)
        return json.loads(resp.read())

    def _ua(self):
        ua = self._ua_field.getText().strip()
        return ua if ua else DEFAULT_UA

    # -- HTTP request helpers (through Burp) -----------------------------------

    def _send_request(self, url, ua):
        """Send a request through Burp and add the result to the sitemap."""
        try:
            service = self._helpers.buildHttpService(*self._url_to_service(url))
            raw_req = self._helpers.stringToBytes(self._build_raw_request(url, ua))
            resp = self._callbacks.makeHttpRequest(service, raw_req)
            if resp is not None:
                self._callbacks.addToSiteMap(resp)
            return resp
        except Exception as e:
            self._log("  [!] Request error for {}: {}".format(url, str(e)))
            return None

    def _url_to_service(self, url):
        """Returns (host, port, useHttps) tuple."""
        m = re.match(r"(https?)://([^/:]+)(?::(\d+))?", url)
        if not m:
            raise ValueError("Cannot parse URL: " + url)
        scheme, host, port_str = m.group(1), m.group(2), m.group(3)
        use_https = (scheme == "https")
        if port_str:
            port = int(port_str)
        else:
            port = 443 if use_https else 80
        return host, port, use_https

    def _build_raw_request(self, url, ua):
        """Build a minimal HTTP GET request string."""
        m = re.match(r"https?://[^/]+(/.*)$", url)
        path = m.group(1) if m else "/"
        m2   = re.match(r"https?://([^/]+)", url)
        host_header = m2.group(1) if m2 else ""
        return (
            "GET {} HTTP/1.1\r\n"
            "Host: {}\r\n"
            "User-Agent: {}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).format(path, host_header, ua)

    def _is_in_scope(self, url):
        try:
            from java.net import URL as JavaURL
            return self._callbacks.isInScope(JavaURL(url))
        except Exception:
            return False

    # -- Action Handlers (run in background threads) ---------------------------

    def _threaded(self, fn, *args, **kwargs):
        def run():
            self._set_buttons_enabled(False)
            try:
                fn(*args, **kwargs)
            except Exception as e:
                self._log("[!] Error: " + traceback.format_exc())
            finally:
                self._set_buttons_enabled(True)
                self._set_status("Done.")
        threading.Thread(target=run).start()

    def _do_populate(self):
        self._threaded(self._populate_targets, scope_only=False, by_ip=False, by_host=False)

    def _do_populate_scope(self):
        self._threaded(self._populate_targets, scope_only=True, by_ip=False, by_host=False)

    def _do_populate_ip(self):
        self._threaded(self._populate_targets, scope_only=False, by_ip=True, by_host=False)

    def _do_populate_hostname(self):
        self._threaded(self._populate_targets, scope_only=False, by_ip=False, by_host=True)

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
        sent = 0
        skipped = 0

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

        mode = "IP" if by_ip else ("hostname" if by_host else "all")
        self._log("[+] Sitemap populated: {} requests sent, {} skipped (scope filter)".format(
            sent, skipped))

    def _do_vhost_blast(self):
        self._threaded(self._vhost_blast)

    def _vhost_blast(self):
        self._set_status("Starting VHost Blast...")
        self._log("\n[*] Starting VHost Blast...")

        valid_codes_raw = self._vhost_codes_field.getText().strip()
        try:
            valid_codes = set(int(c.strip()) for c in valid_codes_raw.split(",") if c.strip())
        except ValueError:
            valid_codes = {200, 301, 302, 401}
        self._log("[*] Valid response codes: {}".format(sorted(valid_codes)))

        try:
            targets_data = self._api_get("/api/targets")
            vhosts_data  = self._api_get("/api/vhosts")
        except Exception as e:
            self._log("[!] Cannot reach Periscope API: " + str(e))
            self._set_status("API unreachable.")
            return

        targets  = targets_data.get("targets", [])
        vhosts   = vhosts_data.get("vhosts", [])

        # Collect unique IPs and their open port/scheme
        ip_services = {}  # ip -> [(port, scheme)]
        known_hostnames = set()
        for rec in targets:
            ip     = rec.get("ip", "")
            port   = rec.get("port", 80)
            scheme = rec.get("scheme", "http")
            host   = rec.get("hostname", "")
            if ip:
                if ip not in ip_services:
                    ip_services[ip] = []
                svc = (port, scheme)
                if svc not in ip_services[ip]:
                    ip_services[ip].append(svc)
            if host:
                known_hostnames.add(host)

        # All vhosts to try = potential_vhosts + known_hostnames
        all_candidate_hosts = list(set(vhosts) | known_hostnames)

        self._log("[*] IPs to blast: {}  |  VHost candidates: {}".format(
            len(ip_services), len(all_candidate_hosts)))

        ua = self._ua()
        found_new = []

        for ip, services in ip_services.items():
            for candidate_host in all_candidate_hosts:
                if candidate_host == ip:
                    continue
                for (port, scheme) in services:
                    if port in (443, 80):
                        url = "{}://{}/".format(scheme, ip)
                    else:
                        url = "{}://{}:{}/".format(scheme, ip, port)

                    # Build request with candidate as Host header
                    try:
                        service = self._helpers.buildHttpService(ip, port, scheme == "https")
                        path    = "/"
                        raw_req = (
                            "GET {} HTTP/1.1\r\n"
                            "Host: {}\r\n"
                            "User-Agent: {}\r\n"
                            "Accept: */*\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                        ).format(path, candidate_host, ua)
                        resp_obj = self._callbacks.makeHttpRequest(
                            service, self._helpers.stringToBytes(raw_req))

                        if resp_obj and resp_obj.getResponse():
                            resp_info = self._helpers.analyzeResponse(resp_obj.getResponse())
                            status = resp_info.getStatusCode()
                            if status in valid_codes:
                                self._callbacks.addToSiteMap(resp_obj)
                                entry = "{}://{}:{}/  [Host: {}]  -> {}".format(
                                    scheme, ip, port, candidate_host, status)
                                self._log("[+] NEW VHOST: " + entry)
                                found_new.append(entry)
                    except Exception as e:
                        self._log("  [!] Error blasting {}:{} with host {}: {}".format(
                            ip, port, candidate_host, str(e)))

        self._log("\n[+] VHost Blast complete. {} potential new vhosts found.".format(len(found_new)))
        if found_new:
            self._log("\n--- Confirmed VHosts ---")
            for entry in found_new:
                self._log("  " + entry)

        self._set_status("VHost Blast done. {} hits.".format(len(found_new)))


# -----------------------------------------------------------------------------
# Helper: ActionListener wrapper
# -----------------------------------------------------------------------------

class _ClickHandler(ActionListener):
    def __init__(self, fn):
        self._fn = fn

    def actionPerformed(self, event):
        self._fn()
