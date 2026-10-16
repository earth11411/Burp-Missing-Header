# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab
from javax.swing import (JPanel, JTextArea, JButton, JScrollPane,
                         Box, JLabel, JSplitPane, JEditorPane, JFileChooser, JOptionPane,
                         JTable, JComboBox, JTextField)
from javax.swing import SwingUtilities
from javax.swing.table import DefaultTableModel
from java.awt import Font, BorderLayout, Dimension
from java.io import File, BufferedWriter, FileWriter
from java.net import URL
from java.util import ArrayList
from java.util.concurrent import Executors, TimeUnit
import threading
import urlparse # Use urlparse for Python 2.7 (Jython)
import cgi # Import cgi for escaping HTML
import re

# We use threading to run the scan in the background
# without freezing Burp's UI.

# --- Define headers to check ---
HEADERS_TO_CHECK = [
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Access-Control-Allow-Methods",
    "Cache-Control"
]

# HTTP methods that should never be permitted via CORS / at all on a production endpoint
HIGH_RISK_CORS_METHODS = ["TRACE", "CONNECT"]
# HTTP methods that are not inherently dangerous but warrant a caution note if exposed cross-origin
CAUTION_CORS_METHODS = ["PUT", "DELETE"]

# --- Header attribute/value validators -----------------------------------
# Each function receives the raw header value (or None if the header was
# absent) and returns a (status, note) tuple. "status" is one of:
#   Missing / Present / Weak / N/A
# "note" is a short, human readable explanation used in the detailed report.

def _check_hsts_value(value):
    """Validate Strict-Transport-Security max-age / includeSubDomains."""
    if value is None:
        return ("Missing", "Header not present")
    v = value.lower()
    issues = []
    match = re.search(r'max-age\s*=\s*(\d+)', v)
    if not match:
        issues.append("no 'max-age' directive found")
    else:
        max_age = int(match.group(1))
        if max_age <= 0:
            issues.append("'max-age' is 0 (HSTS effectively disabled)")
        elif max_age < 31536000:
            issues.append("'max-age' is only {}s (recommended >= 31536000, i.e. 1 year)".format(max_age))
    if "includesubdomains" not in v:
        issues.append("missing 'includeSubDomains'")
    if issues:
        return ("Weak", "; ".join(issues))
    return ("Present", "max-age and includeSubDomains correctly configured")

def _check_csp_value(value):
    """Validate Content-Security-Policy for common weakening directives."""
    if value is None:
        return ("Missing", "Header not present")
    v = value.lower()
    issues = []
    if "unsafe-inline" in v:
        issues.append("allows 'unsafe-inline'")
    if "unsafe-eval" in v:
        issues.append("allows 'unsafe-eval'")
    if re.search(r"(default-src|script-src|style-src)\s*[^;]*\*(?!\.)", v):
        issues.append("uses a wildcard ('*') source")
    if "default-src" not in v and "script-src" not in v:
        issues.append("missing both 'default-src' and 'script-src' directives")
    if issues:
        return ("Weak", "; ".join(issues))
    return ("Present", "No wildcard / unsafe-inline / unsafe-eval directives found")

def _check_xfo_value(value):
    """Validate X-Frame-Options is one of the three recognised values."""
    if value is None:
        return ("Missing", "Header not present")
    v = value.strip().lower()
    if v == "deny" or v == "sameorigin" or v.startswith("allow-from"):
        return ("Present", "")
    return ("Weak", "Unrecognized value '{}' (expected DENY, SAMEORIGIN or ALLOW-FROM uri)".format(value))

def _check_xcto_value(value):
    """Validate X-Content-Type-Options is exactly 'nosniff'."""
    if value is None:
        return ("Missing", "Header not present")
    if value.strip().lower() != "nosniff":
        return ("Weak", "Value should be exactly 'nosniff', found '{}'".format(value))
    return ("Present", "")

def _check_xxss_value(value):
    """
    X-XSS-Protection is deprecated. Best practice is to remove/disable it and
    rely on Content-Security-Policy instead, so its absence is NOT a finding.
    """
    if value is None:
        return ("N/A", "Not present (fine - deprecated header, rely on CSP for XSS mitigation)")
    v = value.strip()
    if v == "0":
        return ("Present", "Explicitly disabled, as recommended")
    return ("Weak", "Deprecated header is enabled ('{}'). Remove it or set it to '0' and rely on CSP instead".format(value))

def _check_cors_methods_value(value):
    """
    Validate Access-Control-Allow-Methods. Only meaningful when the server
    actually returns it (typically on CORS/OPTIONS preflight responses).
    """
    if value is None:
        return ("N/A", "Header not observed on this response (only applies to CORS preflight responses)")
    methods = [m.strip().upper() for m in value.split(",") if m.strip()]
    high_risk = [m for m in methods if m in HIGH_RISK_CORS_METHODS]
    caution = [m for m in methods if m in CAUTION_CORS_METHODS]
    if high_risk:
        return ("Weak", "Dangerous method(s) allowed: {}. TRACE/CONNECT should be explicitly disabled".format(", ".join(high_risk)))
    if caution:
        return ("Present", "Allowed: {}. Note: {} should only be permitted if actually required".format(", ".join(methods), ", ".join(caution)))
    return ("Present", "Allowed: {}".format(", ".join(methods)) if methods else "")

def _check_cache_control_value(present_headers_map):
    """
    Validate Cache-Control against the two recommended patterns:
      1) Permissive (store + revalidate): no-cache, must-revalidate + ETag
      2) Strict (no caching at all): no-store, no-cache, must-revalidate,
         max-age=0 + Pragma: no-cache + Expires: 0
    """
    cache_control = present_headers_map.get("cache-control")
    if cache_control is None:
        return ("Missing", "No Cache-Control header found; responses may be cached indefinitely by the browser")
    v = cache_control.lower()
    has_no_store = "no-store" in v
    has_no_cache = "no-cache" in v
    has_must_revalidate = "must-revalidate" in v
    pragma = present_headers_map.get("pragma", "")
    expires = present_headers_map.get("expires", "")
    etag = present_headers_map.get("etag")

    if has_no_store and has_no_cache and has_must_revalidate:
        notes = ["Strict no-cache policy (no-store, no-cache, must-revalidate)"]
        if "no-cache" not in pragma.lower():
            notes.append("missing 'Pragma: no-cache'")
        if expires.strip() != "0":
            notes.append("missing 'Expires: 0'")
        return ("Present", "; ".join(notes))
    if has_no_cache and has_must_revalidate and not has_no_store:
        notes = ["Permissive caching with mandatory revalidation (no-cache, must-revalidate)"]
        if not etag:
            notes.append("missing ETag for revalidation")
        return ("Present", "; ".join(notes))
    return ("Weak", "Does not enforce no-cache/no-store + must-revalidate; response may be cached and reused without revalidation")
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Missing Header Checker")
        
        # --- NEW: Store last scan results ---
        self._last_scan_results = []

        # --- Create GUI ---
        self._panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._panel.setResizeWeight(0.3) 

        # Top Panel (Input)
        input_panel = JPanel(BorderLayout(10, 10))
        input_box = Box.createVerticalBox()
        input_box.add(JLabel("Enter URLs (one per line, comma-separated allowed):"))
        self._url_input = JTextArea(10, 80)
        self._url_input.setText("https://google.com, https://example.com\nhttps://owasp.org")
        input_box.add(JScrollPane(self._url_input))

        # --- NEW: Cookie Panel ---
        input_box.add(Box.createVerticalStrut(8))
        input_box.add(JLabel("Cookies (optional) - Target: host (example.com), wildcard (*.example.com), "
                             "URL prefix (https://example.com/app) or * = all hosts"))

        cookie_row = Box.createHorizontalBox()
        cookie_row.add(JLabel("Target: "))
        self._cookie_target = JComboBox()
        self._cookie_target.setEditable(True)
        self._cookie_target.setPreferredSize(Dimension(260, 26))
        self._cookie_target.setMaximumSize(Dimension(320, 26))
        cookie_row.add(self._cookie_target)
        cookie_row.add(Box.createHorizontalStrut(5))
        cookie_row.add(JButton("Load Hosts", actionPerformed=self.load_hosts_into_combo))
        cookie_row.add(Box.createHorizontalStrut(10))
        cookie_row.add(JLabel("Cookie: "))
        self._cookie_value = JTextField(40)
        self._cookie_value.setMaximumSize(Dimension(2000, 26))
        self._cookie_value.setToolTipText("e.g. SESSIONID=abc123; token=xyz  (a leading 'Cookie:' is stripped automatically)")
        cookie_row.add(self._cookie_value)
        cookie_row.add(Box.createHorizontalStrut(5))
        cookie_row.add(JButton("Add", actionPerformed=self.add_cookie_rule))
        cookie_row.add(Box.createHorizontalStrut(5))
        cookie_row.add(JButton("Add to All Hosts", actionPerformed=self.add_cookie_all_hosts))
        input_box.add(cookie_row)

        self._cookie_model = DefaultTableModel(["Target", "Cookie"], 0)
        self._cookie_table = JTable(self._cookie_model)  # cells are editable by double-click
        self._cookie_table.getColumnModel().getColumn(0).setPreferredWidth(250)
        self._cookie_table.getColumnModel().getColumn(1).setPreferredWidth(600)
        cookie_scroll = JScrollPane(self._cookie_table)
        cookie_scroll.setPreferredSize(Dimension(800, 90))
        input_box.add(cookie_scroll)

        cookie_btn_row = Box.createHorizontalBox()
        cookie_btn_row.add(JButton("Remove Selected", actionPerformed=self.remove_cookie_rule))
        cookie_btn_row.add(Box.createHorizontalStrut(10))
        cookie_btn_row.add(JButton("Clear All Cookies", actionPerformed=self.clear_cookie_rules))
        input_box.add(cookie_btn_row)
        input_box.add(Box.createVerticalStrut(8))
        self._cookie_rules = []
        # --- End Cookie Panel ---

        # --- NEW: Button Panel with 3 Buttons ---
        button_panel = Box.createHorizontalBox()
        self._run_button = JButton("Run Scan", actionPerformed=self.start_scan)
        self._stop_button = JButton("Stop", actionPerformed=self.stop_scan)
        self._report_button = JButton("Report", actionPerformed=self.show_report)
        self._details_button = JButton("Show Details", actionPerformed=self.show_details)
        self._save_button = JButton("Save...", actionPerformed=self.show_save_options)
        
        # Disable report/details/stop buttons until scan is run
        self._stop_button.setEnabled(False)
        self._report_button.setEnabled(False)
        self._details_button.setEnabled(False)
        self._save_button.setEnabled(False)
        
        button_panel.add(self._run_button)
        button_panel.add(Box.createHorizontalStrut(10)) # Spacer
        button_panel.add(self._stop_button)
        button_panel.add(Box.createHorizontalStrut(10)) # Spacer
        button_panel.add(self._report_button)
        button_panel.add(Box.createHorizontalStrut(10)) # Spacer
        button_panel.add(self._details_button)
        button_panel.add(Box.createHorizontalStrut(10)) # Spacer
        button_panel.add(self._save_button)
        input_box.add(button_panel)
        # --- End NEW ---
        
        self._is_scanning = False
        
        input_panel.add(input_box, BorderLayout.CENTER)
        self._panel.setTopComponent(input_panel)

        # Bottom Panel (Results)
        results_panel = JPanel(BorderLayout(10, 10))
        results_box = Box.createVerticalBox()
        results_box.add(JLabel("Results:"))
        
        self._results_output = JEditorPane("text/html", "<html><body>Ready. Please enter URLs and click 'Run Scan'.</body></html>")
        self._results_output.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._results_output.setEditable(False)
        results_scroll_pane = JScrollPane(self._results_output)
        
        results_box.add(results_scroll_pane)
        
        results_panel.add(results_box, BorderLayout.CENTER)
        self._panel.setBottomComponent(results_panel)

        callbacks.addSuiteTab(self)
        print("Missing Header Checker extension loaded.")

    def getTabCaption(self):
        return "Missing Headers"

    def getUiComponent(self):
        return self._panel

    def make_request_with_timeout(self, http_service, request_bytes, timeout_seconds):
        """Helper to execute makeHttpRequest with a timeout."""
        result_holder = {"response": None, "exception": None}
        
        def target():
            try:
                result_holder["response"] = self._callbacks.makeHttpRequest(http_service, request_bytes)
            except Exception as e:
                result_holder["exception"] = e
                
        t = threading.Thread(target=target)
        t.start()
        t.join(timeout_seconds)
        
        if t.isAlive():
            # Thread is still running, meaning we timed out.
            # We cannot easily kill the thread in Jython/Java safely without deprecated methods,
            # so we abandon it.
            return None, "Connection failed (Timeout)"
        
        if result_holder["exception"]:
            return None, str(result_holder["exception"])
            
        return result_holder["response"], None

    # --- Cookie management -------------------------------------------------
    def _extract_hosts_from_input(self):
        """Return unique hostnames from the URL input box (keeps input order)."""
        hosts = []
        for line in self._url_input.getText().splitlines():
            for u in line.split(","):
                u = u.strip()
                if not u:
                    continue
                if not re.match(r"^https?://", u, re.I):
                    u = "https://" + u
                try:
                    h = urlparse.urlparse(u).hostname
                except Exception:
                    h = None
                if h and h not in hosts:
                    hosts.append(h)
        return hosts

    def load_hosts_into_combo(self, event):
        """Fill the Target drop-down with the hosts from the URL list."""
        current = self._cookie_target.getEditor().getItem()
        self._cookie_target.removeAllItems()
        for h in self._extract_hosts_from_input():
            self._cookie_target.addItem(h)
        if current:
            self._cookie_target.setSelectedItem(current)

    def _normalize_cookie(self, raw):
        """Strip a leading 'Cookie:', CR/LF (header injection) and trailing ';'."""
        if raw is None:
            return ""
        v = unicode(raw).replace("\r", "").replace("\n", "").strip()
        if v.lower().startswith("cookie:"):
            v = v[7:].strip()
        return v.rstrip(";").strip()

    def add_cookie_rule(self, event):
        item = self._cookie_target.getEditor().getItem()
        target = unicode(item).strip() if item else ""
        cookie = self._normalize_cookie(self._cookie_value.getText())
        if not target:
            JOptionPane.showMessageDialog(self._panel, "Please enter or select a Target (host / URL), or use 'Add to All Hosts'.")
            return
        if not cookie:
            JOptionPane.showMessageDialog(self._panel, "Please enter a cookie value, e.g. SESSIONID=abc123")
            return
        self._cookie_model.addRow([target, cookie])
        self._cookie_value.setText("")

    def add_cookie_all_hosts(self, event):
        cookie = self._normalize_cookie(self._cookie_value.getText())
        if not cookie:
            JOptionPane.showMessageDialog(self._panel, "Please enter a cookie value, e.g. SESSIONID=abc123")
            return
        self._cookie_model.addRow(["*", cookie])
        self._cookie_value.setText("")

    def remove_cookie_rule(self, event):
        if self._cookie_table.isEditing():
            self._cookie_table.getCellEditor().stopCellEditing()
        for r in sorted(list(self._cookie_table.getSelectedRows()), reverse=True):
            self._cookie_model.removeRow(r)

    def clear_cookie_rules(self, event):
        if self._cookie_table.isEditing():
            self._cookie_table.getCellEditor().stopCellEditing()
        self._cookie_model.setRowCount(0)

    def _snapshot_cookie_rules(self):
        """Copy table rows into a plain list (called on the Swing thread before scanning)."""
        if self._cookie_table.isEditing():
            self._cookie_table.getCellEditor().stopCellEditing()
        rules = []
        for i in range(self._cookie_model.getRowCount()):
            t = self._cookie_model.getValueAt(i, 0)
            c = self._cookie_model.getValueAt(i, 1)
            t = unicode(t).strip() if t else ""
            c = self._normalize_cookie(c)
            if t and c:
                rules.append((t, c))
        return rules

    @staticmethod
    def _default_port(scheme):
        return 443 if scheme == "https" else 80

    def _rule_matches(self, target, url_str):
        """Check whether a cookie rule target applies to the URL being requested."""
        t = target.strip().lower()
        if t == "*":
            return True
        up = urlparse.urlparse(url_str)
        u_host = (up.hostname or "").lower()
        u_port = up.port or self._default_port(up.scheme)

        # URL prefix rule: scheme + host + port must match, path is a prefix
        if t.startswith("http://") or t.startswith("https://"):
            tp = urlparse.urlparse(t)
            if tp.scheme != up.scheme.lower() or (tp.hostname or "") != u_host:
                return False
            if (tp.port or self._default_port(tp.scheme)) != u_port:
                return False
            t_path = tp.path or "/"
            u_path = (up.path or "/").lower()
            if t_path == "/" or u_path == t_path:
                return True
            return u_path.startswith(t_path.rstrip("/") + "/") or u_path.startswith(t_path)

        # Host rule (optionally host:port)
        t_port = None
        m = re.match(r"^(.*):(\d+)$", t)
        if m:
            t, t_port = m.group(1), int(m.group(2))
        if t_port is not None and t_port != u_port:
            return False
        if t.startswith("*."):
            base = t[2:]
            return u_host == base or u_host.endswith("." + base)
        return u_host == t

    def _cookies_for(self, url_str):
        """Combine all matching cookie rules into one Cookie header value."""
        values = []
        for target, cookie in self._cookie_rules:
            try:
                if self._rule_matches(target, url_str) and cookie not in values:
                    values.append(cookie)
            except Exception as e:
                print("Cookie rule error ({}): {}".format(target, e))
        return "; ".join(values)

    def _add_cookie_header(self, request_bytes, cookie_value):
        """Return a copy of the request with the Cookie header set/replaced."""
        req_info = self._helpers.analyzeRequest(request_bytes)
        new_headers = ArrayList()
        for h in req_info.getHeaders():
            if not h.lower().startswith("cookie:"):
                new_headers.add(h)
        new_headers.add("Cookie: " + cookie_value)
        body = request_bytes[req_info.getBodyOffset():]
        return self._helpers.buildHttpMessage(new_headers, body)
    # -------------------------------------------------------------------------

    # --- Button Action 1: Start Scan ---
    def start_scan(self, event):
        """Wrapper to run the scan in a new thread."""
        # Disable all buttons except Stop
        self._run_button.setEnabled(False)
        self._stop_button.setEnabled(True)
        self._report_button.setEnabled(False)
        self._details_button.setEnabled(False)
        self._save_button.setEnabled(False)
        
        self._run_button.setText("Scanning...")
        self._results_output.setText("<html><body>Starting scan...</body></html>")
        
        self._is_scanning = True
        
        # Clear old results
        self._last_scan_results = []
        self._first_example_data = None
        self._scan_lock = threading.Lock()

        # Take a snapshot of cookie rules (read on the Swing thread)
        self._cookie_rules = self._snapshot_cookie_rules()

        # Run the full scan
        thread = threading.Thread(target=self.scan_urls) 
        thread.start()

    def stop_scan(self, event):
        """Stops the running scan."""
        if self._is_scanning:
            self._is_scanning = False
            self._stop_button.setEnabled(False)
            self._results_output.setText("<html><body>Stopping scan... please wait for current request to finish.</body></html>")

    # --- Button Action 2: Show Report (Original Style) ---
    def show_report(self, event):
        """Shows the original report (summary table + example) from the last scan."""
        if not self._last_scan_results:
            self._results_output.setText("<html><body>No results to display. Please 'Run Scan' first.</body></html>")
            return
            
        report_html = self.generate_report_html(self._last_scan_results)
        self._results_output.setText(report_html)
        self._results_output.setCaretPosition(0)

    # --- Button Action 3: Show Details (Check.py Style) ---
    def show_details(self, event):
        """Shows detailed results (table per URL) from the last scan."""
        if not self._last_scan_results:
            self._results_output.setText("<html><body>No results to display. Please 'Run Scan' first.</body></html>")
            return
            
        details_html = self.generate_details_html(self._last_scan_results)
        self._results_output.setText(details_html)
        self._results_output.setCaretPosition(0)

    # --- Core Scan Logic (Runs in Thread) ---
    def process_single_url(self, original_url_str, results_summary):
        MAX_REDIRECTS = 5
        
        if not original_url_str:
            return
        
        # --- Protocol Guessing Logic ---
        targets_to_attempt = []
        lower_url = original_url_str.lower()
        if not lower_url.startswith("http://") and not lower_url.startswith("https://"):
            targets_to_attempt.append("https://" + original_url_str)
            targets_to_attempt.append("http://" + original_url_str)
        else:
            targets_to_attempt.append(original_url_str)

        response_to_analyze = None
        final_url_for_analysis = original_url_str
        header_details = {}
        scan_error_msg = None
        last_cookie_applied = False

        for attempt_url in targets_to_attempt:
            if not self._is_scanning: 
                return 
                
            current_url_str = attempt_url
            scan_error_msg = None 
            
            try:
                for redirect_count in range(MAX_REDIRECTS):
                    parsed_url = urlparse.urlparse(current_url_str)
                    host = parsed_url.hostname
                    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
                    is_https = parsed_url.scheme == "https"
                    
                    path = parsed_url.path if parsed_url.path else "/"
                    if not path.startswith("/"):
                        path = "/" + path
                        
                    if parsed_url.query:
                        path = path + "?" + parsed_url.query

                    url_obj = URL(parsed_url.scheme, host, port, path)
                    request_bytes = self._helpers.buildHttpRequest(url_obj)

                    # --- NEW: attach matching cookies ---
                    cookie_header = self._cookies_for(current_url_str)
                    if cookie_header:
                        request_bytes = self._add_cookie_header(request_bytes, cookie_header)
                    last_cookie_applied = bool(cookie_header)

                    http_service = self._helpers.buildHttpService(host, port, is_https)
                    
                    # Make request with 60s timeout
                    response, err_msg = self.make_request_with_timeout(http_service, request_bytes, 60)
                    
                    if err_msg:
                        raise Exception(err_msg)
                    
                    if not response:
                        raise Exception("Failed to connect (response is null)")

                    response_info = self._helpers.analyzeResponse(response.getResponse())
                    status_code = response_info.getStatusCode()

                    if status_code >= 300 and status_code < 400:
                        location_header = None
                        for h in response_info.getHeaders():
                            if h.lower().startswith("location:"):
                                location_header = h.split(":", 1)[1].strip()
                                break
                        
                        if location_header:
                            current_url_str = urlparse.urljoin(current_url_str, location_header)
                            final_url_for_analysis = current_url_str
                            continue
                        else:
                            response_to_analyze = response
                            break 
                    else:
                        response_to_analyze = response
                        final_url_for_analysis = current_url_str 
                        break
                
                if response_to_analyze:
                    break 

            except Exception as e:
                scan_error_msg = str(e)
        
        if not response_to_analyze:
            error_text = "Error scanning URL"
            if scan_error_msg:
                error_text += ": " + scan_error_msg
            with self._scan_lock:
                results_summary.append((original_url_str, final_url_for_analysis, error_text, {}, None))
            return

        try:
            response_info = self._helpers.analyzeResponse(response_to_analyze.getResponse())
            headers = response_info.getHeaders()
            
            present_headers_map = {}
            for h in headers:
                if ":" in h:
                    parts = h.split(":", 1)
                    present_headers_map[parts[0].strip().lower()] = parts[1].strip()

            missing = []
            header_details["_cookie_applied"] = last_cookie_applied
            final_url_scheme =urlparse.urlparse(final_url_for_analysis).scheme

            # 1. X-Content-Type-Options
            header_name_lower = "x-content-type-options"
            raw_value = present_headers_map.get(header_name_lower)
            status, note = _check_xcto_value(raw_value)
            header_details["X-Content-Type-Options"] = (status, raw_value or "", note)
            if status in ("Missing", "Weak"):
                missing.append("X-Content-Type-Options" + (" (Weak)" if status == "Weak" else ""))

            # 2. Referrer-Policy
            header_name_lower = "referrer-policy"
            if header_name_lower not in present_headers_map:
                missing.append("Referrer-Policy")
                header_details["Referrer-Policy"] = ("Missing", "", "")
            else:
                header_details["Referrer-Policy"] = ("Present", present_headers_map[header_name_lower], "")
                
            # 3. Permissions-Policy
            header_name_lower = "permissions-policy"
            if header_name_lower not in present_headers_map:
                missing.append("Permissions-Policy")
                header_details["Permissions-Policy"] = ("Missing", "", "")
            else:
                header_details["Permissions-Policy"] = ("Present", present_headers_map[header_name_lower], "")

            # 4. Strict-Transport-Security
            header_name_lower = "strict-transport-security"
            if final_url_scheme == "https":
                raw_value = present_headers_map.get(header_name_lower)
                status, note = _check_hsts_value(raw_value)
                header_details["Strict-Transport-Security"] = (status, raw_value or "", note)
                if status in ("Missing", "Weak"):
                    missing.append("Strict-Transport-Security" + (" (Weak)" if status == "Weak" else ""))
            else:
                header_details["Strict-Transport-Security"] = ("N/A (HTTP)", "", "HSTS only applies to HTTPS responses")

            # 5. CSP / XFO Logic
            csp_raw = present_headers_map.get("content-security-policy")
            csp_status, csp_note = _check_csp_value(csp_raw)
            header_details["Content-Security-Policy"] = (csp_status, csp_raw or "", csp_note)
            if csp_status in ("Missing", "Weak"):
                missing.append("Content-Security-Policy" + (" (Weak)" if csp_status == "Weak" else ""))

            has_frame_ancestors = bool(csp_raw) and "frame-ancestors" in csp_raw.lower()
            xfo_raw = present_headers_map.get("x-frame-options")
            if xfo_raw is None and has_frame_ancestors:
                header_details["X-Frame-Options"] = ("N/A (Covered by CSP)", "", "'frame-ancestors' directive present in CSP")
            else:
                xfo_status, xfo_note = _check_xfo_value(xfo_raw)
                header_details["X-Frame-Options"] = (xfo_status, xfo_raw or "", xfo_note)
                if xfo_status in ("Missing", "Weak"):
                    missing.append("X-Frame-Options" + (" (Weak)" if xfo_status == "Weak" else ""))

            # 6. X-XSS-Protection (deprecated - absence is fine, presence must be '0')
            xxss_raw = present_headers_map.get("x-xss-protection")
            xxss_status, xxss_note = _check_xxss_value(xxss_raw)
            header_details["X-XSS-Protection"] = (xxss_status, xxss_raw or "", xxss_note)
            if xxss_status == "Weak":
                missing.append("X-XSS-Protection (Weak)")

            # 7. Access-Control-Allow-Methods (only meaningful if server returned it)
            acam_raw = present_headers_map.get("access-control-allow-methods")
            acam_status, acam_note = _check_cors_methods_value(acam_raw)
            header_details["Access-Control-Allow-Methods"] = (acam_status, acam_raw or "", acam_note)
            if acam_status == "Weak":
                missing.append("Access-Control-Allow-Methods (Weak)")

            # 8. Cache-Control (+ Pragma / Expires / ETag as supporting evidence)
            cache_status, cache_note = _check_cache_control_value(present_headers_map)
            header_details["Cache-Control"] = (cache_status, present_headers_map.get("cache-control", ""), cache_note)
            if cache_status in ("Missing", "Weak"):
                missing.append("Cache-Control" + (" (Weak)" if cache_status == "Weak" else ""))

            missing_list_str = ", ".join(sorted(missing))
            if not missing_list_str:
                missing_list_str = "All required headers are present."
                
            # Store data for the first example
            example_data = None
            if missing:
                example_data = {
                    "url": original_url_str,
                    "final_url": final_url_for_analysis,
                    "headers": "\n".join(headers),
                    "missing": missing
                }
                with self._scan_lock:
                    if not self._first_example_data:
                        self._first_example_data = example_data
            
            with self._scan_lock:
                results_summary.append((original_url_str, final_url_for_analysis, missing_list_str, header_details, example_data))

        except Exception as e:
            import traceback
            print("Error scanning {}: {}".format(original_url_str, e))
            traceback.print_exc()
            with self._scan_lock:
                results_summary.append((original_url_str, original_url_str, "Error scanning URL", {}, None))

    def scan_urls(self):
        """
        The main scanning logic. Runs scan, saves results,
        and calls the UI update function.
        """
        lines = self._url_input.getText().splitlines()
        all_urls = []
        for line in lines:
            urls_on_line = [url.strip() for url in line.split(',')]
            all_urls.extend([url for url in urls_on_line if url])

        if not all_urls:
            SwingUtilities.invokeLater(lambda: self.finish_scan_ui())
            return

        # results_summary will store tuples:
        # (original_url, final_url, missing_list_string, header_details_dict, first_example_data_dict)
        results_summary = []
        
        # Thread pool
        MAX_THREADS = 20
        executor = Executors.newFixedThreadPool(MAX_THREADS)

        for original_url_str in all_urls:
            if not self._is_scanning:
                break
            executor.submit(lambda url=original_url_str: self.process_single_url(url, results_summary))
            
        executor.shutdown()
        
        try:
            # Wait for all tasks to finish or user to stop
            while not executor.awaitTermination(1, TimeUnit.SECONDS):
                if not self._is_scanning:
                    executor.shutdownNow()
                    break
        except Exception as e:
             print("Executor exception: " + str(e))
        
        # Save results for buttons
        self._last_scan_results = results_summary
        
        # Update UI in Swing thread
        SwingUtilities.invokeLater(self.finish_scan_ui)

    # --- UI Update Helper (Runs in Swing Thread) ---
    def finish_scan_ui(self):
        """Safely updates the UI from the scan thread."""
        self._is_scanning = False # Ensure flag is off
        self._run_button.setEnabled(True)
        self._run_button.setText("Run Scan")
        self._stop_button.setEnabled(False)
        
        if self._last_scan_results:
            self._report_button.setEnabled(True)
            self._details_button.setEnabled(True)
            self._save_button.setEnabled(True)
            self._results_output.setText("<html><body>Scan complete (or stopped). Click 'Report' or 'Show Details' to view results.</body></html>")
        else:
            self._results_output.setText("<html><body>Scan complete. No URLs were processed.</body></html>")
            
        self._results_output.setCaretPosition(0)
        print("Scan complete.")

    # --- HTML Generator 1: Report (Summary + Example) ---
    def generate_report_html(self, results):
        """Generates the HTML for the main summary table + example."""
        report_html = ["<html><body style='font-family: Monospaced; font-size: 12px;'>"]
        
        # --- 1. Summary Table ---
        report_html.append("<h2>The following table provides the target hosts that HTTP security headers are missing.</h2>")
        report_html.append("<table border='1' cellpadding='5' cellspacing='0' style='border-collapse: collapse; font-size: 12px;'>")
        report_html.append("<tr style='background-color: #f0f0f0;'>")
        report_html.append("<th>URL</th>")
        report_html.append("<th>Missing HTTP Security Header</th>")
        report_html.append("</tr>")
        
        first_example_data = None

        for orig_url, final_url, missing_list, header_details, example_data in results:
            if "Timeout" in missing_list:
                continue

            report_html.append("<tr>")
            report_html.append("<td>{}</td>".format(cgi.escape(final_url)))
            
            color = "orange"
            if "Error" in missing_list:
                color = "red"
            elif "All" in missing_list:
                color = "green"
            
            report_html.append("<td style='color: {};'><b>{}</b></td>".format(color, cgi.escape(missing_list)))
            report_html.append("</tr>")
            
            # Find the first example with missing headers
            if not first_example_data and example_data:
                first_example_data = example_data

        report_html.append("</table>")
        report_html.append("<hr>")

        # --- 2. Example Section ---
        if first_example_data:
            report_html.append("<h2>The following HTTP response was analyzed and identified that the HTTP security headers are missing.</h2>")
            
            report_html.append("<p><b>Example URL:</b> {}</p>".format(cgi.escape(first_example_data["url"])))
            
            # --- BUG FIX: Normalize URLs before comparing ---
            orig_url_norm = first_example_data["url"].rstrip('/')
            final_url_norm = first_example_data["final_url"].rstrip('/')
            
            if orig_url_norm != final_url_norm:
                report_html.append("<p><b>Final URL Analyzed:</b> {}</p>".format(cgi.escape(first_example_data["final_url"])))
            # --- END BUG FIX ---
            
            report_html.append("<pre style='background-color: #eee; border: 1px solid #ccc; padding: 10px; word-wrap: break-word; white-space: pre-wrap;'>")
            report_html.append(cgi.escape(first_example_data["headers"]))
            report_html.append("</pre>")
            
            report_html.append("<p>The result points toward the fact that the following HTTP security headers are not properly configured.</p>")
            report_html.append("<ul>")
            for m in sorted(first_example_data["missing"]):
                report_html.append("<li>{}</li>".format(cgi.escape(m)))
            report_html.append("</ul>")

        elif not results:
             report_html.append("<p>No URLs were scanned.</p>")
        else:
            report_html.append("<p>No missing headers found in the scanned URLs.</p>")

        report_html.append("</body></html>")
        return "\n".join(report_html)

    # --- HTML Generator 2: Detailed View ---
    def generate_details_html(self, results):
        """Generates the HTML for the detailed analysis view (table per URL)."""
        report_html = ["<html><body style='font-family: Monospaced; font-size: 12px;'>"]
        report_html.append("<h2>Detailed Header Analysis</h2>")
        
        if not results:
            report_html.append("<p>No results to display. Run a scan first.</p>")
            report_html.append("</body></html>")
            return "\n".join(report_html)

        for orig_url, final_url, missing_list, header_details, example_data in results:
            report_html.append("<h3>Analysis for: {}</h3>".format(cgi.escape(orig_url)))
            
            # --- BUG FIX: Normalize URLs before comparing ---
            orig_url_norm = orig_url.rstrip('/')
            final_url_norm = final_url.rstrip('/')
            
            if orig_url_norm != final_url_norm:
                report_html.append("<p><b>Final URL:</b> {}</p>".format(cgi.escape(final_url)))
            # --- END BUG FIX ---
            
            if not header_details:
                if "Error" in missing_list or "Timeout" in missing_list:
                     report_html.append("<p style='color:red;'><b>Error: {}</b></p>".format(cgi.escape(missing_list)))
                else:
                    report_html.append("<p><i>No header data to display (scan may have failed).</i></p>")
                report_html.append("<br>")
                continue

            if header_details.get("_cookie_applied"):
                report_html.append("<p style='color:#336699;'><i>Authenticated request: cookie was sent with this request.</i></p>")

            report_html.append("<table border='1' cellpadding='5' cellspacing='0' style='border-collapse: collapse; font-size: 12px;'>")
            report_html.append("<tr style='background-color: #f0f0f0;'>")
            report_html.append("<th>Header Name</th>")
            report_html.append("<th>Status</th>")
            report_html.append("<th>Value</th>")
            report_html.append("<th>Note</th>")
            report_html.append("</tr>")

            # Loop through the headers in our defined order
            for header_name_in_order in HEADERS_TO_CHECK:
                if header_name_in_order in header_details:
                    status, value, note = header_details[header_name_in_order]
                    
                    color = "black"
                    if status == "Missing":
                        color = "red"
                    elif status == "Weak":
                        color = "orange"
                    elif status == "Present":
                        color = "green"
                    elif "N/A" in status:
                        color = "gray"

                    report_html.append("<tr>")
                    report_html.append("<td>{}</td>".format(cgi.escape(header_name_in_order)))
                    report_html.append("<td style='color: {};'><b>{}</b></td>".format(color, cgi.escape(status)))
                    report_html.append("<td>{}</td>".format(cgi.escape(value)))
                    report_html.append("<td>{}</td>".format(cgi.escape(note) if note else ""))
                    report_html.append("</tr>")
            
            report_html.append("</table>")
        report_html.append("</body></html>")
        return "\n".join(report_html)

    # --- Button Action 4: Save Options ---
    def show_save_options(self, event):
        """Shows a dialog to choose between saving a Summary Report (CSV) or Full Details (HTML)."""
        if not self._last_scan_results:
            return

        options = ["Summary Report (CSV)", "Full Result (HTML)"]
        choice = JOptionPane.showOptionDialog(
            self._panel,
            "Select the type of file to save:",
            "Save Options",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            None,
            options,
            options[0]
        )

        if choice == 0:
            self.save_summary_csv()
        elif choice == 1:
            self.save_details_html()

    def save_summary_csv(self):
        """
        Option 1: Save Report (CSV).
        Only includes domains where headers are actually missing.
        """
        import csv
        import StringIO
        
        # Filter results
        filtered_results = []
        for res in self._last_scan_results:
            # res structure: (orig_url, final_url, missing_list_str, details_dict, example_data)
            missing_str = res[2]
            
            # Logic: If "Error" or "All required" is in the string, it's not a "missing header" case for the report table.
            if "Error" in missing_str:
                continue
            if "All required headers are present" in missing_str:
                continue
                
            filtered_results.append(res)
            
        if not filtered_results:
            JOptionPane.showMessageDialog(self._panel, "No domains with missing headers found to export.")
            return

        # Generate CSV
        output = StringIO.StringIO()
        csv_writer = csv.writer(output, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(['URL', 'Missing HTTP Security Headers'])
        
        for res in filtered_results:
            csv_writer.writerow([res[1], res[2]]) # Final URL, Missing List

        self._write_to_file("MissingHeader_Report.csv", output.getvalue())

    def save_details_html(self):
        """
        Option 2: Save Result (HTML).
        Saves the exact content of the 'Show Details' view.
        """
        html_content = self.generate_details_html(self._last_scan_results)
        self._write_to_file("Scan_Result_Details.html", html_content)

    def _write_to_file(self, default_name, content):
        """Helper to write content to a file chosen by the user."""
        chooser = JFileChooser()
        chooser.setSelectedFile(File(default_name))
        chooser.setDialogTitle("Save File")
        
        user_selection = chooser.showSaveDialog(self._panel)
        
        if user_selection == JFileChooser.APPROVE_OPTION:
            file_to_save = chooser.getSelectedFile()
            try:
                writer = BufferedWriter(FileWriter(file_to_save))
                writer.write(content)
                writer.close()
                print("File saved to: " + file_to_save.getAbsolutePath())
                
                SwingUtilities.invokeLater(lambda: self._results_output.setText(
                    "<html><body>"
                    "File successfully saved to:<br><b>" + file_to_save.getAbsolutePath() + "</b>"
                    "</body></html>"
                ))
            except Exception as e:
                import traceback
                traceback.print_exc()
                SwingUtilities.invokeLater(lambda: self._results_output.setText(
                    "<html><body>Error saving file: " + str(e) + "</body></html>"
                ))