Missing Header Checker (Burp Suite Extension)
A professional Burp Suite extension, written in Python (Jython), designed to efficiently scan multiple targets for missing HTTP security headers without freezing the UI.

<img width="984" height="429" alt="Screenshot 2569-02-02 at 02 07 31" src="https://github.com/user-attachments/assets/6d70eb63-a61a-496c-b2ad-4afb728fd528" />

🌟 Key Features
Smart Input Support: Supports full URLs (https://example.com) or just naked domains (example.com). The extension automatically guesses the protocol and follows redirects to the final destination.


Asynchronous Scanning: Runs scans in the background using a thread pool, ensuring Burp Suite's UI remains responsive during large-scale tests.

Enhanced 5-Button UI:

- Run Scan: Executes the scan in a background thread.
- Stop: Allows immediate cancellation of an ongoing scan.
- Report: Displays a high-level summary table and a detailed finding example for reporting.
- Show Details: Provides a granular breakdown (Status + Value) for every header across all targets.
- Save: Export findings into two professional formats: Summary Report (CSV) for quick stats or Full Result (HTML) for detailed records.

Comprehensive Header Coverage:

- X-Content-Type-Options 
- Referrer-Policy 
- Permissions-Policy 
- Strict-Transport-Security (HSTS) 
- Content-Security-Policy (CSP) 
- X-Frame-Options (XFO) (With logic to detect if covered by CSP frame-ancestors) 

🛠️ Installation
Requirements:
- Burp Suite (Pro or Community)
- Jython Standalone JAR (v2.7.x)

Steps:
Open Burp Suite.
1. Go to Extensions > Extension Settings > Python Environment.
2. Select your jython-standalone.jar file.
3. Go to Extensions > Installed > Add.
4. Set Extension type to Python and select MissingHeadersCheck.py.
5. The "Missing Headers" tab will appear once loaded.

🖱️ Usage
1. Navigate to the "Missing Headers" tab.
2. Input your targets (URLs or Domains) separated by commas or new lines.
3. Click "Run Scan".
4. Use "Report" or "Show Details" to view findings within Burp.
5. Click "Save..." to export your results as a CSV report or a full HTML analysis.
