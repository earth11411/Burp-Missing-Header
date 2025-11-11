# Missing Header Checker (Burp Suite Extension)

A Burp Suite extension, written in Python (Jython), to scan websites for missing HTTP security headers.


<img width="1268" height="673" alt="Screenshot 2568-11-11 at 18 04 30" src="https://github.com/user-attachments/assets/738f572f-a24c-4492-867e-c91fa2e01b99" />


---

## 🌟 Features

* **Follows Redirects:** Automatically follows 30x redirects to scan the final destination page.
* **Multi-URL Input:** Scan multiple URLs at once (comma-separated or on new lines).
* **3-Button UI:**
    * **Run Scan:** Performs the scan in the background.
    * **Report:** Shows a high-level summary table (color-coded) and an example of the first finding.
    * **Show Details:** Provides a detailed breakdown (Present/Missing + Value) for every header, for every URL scanned.
* **Headers Checked:**
    * X-Content-Type-Options
    * Referrer-Policy
    * Permissions-Policy
    * Strict-Transport-Security (HSTS)
    * Content-Security-Policy (CSP)
    * X-Frame-Options (XFO)

---

## 🛠️ Installation

1.  **Requirements:**
    * Burp Suite (Pro or Community)
    * [Jython Standalone JAR](https://www.jython.org/download) (v2.7.x)

2.  **Steps:**
    * Open Burp Suite.
    * Go to the **Extender** tab > **Options** tab.
    * Under "Python Environment", click **"Select file"** and choose your `jython-standalone.jar` file.
    * Go to the **Extender** tab > **Extensions** tab.
    * Click **"Add"**.
    * Under "Extension Details", set **Extension type** to **Python**.
    * Click **"Select file"** and choose the `MissingHeadersCheck.py` file.
    * Click **"Next"**. The extension should load, and a new "Missing Headers" tab will appear.

---

## 🖱️ Usage

1.  Go to the **"Missing Headers"** tab.
2.  Paste one or more target URLs into the text box (e.g., `https://google.com`).
3.  Click **"Run Scan"**.
4.  Wait for the scan to complete (a message will appear).
5.  Click **"Report"** for the summary table or **"Show Details"** for the full breakdown.
