# 🛡️ Domain Recon Tool (OSINT Recon Platform)

> **Passive Domain Intelligence & Perimeter Reconnaissance Platform**  
> Fast, multi-threaded intelligence gathering with zero paid API keys, structured JSON/HTML reporting, and an Executive Obsidian web dashboard.

🌐 **Live Web Application:** [https://domainrecontool.vercel.app](https://domainrecontool.vercel.app)  
📁 **Repository:** [https://github.com/Surajgore007/domain_recon_tool](https://github.com/Surajgore007/domain_recon_tool)

---

## 💡 What Is This Project?

**Domain Recon Tool** is an automated reconnaissance tool designed for security analysts, penetration testers, and developers to analyze external attack surfaces and domain configurations.

It performs passive reconnaissance across **9 parallel vectors** without touching paid intelligence feeds or requiring heavy SIEM setups.

---

## ⚡ Key Modules (What It Finds)

| Module | Source / Method | What It Analyzes |
| :--- | :--- | :--- |
| **🌐 DNS** | System Resolver | Resolves A, AAAA, MX, NS, TXT, CNAME, and SOA records |
| **🏢 WHOIS** | Public WHOIS | Registrar info, creation/expiration dates, nameservers, contact org |
| **🔍 Subdomains** | Certificate Transparency (`crt.sh`) | Passively discovers subdomains from public SSL/TLS certificate logs |
| **🛡️ Headers** | HTTP / HTTPS Probe | Analyzes 7 defensive headers (HSTS, CSP, X-Frame-Options, etc.) + 0–100% score |
| **🔌 Ports** | Parallel TCP Connect | Checks 18 common ports; flags critical risks (SMB 445, RDP 3389, Telnet 23, Redis, MongoDB) |
| **🔒 TLS / SSL** | SSL Handshake | Validates cipher suites, expiration countdown, issuer, and SANs |
| **✉️ Email Security** | DNS TXT Probes | Evaluates SPF policies, common DKIM selectors, and DMARC enforcement |
| **⚙️ Tech Stack** | HTTP Headers & Signatures | Fingerprints web servers (Nginx, Apache, Cloudflare), frameworks, and CMS |
| **⏳ Wayback** | Archive.org CDX API | Extracts historical snapshots and exposes sensitive endpoints (`.env`, `admin`, `api`) |

---

## 🖥️ Interactive Web Dashboard (GUI)

The web dashboard features an **Executive Obsidian Slate** UI with zero neon clichés, providing real-time Server-Sent Events (SSE) streaming progress, KPI scorecards, interactive deep-dive tabs, and 1-click report exports.

### Running Locally:

```bash
# 1. Clone repository
git clone https://github.com/Surajgore007/domain_recon_tool.git
cd domain_recon_tool

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch Dashboard:
# Option A (Windows shortcut):
run_gui.bat

# Option B (Python auto-launch):
python run_gui.py

# Option C (FastAPI server directly):
python app.py
```

Open your browser at **http://127.0.0.1:8000**.

---

## 💻 CLI Usage (Terminal Mode)

You can also run reconnaissance directly from the command line:

```bash
# Run all 9 modules
python recon.py example.com

# Run specific modules only
python recon.py example.com --modules dns,crtsh,headers,email

# Custom timeout and output format
python recon.py example.com --timeout 20 --format both --output reports
```

### CLI Flags:
- `--modules` / `-m`: Comma-separated list (`dns,whois,crtsh,headers,ports,tls,email,tech,wayback`). Default: `all`.
- `--output` / `-o`: Directory to store generated reports (default: `reports/`).
- `--format` / `-f`: Output format: `json`, `html`, or `both`.
- `--timeout` / `-t`: Timeout in seconds per module (default: `10`).

---

## 📊 Reports & Output

Every scan automatically generates structured reports in `reports/`:
- **`target_YYYYMMDD_HHMMSS.json`**: Machine-readable raw JSON data.
- **`target_YYYYMMDD_HHMMSS.html`**: Self-contained, dark-mode visual HTML report suitable for client delivery.

---

## 📂 Project Structure

```
domain_recon_tool/
├── app.py                  # FastAPI web server (REST + SSE streaming)
├── run_gui.py              # Auto-launch Python script for local GUI
├── run_gui.bat             # 1-click Windows batch launcher
├── recon.py                # Command-line interface orchestrator
├── reporter.py             # JSON and HTML report generation engine
├── vercel.json             # Vercel serverless routing configuration
├── requirements.txt        # Python package dependencies
├── api/
│   └── index.py            # Vercel serverless ASGI entrypoint
├── modules/
│   ├── dns_module.py       # DNS enumeration
│   ├── whois_module.py     # WHOIS lookup
│   ├── crtsh_module.py     # Certificate Transparency subdomain discovery
│   ├── headers_module.py   # HTTP security headers audit
│   ├── portscan.py         # Perimeter port & service scanner
│   ├── tls_module.py       # TLS/SSL cryptographic assessment
│   ├── email_security.py   # SPF, DKIM, and DMARC analyzer
│   ├── tech_fingerprint.py # Technology stack signature detection
│   └── wayback.py          # Historical archive endpoint discovery
└── static/
    ├── index.html          # Executive Obsidian dashboard SPA
    ├── css/style.css       # Obsidian Slate styling & design system
    └── js/app.js           # Live SSE stream receiver & interactive UI logic
```

---

## ⚖️ Legal Disclaimer

*This tool is intended strictly for authorized security auditing, defensive assessment, and authorized educational research. Always obtain written authorization before scanning third-party infrastructure.*
