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

## ⚡ Key Intelligence Modules (What It Finds)

| Module | Source / Method | What It Analyzes |
| :--- | :--- | :--- |
| **🌐 DNS & IP Intel** | DNS + IP-API Geolocation | Resolves A, AAAA, MX, NS, TXT, CNAME, SOA, and CAA records; enriches primary IP with ASN, ISP, country, city, and reverse PTR |
| **🏢 WHOIS** | Hybrid RDAP (HTTPS) + Socket | Resilient domain registration extraction (registrar, created/expiration dates, nameservers, organization) with 100% serverless/cloud compatibility |
| **🔍 Subdomains** | crt.sh + HackerTarget Passive DNS | Discovers subdomains from certificate transparency logs and passive DNS with live resolved IP address mapping (`HOSTED_ON`) |
| **🛡️ Headers** | HTTP / HTTPS Audit | Analyzes 7 defensive headers (HSTS, CSP, X-Frame-Options, etc.), server version disclosures, 0–100% score, and copy-paste remediation directives |
| **🔌 Ports** | Parallel TCP Connect | Scans common perimeter ports; checks reachability, flags risky exposures (SMB, RDP, Telnet, Redis, MongoDB), and assesses host risk |
| **🔒 TLS / SSL** | SSL Handshake + DER Decoder | Validates cipher suites, protocol versions (TLS 1.0–1.3), expiration countdown, issuer, and SANs; resilient against expired/self-signed certs |
| **✉️ Email Security** | DNS SPF / DKIM / DMARC | Audits MX mail providers, probes 19 DKIM selectors, checks DMARC enforcement policies, and computes an explicit Domain Spoofing Risk verdict |
| **⚙️ Tech Stack** | HTTP Headers & Signatures | Fingerprints 60+ technologies across web servers (Nginx, Apache, GWS, Cloudflare), languages (PHP), frontend frameworks, CMS, and analytics |
| **⏳ Wayback** | Archive.org CDX API | Extracts historical snapshots and exposes sensitive historical routes (`.env`, `admin`, `api`, `config`, `.git`) |

---

## 🌐 Interactive Force-Directed Topology Graph

The web dashboard includes an interactive force-directed canvas graph that maps the target domain's perimeter infrastructure:
- **Central Domain Node**: Core apex target.
- **Subdomain Nodes**: Discovered child domains linked to parent infrastructure.
- **IP Infrastructure Nodes**: Enriched with hosting provider, ASN, and country location, with direct `HOSTED_ON` links to resolving subdomains.
- **Nameservers & Mail Exchangers**: Visual mapping of DNS and mail routing redundancy.


---

## 🖥️ Interactive Web Dashboard (GUI)

The web dashboard features an **Executive Obsidian Slate** UI with zero neon clichés, providing real-time Server-Sent Events (SSE) streaming progress, KPI scorecards, interactive deep-dive tabs, and 1-click report exports.

### Running Locally:

```bash
# 1. Clone repository
git clone https://github.com/Surajgore007/domain_recon_tool.git
cd domain_recon_tool

# 2. (Recommended) Create and activate virtual environment
# On Windows:
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# On Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch Dashboard:
# Option A (Windows 1-click):
run_gui.bat

# Option B (Python launcher - auto-opens browser):
python run_gui.py

# Option C (FastAPI server directly):
python app.py
```

Open your browser at **http://127.0.0.1:8000**.

---

## 💻 CLI Usage (Terminal Mode)

You can also run reconnaissance directly from the command line. Make sure your virtual environment is active so required dependencies (`rich`, `dnspython`, `requests`, etc.) are accessible:

```bash
# Ensure virtual environment is active
# Windows: .\.venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate

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
- **`target_YYYYMMDD_HHMMSS.html`**: Self-contained, dark-mode visual HTML report suitable for client delivery and offline auditing.

---

## ☁️ Deployment

### 1. Vercel (Serverless)
The repository is pre-configured with `vercel.json` and `api/index.py`:
- Push to GitHub and import the repository into [Vercel](https://vercel.com).
- Vercel automatically runs the FastAPI backend via AWS Lambda serverless functions.
- Reports automatically fallback to `/tmp/osint_reports` on serverless read-only filesystems.

### 2. Render / Railway / Heroku (PaaS Containers)
The repository includes `Procfile`, `runtime.txt`, and `main.py`:
- **Procfile**: `web: uvicorn app:app --host 0.0.0.0 --port $PORT`
- **Runtime**: Python 3.11
- Deploy as a Web Service on Render or Railway with 1 click from your GitHub repo.

---

## 📂 Project Structure

```
domain_recon_tool/
├── app.py                  # FastAPI web server (REST + SSE streaming)
├── main.py                 # ASGI entrypoint for Render / Heroku / local servers
├── run_gui.py              # Auto-launch Python script for local GUI
├── run_gui.bat             # 1-click Windows batch launcher
├── recon.py                # Command-line interface orchestrator (Rich UI)
├── reporter.py             # JSON and HTML report generation engine
├── vercel.json             # Vercel serverless routing configuration
├── Procfile                # Process definition for Render / Railway / Heroku
├── runtime.txt             # Python 3.11 runtime specification
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
├── reports/                # Output directory for generated JSON & HTML reports
└── static/
    ├── index.html          # Executive Obsidian dashboard SPA
    ├── css/style.css       # Obsidian Slate styling & design system
    └── js/app.js           # Live SSE stream receiver & interactive UI logic
```

---

## ⚖️ Legal Disclaimer

*This tool is intended strictly for authorized security auditing, defensive assessment, and authorized educational research. Always obtain written authorization before scanning third-party infrastructure.*

