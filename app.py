import os
import sys
import json
import socket
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Import modules and reporter from current directory
from modules import (
    dns_module,
    whois_module,
    crtsh_module,
    headers_module,
    portscan,
    tls_module,
    email_security,
    tech_fingerprint,
    wayback,
)
from reporter import generate_report

app = FastAPI(
    title="OSINT Recon Web Platform",
    description="Professional Passive Domain Reconnaissance Intelligence Dashboard",
    version="2.0.0"
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

# Handle read-only filesystems (e.g. Vercel/serverless /tmp directory)
try:
    REPORTS_DIR = BASE_DIR / "reports"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    _test = REPORTS_DIR / ".write_check"
    _test.touch()
    _test.unlink()
except (OSError, PermissionError):
    import tempfile
    REPORTS_DIR = Path(tempfile.gettempdir()) / "osint_reports"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

MODULES = {
    "dns":     {"func": dns_module.run, "name": "DNS Enumeration", "category": "Network", "desc": "Resolves A, AAAA, MX, NS, TXT, CNAME, SOA records"},
    "whois":   {"func": whois_module.run, "name": "WHOIS Registration", "category": "Identity", "desc": "Registrar, creation, expiration, contacts & nameservers"},
    "crtsh":   {"func": crtsh_module.run, "name": "Certificate Transparency", "category": "Discovery", "desc": "Passive subdomain enumeration via crt.sh logs"},
    "headers": {"func": headers_module.run, "name": "Security Headers", "category": "Web Security", "desc": "Evaluates HSTS, CSP, X-Frame-Options, Referrer-Policy & score"},
    "ports":   {"func": portscan.run, "name": "Port & Service Scanner", "category": "Network", "desc": "Probes 18 common ports & flags high-risk exposures (SMB, RDP, Telnet, DBs)"},
    "tls":     {"func": tls_module.run, "name": "TLS/SSL Certificate", "category": "Cryptography", "desc": "Cipher suites, certificate validity, expiration & SANs"},
    "email":   {"func": email_security.run, "name": "Email Security Posture", "category": "Identity", "desc": "Inspects SPF, DKIM selectors & DMARC enforcement policies"},
    "tech":    {"func": tech_fingerprint.run, "name": "Technology Fingerprint", "category": "Intelligence", "desc": "Detects web servers, frameworks, CDNs, CMS & analytics signatures"},
    "wayback": {"func": wayback.run, "name": "Wayback Machine Archive", "category": "Historical", "desc": "Discovers archived URLs, snapshots & interesting endpoints (.env, admin, api)"},
}

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain, e.g. example.com")
    modules: Optional[List[str]] = Field(default=None, description="List of modules to execute")
    timeout: Optional[int] = Field(default=15, ge=3, le=60, description="Per-module timeout in seconds")
    save_report: Optional[bool] = Field(default=True, description="Whether to save JSON & HTML reports to disk")

def clean_domain(domain: str) -> str:
    cleaned = domain.strip().lower()
    cleaned = cleaned.removeprefix("http://").removeprefix("https://")
    cleaned = cleaned.split("/")[0].split("?")[0].split(":")[0]
    return cleaned

def summarize_module_result(mod: str, data: dict) -> dict:
    if "error" in data:
        return {"status": "error", "summary": data.get("error", "Error")}
    
    if mod == "dns":
        count = sum(len(v) for v in data.values() if isinstance(v, list))
        return {"status": "ok", "summary": f"{count} DNS records resolved"}
    elif mod == "whois":
        reg = data.get("registrar") or "Unknown Registrar"
        exp = data.get("expiration_date") or ""
        return {"status": "ok", "summary": f"Registrar: {reg}"}
    elif mod == "crtsh":
        subs = len(data.get("subdomains", []))
        return {"status": "ok", "summary": f"{subs} subdomains discovered"}
    elif mod == "headers":
        https_data = data.get("https", {})
        score = https_data.get("security_score", 0)
        return {"status": "ok", "summary": f"Security score: {score}%"}
    elif mod == "ports":
        open_p = len(data.get("open_ports", []))
        risky_p = len(data.get("risky", []))
        return {"status": "ok", "summary": f"{open_p} open ports ({risky_p} risky)"}
    elif mod == "tls":
        cert = data.get("cert", {})
        days = cert.get("days_left", "?")
        ver = data.get("negotiated_version", "TLS")
        return {"status": "ok", "summary": f"{ver} · {days} days valid"}
    elif mod == "email":
        score = data.get("score", 0)
        spf = "SPF✓" if data.get("spf", {}).get("present") else "SPF✗"
        dmarc = "DMARC✓" if data.get("dmarc", {}).get("present") else "DMARC✗"
        return {"status": "ok", "summary": f"Score {score}% ({spf}, {dmarc})"}
    elif mod == "tech":
        tot = data.get("total", 0)
        return {"status": "ok", "summary": f"{tot} technologies detected"}
    elif mod == "wayback":
        snaps = data.get("total_snapshots", 0)
        inter = len(data.get("interesting", []))
        return {"status": "ok", "summary": f"{snaps} snapshots, {inter} endpoints"}
    return {"status": "ok", "summary": "Finished successfully"}

@app.get("/api/modules")
def get_available_modules():
    return [
        {
            "id": k,
            "name": v["name"],
            "category": v["category"],
            "description": v["desc"],
            "default": True
        }
        for k, v in MODULES.items()
    ]

@app.post("/api/scan")
def execute_scan(req: ScanRequest):
    target = clean_domain(req.target)
    if not target or "." not in target:
        raise HTTPException(status_code=400, detail="Invalid domain target specified.")
    
    selected_mods = req.modules or list(MODULES.keys())
    valid_mods = [m for m in selected_mods if m in MODULES]
    if not valid_mods:
        raise HTTPException(status_code=400, detail="No valid modules selected.")
    
    results = {}
    with ThreadPoolExecutor(max_workers=min(len(valid_mods), 12)) as executor:
        futures = {
            executor.submit(MODULES[m]["func"], target, req.timeout): m
            for m in valid_mods
        }
        for future in as_completed(futures):
            mod_name = futures[future]
            try:
                results[mod_name] = future.result()
            except Exception as e:
                results[mod_name] = {"error": str(e)}

    report_payload = {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "modules": results
    }

    report_paths = {}
    if req.save_report:
        saved = generate_report(report_payload, REPORTS_DIR, "both")
        report_paths = {k: v.name for k, v in saved.items()}

    return {
        "target": target,
        "timestamp": report_payload["timestamp"],
        "modules": results,
        "saved_reports": report_paths
    }

@app.get("/api/scan/stream")
def execute_scan_stream(
    target: str = Query(..., description="Target domain"),
    modules: Optional[str] = Query(None, description="Comma-separated module names"),
    timeout: int = Query(15, ge=3, le=60, description="Timeout seconds per module"),
    save_report: bool = Query(True, description="Save report to reports folder")
):
    cleaned = clean_domain(target)
    if not cleaned or "." not in cleaned:
        def err_stream():
            yield f"event: error\ndata: {json.dumps({'error': 'Invalid domain format. Enter a valid domain e.g. domain.com'})}\n\n"
        return StreamingResponse(err_stream(), media_type="text/event-stream")

    if modules:
        selected_mods = [m.strip() for m in modules.split(",") if m.strip() in MODULES]
    else:
        selected_mods = list(MODULES.keys())

    if not selected_mods:
        selected_mods = list(MODULES.keys())

    def event_generator():
        yield f"event: start\ndata: {json.dumps({'target': cleaned, 'modules': selected_mods, 'total': len(selected_mods)})}\n\n"

        results = {}
        completed_count = 0
        total = len(selected_mods)

        with ThreadPoolExecutor(max_workers=min(total, 12)) as executor:
            futures = {
                executor.submit(MODULES[m]["func"], cleaned, timeout): m
                for m in selected_mods
            }
            for future in as_completed(futures):
                mod_name = futures[future]
                completed_count += 1
                try:
                    res = future.result()
                    results[mod_name] = res
                    summary_info = summarize_module_result(mod_name, res)
                    payload = {
                        "module": mod_name,
                        "progress": round((completed_count / total) * 100),
                        "completed_count": completed_count,
                        "total": total,
                        "status": summary_info["status"],
                        "summary": summary_info["summary"],
                        "data": res
                    }
                except Exception as e:
                    err_res = {"error": str(e)}
                    results[mod_name] = err_res
                    payload = {
                        "module": mod_name,
                        "progress": round((completed_count / total) * 100),
                        "completed_count": completed_count,
                        "total": total,
                        "status": "error",
                        "summary": str(e),
                        "data": err_res
                    }
                yield f"event: module_done\ndata: {json.dumps(payload)}\n\n"

        full_payload = {
            "target": cleaned,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "modules": results
        }

        saved_files = {}
        if save_report:
            try:
                paths = generate_report(full_payload, REPORTS_DIR, "both")
                saved_files = {k: v.name for k, v in paths.items()}
            except Exception as e:
                saved_files = {"error": str(e)}

        complete_event = {
            "target": cleaned,
            "timestamp": full_payload["timestamp"],
            "saved_reports": saved_files,
            "results": full_payload
        }
        yield f"event: complete\ndata: {json.dumps(complete_event)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@app.get("/api/reports")
def list_reports():
    reports = []
    for file in sorted(REPORTS_DIR.glob("*.json"), key=os.path.getmtime, reverse=True):
        try:
            stat = file.stat()
            # Corresponding HTML
            html_file = file.with_suffix(".html")
            has_html = html_file.exists()

            with open(file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            target = data.get("target", file.stem.split("_")[0])
            ts = data.get("timestamp", datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat())
            mods = list(data.get("modules", {}).keys())

            reports.append({
                "id": file.stem,
                "json_file": file.name,
                "html_file": html_file.name if has_html else None,
                "target": target,
                "timestamp": ts,
                "modules": mods,
                "size_bytes": stat.st_size
            })
        except Exception:
            continue
    return reports

@app.get("/api/reports/{filename}")
def get_report_content(filename: str):
    file_path = REPORTS_DIR / filename
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report file not found")
    
    if filename.endswith(".json"):
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    elif filename.endswith(".html"):
        return FileResponse(file_path, media_type="text/html")
    else:
        raise HTTPException(status_code=400, detail="Unsupported file format")

@app.delete("/api/reports/{report_id}")
def delete_report(report_id: str):
    json_path = REPORTS_DIR / f"{report_id}.json"
    html_path = REPORTS_DIR / f"{report_id}.html"
    deleted = []
    if json_path.exists():
        json_path.unlink()
        deleted.append(json_path.name)
    if html_path.exists():
        html_path.unlink()
        deleted.append(html_path.name)
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"message": "Report deleted successfully", "deleted": deleted}

# Static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", response_class=HTMLResponse)
def index():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>Dashboard index.html is being prepared...</h1>")
    return HTMLResponse(index_file.read_text(encoding="utf-8"))

def main():
    import uvicorn
    import webbrowser
    
    host = "127.0.0.1"
    port = 8000
    print(f"\n" + "="*60)
    print(f"  OSINT Reconnaissance Web Dashboard")
    print(f"  Local URL: http://{host}:{port}")
    print(f"="*60 + "\n")
    
    # Optionally open browser
    try:
        webbrowser.open(f"http://{host}:{port}")
    except Exception:
        pass
    
    uvicorn.run("app:app", host=host, port=port, reload=True)

if __name__ == "__main__":
    main()
