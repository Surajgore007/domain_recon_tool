import requests

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

HEADER_REMEDIATIONS = {
    "Strict-Transport-Security": {
        "risk": "Susceptible to SSL stripping and man-in-the-middle (MITM) downgrade attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "risk": "Elevated risk of Cross-Site Scripting (XSS) and unauthorized script injection.",
        "remediation": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'"
    },
    "X-Frame-Options": {
        "risk": "Target pages can be embedded in hidden iframes for Clickjacking attacks.",
        "remediation": "Add: X-Frame-Options: SAMEORIGIN (or DENY)"
    },
    "X-Content-Type-Options": {
        "risk": "Browsers may execute non-executable MIME types (MIME-sniffing exploit).",
        "remediation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "risk": "Sensitive tokens and internal URLs may leak via the Referer HTTP header.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "risk": "Unauthorized origins may activate camera, microphone, or geolocation APIs.",
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
    "X-XSS-Protection": {
        "risk": "Legacy browser reflection filter is disabled or unconfigured.",
        "remediation": "Add: X-XSS-Protection: 1; mode=block"
    },
}

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def _analyze_target(url: str, timeout: int) -> dict:
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": UA},
        )
    except Exception as e:
        return {"error": str(e)}

    headers = dict(resp.headers)
    sec = {}
    missing = []

    for h in SECURITY_HEADERS:
        val = headers.get(h)
        # Check case-insensitive
        if val is None:
            for k, v in headers.items():
                if k.lower() == h.lower():
                    val = v
                    break

        is_present = val is not None
        sec[h] = {
            "present": is_present,
            "value": val,
            "risk_impact": HEADER_REMEDIATIONS[h]["risk"] if not is_present else None,
            "remediation": HEADER_REMEDIATIONS[h]["remediation"] if not is_present else None,
        }
        if not is_present:
            missing.append(h)

    score = round((len(SECURITY_HEADERS) - len(missing)) / len(SECURITY_HEADERS) * 100)

    # Server banner information disclosure risk
    server_hdr = headers.get("Server") or headers.get("server")
    powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
    info_leak = []
    if server_hdr and any(c.isdigit() for c in server_hdr):
        info_leak.append(f"Server header exposes exact version: {server_hdr}")
    if powered_by:
        info_leak.append(f"X-Powered-By header discloses backend runtime: {powered_by}")

    return {
        "status_code":              resp.status_code,
        "final_url":                resp.url,
        "server":                   server_hdr,
        "x_powered_by":             powered_by,
        "security_headers":         sec,
        "missing_security_headers": missing,
        "security_score":           score,
        "information_disclosures":  info_leak,
        "redirect_history":         [r.url for r in resp.history],
    }


def run(domain: str, timeout: int = 10) -> dict:
    # 1. Probe HTTPS
    https_res = _analyze_target(f"https://{domain}", timeout)

    # 2. If apex HTTPS fails, try www.{domain} fallback
    if "error" in https_res and not domain.startswith("www."):
        www_res = _analyze_target(f"https://www.{domain}", timeout)
        if "error" not in www_res:
            https_res = www_res

    # 3. If HTTPS completely fails, try plain HTTP
    if "error" in https_res:
        http_res = _analyze_target(f"http://{domain}", timeout)
        return {"https": https_res, "http": http_res}

    return {"https": https_res}
