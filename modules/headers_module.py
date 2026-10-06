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

UA = "Mozilla/5.0 (compatible; osint-recon/1.0)"


def _analyze(domain: str, scheme: str, timeout: int) -> dict:
    url = f"{scheme}://{domain}"
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
    for h in SECURITY_HEADERS:
        val = headers.get(h)
        sec[h] = {"present": val is not None, "value": val}

    missing = [h for h, v in sec.items() if not v["present"]]
    score = round((len(SECURITY_HEADERS) - len(missing)) / len(SECURITY_HEADERS) * 100)

    return {
        "status_code":              resp.status_code,
        "final_url":                resp.url,
        "server":                   headers.get("Server"),
        "x_powered_by":             headers.get("X-Powered-By"),
        "security_headers":         sec,
        "missing_security_headers": missing,
        "security_score":           score,
    }


def run(domain: str, timeout: int = 10) -> dict:
    result = _analyze(domain, "https", timeout)
    # If https fails due to connection error, attempt http fallback
    if "error" in result:
        http_result = _analyze(domain, "http", timeout)
        return {"https": result, "http": http_result}
    return {"https": result}
