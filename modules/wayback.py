import requests
import json as _json
from urllib.parse import urlparse
from collections import Counter

CDX_URL          = "https://web.archive.org/cdx/search/cdx"
AVAILABILITY_URL = "https://archive.org/wayback/available"

# Extensiones y patrones de endpoints interesantes para OSINT
INTERESTING_PATTERNS = [
    "/admin", "/login", "/api/", "/config", "/.env", "/backup",
    "/wp-admin", "/phpmyadmin", "/.git", "/swagger", "/graphql",
    "/debug", "/actuator", "/console", "/dashboard",
]


def _availability(domain: str, timeout: int) -> dict | None:
    """Consulta rápida de snapshot más reciente vía availability API."""
    try:
        resp = requests.get(AVAILABILITY_URL, params={"url": domain},
                            timeout=timeout, headers={"User-Agent": "osint-recon/1.0"})
        data = resp.json()
        snap = data.get("archived_snapshots", {}).get("closest", {})
        if snap.get("available"):
            return snap
    except Exception:
        pass
    return None


def _cdx_query(domain: str, timeout: int) -> list | None:
    """Stream de la CDX API — lee línea a línea para no esperar el payload completo."""
    params = {
        "url":      f"*.{domain}",
        "output":   "json",
        "fl":       "original,timestamp,statuscode,mimetype",
        "collapse": "urlkey",
        "limit":    "300",
        "filter":   "statuscode:200",
    }
    try:
        with requests.get(CDX_URL, params=params, timeout=(5, timeout),
                          headers={"User-Agent": "osint-recon/1.0"}, stream=True) as resp:
            resp.raise_for_status()
            rows = []
            for line in resp.iter_lines():
                if line:
                    try:
                        rows.append(_json.loads(line))
                    except _json.JSONDecodeError:
                        pass
            return rows if rows else None
    except Exception:
        return None


def run(domain: str, timeout: int = 10) -> dict:
    # Primero: consulta rápida de disponibilidad
    snap = _availability(domain, min(timeout, 8))

    # Segundo: CDX para URLs históricas (puede tardar más)
    raw = _cdx_query(domain, timeout)

    # Si ambos fallaron, reportamos lo que sí obtuvimos
    if not snap and not raw:
        return {"error": "No se pudo conectar a archive.org (CDX API lenta o no disponible)"}

    if not raw or len(raw) < 2:
        result = {"total_snapshots": 0, "urls": [], "interesting": [], "subdomains": [], "mime_breakdown": {}}
        if snap:
            result["latest_snapshot"] = snap.get("url")
            result["latest_timestamp"] = _fmt_date(snap.get("timestamp", "")[:8])
        return result

    # Primera fila es cabecera
    header, *rows = raw
    idx = {h: i for i, h in enumerate(header)}

    urls        : list[str] = []
    timestamps  : list[str] = []
    mimetypes   : list[str] = []
    subdomains  : set[str]  = set()

    for row in rows:
        url  = row[idx["original"]]
        ts   = row[idx["timestamp"]]
        mime = row[idx["mimetype"]]

        urls.append(url)
        timestamps.append(ts)
        mimetypes.append(mime)

        host = urlparse(url).hostname or ""
        if host.endswith(domain) and host != domain:
            subdomains.add(host)

    # Endpoints interesantes
    interesting = [u for u in urls if any(p in u.lower() for p in INTERESTING_PATTERNS)]

    # Distribución de tipos MIME
    mime_counter = Counter(mimetypes)
    mime_breakdown = {k: v for k, v in mime_counter.most_common(8)}

    # Fechas extremas
    first_seen = min(timestamps)[:8] if timestamps else None  # YYYYMMDD
    last_seen  = max(timestamps)[:8] if timestamps else None

    return {
        "total_snapshots": len(rows),
        "first_seen":      _fmt_date(first_seen),
        "last_seen":       _fmt_date(last_seen),
        "subdomains":      sorted(subdomains),
        "interesting":     interesting[:30],
        "mime_breakdown":  mime_breakdown,
        "sample_urls":     urls[:20],
    }


def _fmt_date(d: str | None) -> str | None:
    if not d or len(d) < 8:
        return d
    return f"{d[:4]}-{d[4:6]}-{d[6:8]}"
