import requests
import json as _json
from urllib.parse import urlparse
from collections import Counter

CDX_URL          = "https://web.archive.org/cdx/search/cdx"
AVAILABILITY_URL = "https://archive.org/wayback/available"

INTERESTING_PATTERNS = [
    "/admin", "/login", "/api/", "/config", "/.env", "/backup",
    "/wp-admin", "/phpmyadmin", "/.git", "/swagger", "/graphql",
    "/debug", "/actuator", "/console", "/dashboard", "/user",
    "/portal", "/auth", "/v1/", "/v2/", ".sql", ".bak"
]


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}


def _availability(domain: str, timeout: int) -> dict | None:
    try:
        resp = requests.get(
            AVAILABILITY_URL,
            params={"url": domain},
            timeout=min(timeout, 5),
            headers=HEADERS
        )
        if resp.status_code == 200:
            data = resp.json()
            snap = data.get("archived_snapshots", {}).get("closest", {})
            if snap.get("available"):
                return snap
    except Exception:
        pass
    return None


def _cdx_query(domain: str, timeout: int) -> list | None:
    # First attempt: exact domain query (fastest, rarely times out)
    queries = [
        {"url": domain, "fl": "original,timestamp,statuscode,mimetype", "limit": "100", "output": "json"},
        {"url": f"www.{domain}", "fl": "original,timestamp,statuscode,mimetype", "limit": "100", "output": "json"},
    ]

    all_rows = []
    header = None

    for p in queries:
        try:
            resp = requests.get(
                CDX_URL,
                params=p,
                timeout=(3, min(timeout, 6)),
                headers=HEADERS,
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    if not header:
                        header = data[0]
                    all_rows.extend(data[1:])
        except Exception:
            continue

    # Also try wildcard if we got fewer than 10 rows and have time left
    if len(all_rows) < 10 and timeout >= 6:
        try:
            resp = requests.get(
                CDX_URL,
                params={
                    "url": f"{domain}/*",
                    "output": "json",
                    "fl": "original,timestamp,statuscode,mimetype",
                    "limit": "80",
                    "filter": "statuscode:200",
                },
                timeout=(3, 5),
                headers=HEADERS,
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    if not header:
                        header = data[0]
                    all_rows.extend(data[1:])
        except Exception:
            pass

    if header and all_rows:
        return [header] + all_rows
    return None



def _fmt_date(d: str | None) -> str | None:
    if not d or len(d) < 8:
        return d
    return f"{d[:4]}-{d[4:6]}-{d[6:8]}"


def run(domain: str, timeout: int = 10) -> dict:
    # 1. Quick availability query
    snap = _availability(domain, min(timeout, 6))

    # 2. CDX historical query
    raw = _cdx_query(domain, timeout)

    if not snap and not raw:
        return {
            "total_snapshots": 0,
            "first_seen":      None,
            "last_seen":       None,
            "subdomains":      [],
            "interesting":     [],
            "mime_breakdown":  {},
            "sample_urls":     [],
            "note":            "Archive.org CDX API timed out or no public archives recorded for domain."
        }

    if not raw or len(raw) < 2:
        return {
            "total_snapshots": 1 if snap else 0,
            "latest_snapshot": snap.get("url") if snap else None,
            "latest_timestamp": _fmt_date(snap.get("timestamp", "")[:8]) if snap else None,
            "first_seen":      _fmt_date(snap.get("timestamp", "")[:8]) if snap else None,
            "last_seen":       _fmt_date(snap.get("timestamp", "")[:8]) if snap else None,
            "subdomains":      [],
            "interesting":     [],
            "mime_breakdown":  {},
            "sample_urls":     [snap.get("url")] if snap and snap.get("url") else [],
        }

    header, *rows = raw
    idx = {h: i for i, h in enumerate(header)}

    urls: list[str] = []
    timestamps: list[str] = []
    mimetypes: list[str] = []
    subdomains: set[str] = set()

    for row in rows:
        try:
            url  = row[idx["original"]]
            ts   = row[idx["timestamp"]]
            mime = row[idx["mimetype"]]

            urls.append(url)
            timestamps.append(ts)
            mimetypes.append(mime)

            host = urlparse(url).hostname or ""
            if host.endswith(domain) and host != domain:
                subdomains.add(host)
        except (IndexError, KeyError):
            continue

    interesting = [u for u in urls if any(p in u.lower() for p in INTERESTING_PATTERNS)]
    mime_counter = Counter(mimetypes)

    first_seen = min(timestamps)[:8] if timestamps else (snap.get("timestamp", "")[:8] if snap else None)
    last_seen  = max(timestamps)[:8] if timestamps else (snap.get("timestamp", "")[:8] if snap else None)

    return {
        "total_snapshots": len(rows),
        "latest_snapshot": snap.get("url") if snap else (urls[0] if urls else None),
        "latest_timestamp": _fmt_date(snap.get("timestamp", "")[:8]) if snap else (_fmt_date(last_seen) if last_seen else None),
        "first_seen":      _fmt_date(first_seen),
        "last_seen":       _fmt_date(last_seen),
        "subdomains":      sorted(subdomains),
        "interesting":     interesting[:35],
        "mime_breakdown":  dict(mime_counter.most_common(8)),
        "sample_urls":     urls[:25],
    }
