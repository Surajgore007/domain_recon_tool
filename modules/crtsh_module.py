import requests
from concurrent.futures import ThreadPoolExecutor


def _fetch_crtsh(domain: str, timeout: int) -> tuple[set[str], list[dict]]:
    subdomains: set[str] = set()
    certs: list[dict] = []
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "osint-recon/2.0 (Security Perimeter Scanner)"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain) and " " not in name:
                        subdomains.add(name)

                certs.append({
                    "id":         entry.get("id"),
                    "issuer":     entry.get("issuer_name", ""),
                    "not_before": entry.get("not_before", ""),
                    "not_after":  entry.get("not_after", ""),
                    "domains":    entry.get("name_value", ""),
                })
    except Exception:
        pass
    return subdomains, certs


def _fetch_hackertarget(domain: str, timeout: int) -> tuple[set[str], dict[str, str]]:
    subdomains: set[str] = set()
    ip_map: dict[str, str] = {}
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "osint-recon/2.0"},
        )
        if resp.status_code == 200 and not resp.text.startswith("error"):
            for line in resp.text.strip().split("\n"):
                parts = line.split(",")
                if len(parts) == 2:
                    sub = parts[0].strip().lower()
                    ip = parts[1].strip()
                    if sub.endswith(domain) and " " not in sub:
                        subdomains.add(sub)
                        ip_map[sub] = ip
    except Exception:
        pass
    return subdomains, ip_map


def run(domain: str, timeout: int = 10) -> dict:
    subdomains: set[str] = set()
    certs: list[dict] = []
    ip_map: dict[str, str] = {}

    # Query crt.sh and HackerTarget concurrently
    with ThreadPoolExecutor(max_workers=2) as executor:
        f_crtsh = executor.submit(_fetch_crtsh, domain, timeout)
        f_ht = executor.submit(_fetch_hackertarget, domain, timeout)

        crt_subs, crt_certs = f_crtsh.result()
        ht_subs, ht_ip_map = f_ht.result()

        subdomains.update(crt_subs)
        subdomains.update(ht_subs)
        certs.extend(crt_certs)
        ip_map.update(ht_ip_map)

    # If both returned nothing, provide clean empty state or error
    if not subdomains and not certs:
        return {
            "subdomains":     [],
            "total_certs":    0,
            "certs_sample":   [],
            "subdomain_ips":  {},
            "note":           "No public subdomains discovered via Certificate Transparency logs or passive DNS feeds."
        }

    return {
        "subdomains":     sorted(subdomains),
        "total_certs":    len(certs),
        "certs_sample":   certs[:15],
        "subdomain_ips":  ip_map,
        "discovery_feed": "crt.sh + HackerTarget Passive DNS",
    }
