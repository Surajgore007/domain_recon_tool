import requests


def run(domain: str, timeout: int = 10) -> dict:
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "osint-recon/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"error": str(e)}

    subdomains: set[str] = set()
    certs: list[dict] = []

    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.")
            if name.endswith(domain) and " " not in name:
                subdomains.add(name)

        certs.append({
            "id":         entry.get("id"),
            "issuer":     entry.get("issuer_name", ""),
            "not_before": entry.get("not_before", ""),
            "not_after":  entry.get("not_after", ""),
            "domains":    entry.get("name_value", ""),
        })

    return {
        "subdomains":   sorted(subdomains),
        "total_certs":  len(certs),
        "certs_sample": certs[:15],
    }
