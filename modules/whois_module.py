import requests
import whois
from datetime import datetime


def _normalize(val):
    if val is None:
        return None
    if isinstance(val, list):
        return [str(v).strip() for v in val if v]
    return str(val).strip()


def _query_rdap(domain: str, timeout: int = 6) -> dict | None:
    """Query ICANN RDAP (Registration Data Access Protocol) over HTTPS."""
    try:
        url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(
            url,
            timeout=timeout,
            headers={
                "Accept": "application/json",
                "User-Agent": "osint-recon/2.0 (Security Perimeter Scanner)"
            }
        )
        if resp.status_code != 200:
            return None
        data = resp.json()

        # Events (Registration, Expiration, Last Changed)
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        creation = events.get("registration")
        expiration = events.get("expiration")
        updated = events.get("last changed")

        # Nameservers
        ns = [n.get("ldhName").lower() for n in data.get("nameservers", []) if n.get("ldhName")]

        # Status codes
        status = data.get("status", [])

        # Entities extraction (Registrar, Registrant, Contacts)
        org = None
        registrar = None
        country = None
        emails = []

        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])
            props = vcard[1] if len(vcard) > 1 else []

            for item in props:
                prop_name = item[0]
                val = item[3] if len(item) > 3 else None
                if prop_name == "fn" and val and "registrar" in roles and not registrar:
                    registrar = val
                if prop_name == "org" and val and "registrant" in roles and not org:
                    org = val
                if prop_name == "adr" and isinstance(item[1], dict) and "cc" in item[1] and not country:
                    country = item[1]["cc"]
                if prop_name == "email" and val and val not in emails:
                    emails.append(val)

        return {
            "registrar":       registrar,
            "creation_date":   creation,
            "expiration_date": expiration,
            "updated_date":    updated,
            "name_servers":    ns if ns else None,
            "status":          status if status else None,
            "country":         country,
            "org":             org,
            "emails":          emails if emails else None,
        }
    except Exception:
        return None


def run(domain: str, timeout: int = 10) -> dict:
    # 1. Try RDAP first (modern, HTTPS-based, works reliably on serverless/cloud environments)
    rdap_res = _query_rdap(domain, timeout=min(timeout, 6))

    # 2. Try standard WHOIS socket
    w_res = None
    try:
        w = whois.whois(domain)
        w_res = {
            "registrar":       _normalize(w.registrar),
            "creation_date":   _normalize(w.creation_date),
            "expiration_date": _normalize(w.expiration_date),
            "updated_date":    _normalize(w.updated_date),
            "name_servers":    _normalize(w.name_servers),
            "status":          _normalize(w.status),
            "country":         _normalize(w.country),
            "org":             _normalize(w.org),
            "emails":          _normalize(w.emails),
        }
    except Exception:
        pass

    # 3. Merge results for comprehensive intelligence (no nulls where data exists)
    if not rdap_res and not w_res:
        return {"error": f"WHOIS/RDAP registry query failed or timed out for {domain}"}

    def pick(key):
        val_rdap = rdap_res.get(key) if rdap_res else None
        val_w = w_res.get(key) if w_res else None
        if val_rdap is not None and val_rdap != "" and val_rdap != []:
            return val_rdap
        return val_w

    final_result = {
        "registrar":       pick("registrar"),
        "creation_date":   pick("creation_date"),
        "expiration_date": pick("expiration_date"),
        "updated_date":    pick("updated_date"),
        "name_servers":    pick("name_servers"),
        "status":          pick("status"),
        "country":         pick("country"),
        "org":             pick("org"),
        "emails":          pick("emails"),
        "source":          "RDAP (ICANN)" if rdap_res and not w_res else ("WHOIS Socket" if w_res and not rdap_res else "RDAP + WHOIS Hybrid")
    }

    return final_result
