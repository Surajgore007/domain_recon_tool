import whois


def _normalize(val):
    if val is None:
        return None
    if isinstance(val, list):
        return [str(v) for v in val]
    return str(val)


def run(domain: str, timeout: int = 10) -> dict:
    try:
        w = whois.whois(domain)
        return {
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
    except Exception as e:
        return {"error": str(e)}
