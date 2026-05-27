import dns.resolver
import re

# Selectores DKIM comunes a probar
DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "email",
    "selector1", "selector2", "k1", "smtp", "mta",
]


def _query_txt(resolver, name: str) -> list[str]:
    try:
        answers = resolver.resolve(name, "TXT")
        return [str(r).strip('"') for r in answers]
    except Exception:
        return []


def _analyze_spf(records: list[str]) -> dict:
    spf = next((r for r in records if r.startswith("v=spf1")), None)
    if not spf:
        return {"present": False, "record": None, "policy": None, "issues": ["Sin registro SPF"]}

    issues = []
    policy = None
    if "-all" in spf:
        policy = "fail"        # política estricta — correos no autorizados se rechazan
    elif "~all" in spf:
        policy = "softfail"    # política permisiva — correos no autorizados marcados como spam
    elif "?all" in spf:
        policy = "neutral"
        issues.append("Política SPF neutral (?all) — no protege contra spoofing")
    elif "+all" in spf:
        policy = "pass"
        issues.append("Política SPF +all — cualquier servidor puede enviar correo")
    else:
        issues.append("Sin mecanismo 'all' — SPF incompleto")

    # Detectar demasiados lookups DNS (límite es 10)
    lookup_mechanisms = re.findall(r"\b(include|a|mx|ptr|exists|redirect)\b", spf)
    if len(lookup_mechanisms) > 10:
        issues.append(f"Demasiados lookups DNS ({len(lookup_mechanisms)}) — puede causar fallos SPF")

    return {"present": True, "record": spf, "policy": policy, "issues": issues}


def _analyze_dmarc(records: list[str]) -> dict:
    dmarc = next((r for r in records if r.startswith("v=DMARC1")), None)
    if not dmarc:
        return {"present": False, "record": None, "policy": None, "issues": ["Sin registro DMARC"]}

    issues = []
    policy_match = re.search(r"\bp=(\w+)", dmarc)
    policy = policy_match.group(1) if policy_match else None

    if policy == "none":
        issues.append("DMARC p=none — solo monitoreo, sin acción sobre correos fallidos")
    elif policy == "quarantine":
        pass  # aceptable
    elif policy == "reject":
        pass  # política más estricta, ideal

    pct_match = re.search(r"\bpct=(\d+)", dmarc)
    pct = int(pct_match.group(1)) if pct_match else 100
    if pct < 100:
        issues.append(f"DMARC pct={pct}% — política aplicada solo a {pct}% de los mensajes")

    rua_match = re.search(r"\brua=([^\s;]+)", dmarc)
    rua = rua_match.group(1) if rua_match else None
    if not rua:
        issues.append("Sin rua — no se recibirán reportes DMARC agregados")

    return {
        "present": True,
        "record":  dmarc,
        "policy":  policy,
        "pct":     pct,
        "rua":     rua,
        "issues":  issues,
    }


def _find_dkim(resolver, domain: str) -> dict:
    found = []
    for selector in DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        records = _query_txt(resolver, name)
        for r in records:
            if "v=DKIM1" in r or "p=" in r:
                found.append({"selector": selector, "record": r[:120] + ("…" if len(r) > 120 else "")})
                break
    return {
        "found":     len(found) > 0,
        "selectors": found,
        "issues":    [] if found else ["No se encontraron selectores DKIM comunes"],
    }


def run(domain: str, timeout: int = 10) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    txt_root  = _query_txt(resolver, domain)
    txt_dmarc = _query_txt(resolver, f"_dmarc.{domain}")

    spf   = _analyze_spf(txt_root)
    dmarc = _analyze_dmarc(txt_dmarc)
    dkim  = _find_dkim(resolver, domain)

    all_issues = spf["issues"] + dmarc["issues"] + dkim["issues"]

    return {
        "spf":        spf,
        "dkim":       dkim,
        "dmarc":      dmarc,
        "all_issues": all_issues,
        "score": _score(spf, dkim, dmarc),
    }


def _score(spf: dict, dkim: dict, dmarc: dict) -> int:
    """Puntaje simple de 0 a 100 basado en presencia y políticas."""
    pts = 0
    if spf["present"]:
        pts += 25
        if spf["policy"] in ("fail", "softfail"):
            pts += 15
    if dkim["found"]:
        pts += 30
    if dmarc["present"]:
        pts += 15
        if dmarc.get("policy") in ("quarantine", "reject"):
            pts += 15
    return min(pts, 100)
