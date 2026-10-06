import dns.resolver
import re

# Common DKIM selectors to probe
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
        return {"present": False, "record": None, "policy": None, "issues": ["No SPF record found"]}

    issues = []
    policy = None
    if "-all" in spf:
        policy = "fail"        # strict policy — unauthorized emails are rejected
    elif "~all" in spf:
        policy = "softfail"    # permissive policy — unauthorized emails marked as spam
    elif "?all" in spf:
        policy = "neutral"
        issues.append("Neutral SPF policy (?all) — provides no protection against spoofing")
    elif "+all" in spf:
        policy = "pass"
        issues.append("Permissive SPF policy (+all) — permits any mail server to send on behalf of domain")
    else:
        issues.append("Missing 'all' mechanism — incomplete SPF configuration")

    # Detect too many DNS lookups (RFC limit is 10)
    lookup_mechanisms = re.findall(r"\b(include|a|mx|ptr|exists|redirect)\b", spf)
    if len(lookup_mechanisms) > 10:
        issues.append(f"Excessive DNS lookups ({len(lookup_mechanisms)}) — exceeds RFC limit of 10 and may cause SPF evaluation failures")

    return {"present": True, "record": spf, "policy": policy, "issues": issues}


def _analyze_dmarc(records: list[str]) -> dict:
    dmarc = next((r for r in records if r.startswith("v=DMARC1")), None)
    if not dmarc:
        return {"present": False, "record": None, "policy": None, "issues": ["No DMARC record found"]}

    issues = []
    policy_match = re.search(r"\bp=(\w+)", dmarc)
    policy = policy_match.group(1) if policy_match else None

    if policy == "none":
        issues.append("DMARC p=none policy — monitoring only, no rejection or quarantine applied to fraudulent emails")
    elif policy == "quarantine":
        pass  # acceptable
    elif policy == "reject":
        pass  # strictest, recommended

    pct_match = re.search(r"\bpct=(\d+)", dmarc)
    pct = int(pct_match.group(1)) if pct_match else 100
    if pct < 100:
        issues.append(f"DMARC pct={pct}% — policy applied only to {pct}% of inbound messages")

    rua_match = re.search(r"\brua=([^\s;]+)", dmarc)
    rua = rua_match.group(1) if rua_match else None
    if not rua:
        issues.append("Missing rua destination — aggregate DMARC telemetry reports will not be received")

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
        "issues":    [] if found else ["No common DKIM selectors identified"],
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
    """Security score from 0 to 100 based on presence and strictness of email records."""
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
