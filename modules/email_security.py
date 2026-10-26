import dns.resolver
import dns.exception
import re

PUBLIC_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]

# Comprehensive enterprise DKIM selectors to probe
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1",
    "s1", "s2", "mail", "dkim", "email", "smtp", "mta",
    "mandrill", "mailgun", "sendgrid", "zendesk", "hubspot",
    "protection", "office365"
]

EMAIL_PROVIDERS = [
    (r"google|googlemail|aspmx", "Google Workspace / Gmail"),
    (r"outlook|microsoft|protection\.outlook", "Microsoft 365 / Exchange Online"),
    (r"pphosted|proofpoint", "Proofpoint Enterprise Gateway"),
    (r"mimecast", "Mimecast Email Security"),
    (r"zoho", "Zoho Mail"),
    (r"protonmail|proton\.ch", "ProtonMail"),
    (r"sendgrid", "Twilio SendGrid"),
    (r"mailgun", "Mailgun"),
    (r"amazonses|awsdns", "Amazon SES"),
]


def _resolve_txt_records(resolver, name: str, timeout: int) -> list[str]:
    """Query TXT records with fallback to public nameservers if local resolver fails."""
    try:
        answers = resolver.resolve(name, "TXT")
        return [str(r).strip('"') for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        # Fallback to public DNS
        try:
            fb = dns.resolver.Resolver(configure=False)
            fb.nameservers = PUBLIC_NAMESERVERS
            fb.lifetime = min(timeout, 4)
            answers = fb.resolve(name, "TXT")
            return [str(r).strip('"') for r in answers]
        except Exception:
            return []


def _resolve_mx_records(resolver, domain: str, timeout: int) -> tuple[list[str], str | None]:
    """Query MX records and identify the underlying mail security provider."""
    mx_list = []
    try:
        answers = resolver.resolve(domain, "MX")
        mx_list = [str(r.exchange).rstrip(".") for r in answers]
    except Exception:
        try:
            fb = dns.resolver.Resolver(configure=False)
            fb.nameservers = PUBLIC_NAMESERVERS
            fb.lifetime = min(timeout, 4)
            answers = fb.resolve(domain, "MX")
            mx_list = [str(r.exchange).rstrip(".") for r in answers]
        except Exception:
            pass

    provider = None
    if mx_list:
        combined = " ".join(mx_list).lower()
        for pat, prov_name in EMAIL_PROVIDERS:
            if re.search(pat, combined):
                provider = prov_name
                break
        if not provider:
            provider = "Self-Hosted / Independent Mail Server"

    return mx_list, provider


def _analyze_spf(records: list[str]) -> dict:
    spf = next((r for r in records if r.startswith("v=spf1")), None)
    if not spf:
        return {
            "present": False,
            "record": None,
            "policy": None,
            "issues": ["No SPF record configured — domain allows arbitrary hosts to send email"]
        }

    issues = []
    policy = None
    if "-all" in spf:
        policy = "fail"        # Strict reject policy
    elif "~all" in spf:
        policy = "softfail"    # Permissive mark as spam
    elif "?all" in spf:
        policy = "neutral"
        issues.append("Neutral SPF policy (?all) — provides zero spoofing protection")
    elif "+all" in spf:
        policy = "pass"
        issues.append("Dangerous permissive policy (+all) — authorizes any IP to send mail for this domain")
    else:
        issues.append("Incomplete SPF record — missing 'all' enforcement mechanism")

    # Check DNS lookup mechanism count (RFC 7208 maximum is 10)
    lookup_mechanisms = re.findall(r"\b(include|a|mx|ptr|exists|redirect)\b", spf)
    if len(lookup_mechanisms) > 10:
        issues.append(f"Excessive DNS lookups ({len(lookup_mechanisms)}) — exceeds RFC 7208 limit of 10")

    return {"present": True, "record": spf, "policy": policy, "issues": issues}


def _analyze_dmarc(records: list[str]) -> dict:
    dmarc = next((r for r in records if r.startswith("v=DMARC1")), None)
    if not dmarc:
        return {
            "present": False,
            "record": None,
            "policy": None,
            "pct": 0,
            "rua": None,
            "issues": ["No DMARC record found — high vulnerability to executive domain spoofing"]
        }

    issues = []
    policy_match = re.search(r"\bp=(\w+)", dmarc)
    policy = policy_match.group(1).lower() if policy_match else None

    if policy == "none":
        issues.append("DMARC policy set to 'p=none' (monitoring only) — fraudulent spoofed emails are NOT rejected")
    elif policy == "quarantine":
        pass  # Divert to spam
    elif policy == "reject":
        pass  # Gold standard

    pct_match = re.search(r"\bpct=(\d+)", dmarc)
    pct = int(pct_match.group(1)) if pct_match else 100
    if pct < 100:
        issues.append(f"DMARC partial enforcement: applied to only {pct}% of inbound messages")

    rua_match = re.search(r"\brua=([^\s;]+)", dmarc)
    rua = rua_match.group(1) if rua_match else None
    if not rua:
        issues.append("No aggregate telemetry reporting URI (rua) defined")

    return {
        "present": True,
        "record":  dmarc,
        "policy":  policy,
        "pct":     pct,
        "rua":     rua,
        "issues":  issues,
    }


def _find_dkim(resolver, domain: str, timeout: int) -> dict:
    found = []
    for selector in DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        records = _resolve_txt_records(resolver, name, timeout)
        for r in records:
            if "v=DKIM1" in r or "p=" in r:
                found.append({
                    "selector": selector,
                    "record": r[:120] + ("…" if len(r) > 120 else "")
                })
                break
    return {
        "found":     len(found) > 0,
        "selectors": found,
        "issues":    [] if found else ["No active DKIM public keys discovered among standard selectors"],
    }


def run(domain: str, timeout: int = 10) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 4)

    txt_root = _resolve_txt_records(resolver, domain, timeout)
    txt_dmarc = _resolve_txt_records(resolver, f"_dmarc.{domain}", timeout)
    mx_list, mx_provider = _resolve_mx_records(resolver, domain, timeout)

    spf = _analyze_spf(txt_root)
    dmarc = _analyze_dmarc(txt_dmarc)
    dkim = _find_dkim(resolver, domain, timeout)

    all_issues = spf["issues"] + dmarc["issues"] + dkim["issues"]

    # Security Posture Assessment
    is_spoofable = not dmarc["present"] or dmarc.get("policy") == "none"
    risk_level = "High" if is_spoofable else ("Medium" if not spf["present"] or not dkim["found"] else "Low")

    if not mx_list:
        all_issues.append("No MX records found — domain is not configured for receiving incoming emails")

    score = _calculate_score(spf, dkim, dmarc, mx_list)

    return {
        "spf":                 spf,
        "dkim":                dkim,
        "dmarc":               dmarc,
        "mx_records":          mx_list,
        "mx_provider":         mx_provider,
        "spoofing_vulnerable": is_spoofable,
        "risk_level":          risk_level,
        "all_issues":          all_issues,
        "score":               score,
    }


def _calculate_score(spf: dict, dkim: dict, dmarc: dict, mx_list: list) -> int:
    score = 0
    if spf.get("present"):
        score += 25
        if spf.get("policy") in ("fail", "softfail"):
            score += 15
    if dkim.get("found"):
        score += 25
    if dmarc.get("present"):
        score += 15
        if dmarc.get("policy") in ("quarantine", "reject"):
            score += 20
    return min(score, 100)
