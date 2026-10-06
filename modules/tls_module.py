import ssl
import socket
from datetime import datetime, timezone

# Versions considered obsolete or weak
WEAK_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def _check_version(host: str, port: int, version_const, label: str, timeout: int) -> dict:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version_const
        ctx.maximum_version = version_const
    except (AttributeError, ssl.SSLError):
        return {"supported": False, "label": label}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return {"supported": True, "label": label}
    except (ssl.SSLError, OSError):
        return {"supported": False, "label": label}


def run(domain: str, timeout: int = 10) -> dict:
    port = 443

    # Obtain primary certificate
    # CERT_OPTIONAL: requests certificate without strict verification so getpeercert() returns certificate metadata
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert    = ssock.getpeercert()
                cipher  = ssock.cipher()
                tls_ver = ssock.version()
    except Exception as e:
        return {"error": str(e)}

    # Parse validity dates
    not_before_raw = cert.get("notBefore", "")
    not_after_raw  = cert.get("notAfter", "")
    try:
        fmt = "%b %d %H:%M:%S %Y %Z"
        not_before = datetime.strptime(not_before_raw, fmt).replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(not_after_raw,  fmt).replace(tzinfo=timezone.utc)
        now        = datetime.now(timezone.utc)
        days_left  = (not_after - now).days
        expired    = days_left < 0
    except ValueError:
        not_before = not_before_raw
        not_after  = not_after_raw
        days_left  = None
        expired    = None

    # SANs (Subject Alternative Names)
    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    # Issuer and subject extraction
    issuer  = dict(x[0] for x in cert.get("issuer",  []))
    subject = dict(x[0] for x in cert.get("subject", []))

    # Probe deprecated TLS protocol versions
    version_checks = []
    try:
        for label, const in [
            ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
            ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
            ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
            ("TLS 1.0", ssl.TLSVersion.TLSv1),
        ]:
            version_checks.append(_check_version(domain, port, const, label, timeout))
    except AttributeError:
        pass

    weak_supported = [v["label"] for v in version_checks if v["supported"] and v["label"] in {"TLS 1.0", "TLS 1.1"}]

    return {
        "negotiated_version": tls_ver,
        "cipher":             {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None,
        "cert": {
            "subject_cn":   subject.get("commonName"),
            "issuer_cn":    issuer.get("commonName"),
            "issuer_org":   issuer.get("organizationName"),
            "not_before":   str(not_before),
            "not_after":    str(not_after),
            "days_left":    days_left,
            "expired":      expired,
            "sans":         sans,
            "san_count":    len(sans),
        },
        "version_support":    version_checks,
        "weak_versions":      weak_supported,
        "issues": (
            (["Certificate expired"] if expired else []) +
            (["Certificate expires in less than 30 days"] if isinstance(days_left, int) and 0 <= days_left < 30 else []) +
            ([f"Weak TLS versions supported: {', '.join(weak_supported)}"] if weak_supported else [])
        ),
    }
