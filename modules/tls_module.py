import ssl
import socket
import tempfile
import os
from datetime import datetime, timezone

WEAK_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def _decode_binary_cert(der_bytes: bytes) -> dict:
    """Decode raw DER bytes into standard certificate dict without external dependencies."""
    if not der_bytes:
        return {}
    try:
        pem = ssl.DER_cert_to_PEM_cert(der_bytes)
        fd, temp_path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(pem)
        try:
            return ssl._ssl._test_decode_cert(temp_path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    except Exception:
        return {}


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
    cert = {}
    cipher = None
    tls_ver = None
    verify_failed = False
    verify_error_msg = None

    # Step 1: Attempt standard SSL handshake
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert() or {}
                cipher = ssock.cipher()
                tls_ver = ssock.version()
    except ssl.SSLCertVerificationError as e:
        verify_failed = True
        verify_error_msg = str(e)
    except Exception as e:
        # Host might not support SSL or connection refused
        return {"error": f"TLS connection to {domain}:{port} failed: {e}"}

    # Step 2: If verification failed or cert empty, reconnect with CERT_NONE and decode raw DER cert
    if not cert or verify_failed:
        try:
            ctx_raw = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_raw.check_hostname = False
            ctx_raw.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with ctx_raw.wrap_socket(sock, server_hostname=domain) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        cert = _decode_binary_cert(der)
                    if not cipher:
                        cipher = ssock.cipher()
                    if not tls_ver:
                        tls_ver = ssock.version()
        except Exception as e:
            if not cert:
                return {"error": f"TLS handshake failed: {e}"}

    # Step 3: Parse validity dates
    not_before_raw = cert.get("notBefore", "")
    not_after_raw  = cert.get("notAfter", "")
    days_left = None
    expired = None
    not_before_str = str(not_before_raw)
    not_after_str = str(not_after_raw)

    if not_before_raw and not_after_raw:
        try:
            fmt = "%b %d %H:%M:%S %Y %Z"
            not_before = datetime.strptime(not_before_raw, fmt).replace(tzinfo=timezone.utc)
            not_after  = datetime.strptime(not_after_raw,  fmt).replace(tzinfo=timezone.utc)
            now        = datetime.now(timezone.utc)
            days_left  = (not_after - now).days
            expired    = days_left < 0
            not_before_str = not_before.strftime("%Y-%m-%d %H:%M:%S UTC")
            not_after_str  = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            pass

    # SANs (Subject Alternative Names)
    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    # Issuer and subject extraction
    issuer_dict = {}
    for entry in cert.get("issuer", []):
        for k, v in entry:
            issuer_dict[k] = v

    subject_dict = {}
    for entry in cert.get("subject", []):
        for k, v in entry:
            subject_dict[k] = v

    # Probe protocol versions
    version_checks = []
    try:
        for label, const in [
            ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
            ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
            ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
            ("TLS 1.0", ssl.TLSVersion.TLSv1),
        ]:
            version_checks.append(_check_version(domain, port, const, label, min(timeout, 4)))
    except AttributeError:
        pass

    weak_supported = [v["label"] for v in version_checks if v["supported"] and v["label"] in {"TLS 1.0", "TLS 1.1"}]

    issues = []
    if expired:
        issues.append(f"TLS certificate expired ({days_left} days ago)")
    elif isinstance(days_left, int) and days_left < 30:
        issues.append(f"TLS certificate expires soon ({days_left} days remaining)")

    if verify_failed:
        issues.append(f"Certificate trust verification failed: {verify_error_msg}")

    if weak_supported:
        issues.append(f"Legacy weak TLS protocols active: {', '.join(weak_supported)}")

    return {
        "negotiated_version": tls_ver or "TLS",
        "cipher": {
            "name": cipher[0] if cipher else "Unknown",
            "protocol": cipher[1] if cipher else "TLS",
            "bits": cipher[2] if cipher else 0
        } if cipher else None,
        "cert": {
            "subject_cn":   subject_dict.get("commonName") or domain,
            "issuer_cn":    issuer_dict.get("commonName") or "Unknown Issuer",
            "issuer_org":   issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Org",
            "not_before":   not_before_str,
            "not_after":    not_after_str,
            "days_left":    days_left,
            "expired":      expired,
            "sans":         sans,
            "san_count":    len(sans),
            "trust_verified": not verify_failed,
        },
        "version_support": version_checks,
        "weak_versions": weak_supported,
        "issues": issues,
    }
