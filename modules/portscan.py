import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    587:   "SMTP/TLS",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    6379:  "Redis",
    8080:  "HTTP-alt",
    8443:  "HTTPS-alt",
    27017: "MongoDB",
}

RISKY_PORTS = {23, 445, 3389, 6379, 27017}


def _probe_port(host: str, port: int, service: str, timeout: float) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {
                "port":    port,
                "service": service,
                "state":   "open",
                "risk":    port in RISKY_PORTS,
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def _get_ip_asn(ip: str, timeout: int = 3) -> dict:
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,isp,org,as,country,city",
            timeout=timeout
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "asn":     data.get("as"),
                    "isp":     data.get("isp"),
                    "org":     data.get("org"),
                    "country": data.get("country"),
                    "city":    data.get("city"),
                }
    except Exception:
        pass
    return {}


def run(domain: str, timeout: int = 10) -> dict:
    # 1. Resolve host IP (try apex, fallback to www)
    ip = None
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        if not domain.startswith("www."):
            try:
                ip = socket.gethostbyname(f"www.{domain}")
            except socket.gaierror as e:
                return {"error": f"DNS resolution failed: {e}"}
        else:
            return {"error": "Domain could not be resolved to an IP address."}

    # 2. IP Intelligence & Cloud Proxy Detection
    ip_meta = _get_ip_asn(ip)

    # 3. Probe ports in parallel
    per_port = max(1.2, timeout / len(COMMON_PORTS))
    open_ports: list[dict] = []

    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = {
            executor.submit(_probe_port, ip, port, svc, per_port): port
            for port, svc in COMMON_PORTS.items()
        }
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x["port"])
    risky = [p for p in open_ports if p["risk"]]

    # Perimeter exposure assessment
    assessment = "Standard web services exposed."
    if risky:
        assessment = f"CRITICAL: {len(risky)} high-risk administrative or database ports publicly accessible ({', '.join(p['service'] for p in risky)})!"
    elif len(open_ports) == 0:
        assessment = "No open perimeter ports identified among the 18 common audited services (host may be firewalled)."

    return {
        "ip":          ip,
        "ip_info":     ip_meta,
        "open_ports":  open_ports,
        "total_open":  len(open_ports),
        "risky":       risky,
        "assessment":  assessment,
    }
