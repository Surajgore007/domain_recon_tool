import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Solo puertos comunes — no es un scan exhaustivo
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


def _probe(host: str, port: int, service: str, timeout: float) -> dict | None:
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


def run(domain: str, timeout: int = 10) -> dict:
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return {"error": str(e)}

    # Distribuye el timeout entre todos los puertos, mínimo 1 s
    per_port = max(1.0, timeout / len(COMMON_PORTS))
    open_ports: list[dict] = []

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {
            executor.submit(_probe, ip, port, svc, per_port): port
            for port, svc in COMMON_PORTS.items()
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])

    return {
        "ip":         ip,
        "open_ports": open_ports,
        "total_open": len(open_ports),
        "risky":      [p for p in open_ports if p["risk"]],
    }
