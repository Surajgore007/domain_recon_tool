import dns.resolver
import dns.exception
import socket
import requests

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
PUBLIC_NAMESERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def _get_ip_intelligence(ip: str, timeout: int = 4) -> dict | None:
    """Enrich resolved IP address with ASN, ISP, Organization, and Geolocation."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip":          ip,
                    "country":     data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region":      data.get("regionName"),
                    "city":        data.get("city"),
                    "isp":         data.get("isp"),
                    "org":         data.get("org"),
                    "asn":         data.get("as"),
                }
    except Exception:
        pass
    return None


def _get_ptr(ip: str) -> str | None:
    """Reverse DNS PTR lookup."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def run(domain: str, timeout: int = 10) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 4)

    results = {}

    for rtype in RECORD_TYPES:
        answers = None
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(r).strip('"') for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results[rtype] = []
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            # Fallback to public resolvers (8.8.8.8 / 1.1.1.1)
            try:
                fb_resolver = dns.resolver.Resolver(configure=False)
                fb_resolver.nameservers = PUBLIC_NAMESERVERS
                fb_resolver.lifetime = min(timeout, 5)
                answers = fb_resolver.resolve(domain, rtype)
                results[rtype] = [str(r).strip('"') for r in answers]
            except Exception:
                results[rtype] = []
        except Exception as e:
            results[rtype] = []

    # Enrich IP addresses with Geolocation, ASN, and Reverse PTR
    ip_records = results.get("A", []) + results.get("AAAA", [])
    ip_intel_list = []
    
    # Analyze primary IP (up to first 2 to keep response prompt)
    for ip in ip_records[:2]:
        ptr = _get_ptr(ip)
        intel = _get_ip_intelligence(ip)
        if intel:
            intel["ptr"] = ptr
            ip_intel_list.append(intel)
        elif ptr:
            ip_intel_list.append({"ip": ip, "ptr": ptr})

    results["ip_intelligence"] = ip_intel_list
    results["primary_ip"] = ip_records[0] if ip_records else None

    return results
