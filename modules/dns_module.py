import dns.resolver

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def run(domain: str, timeout: int = 10) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    results = {}

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results[rtype] = []
        except dns.exception.Timeout:
            results[rtype] = {"error": "timeout"}
        except Exception as e:
            results[rtype] = {"error": str(e)}

    return results
