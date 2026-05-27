import re
import requests

UA = "Mozilla/5.0 (compatible; osint-recon/1.0)"

# Firmas: (patrón_regex, campo_donde_buscar, tecnología, categoría)
SIGNATURES: list[tuple[str, str, str, str]] = [
    # Servidores web
    (r"nginx",              "server",      "Nginx",           "web-server"),
    (r"apache",             "server",      "Apache",          "web-server"),
    (r"cloudflare",         "server",      "Cloudflare",      "cdn"),
    (r"AmazonS3",           "server",      "Amazon S3",       "hosting"),
    (r"LiteSpeed",          "server",      "LiteSpeed",       "web-server"),
    (r"Microsoft-IIS",      "server",      "IIS",             "web-server"),
    (r"openresty",          "server",      "OpenResty",       "web-server"),
    (r"Caddy",              "server",      "Caddy",           "web-server"),
    # Lenguajes/frameworks desde headers
    (r"PHP/[\d.]+",         "x-powered-by","PHP",             "language"),
    (r"ASP\.NET",           "x-powered-by","ASP.NET",         "framework"),
    (r"Express",            "x-powered-by","Express.js",      "framework"),
    (r"Next\.js",           "x-powered-by","Next.js",         "framework"),
    # CDN / proxy
    (r"varnish",            "via",         "Varnish",         "cdn"),
    (r"cloudfront",         "via",         "CloudFront",      "cdn"),
    # Cookies reveladoras
    (r"PHPSESSID",          "set-cookie",  "PHP",             "language"),
    (r"ASP\.NET_SessionId", "set-cookie",  "ASP.NET",         "framework"),
    (r"JSESSIONID",         "set-cookie",  "Java/Spring",     "framework"),
    (r"laravel_session",    "set-cookie",  "Laravel",         "framework"),
    (r"wp-settings",        "set-cookie",  "WordPress",       "cms"),
    (r"_rails",             "set-cookie",  "Ruby on Rails",   "framework"),
    # HTML — meta generator
    (r'WordPress [\d.]+',   "html",        "WordPress",       "cms"),
    (r'Joomla!',            "html",        "Joomla",          "cms"),
    (r'Drupal',             "html",        "Drupal",          "cms"),
    (r'Shopify',            "html",        "Shopify",         "ecommerce"),
    (r'Wix\.com',           "html",        "Wix",             "website-builder"),
    # JS libs en HTML
    (r'react(?:\.min)?\.js|__REACT',       "html", "React",       "js-framework"),
    (r'vue(?:\.min)?\.js|__VUE__',         "html", "Vue.js",      "js-framework"),
    (r'angular(?:\.min)?\.js|ng-version',  "html", "Angular",     "js-framework"),
    (r'jquery(?:\.min)?\.js',              "html", "jQuery",      "js-library"),
    (r'bootstrap(?:\.min)?\.css',          "html", "Bootstrap",   "css-framework"),
    (r'tailwindcss',                        "html", "Tailwind CSS","css-framework"),
    (r'next/dist|__NEXT',                  "html", "Next.js",     "js-framework"),
    (r'nuxt',                               "html", "Nuxt.js",     "js-framework"),
    # Analytics/tracking en HTML
    (r'google-analytics\.com|gtag\(',      "html", "Google Analytics", "analytics"),
    (r'googletagmanager\.com',             "html", "Google Tag Manager","analytics"),
    (r'hotjar\.com',                       "html", "Hotjar",      "analytics"),
]


def _fetch(domain: str, timeout: int) -> tuple[dict, str] | None:
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}",
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": UA},
            )
            return dict(resp.headers), resp.text
        except Exception:
            continue
    return None, ""


def run(domain: str, timeout: int = 10) -> dict:
    headers, html = _fetch(domain, timeout)
    if headers is None:
        return {"error": f"No se pudo conectar a {domain}"}

    # Normalizar headers a minúsculas para búsqueda
    h = {k.lower(): v for k, v in headers.items()}
    html_lower = html[:50000].lower()  # limitar para no tardar

    found: dict[str, dict] = {}  # tech -> {categoria, evidencia}

    for pattern, field, tech, category in SIGNATURES:
        if tech in found:
            continue
        target_text = ""
        if field == "html":
            target_text = html_lower
        else:
            target_text = h.get(field, "")

        match = re.search(pattern, target_text, re.IGNORECASE)
        if match:
            found[tech] = {
                "category":  category,
                "evidence":  f"{field}: {match.group()[:80]}",
            }

    # Versión PHP desde header si disponible
    php_ver = re.search(r"PHP/([\d.]+)", h.get("x-powered-by", ""), re.IGNORECASE)
    if php_ver and "PHP" in found:
        found["PHP"]["version"] = php_ver.group(1)

    # Agrupar por categoría
    by_category: dict[str, list] = {}
    for tech, info in found.items():
        cat = info["category"]
        by_category.setdefault(cat, []).append(tech)

    return {
        "technologies": found,
        "by_category":  by_category,
        "total":        len(found),
        "server":       h.get("server"),
        "x_powered_by": h.get("x-powered-by"),
    }
