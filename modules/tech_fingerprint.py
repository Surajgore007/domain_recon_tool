import re
import requests

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# (regex_pattern, search_field, technology_name, category)
SIGNATURES: list[tuple[str, str, str, str]] = [
    # Web Servers & Edge Gateways
    (r"nginx",                              "server",       "Nginx",              "web-server"),
    (r"apache",                             "server",       "Apache HTTP Server", "web-server"),
    (r"^gws$",                              "server",       "Google Web Server (GWS)", "web-server"),
    (r"^esf$",                              "server",       "Google ESF (Edge)",  "web-server"),
    (r"cloudflare",                         "server",       "Cloudflare Edge",    "cdn"),
    (r"cf-ray",                             "headers",      "Cloudflare CDN",     "cdn"),
    (r"LiteSpeed",                          "server",       "LiteSpeed",          "web-server"),
    (r"Microsoft-IIS|IIS",                  "server",       "Microsoft IIS",      "web-server"),
    (r"openresty",                          "server",       "OpenResty",          "web-server"),
    (r"Caddy",                              "server",       "Caddy",              "web-server"),
    (r"AmazonS3",                           "server",       "Amazon S3",          "hosting"),
    (r"x-amz-cf-id|cloudfront",             "headers",      "AWS CloudFront",     "cdn"),
    (r"x-vercel-id",                        "headers",      "Vercel Platform",    "paas"),
    (r"x-nf-request-id",                    "headers",      "Netlify Edge",       "paas"),
    (r"x-fastly-request-id",                "headers",      "Fastly CDN",         "cdn"),
    (r"x-akamai",                           "headers",      "Akamai CDN",         "cdn"),

    # Languages and Backend Runtimes
    (r"PHP/[\d.]+|PHP",                     "x-powered-by", "PHP",                "language"),
    (r"ASP\.NET",                           "x-powered-by", "ASP.NET",            "framework"),
    (r"Express",                            "x-powered-by", "Express.js",         "framework"),
    (r"Next\.js",                           "x-powered-by", "Next.js",            "framework"),
    (r"Python",                             "server",       "Python",             "language"),
    (r"gunicorn",                           "server",       "Gunicorn (WSGI)",    "web-server"),
    (r"uvicorn",                            "server",       "Uvicorn (ASGI)",     "web-server"),

    # Disclosing Session Cookies
    (r"PHPSESSID",                          "set-cookie",   "PHP",                "language"),
    (r"ASP\.NET_SessionId",                 "set-cookie",   "ASP.NET",            "framework"),
    (r"JSESSIONID",                         "set-cookie",   "Java / Spring",      "framework"),
    (r"laravel_session",                    "set-cookie",   "Laravel",            "framework"),
    (r"csrftoken",                          "set-cookie",   "Django",             "framework"),
    (r"_rails",                             "set-cookie",   "Ruby on Rails",      "framework"),
    (r"wp-settings|wordpress_",            "set-cookie",   "WordPress",          "cms"),
    (r"_shopify",                           "set-cookie",   "Shopify",            "ecommerce"),

    # CMS & Platforms in HTML
    (r'name=["\']generator["\'] content=["\']WordPress', "html", "WordPress",    "cms"),
    (r'name=["\']generator["\'] content=["\']Joomla',    "html", "Joomla",       "cms"),
    (r'name=["\']generator["\'] content=["\']Drupal',    "html", "Drupal",       "cms"),
    (r'shopify\.com|Shopify\.theme',                     "html", "Shopify",      "ecommerce"),
    (r'wix\.com|_wix',                                   "html", "Wix",          "website-builder"),
    (r'squarespace\.com|static1\.squarespace',           "html", "Squarespace",  "website-builder"),
    (r'ghost\.org|ghost-theme',                          "html", "Ghost CMS",    "cms"),
    (r'webflow\.com|w-nav',                              "html", "Webflow",      "website-builder"),

    # Frontend Libraries & Frameworks
    (r'react(?:\.production|\.min)?\.js|__REACT',       "html", "React",         "js-framework"),
    (r'vue(?:\.runtime|\.min)?\.js|__VUE__',             "html", "Vue.js",        "js-framework"),
    (r'angular(?:\.min)?\.js|ng-version|ng-app',        "html", "Angular",       "js-framework"),
    (r'next/dist|__NEXT_DATA__',                         "html", "Next.js",       "js-framework"),
    (r'nuxt|__NUXT__',                                   "html", "Nuxt.js",       "js-framework"),
    (r'svelte',                                          "html", "Svelte",        "js-framework"),
    (r'jquery(?:\.min)?\.js',                            "html", "jQuery",        "js-library"),
    (r'bootstrap(?:\.min)?\.(?:css|js)',                 "html", "Bootstrap",     "css-framework"),
    (r'tailwind',                                        "html", "Tailwind CSS",  "css-framework"),
    (r'font-awesome|fontawesome',                        "html", "Font Awesome",  "icon-library"),

    # Analytics & Tag Managers
    (r'google-analytics\.com|gtag\(|ga\(',              "html", "Google Analytics", "analytics"),
    (r'googletagmanager\.com|gtm\.js',                   "html", "Google Tag Manager", "analytics"),
    (r'hotjar\.com',                                     "html", "Hotjar",        "analytics"),
    (r'clarity\.ms',                                     "html", "Microsoft Clarity", "analytics"),

    # Security & CAPTCHA Protections
    (r'challenges\.cloudflare\.com/turnstile',           "html", "Cloudflare Turnstile", "bot-protection"),
    (r'google\.com/recaptcha',                           "html", "Google reCAPTCHA",     "bot-protection"),
    (r'hcaptcha\.com',                                   "html", "hCaptcha",             "bot-protection"),
]


def _fetch_target(domain: str, timeout: int) -> tuple[dict | None, str, str | None]:
    """Resilient fetch trying HTTPS apex, then HTTP, then www subdomain."""
    candidates = [
        f"https://{domain}",
        f"https://www.{domain}",
        f"http://{domain}",
        f"http://www.{domain}",
    ]

    for url in candidates:
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": UA},
            )
            return dict(resp.headers), resp.text, resp.url
        except Exception:
            continue

    return None, "", None


def run(domain: str, timeout: int = 10) -> dict:
    headers, html, final_url = _fetch_target(domain, timeout)
    if headers is None:
        return {"error": f"Could not establish web connection to {domain} on ports 80/443"}

    # Case-insensitive headers lookup string
    h_lower = {k.lower(): str(v) for k, v in headers.items()}
    headers_all_str = " ".join([f"{k}:{v}" for k, v in h_lower.items()]).lower()
    html_buffer = html[:65000].lower()

    found: dict[str, dict] = {}

    for pattern, search_field, tech_name, category in SIGNATURES:
        if tech_name in found:
            continue

        target_text = ""
        if search_field == "html":
            target_text = html_buffer
        elif search_field == "headers":
            target_text = headers_all_str
        else:
            target_text = h_lower.get(search_field, "")

        match = re.search(pattern, target_text, re.IGNORECASE)
        if match:
            found[tech_name] = {
                "category": category,
                "evidence": f"{search_field}: {match.group()[:60]}",
            }

    # Group by Category
    by_category: dict[str, list] = {}
    for tech, info in found.items():
        cat = info["category"]
        by_category.setdefault(cat, []).append(tech)

    return {
        "technologies": found,
        "by_category":  by_category,
        "total":        len(found),
        "final_url":    final_url,
        "server":       h_lower.get("server"),
        "x_powered_by": h_lower.get("x-powered-by"),
    }
