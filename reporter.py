import json
from pathlib import Path
from datetime import datetime


def generate_report(results: dict, out_dir: Path, fmt: str = "both") -> dict[str, Path]:
    target = results["target"].replace(".", "_")
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base = f"{target}_{ts}"
    paths = {}

    if fmt in ("json", "both"):
        p = out_dir / f"{base}.json"
        p.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        paths["json"] = p

    if fmt in ("html", "both"):
        p = out_dir / f"{base}.html"
        p.write_text(_build_html(results), encoding="utf-8")
        paths["html"] = p

    return paths


# ── HTML ──────────────────────────────────────────────────────────────────────

def _build_html(r: dict) -> str:
    target = r["target"]
    ts     = r.get("timestamp", "")
    mods   = r.get("modules", {})

    dns     = mods.get("dns",     {})
    whois   = mods.get("whois",   {})
    crtsh   = mods.get("crtsh",   {})
    headers = mods.get("headers", {})
    ports   = mods.get("ports",   {})
    tls     = mods.get("tls",     {})
    email   = mods.get("email",   {})

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT Recon — {target}</title>
<style>
  :root {{
    --bg:      #0d1117;
    --surface: #161b22;
    --border:  #30363d;
    --blue:    #388bfd;
    --green:   #3fb950;
    --yellow:  #d29922;
    --red:     #f85149;
    --text:    #e6edf3;
    --muted:   #8b949e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font: 14px/1.6 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  h1 {{ color: var(--blue); font-size: 1.6rem; margin-bottom: .25rem; }}
  h2 {{ color: var(--blue); font-size: 1rem; margin: 1.5rem 0 .75rem; border-bottom: 1px solid var(--border); padding-bottom: .4rem; }}
  .meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 2rem; }}
  .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem 1.4rem; min-width: 140px; }}
  .card .num {{ font-size: 2rem; font-weight: 700; color: var(--blue); }}
  .card .lbl {{ color: var(--muted); font-size: .8rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 1rem; }}
  th {{ background: var(--surface); color: var(--muted); font-size: .8rem; text-align: left; padding: .5rem .75rem; border-bottom: 1px solid var(--border); }}
  td {{ padding: .45rem .75rem; border-bottom: 1px solid var(--border); font-size: .85rem; word-break: break-all; }}
  tr:hover td {{ background: var(--surface); }}
  .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }}
  .ok  {{ background: #1a3a24; color: var(--green); }}
  .bad {{ background: #3a1a1a; color: var(--red); }}
  .warn{{ background: #3a2e0a; color: var(--yellow); }}
  .score-bar {{ height: 8px; border-radius: 4px; background: var(--border); margin-top: .3rem; }}
  .score-fill {{ height: 100%; border-radius: 4px; transition: width .3s; }}
  .subdomain-list {{ display: flex; flex-wrap: wrap; gap: .4rem; }}
  .subdomain-list span {{ background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: .2rem .6rem; font-size: .8rem; font-family: monospace; }}
  pre {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; overflow-x: auto; font-size: .8rem; }}
</style>
</head>
<body>
<h1>OSINT Recon</h1>
<div class="meta">Target: <strong>{target}</strong> &nbsp;·&nbsp; {ts} UTC</div>

{_summary_cards(crtsh, ports, headers)}
{_dns_section(dns)}
{_whois_section(whois)}
{_crtsh_section(crtsh)}
{_headers_section(headers)}
{_tls_section(tls)}
{_email_section(email)}
{_ports_section(ports)}
</body>
</html>"""


def _summary_cards(crtsh, ports, headers) -> str:
    subs  = len(crtsh.get("subdomains", []))
    open_ = ports.get("total_open", "—")
    risky = len(ports.get("risky", []))
    https = headers.get("https", {})
    score = https.get("security_score", "—")
    score_color = "var(--green)" if isinstance(score, int) and score >= 70 else "var(--yellow)" if isinstance(score, int) and score >= 40 else "var(--red)"
    return f"""<div class="cards">
  <div class="card"><div class="num">{subs}</div><div class="lbl">Subdominios</div></div>
  <div class="card"><div class="num">{open_}</div><div class="lbl">Puertos abiertos</div></div>
  <div class="card"><div class="num" style="color:{score_color}">{score}%</div><div class="lbl">Security headers</div></div>
  <div class="card"><div class="num" style="color:var(--red)">{risky}</div><div class="lbl">Puertos riesgosos</div></div>
</div>"""


def _dns_section(dns: dict) -> str:
    if "error" in dns:
        return f'<h2>DNS</h2><p class="badge bad">{dns["error"]}</p>'
    rows = ""
    for rtype, vals in dns.items():
        if not vals or isinstance(vals, dict):
            continue
        for v in vals:
            rows += f"<tr><td>{rtype}</td><td><code>{v}</code></td></tr>"
    if not rows:
        return '<h2>DNS</h2><p style="color:var(--muted)">Sin registros encontrados.</p>'
    return f"""<h2>DNS</h2>
<table><thead><tr><th>Tipo</th><th>Valor</th></tr></thead><tbody>{rows}</tbody></table>"""


def _whois_section(w: dict) -> str:
    if "error" in w:
        return f'<h2>WHOIS</h2><p class="badge bad">{w["error"]}</p>'
    rows = ""
    labels = {
        "registrar": "Registrar", "creation_date": "Creado", "expiration_date": "Vence",
        "updated_date": "Actualizado", "country": "País", "org": "Organización",
        "emails": "Emails", "name_servers": "Name servers", "status": "Estado",
    }
    for key, label in labels.items():
        val = w.get(key)
        if not val:
            continue
        if isinstance(val, list):
            val = ", ".join(val)
        rows += f"<tr><td><strong>{label}</strong></td><td>{val}</td></tr>"
    return f"""<h2>WHOIS</h2>
<table><thead><tr><th>Campo</th><th>Valor</th></tr></thead><tbody>{rows}</tbody></table>"""


def _crtsh_section(c: dict) -> str:
    if "error" in c:
        return f'<h2>Certificate Transparency / Subdominios</h2><p class="badge bad">{c["error"]}</p>'
    subs = c.get("subdomains", [])
    if not subs:
        return '<h2>Certificate Transparency / Subdominios</h2><p style="color:var(--muted)">Sin subdominios encontrados.</p>'
    tags = "".join(f"<span>{s}</span>" for s in subs)
    return f"""<h2>Certificate Transparency / Subdominios ({len(subs)})</h2>
<div class="subdomain-list">{tags}</div>"""


def _headers_section(h: dict) -> str:
    https = h.get("https", {})
    if "error" in https:
        http = h.get("http", {})
        if "error" in http:
            return f'<h2>HTTP Headers</h2><p class="badge bad">No se pudo conectar: {https["error"]}</p>'
        https = http

    score = https.get("security_score", 0)
    color = "#3fb950" if score >= 70 else "#d29922" if score >= 40 else "#f85149"
    sec = https.get("security_headers", {})
    rows = ""
    for header, info in sec.items():
        badge = '<span class="badge ok">PRESENTE</span>' if info["present"] else '<span class="badge bad">AUSENTE</span>'
        val = info.get("value") or "—"
        rows += f"<tr><td>{header}</td><td>{badge}</td><td style='color:var(--muted)'>{val[:80] if val != '—' else val}</td></tr>"

    return f"""<h2>Security Headers</h2>
<div style="margin-bottom:.75rem">
  Score: <strong style="color:{color}">{score}%</strong>
  <div class="score-bar"><div class="score-fill" style="width:{score}%;background:{color}"></div></div>
</div>
<p style="color:var(--muted);font-size:.8rem;margin-bottom:.75rem">URL: {https.get('final_url','—')} · Server: {https.get('server','—')}</p>
<table><thead><tr><th>Header</th><th>Estado</th><th>Valor</th></tr></thead><tbody>{rows}</tbody></table>"""


def _ports_section(p: dict) -> str:
    if "error" in p:
        return f'<h2>Puertos</h2><p class="badge bad">{p["error"]}</p>'
    ip = p.get("ip", "—")
    open_ = p.get("open_ports", [])
    if not open_:
        return f'<h2>Puertos (IP: {ip})</h2><p style="color:var(--muted)">Sin puertos abiertos detectados.</p>'
    rows = ""
    for port_info in open_:
        risk = '<span class="badge warn">RIESGO</span>' if port_info.get("risk") else ""
        rows += f"<tr><td>{port_info['port']}</td><td>{port_info['service']}</td><td>{risk}</td></tr>"
    return f"""<h2>Puertos abiertos (IP: {ip})</h2>
<table><thead><tr><th>Puerto</th><th>Servicio</th><th>Riesgo</th></tr></thead><tbody>{rows}</tbody></table>"""


def _tls_section(tls: dict) -> str:
    if not tls:
        return ""
    if "error" in tls:
        return f'<h2>TLS / SSL</h2><p class="badge bad">{tls["error"]}</p>'

    cert    = tls.get("cert", {})
    cipher  = tls.get("cipher", {})
    days    = cert.get("days_left")
    ver_sup = tls.get("version_support", [])
    issues  = tls.get("issues", [])

    if isinstance(days, int):
        days_color = "var(--green)" if days > 30 else "var(--yellow)" if days >= 0 else "var(--red)"
        days_label = f'<span style="color:{days_color}">{days} días restantes</span>'
    else:
        days_label = "—"

    ver_rows = ""
    for v in ver_sup:
        badge = '<span class="badge ok">SI</span>' if v["supported"] else '<span class="badge bad">NO</span>'
        ver_rows += f"<tr><td>{v['label']}</td><td>{badge}</td></tr>"

    issue_html = ""
    if issues:
        items = "".join(f"<li>{i}</li>" for i in issues)
        issue_html = f'<div class="badge bad" style="margin-bottom:.5rem">⚠ {len(issues)} problema(s)</div><ul style="margin-left:1rem;color:var(--red)">{items}</ul>'

    sans = ", ".join(cert.get("sans", [])[:8])

    return f"""<h2>TLS / SSL</h2>
{issue_html}
<table><thead><tr><th>Campo</th><th>Valor</th></tr></thead><tbody>
<tr><td>Versión negociada</td><td><code>{tls.get('negotiated_version','—')}</code></td></tr>
<tr><td>Cipher suite</td><td><code>{cipher.get('name','—')}</code> ({cipher.get('bits','?')} bits)</td></tr>
<tr><td>Sujeto (CN)</td><td>{cert.get('subject_cn','—')}</td></tr>
<tr><td>Emisor</td><td>{cert.get('issuer_org','—')} — {cert.get('issuer_cn','—')}</td></tr>
<tr><td>Válido desde</td><td>{cert.get('not_before','—')}</td></tr>
<tr><td>Vence</td><td>{cert.get('not_after','—')} &nbsp; {days_label}</td></tr>
<tr><td>SANs ({cert.get('san_count',0)})</td><td style="font-size:.8rem">{sans}</td></tr>
</tbody></table>
<h2 style="margin-top:.5rem">Versiones TLS soportadas</h2>
<table><thead><tr><th>Versión</th><th>Soportada</th></tr></thead><tbody>{ver_rows}</tbody></table>"""


def _email_section(em: dict) -> str:
    if not em:
        return ""
    if "error" in em:
        return f'<h2>Email Security</h2><p class="badge bad">{em["error"]}</p>'

    score = em.get("score", 0)
    color = "var(--green)" if score >= 70 else "var(--yellow)" if score >= 40 else "var(--red)"

    spf   = em.get("spf",   {})
    dkim  = em.get("dkim",  {})
    dmarc = em.get("dmarc", {})

    spf_badge   = '<span class="badge ok">PRESENTE</span>' if spf.get("present")  else '<span class="badge bad">AUSENTE</span>'
    dkim_badge  = '<span class="badge ok">ENCONTRADO</span>' if dkim.get("found") else '<span class="badge bad">NO ENCONTRADO</span>'
    dmarc_badge = '<span class="badge ok">PRESENTE</span>' if dmarc.get("present") else '<span class="badge bad">AUSENTE</span>'

    selectors_html = ""
    if dkim.get("selectors"):
        sels = "".join(f'<span class="badge ok" style="margin:.1rem">{s["selector"]}</span>' for s in dkim["selectors"])
        selectors_html = f"<br><small style='color:var(--muted)'>Selectores: {sels}</small>"

    issues = em.get("all_issues", [])
    issue_html = ""
    if issues:
        items = "".join(f"<li>{i}</li>" for i in issues)
        issue_html = f'<ul style="margin:.5rem 0 .5rem 1rem;color:var(--yellow)">{items}</ul>'

    return f"""<h2>Email Security &nbsp;<span style="color:{color};font-size:.85rem">Score: {score}%</span></h2>
{issue_html}
<table><thead><tr><th>Protocolo</th><th>Estado</th><th>Política</th></tr></thead><tbody>
<tr><td>SPF</td><td>{spf_badge}</td><td>{spf.get('policy') or '—'}</td></tr>
<tr><td>DKIM</td><td>{dkim_badge}{selectors_html}</td><td>—</td></tr>
<tr><td>DMARC</td><td>{dmarc_badge}</td><td>{dmarc.get('policy') or '—'} (pct={dmarc.get('pct','?')}%)</td></tr>
</tbody></table>"""
