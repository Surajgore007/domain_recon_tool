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
    tech    = mods.get("tech",    {})
    wb      = mods.get("wayback", {})

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT Recon — {target}</title>
<style>
  :root {{
    --bg:      #0b0f19;
    --surface: #131b2e;
    --border:  #232d42;
    --blue:    #38bdf8;
    --green:   #10b981;
    --yellow:  #f59e0b;
    --red:     #ef4444;
    --text:    #f1f5f9;
    --muted:   #94a3b8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font: 14px/1.6 'Inter', 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  h1 {{ color: var(--blue); font-size: 1.6rem; margin-bottom: .25rem; font-weight: 700; }}
  h2 {{ color: var(--blue); font-size: 1rem; margin: 1.5rem 0 .75rem; border-bottom: 1px solid var(--border); padding-bottom: .4rem; }}
  .meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 2rem; }}
  .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.4rem; min-width: 140px; }}
  .card .num {{ font-size: 2rem; font-weight: 700; color: var(--blue); font-family: monospace; }}
  .card .lbl {{ color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: 0.04em; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 1rem; }}
  th {{ background: var(--surface); color: var(--muted); font-size: .8rem; text-align: left; padding: .6rem .75rem; border-bottom: 1px solid var(--border); }}
  td {{ padding: .5rem .75rem; border-bottom: 1px solid var(--border); font-size: .85rem; word-break: break-all; }}
  tr:hover td {{ background: var(--surface); }}
  .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }}
  .ok  {{ background: rgba(16, 185, 129, 0.15); color: var(--green); }}
  .bad {{ background: rgba(239, 68, 68, 0.15); color: var(--red); }}
  .warn{{ background: rgba(245, 158, 11, 0.15); color: var(--yellow); }}
  .score-bar {{ height: 8px; border-radius: 4px; background: var(--border); margin-top: .3rem; }}
  .score-fill {{ height: 100%; border-radius: 4px; transition: width .3s; }}
  .subdomain-list {{ display: flex; flex-wrap: wrap; gap: .4rem; }}
  .subdomain-list span {{ background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: .2rem .6rem; font-size: .8rem; font-family: monospace; }}
  pre {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; overflow-x: auto; font-size: .8rem; }}
</style>
</head>
<body>
<h1>OSINT Recon Intelligence Report</h1>
<div class="meta">Target: <strong>{target}</strong> &nbsp;·&nbsp; {ts} UTC</div>

{_summary_cards(crtsh, ports, headers)}
{_dns_section(dns)}
{_whois_section(whois)}
{_crtsh_section(crtsh)}
{_headers_section(headers)}
{_tls_section(tls)}
{_email_section(email)}
{_tech_section(tech)}
{_wayback_section(wb)}
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
  <div class="card"><div class="num">{subs}</div><div class="lbl">Subdomains</div></div>
  <div class="card"><div class="num">{open_}</div><div class="lbl">Open Ports</div></div>
  <div class="card"><div class="num" style="color:{score_color}">{score}%</div><div class="lbl">Security Headers</div></div>
  <div class="card"><div class="num" style="color:var(--red)">{risky}</div><div class="lbl">Risky Ports</div></div>
</div>"""


def _dns_section(dns: dict) -> str:
    if "error" in dns:
        return f'<h2>DNS Records</h2><p class="badge bad">{dns["error"]}</p>'
    rows = ""
    for rtype, vals in dns.items():
        if not vals or isinstance(vals, dict):
            continue
        for v in vals:
            rows += f"<tr><td><strong>{rtype}</strong></td><td><code>{v}</code></td></tr>"
    if not rows:
        return '<h2>DNS Records</h2><p style="color:var(--muted)">No records found.</p>'
    return f"""<h2>DNS Records</h2>
<table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>"""


def _whois_section(w: dict) -> str:
    if "error" in w:
        return f'<h2>WHOIS Registration</h2><p class="badge bad">{w["error"]}</p>'
    rows = ""
    labels = {
        "registrar": "Registrar", "creation_date": "Created", "expiration_date": "Expires",
        "updated_date": "Updated", "country": "Country", "org": "Organization",
        "emails": "Emails", "name_servers": "Name Servers", "status": "Status",
    }
    for key, label in labels.items():
        val = w.get(key)
        if not val:
            continue
        if isinstance(val, list):
            val = ", ".join(val)
        rows += f"<tr><td><strong>{label}</strong></td><td>{val}</td></tr>"
    return f"""<h2>WHOIS Registration</h2>
<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>"""


def _crtsh_section(c: dict) -> str:
    if "error" in c:
        return f'<h2>Certificate Transparency / Subdomains</h2><p class="badge bad">{c["error"]}</p>'
    subs = c.get("subdomains", [])
    if not subs:
        return '<h2>Certificate Transparency / Subdomains</h2><p style="color:var(--muted)">No subdomains discovered.</p>'
    tags = "".join(f"<span>{s}</span>" for s in subs)
    return f"""<h2>Certificate Transparency / Subdomains ({len(subs)})</h2>
<div class="subdomain-list">{tags}</div>"""


def _headers_section(h: dict) -> str:
    https = h.get("https", {})
    if "error" in https:
        http = h.get("http", {})
        if "error" in http:
            return f'<h2>HTTP Security Headers</h2><p class="badge bad">Could not connect: {https["error"]}</p>'
        https = http

    score = https.get("security_score", 0)
    color = "var(--green)" if score >= 70 else "var(--yellow)" if score >= 40 else "var(--red)"
    sec = https.get("security_headers", {})
    rows = ""
    for header, info in sec.items():
        badge = '<span class="badge ok">PRESENT</span>' if info["present"] else '<span class="badge bad">MISSING</span>'
        val = info.get("value") or "—"
        rows += f"<tr><td>{header}</td><td>{badge}</td><td style='color:var(--muted)'>{val[:80] if val != '—' else val}</td></tr>"

    return f"""<h2>HTTP Security Headers</h2>
<div style="margin-bottom:.75rem">
  Score: <strong style="color:{color}">{score}%</strong>
  <div class="score-bar"><div class="score-fill" style="width:{score}%;background:{color}"></div></div>
</div>
<p style="color:var(--muted);font-size:.8rem;margin-bottom:.75rem">Final URL: {https.get('final_url','—')} · Server: {https.get('server','—')}</p>
<table><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>"""


def _ports_section(p: dict) -> str:
    if "error" in p:
        return f'<h2>Ports</h2><p class="badge bad">{p["error"]}</p>'
    ip = p.get("ip", "—")
    open_ = p.get("open_ports", [])
    if not open_:
        return f'<h2>Open Ports (IP: {ip})</h2><p style="color:var(--muted)">No open ports detected.</p>'
    rows = ""
    for port_info in open_:
        risk = '<span class="badge warn">RISKY</span>' if port_info.get("risk") else ""
        rows += f"<tr><td>{port_info['port']}</td><td>{port_info['service']}</td><td>{risk}</td></tr>"
    return f"""<h2>Open Ports (IP: {ip})</h2>
<table><thead><tr><th>Port</th><th>Service</th><th>Risk</th></tr></thead><tbody>{rows}</tbody></table>"""


def _tls_section(tls: dict) -> str:
    if not tls:
        return ""
    if "error" in tls:
        return f'<h2>TLS / SSL Certificate</h2><p class="badge bad">{tls["error"]}</p>'

    cert    = tls.get("cert", {})
    cipher  = tls.get("cipher", {})
    days    = cert.get("days_left")
    ver_sup = tls.get("version_support", [])
    issues  = tls.get("issues", [])

    if isinstance(days, int):
        days_color = "var(--green)" if days > 30 else "var(--yellow)" if days >= 0 else "var(--red)"
        days_label = f'<span style="color:{days_color}">{days} days remaining</span>'
    else:
        days_label = "—"

    ver_rows = ""
    for v in ver_sup:
        badge = '<span class="badge ok">YES</span>' if v["supported"] else '<span class="badge bad">NO</span>'
        ver_rows += f"<tr><td>{v['label']}</td><td>{badge}</td></tr>"

    issue_html = ""
    if issues:
        items = "".join(f"<li>{i}</li>" for i in issues)
        issue_html = f'<div class="badge bad" style="margin-bottom:.5rem">⚠ {len(issues)} issue(s) detected</div><ul style="margin-left:1rem;color:var(--red)">{items}</ul>'

    sans = ", ".join(cert.get("sans", [])[:8])

    return f"""<h2>TLS / SSL Certificate</h2>
{issue_html}
<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>
<tr><td>Negotiated Version</td><td><code>{tls.get('negotiated_version','—')}</code></td></tr>
<tr><td>Cipher Suite</td><td><code>{cipher.get('name','—')}</code> ({cipher.get('bits','?')} bits)</td></tr>
<tr><td>Subject (CN)</td><td>{cert.get('subject_cn','—')}</td></tr>
<tr><td>Issuer</td><td>{cert.get('issuer_org','—')} — {cert.get('issuer_cn','—')}</td></tr>
<tr><td>Valid From</td><td>{cert.get('not_before','—')}</td></tr>
<tr><td>Expires</td><td>{cert.get('not_after','—')} &nbsp; {days_label}</td></tr>
<tr><td>SANs ({cert.get('san_count',0)})</td><td style="font-size:.8rem">{sans}</td></tr>
</tbody></table>
<h2 style="margin-top:.5rem">Supported TLS Versions</h2>
<table><thead><tr><th>Version</th><th>Supported</th></tr></thead><tbody>{ver_rows}</tbody></table>"""


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

    spf_badge   = '<span class="badge ok">PRESENT</span>' if spf.get("present")  else '<span class="badge bad">MISSING</span>'
    dkim_badge  = '<span class="badge ok">FOUND</span>' if dkim.get("found") else '<span class="badge bad">NOT FOUND</span>'
    dmarc_badge = '<span class="badge ok">PRESENT</span>' if dmarc.get("present") else '<span class="badge bad">MISSING</span>'

    selectors_html = ""
    if dkim.get("selectors"):
        sels = "".join(f'<span class="badge ok" style="margin:.1rem">{s["selector"]}</span>' for s in dkim["selectors"])
        selectors_html = f"<br><small style='color:var(--muted)'>Selectors: {sels}</small>"

    issues = em.get("all_issues", [])
    issue_html = ""
    if issues:
        items = "".join(f"<li>{i}</li>" for i in issues)
        issue_html = f'<ul style="margin:.5rem 0 .5rem 1rem;color:var(--yellow)">{items}</ul>'

    return f"""<h2>Email Security &nbsp;<span style="color:{color};font-size:.85rem">Score: {score}%</span></h2>
{issue_html}
<table><thead><tr><th>Protocol</th><th>Status</th><th>Policy</th></tr></thead><tbody>
<tr><td>SPF</td><td>{spf_badge}</td><td>{spf.get('policy') or '—'}</td></tr>
<tr><td>DKIM</td><td>{dkim_badge}{selectors_html}</td><td>—</td></tr>
<tr><td>DMARC</td><td>{dmarc_badge}</td><td>{dmarc.get('policy') or '—'} (pct={dmarc.get('pct','?')}%)</td></tr>
</tbody></table>"""


def _tech_section(tech: dict) -> str:
    if not tech:
        return ""
    if "error" in tech:
        return f'<h2>Tech Stack</h2><p class="badge bad">{tech["error"]}</p>'

    techs  = tech.get("technologies", {})

    if not techs:
        return '<h2>Tech Stack</h2><p style="color:var(--muted)">Stack unidentified (may be obfuscated).</p>'

    rows = ""
    for name, info in techs.items():
        evidence = info.get("evidence", "")
        ver      = f' <span style="color:var(--muted);font-size:.8rem">{info["version"]}</span>' if info.get("version") else ""
        rows += f'<tr><td>{name}{ver}</td><td><span class="badge ok">{info["category"]}</span></td><td style="color:var(--muted);font-size:.8rem">{evidence}</td></tr>'

    return f"""<h2>Tech Stack ({len(techs)} technologies)</h2>
<table><thead><tr><th>Technology</th><th>Category</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>"""


def _wayback_section(wb: dict) -> str:
    if not wb:
        return ""
    if "error" in wb:
        return f'<h2>Wayback Machine</h2><p style="color:var(--muted)">{wb["error"]}</p>'

    total       = wb.get("total_snapshots", 0)
    latest      = wb.get("latest_snapshot", "")
    latest_ts   = wb.get("latest_timestamp", "")
    first       = wb.get("first_seen", "")
    last        = wb.get("last_seen", "")
    subs        = wb.get("subdomains", [])
    interesting = wb.get("interesting", [])
    mime        = wb.get("mime_breakdown", {})

    snapshot_html = f'<p><a href="{latest}" target="_blank" style="color:var(--blue)">{latest}</a> &nbsp;<span style="color:var(--muted)">({latest_ts})</span></p>' if latest else ""

    sub_html = ""
    if subs:
        sub_html = f"<p style='margin:.5rem 0 .25rem;color:var(--muted);font-size:.8rem'>Subdomains found in archive:</p><div class='subdomain-list'>" + "".join(f"<span>{s}</span>" for s in subs) + "</div>"

    int_html = ""
    if interesting:
        rows = "".join(f'<tr><td style="font-size:.8rem;font-family:monospace">{u[:100]}</td></tr>' for u in interesting[:15])
        int_html = f'<h2 style="margin-top:.75rem">Interesting Endpoints ({len(interesting)})</h2><table><tbody>{rows}</tbody></table>'

    mime_html = ""
    if mime:
        rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in list(mime.items())[:6])
        mime_html = f'<h2 style="margin-top:.75rem">Archived Content Types</h2><table><thead><tr><th>MIME Type</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>'

    meta = ""
    if first and last:
        meta = f'<p style="color:var(--muted);font-size:.8rem">First Snapshot: {first} &nbsp;·&nbsp; Last Snapshot: {last} &nbsp;·&nbsp; Total Archival URLs: {total}</p>'

    return f"""<h2>Wayback Machine</h2>
<p style="color:var(--muted);font-size:.85rem">Latest Snapshot:</p>
{snapshot_html}
{meta}
{sub_html}
{int_html}
{mime_html}"""
