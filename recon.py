"""
OSINT Recon — reconocimiento pasivo de dominios.
Solo usar contra infraestructura propia o con autorización explícita.
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from modules import dns_module, whois_module, crtsh_module, headers_module, portscan, tls_module, email_security, tech_fingerprint
from reporter import generate_report

console = Console()

MODULES = {
    "dns":     dns_module.run,
    "whois":   whois_module.run,
    "crtsh":   crtsh_module.run,
    "headers": headers_module.run,
    "ports":   portscan.run,
    "tls":     tls_module.run,
    "email":   email_security.run,
    "tech":    tech_fingerprint.run,
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="OSINT Recon — reconocimiento pasivo de dominios",
        epilog="Ejemplo: python recon.py example.com --modules dns,crtsh,headers",
    )
    p.add_argument("target", help="Dominio objetivo (ej: example.com)")
    p.add_argument(
        "--modules", "-m",
        default=",".join(MODULES),
        help=f"Módulos a ejecutar separados por coma. Disponibles: {', '.join(MODULES)}",
    )
    p.add_argument(
        "--output", "-o",
        default="reports",
        help="Directorio de salida (default: reports/)",
    )
    p.add_argument(
        "--format", "-f",
        choices=["json", "html", "both"],
        default="both",
        help="Formato del reporte (default: both)",
    )
    p.add_argument(
        "--timeout", "-t",
        type=int,
        default=10,
        help="Timeout en segundos por módulo (default: 10)",
    )
    return p.parse_args()


def run_modules(target: str, selected: list[str], timeout: int) -> dict:
    results: dict[str, dict] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        tasks = {m: progress.add_task(f"[cyan]{m}[/cyan]", total=None) for m in selected}

        with ThreadPoolExecutor(max_workers=len(selected)) as executor:
            futures = {
                executor.submit(MODULES[m], target, timeout): m
                for m in selected
            }
            for future in as_completed(futures):
                mod = futures[future]
                try:
                    results[mod] = future.result()
                    progress.update(tasks[mod], description=f"[green]✓ {mod}[/green]")
                except Exception as e:
                    results[mod] = {"error": str(e)}
                    progress.update(tasks[mod], description=f"[red]✗ {mod}[/red]")

    return results


def print_summary(target: str, results: dict) -> None:
    console.print()

    # DNS
    if "dns" in results and "error" not in results["dns"]:
        t = Table("Tipo", "Registros", box=box.SIMPLE, show_header=True, header_style="bold cyan")
        for rtype, vals in results["dns"].items():
            if vals and not isinstance(vals, dict):
                t.add_row(rtype, ", ".join(str(v) for v in vals[:3]) + ("…" if len(vals) > 3 else ""))
        if t.row_count:
            console.print("[bold]DNS[/bold]")
            console.print(t)

    # WHOIS
    if "whois" in results and "error" not in results["whois"]:
        w = results["whois"]
        console.print("[bold]WHOIS[/bold]")
        for field in ("registrar", "creation_date", "expiration_date", "country", "org"):
            val = w.get(field)
            if val:
                val = val[0] if isinstance(val, list) else val
                console.print(f"  [cyan]{field:<18}[/cyan] {val}")
        console.print()

    # crt.sh
    if "crtsh" in results and "error" not in results["crtsh"]:
        subs = results["crtsh"].get("subdomains", [])
        console.print(f"[bold]Subdominios[/bold]  ({len(subs)} encontrados)")
        for s in subs[:20]:
            console.print(f"  [dim]·[/dim] {s}")
        if len(subs) > 20:
            console.print(f"  [dim]… y {len(subs) - 20} más en el reporte[/dim]")
        console.print()

    # Headers
    if "headers" in results:
        https = results["headers"].get("https", {})
        if "error" not in https:
            score = https.get("security_score", 0)
            color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
            missing = https.get("missing_security_headers", [])
            console.print(f"[bold]Security Headers[/bold]  score: [{color}]{score}%[/{color}]")
            if missing:
                console.print(f"  [red]Ausentes:[/red] {', '.join(missing)}")
            console.print()

    # Ports
    if "ports" in results and "error" not in results["ports"]:
        open_ = results["ports"].get("open_ports", [])
        risky = results["ports"].get("risky", [])
        console.print(f"[bold]Puertos abiertos[/bold]  ({len(open_)} detectados)")
        for p in open_:
            warn = " [yellow]⚠ RIESGO[/yellow]" if p.get("risk") else ""
            console.print(f"  [dim]·[/dim] {p['port']}/{p['service']}{warn}")
        if risky:
            console.print(f"  [red]Puertos de alto riesgo expuestos: {len(risky)}[/red]")
        console.print()

    # Tech fingerprint
    if "tech" in results and "error" not in results["tech"]:
        tech = results["tech"]
        by_cat = tech.get("by_category", {})
        console.print(f"[bold]Tech Stack[/bold]  ({tech.get('total', 0)} tecnologías detectadas)")
        for cat, techs in by_cat.items():
            console.print(f"  [cyan]{cat:<18}[/cyan] {', '.join(techs)}")
        if not by_cat:
            console.print("  [dim]Stack no identificado (puede estar obfuscado)[/dim]")
        console.print()

    # Email security
    if "email" in results and "error" not in results["email"]:
        em = results["email"]
        score = em.get("score", 0)
        color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
        console.print(f"[bold]Email Security[/bold]  score: [{color}]{score}%[/{color}]")
        spf   = em.get("spf",   {})
        dkim  = em.get("dkim",  {})
        dmarc = em.get("dmarc", {})
        console.print(f"  [cyan]SPF:[/cyan]   {'presente' if spf.get('present') else '[red]AUSENTE[/red]'}  política: {spf.get('policy') or '—'}")
        sels = ", ".join(s["selector"] for s in dkim.get("selectors", []))
        console.print(f"  [cyan]DKIM:[/cyan]  {'encontrado' if dkim.get('found') else '[red]NO ENCONTRADO[/red]'}  {f'(selectores: {sels})' if sels else ''}")
        console.print(f"  [cyan]DMARC:[/cyan] {'presente' if dmarc.get('present') else '[red]AUSENTE[/red]'}  política: {dmarc.get('policy') or '—'}")
        for issue in em.get("all_issues", []):
            console.print(f"  [yellow]⚠ {issue}[/yellow]")
        console.print()

    # TLS
    if "tls" in results and "error" not in results["tls"]:
        tls = results["tls"]
        cert = tls.get("cert", {})
        days = cert.get("days_left")
        days_color = "green" if isinstance(days, int) and days > 30 else "yellow" if isinstance(days, int) and days >= 0 else "red"
        console.print(f"[bold]TLS[/bold]  {tls.get('negotiated_version','?')} · {tls.get('cipher',{}).get('name','?')}")
        console.print(f"  [cyan]Emisor:[/cyan] {cert.get('issuer_org','?')} ({cert.get('issuer_cn','?')})")
        console.print(f"  [cyan]Vence:[/cyan]  {cert.get('not_after','?')}  [{days_color}]{days} días[/{days_color}]")
        console.print(f"  [cyan]SANs:[/cyan]   {', '.join(cert.get('sans', [])[:5])}")
        issues = tls.get("issues", [])
        if issues:
            for issue in issues:
                console.print(f"  [red]⚠ {issue}[/red]")
        console.print()


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = parse_args()

    target = args.target.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
    selected = [m.strip() for m in args.modules.split(",") if m.strip() in MODULES]

    if not selected:
        console.print(f"[red]Módulos inválidos. Disponibles: {', '.join(MODULES)}[/red]")
        sys.exit(1)

    console.print(Panel(
        f"[bold cyan]OSINT Recon[/bold cyan]\n"
        f"[dim]Target:[/dim]  [yellow]{target}[/yellow]\n"
        f"[dim]Módulos:[/dim] {', '.join(selected)}",
        border_style="cyan",
        expand=False,
    ))

    from datetime import datetime, timezone
    results_full = {
        "target":    target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "modules":   run_modules(target, selected, args.timeout),
    }

    print_summary(target, results_full["modules"])

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = generate_report(results_full, out_dir, args.format)

    console.print("[green]Reporte guardado:[/green]")
    for fmt, path in paths.items():
        console.print(f"  [cyan]{fmt}[/cyan]  {path}")


if __name__ == "__main__":
    main()
