"""
OSINT Recon — Passive Domain Reconnaissance Tool.
Authorized use only: Only scan infrastructure you own or have explicit authorization to test.
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

from modules import dns_module, whois_module, crtsh_module, headers_module, portscan, tls_module, email_security, tech_fingerprint, wayback
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
    "wayback": wayback.run,
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="OSINT Recon — Passive Domain Reconnaissance Intelligence CLI",
        epilog="Example: python recon.py example.com --modules dns,crtsh,headers",
    )
    p.add_argument("target", help="Target domain (e.g. example.com)")
    p.add_argument(
        "--modules", "-m",
        default=",".join(MODULES),
        help=f"Comma-separated modules to execute. Available: {', '.join(MODULES)}",
    )
    p.add_argument(
        "--output", "-o",
        default="reports",
        help="Output directory (default: reports/)",
    )
    p.add_argument(
        "--format", "-f",
        choices=["json", "html", "both"],
        default="both",
        help="Report export format (default: both)",
    )
    p.add_argument(
        "--timeout", "-t",
        type=int,
        default=10,
        help="Timeout in seconds per module (default: 10)",
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
        t = Table("Type", "Records", box=box.SIMPLE, show_header=True, header_style="bold cyan")
        for rtype, vals in results["dns"].items():
            if vals and not isinstance(vals, dict):
                t.add_row(rtype, ", ".join(str(v) for v in vals[:3]) + ("…" if len(vals) > 3 else ""))
        if t.row_count:
            console.print("[bold]DNS Records[/bold]")
            console.print(t)

    # WHOIS
    if "whois" in results and "error" not in results["whois"]:
        w = results["whois"]
        console.print("[bold]WHOIS Registration[/bold]")
        for field in ("registrar", "creation_date", "expiration_date", "country", "org"):
            val = w.get(field)
            if val:
                val = val[0] if isinstance(val, list) else val
                console.print(f"  [cyan]{field:<18}[/cyan] {val}")
        console.print()

    # crt.sh
    if "crtsh" in results and "error" not in results["crtsh"]:
        subs = results["crtsh"].get("subdomains", [])
        console.print(f"[bold]Subdomains[/bold]  ({len(subs)} discovered)")
        for s in subs[:20]:
            console.print(f"  [dim]·[/dim] {s}")
        if len(subs) > 20:
            console.print(f"  [dim]… and {len(subs) - 20} more in report[/dim]")
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
                console.print(f"  [red]Missing:[/red] {', '.join(missing)}")
            console.print()

    # Ports
    if "ports" in results and "error" not in results["ports"]:
        open_ = results["ports"].get("open_ports", [])
        risky = results["ports"].get("risky", [])
        console.print(f"[bold]Open Ports[/bold]  ({len(open_)} detected)")
        for p in open_:
            warn = " [yellow]⚠ RISKY[/yellow]" if p.get("risk") else ""
            console.print(f"  [dim]·[/dim] {p['port']}/{p['service']}{warn}")
        if risky:
            console.print(f"  [red]High-risk ports exposed: {len(risky)}[/red]")
        console.print()

    # Wayback Machine
    if "wayback" in results and "error" not in results["wayback"]:
        wb = results["wayback"]
        total = wb.get("total_snapshots", 0)
        latest = wb.get("latest_snapshot")
        interesting = wb.get("interesting", [])
        console.print(f"[bold]Wayback Machine[/bold]  ({total} historical URLs)")
        if latest:
            console.print(f"  [cyan]Latest snapshot:[/cyan] {wb.get('latest_timestamp','?')} — {latest}")
        if wb.get("subdomains"):
            console.print(f"  [cyan]Archived subdomains:[/cyan] {', '.join(wb['subdomains'][:5])}")
        if interesting:
            console.print(f"  [yellow]Interesting endpoints ({len(interesting)}):[/yellow]")
            for u in interesting[:5]:
                console.print(f"    [dim]·[/dim] {u}")
        console.print()

    # Tech fingerprint
    if "tech" in results and "error" not in results["tech"]:
        tech = results["tech"]
        by_cat = tech.get("by_category", {})
        console.print(f"[bold]Tech Stack[/bold]  ({tech.get('total', 0)} technologies detected)")
        for cat, techs in by_cat.items():
            console.print(f"  [cyan]{cat:<18}[/cyan] {', '.join(techs)}")
        if not by_cat:
            console.print("  [dim]Stack unidentified (may be obfuscated)[/dim]")
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
        console.print(f"  [cyan]SPF:[/cyan]   {'present' if spf.get('present') else '[red]MISSING[/red]'}  policy: {spf.get('policy') or '—'}")
        sels = ", ".join(s["selector"] for s in dkim.get("selectors", []))
        console.print(f"  [cyan]DKIM:[/cyan]  {'found' if dkim.get('found') else '[red]NOT FOUND[/red]'}  {f'(selectors: {sels})' if sels else ''}")
        console.print(f"  [cyan]DMARC:[/cyan] {'present' if dmarc.get('present') else '[red]MISSING[/red]'}  policy: {dmarc.get('policy') or '—'}")
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
        console.print(f"  [cyan]Issuer:[/cyan] {cert.get('issuer_org','?')} ({cert.get('issuer_cn','?')})")
        console.print(f"  [cyan]Expires:[/cyan] {cert.get('not_after','?')}  [{days_color}]{days} days[/{days_color}]")
        console.print(f"  [cyan]SANs:[/cyan]    {', '.join(cert.get('sans', [])[:5])}")
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
        console.print(f"[red]Invalid modules specified. Available: {', '.join(MODULES)}[/red]")
        sys.exit(1)

    console.print(Panel(
        f"[bold cyan]OSINT Recon[/bold cyan]\n"
        f"[dim]Target:[/dim]  [yellow]{target}[/yellow]\n"
        f"[dim]Modules:[/dim] {', '.join(selected)}",
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

    console.print("[green]Reports saved successfully:[/green]")
    for fmt, path in paths.items():
        console.print(f"  [cyan]{fmt}[/cyan]  {path}")


if __name__ == "__main__":
    main()
