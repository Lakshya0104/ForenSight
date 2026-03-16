import argparse
import os
import sys
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich.align import Align
from rich.padding import Padding
from rich import box

from src.core.os_fingerprint import fingerprint_os
from src.core.tool_detection import detect_tools
from src.core.log_analyzer import analyze_logs
from src.core.timeline_builder import build_timeline
from src.novelty.temporal_paradox import detect_paradoxes
from src.novelty.mitre_mapper import map_to_mitre
from src.novelty.uefi_fingerprint import fingerprint_uefi
from src.novelty.persona_classifier import classify_persona
from src.report.json_exporter import export_json
from src.report.narrative_engine import generate_narrative

console = Console()

VERSION = "1.0.0"
BANNER = """
███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗ ██╗  ██╗████████╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║  ███╗███████║   ██║   
██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║   ██║██╔══██║   ██║   
██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╔╝██║  ██║   ██║   
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
"""

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "NONE":     "dim green",
    "UNKNOWN":  "dim",
}


def print_banner():
    console.print(f"[bold green]{BANNER}[/bold green]")
    console.print(Panel.fit(
        Align.center(
            "[bold bright_white]Linux Forensic Intelligence System[/bold bright_white]\n"
            "[dim green]Offensive OS Detection  ·  Anti-Forensic Analysis  ·  MITRE ATT&CK Mapping[/dim green]\n"
            "[dim green]Temporal Paradox Engine  ·  UEFI Fingerprinting  ·  Attacker Persona Profiling[/dim green]\n\n"
            f"[dim]v{VERSION}  ·  Team Cyber Nuggets  ·  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC[/dim]"
        ),
        border_style="green",
        padding=(0, 4)
    ))
    console.print()


def _metric_card(label: str, value: str, color: str = "white", width: int = 24) -> Panel:
    return Panel(
        Align.center(f"[bold {color}]{value}[/bold {color}]"),
        title=f"[dim]{label}[/dim]",
        border_style=color,
        width=width,
        padding=(0, 1)
    )


def print_scan_summary(result: dict, elapsed: float):
    console.print(Rule("[bold green]  SCAN SUMMARY  [/bold green]", style="green"))
    console.print()

    tools      = result.get("tools_detected", [])
    paradoxes  = result.get("temporal_paradoxes", [])
    chain      = result.get("mitre_chain", [])
    score      = result.get("evasion_score", 0)
    log        = result.get("log_analysis", {})
    tl         = result.get("timeline", {})
    os_conf    = result.get("os_profile", {}).get("confidence", 0)

    score_color = "red" if score >= 70 else "yellow" if score >= 40 else "green"
    installed   = len([t for t in tools if t["state"] == "installed"])
    removed     = len([t for t in tools if t["state"] == "removed"])
    critical_t  = len([t for t in tools if t.get("risk") == "CRITICAL"])
    missing_logs= len(log.get("missing_logs", [])) + len(log.get("wiped_logs", []))
    phases      = len(set(c["phase"] for c in chain))

    cards = [
        _metric_card("Evasion Score",       f"{score}/100",         score_color),
        _metric_card("Tools Found",         f"{installed}",         "red"    if installed > 0  else "green"),
        _metric_card("Ghost Traces",        f"{removed}",           "yellow" if removed > 0    else "green"),
        _metric_card("Critical Tools",      f"{critical_t}",        "red"    if critical_t > 0 else "green"),
        _metric_card("Log Files Wiped",     f"{missing_logs}",      "red"    if missing_logs>0 else "green"),
        _metric_card("Paradoxes",           f"{len(paradoxes)}",    "red"    if paradoxes       else "green"),
        _metric_card("MITRE Phases",        f"{phases}",            "yellow" if phases > 0     else "green"),
        _metric_card("Files Scanned",       f"{tl.get('total_files_scanned', 0)}", "cyan"),
        _metric_card("Scan Duration",       f"{elapsed:.1f}s",      "dim white"),
    ]
    console.print(Columns(cards, equal=True, expand=True))
    console.print()


def print_os_profile(result: dict):
    console.print(Rule("[bold]  OS PROFILE  [/bold]", style="bright_white"))
    os_p       = result.get("os_profile", {})
    distro     = os_p.get("distro", "Unknown")
    confidence = os_p.get("confidence", 0)
    threat     = os_p.get("threat_level", "NONE")
    version    = os_p.get("version", "Unknown")
    kernel     = os_p.get("kernel", "Unknown")
    pkg_count  = os_p.get("offensive_packages_found", 0)
    evidence   = os_p.get("evidence", [])
    os_color   = "red" if confidence > 0.7 else "yellow" if confidence > 0.3 else "green"

    left = Panel(
        f"[bold {os_color}]{distro}[/bold {os_color}]\n\n"
        f"[dim]Version    [/dim] [white]{version}[/white]\n"
        f"[dim]Kernel     [/dim] [white]{kernel[:60]}[/white]\n"
        f"[dim]Confidence [/dim] [bold {os_color}]{confidence:.0%}[/bold {os_color}]\n"
        f"[dim]Threat     [/dim] [{RISK_COLORS.get(threat, 'white')}]{threat}[/{RISK_COLORS.get(threat, 'white')}]\n"
        f"[dim]Offensive Pkgs [/dim] [{'red' if pkg_count > 0 else 'green'}]{pkg_count} found[/{'red' if pkg_count > 0 else 'green'}]",
        title="[bold]Distro[/bold]",
        border_style=os_color,
        expand=True
    )
    right = Panel(
        "\n".join(f"[dim]▸[/dim] {e}" for e in evidence) or "[dim]No evidence collected[/dim]",
        title="[bold]Evidence[/bold]",
        border_style="dim",
        expand=True
    )
    console.print(Columns([left, right], equal=True, expand=True))
    console.print()


def print_tools(result: dict):
    tools = result.get("tools_detected", [])
    if not tools:
        console.print(Panel("[green]No offensive tools detected.[/green]",
                            title="[bold]Tool Detection[/bold]", border_style="green"))
        console.print()
        return

    console.print(Rule("[bold magenta]  TOOL DETECTION  [/bold magenta]", style="magenta"))

    installed = [t for t in tools if t["state"] == "installed"]
    removed   = [t for t in tools if t["state"] == "removed"]

    for group, label, color in [(installed, "INSTALLED — Active Threats", "red"),
                                 (removed,   "REMOVED — Ghost Traces",     "yellow")]:
        if not group:
            continue
        t = Table(box=box.SIMPLE_HEAVY, show_header=True,
                  header_style=f"bold {color}", border_style=color, expand=True)
        t.add_column("Tool",       style="bold white",  min_width=16, no_wrap=True)
        t.add_column("Category",   style="cyan",        min_width=16)
        t.add_column("Risk",       min_width=10)
        t.add_column("Path",       style="dim",         min_width=22)
        t.add_column("Evidence",   style="dim white")
        for tool in group:
            risk      = tool.get("risk", "UNKNOWN")
            risk_fmt  = f"[{RISK_COLORS.get(risk,'white')}]{risk}[/{RISK_COLORS.get(risk,'white')}]"
            t.add_row(tool["name"], tool["category"], risk_fmt,
                      tool.get("path", "—"), tool.get("evidence", "—"))
        console.print(Panel(t, title=f"[bold {color}]{label}  ({len(group)})[/bold {color}]",
                            border_style=color))

    # Category breakdown
    from collections import Counter
    cats = Counter(t["category"] for t in tools)
    cat_table = Table(box=box.MINIMAL, show_header=False, expand=False)
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Count",    style="bold white", justify="right")
    for cat, cnt in cats.most_common():
        cat_table.add_row(cat.replace("_", " ").title(), str(cnt))
    console.print(Columns([
        Panel(cat_table, title="[dim]Category Breakdown[/dim]", border_style="dim", expand=False),
    ]))
    console.print()


def print_evasion_score(result: dict):
    console.print(Rule("[bold]  EVASION INTENT SCORE  [/bold]", style="bright_white"))
    score     = result.get("evasion_score", 0)
    breakdown = result.get("evasion_breakdown", {})
    log       = result.get("log_analysis", {})
    bar_color = "red" if score >= 70 else "yellow" if score >= 40 else "green"
    filled    = int(score / 2)
    bar       = f"[{bar_color}]{'█' * filled}[/{bar_color}][dim]{'░' * (50 - filled)}[/dim]"

    risk_label = (
        "CRITICAL THREAT" if score >= 80 else
        "HIGH THREAT"     if score >= 60 else
        "MEDIUM THREAT"   if score >= 40 else
        "LOW THREAT"      if score >= 20 else
        "MINIMAL THREAT"
    )

    score_content = (
        f"\n  {bar}  [{bar_color}]{score}/100[/{bar_color}]  "
        f"[bold {bar_color}]{risk_label}[/bold {bar_color}]\n\n"
    )

    t = Table(box=box.SIMPLE, show_header=True, header_style="dim", expand=True)
    t.add_column("Signal",       style="white",      min_width=30)
    t.add_column("Points",       style="bold",       min_width=8,  justify="right")
    t.add_column("Contribution", min_width=24)
    t.add_column("Status",       min_width=10)

    signal_meta = {
        "log_wipe":              ("Critical log files wiped",          "red"),
        "history_clear":         ("Bash history cleared/poisoned",     "red"),
        "timestamp_manipulation":("Filesystem timestamp paradoxes",    "yellow"),
        "anti_forensic_tools":   ("Anti-forensic tools present",       "red"),
        "anonymization_tools":   ("Anonymization tools present",       "yellow"),
        "uefi_boot_anomaly":     ("UEFI USB boot signature detected",  "yellow"),
        "offensive_os":          ("Offensive OS identified",           "red"),
    }
    for key, pts in breakdown.items():
        label, sig_color = signal_meta.get(key, (key.replace("_", " ").title(), "white"))
        contrib_filled = int((pts / 25) * 12) if pts > 0 else 0
        contrib_bar    = f"[{sig_color}]{'▮' * contrib_filled}[/{sig_color}][dim]{'▯' * (12 - contrib_filled)}[/dim]"
        status         = f"[{sig_color}]TRIGGERED[/{sig_color}]" if pts > 0 else "[dim green]CLEAN[/dim green]"
        t.add_row(label, f"[bold]{pts}[/bold]", contrib_bar, status)

    # Extra log stats
    extra = ""
    if log:
        failed   = log.get("failed_logins", 0)
        sudo_a   = log.get("sudo_attempts", 0)
        ssh_c    = log.get("ssh_connections", [])
        evasion  = log.get("evasion_commands_found", [])
        suspicious = log.get("suspicious_commands_found", [])
        coverage = log.get("log_coverage", 0)
        extra = (
            f"\n  [dim]Log Coverage:[/dim] [bold]{coverage:.0%}[/bold]   "
            f"[dim]Failed Logins:[/dim] [bold red]{failed}[/bold red]   "
            f"[dim]Sudo Attempts:[/dim] [bold yellow]{sudo_a}[/bold yellow]   "
            f"[dim]SSH Connections:[/dim] [bold]{len(ssh_c)}[/bold]   "
            f"[dim]Evasion Cmds:[/dim] [bold red]{len(evasion)}[/bold red]   "
            f"[dim]Suspicious Cmds:[/dim] [bold yellow]{len(suspicious)}[/bold yellow]"
        )

    console.print(Panel(
        score_content + str(t) + extra,
        title=f"[bold {bar_color}]Evasion Intent Score — {score}/100[/bold {bar_color}]",
        border_style=bar_color
    ))
    console.print()


def print_temporal_paradoxes(result: dict):
    paradoxes = result.get("temporal_paradoxes", [])
    console.print(Rule("[bold red]  TEMPORAL PARADOX ENGINE  [/bold red]", style="red"))
    if not paradoxes:
        console.print(Panel(
            "[green]No timestamp paradoxes detected.[/green]\n"
            "[dim]All filesystem timestamps are logically consistent.[/dim]",
            title="[bold]Temporal Paradox Engine[/bold]", border_style="green"))
        console.print()
        return

    critical = [p for p in paradoxes if p.get("severity") == "critical"]
    high     = [p for p in paradoxes if p.get("severity") == "high"]

    pt = Table(box=box.SIMPLE_HEAVY, show_header=True,
               header_style="bold red", border_style="red", expand=True)
    pt.add_column("Severity",    min_width=10)
    pt.add_column("Type",        style="bold white", min_width=28)
    pt.add_column("File",        style="dim white",  min_width=28)
    pt.add_column("Delta",       style="yellow",     min_width=10, justify="right")
    pt.add_column("Court Note",  style="dim",        min_width=40)

    for p in paradoxes:
        sev     = p.get("severity", "unknown")
        sev_fmt = f"[bold red]{sev.upper()}[/bold red]" if sev == "critical" else f"[yellow]{sev.upper()}[/yellow]"
        delta   = f"{p.get('delta_seconds', 0):.2f}s" if "delta_seconds" in p else "—"
        pt.add_row(
            sev_fmt,
            p.get("type", "").replace("_", " "),
            p.get("file", ""),
            delta,
            p.get("court_note", "—")
        )

    summary = (
        f"[bold red]{len(critical)} CRITICAL[/bold red]  "
        f"[yellow]{len(high)} HIGH[/yellow]  "
        f"[dim]{len(paradoxes)} total paradox(es)[/dim]\n\n"
        f"[dim italic]These violations represent mathematically impossible filesystem states.\n"
        f"Each is court-admissible proof of deliberate timestamp manipulation.[/dim italic]\n\n"
    )
    console.print(Panel(summary + str(pt),
                        title=f"[bold red]Temporal Paradoxes — {len(paradoxes)} Detected[/bold red]",
                        border_style="red"))
    console.print()


def print_mitre(result: dict):
    chain = result.get("mitre_chain", [])
    console.print(Rule("[bold yellow]  MITRE ATT&CK KILL CHAIN  [/bold yellow]", style="yellow"))
    if not chain:
        console.print(Panel("[green]No MITRE techniques mapped.[/green]",
                            title="[bold]MITRE ATT&CK[/bold]", border_style="green"))
        console.print()
        return

    phases_ordered = [
        "Recon", "Initial Access", "Execution", "Persistence",
        "Privilege Escalation", "Defense Evasion",
        "Credential Access", "Exfiltration", "Cover Tracks"
    ]
    phase_colors = {
        "Recon":                "cyan",
        "Initial Access":       "blue",
        "Execution":            "magenta",
        "Persistence":          "yellow",
        "Privilege Escalation": "red",
        "Defense Evasion":      "bright_red",
        "Credential Access":    "bright_yellow",
        "Exfiltration":         "bright_magenta",
        "Cover Tracks":         "bright_red",
    }

    from collections import defaultdict
    by_phase = defaultdict(list)
    for c in chain:
        by_phase[c["phase"]].append(c)

    # Kill chain flow banner
    hit_phases  = [p for p in phases_ordered if p in by_phase]
    flow_parts  = []
    for p in phases_ordered:
        color = phase_colors.get(p, "white")
        if p in by_phase:
            flow_parts.append(f"[bold {color}]{p}[/bold {color}]")
        else:
            flow_parts.append(f"[dim]{p}[/dim]")
    console.print(Panel(
        Align.center(" → ".join(flow_parts)),
        title="[bold]Kill Chain Coverage[/bold]",
        border_style="yellow",
        padding=(0, 2)
    ))
    console.print()

    mt = Table(box=box.SIMPLE_HEAVY, show_header=True,
               header_style="bold yellow", border_style="yellow", expand=True)
    mt.add_column("Phase",     min_width=22)
    mt.add_column("Tactic",    style="dim cyan",   min_width=18)
    mt.add_column("Technique", style="bold cyan",  min_width=12)
    mt.add_column("Command",   style="dim white")

    for phase in phases_ordered:
        for c in by_phase.get(phase, []):
            color    = phase_colors.get(phase, "white")
            phase_fmt = f"[bold {color}]{phase}[/bold {color}]"
            mt.add_row(phase_fmt, c.get("tactic", "—"),
                       c.get("technique", "—"), c.get("command", "—"))

    console.print(Panel(mt,
                        title=f"[bold yellow]ATT&CK Techniques — {len(chain)} mapped across {len(hit_phases)} phases[/bold yellow]",
                        border_style="yellow"))
    console.print()


def print_persona(result: dict):
    console.print(Rule("[bold cyan]  ATTACKER PERSONA  [/bold cyan]", style="cyan"))
    persona = result.get("persona", "Unknown")
    conf    = result.get("persona_confidence", 0.0)
    conf_color = "red" if conf >= 0.7 else "yellow" if conf >= 0.4 else "dim"

    PERSONA_DESC = {
        "Network Intrusion Operator":    "Focused on network scanning, exploitation, and gaining remote shells.",
        "Data Exfiltrator":              "Prioritizes data theft via covert channels and file transfer tools.",
        "Credential Harvester":          "Targets authentication systems — password cracking and hash dumping.",
        "Web Application Attacker":      "Exploits web application vulnerabilities — SQLi, XSS, directory traversal.",
        "Wireless Attacker":             "Specializes in wireless network attacks — WPA cracking, deauthentication.",
        "Insider Threat":                "Evidence of deliberate cover-up behavior — anti-forensic focus.",
        "Advanced Persistent Threat (APT)": "Long-term access maintenance — persistence mechanisms and covert C2.",
        "Unknown":                       "Insufficient tool data to classify attacker archetype.",
    }

    conf_bar_filled = int(conf * 20)
    conf_bar = f"[{conf_color}]{'█' * conf_bar_filled}[/{conf_color}][dim]{'░' * (20 - conf_bar_filled)}[/dim]"

    content = (
        f"[bold cyan]{persona}[/bold cyan]\n\n"
        f"[dim]{PERSONA_DESC.get(persona, '')}[/dim]\n\n"
        f"Confidence  {conf_bar}  [{conf_color}]{conf:.0%}[/{conf_color}]"
    )
    console.print(Panel(content, title="[bold]Attacker Persona Classification[/bold]",
                        border_style="cyan", padding=(1, 2)))
    console.print()


def print_uefi(result: dict):
    console.print(Rule("[bold]  UEFI FIRMWARE ANALYSIS  [/bold]", style="bright_white"))
    uefi        = result.get("uefi", {})
    usb_sig     = uefi.get("usb_boot_signature", False)
    last_device = uefi.get("last_boot_device", "Unknown")
    entries     = uefi.get("boot_entries", [])
    evidence    = uefi.get("firmware_evidence", "—")
    color       = "red" if usb_sig else "green"

    left = Panel(
        f"USB Boot Signature\n[bold {color}]{'⚠  DETECTED' if usb_sig else '✓  NOT FOUND'}[/bold {color}]\n\n"
        f"[dim]Last Boot Device[/dim]\n[bold]{last_device}[/bold]\n\n"
        f"[dim]Evidence[/dim]\n[italic dim]{evidence}[/italic dim]",
        title="[bold]UEFI Status[/bold]",
        border_style=color,
        expand=True
    )
    entries_text = "\n".join(f"[dim]▸[/dim] {e}" for e in entries) if entries else "[dim]No boot entries found[/dim]"
    right = Panel(
        entries_text + (
            "\n\n[dim italic]UEFI boot signatures survive a full OS wipe.\n"
            "This evidence cannot be erased by the attacker.[/dim italic]"
            if usb_sig else ""
        ),
        title="[bold]Boot Entries[/bold]",
        border_style="dim",
        expand=True
    )
    console.print(Columns([left, right], equal=True, expand=True))
    console.print()


def print_timeline(result: dict):
    tl = result.get("timeline", {})
    if not tl:
        return
    console.print(Rule("[bold]  FILESYSTEM TIMELINE  [/bold]", style="bright_white"))

    suspicious = tl.get("suspicious_files", [])
    recent_mod = tl.get("recently_modified", [])[:10]
    total      = tl.get("total_files_scanned", 0)
    susp_count = tl.get("suspicious_files_found", 0)

    left = Panel(
        "\n".join(f"[red]▸[/red] {f}" for f in suspicious[:12])
        or "[green]No suspicious files found[/green]",
        title=f"[bold red]Suspicious Files ({susp_count})[/bold red]",
        border_style="red", expand=True
    )
    right = Panel(
        "\n".join(f"[dim]▸[/dim] {f}" for f in recent_mod)
        or "[dim]No recent activity[/dim]",
        title="[bold]Recently Modified[/bold]",
        border_style="dim", expand=True
    )
    console.print(Panel(
        f"[dim]Total files scanned:[/dim] [bold cyan]{total}[/bold cyan]   "
        f"[dim]Suspicious:[/dim] [bold red]{susp_count}[/bold red]",
        border_style="dim", padding=(0, 1)
    ))
    console.print(Columns([left, right], equal=True, expand=True))
    console.print()


def print_narrative(result: dict):
    console.print(Rule("[bold]  INVESTIGATIVE NARRATIVE  [/bold]", style="bright_white"))
    narrative = result.get("narrative", "")
    console.print(Panel(
        Padding(f"[italic]{narrative}[/italic]", (1, 2)),
        title="[bold]AI-Generated Investigative Summary[/bold]",
        border_style="white",
        subtitle="[dim]Plain-language report for non-technical investigators[/dim]"
    ))
    console.print()


def print_verdict(result: dict, elapsed: float):
    console.print(Rule("[bold]  FINAL VERDICT  [/bold]", style="bright_white"))
    verdict   = result.get("verdict", "")
    score     = result.get("evasion_score", 0)
    persona   = result.get("persona", "Unknown")
    distro    = result.get("os_profile", {}).get("distro", "Unknown")
    tools     = result.get("tools_detected", [])
    paradoxes = result.get("temporal_paradoxes", [])
    chain     = result.get("mitre_chain", [])
    v_color   = "red" if "HIGH" in verdict else "yellow" if "MEDIUM" in verdict else "green"

    console.print(Panel(
        Align.center(
            f"\n[bold {v_color}]{verdict}[/bold {v_color}]\n\n"
            f"[dim]{'─' * 60}[/dim]\n\n"
            f"[dim]OS Detected       [/dim] [bold]{distro}[/bold]\n"
            f"[dim]Attacker Persona  [/dim] [bold cyan]{persona}[/bold cyan]\n"
            f"[dim]Evasion Score     [/dim] [bold {v_color}]{score}/100[/bold {v_color}]\n"
            f"[dim]Tools Detected    [/dim] [bold]{len(tools)}[/bold]  "
            f"([red]{len([t for t in tools if t['state']=='installed'])} active[/red] · "
            f"[yellow]{len([t for t in tools if t['state']=='removed'])} ghost[/yellow])\n"
            f"[dim]Paradoxes Found   [/dim] [bold red]{len(paradoxes)}[/bold red]\n"
            f"[dim]MITRE Techniques  [/dim] [bold yellow]{len(chain)}[/bold yellow]\n"
            f"[dim]Scan Duration     [/dim] [bold]{elapsed:.2f}s[/bold]\n"
        ),
        title="[bold]ForenSight Verdict[/bold]",
        border_style=v_color,
        padding=(1, 4)
    ))
    console.print()


def print_results(result: dict, elapsed: float):
    print_scan_summary(result, elapsed)
    print_os_profile(result)
    print_tools(result)
    print_evasion_score(result)
    print_temporal_paradoxes(result)
    print_mitre(result)
    print_persona(result)
    print_uefi(result)
    print_timeline(result)
    print_narrative(result)
    print_verdict(result, elapsed)


def run_scan(target: str, output_path: str = "forensight_report.json", demo: bool = False):
    print_banner()
    start = time.time()

    if demo:
        console.print(Panel(
            "[bold yellow]DEMO MODE[/bold yellow] — Running with simulated Tails OS attack scenario\n"
            "[dim]All findings are representative of a real offensive Linux investigation.[/dim]",
            border_style="yellow", padding=(0, 2)
        ))
        console.print()

    result = {
        "scan_meta": {
            "tool":      "ForenSight",
            "version":   VERSION,
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "target":    target,
            "mode":      "demo" if demo else "live"
        }
    }

    steps = [
        ("[1/8] OS Fingerprinting       ", lambda: fingerprint_os(target)),
        ("[2/8] Tool Detection          ", lambda: detect_tools(target)),
        ("[3/8] Log Analysis            ", lambda: analyze_logs(target)),
        ("[4/8] Timeline Reconstruction ", lambda: build_timeline(target)),
        ("[5/8] Temporal Paradox Engine ", lambda: detect_paradoxes(target)),
        ("[6/8] MITRE ATT&CK Mapping    ", lambda: map_to_mitre(target)),
        ("[7/8] UEFI Fingerprinting     ", lambda: fingerprint_uefi()),
        ("[8/8] Persona Classification  ", lambda: classify_persona(
            result.get("tools_detected", []),
            result.get("temporal_paradoxes", [])
        )),
    ]
    keys = ["os_profile", "tools_detected", "log_analysis", "timeline",
            "temporal_paradoxes", "mitre_chain", "uefi", "_persona"]

    with Progress(
        SpinnerColumn(spinner_name="dots", style="bold green"),
        TextColumn("[bold green]{task.description}"),
        BarColumn(bar_width=40, style="green", complete_style="bright_green"),
        TextColumn("[bold white]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False
    ) as progress:
        task = progress.add_task("Initializing...", total=len(steps))
        for (label, fn), key in zip(steps, keys):
            progress.update(task, description=label)
            try:
                val = fn()
                if key == "_persona":
                    result["persona"], result["persona_confidence"] = val
                else:
                    result[key] = val
            except Exception as e:
                result[key] = {"error": str(e)}
                console.print(f"  [red]✗ Error in {key}: {e}[/red]")
            progress.advance(task)

    result["evasion_score"], result["evasion_breakdown"] = calculate_evasion_score(result)
    result["narrative"] = generate_narrative(result)
    result["verdict"]   = generate_verdict(result["evasion_score"])

    elapsed = time.time() - start
    console.print()
    print_results(result, elapsed)
    export_json(result, output_path)

    console.print(Panel(
        f"[bold green]✓ Report saved[/bold green] → [underline]{os.path.abspath(output_path)}[/underline]\n"
        f"[dim]Scan completed in {elapsed:.2f}s[/dim]",
        border_style="green", padding=(0, 2)
    ))
    console.print()
    return result


def calculate_evasion_score(result: dict) -> tuple:
    breakdown = {
        "log_wipe":               0,
        "history_clear":          0,
        "timestamp_manipulation": 0,
        "anti_forensic_tools":    0,
        "anonymization_tools":    0,
        "uefi_boot_anomaly":      0,
        "offensive_os":           0,
    }
    log = result.get("log_analysis", {})
    if log.get("logs_cleared"):
        breakdown["log_wipe"] = 25
    if log.get("history_cleared"):
        breakdown["history_clear"] = 15
    if log.get("evasion_commands_found"):
        breakdown["history_clear"] = min(
            breakdown["history_clear"] + len(log["evasion_commands_found"]) * 2, 20)

    paradoxes = result.get("temporal_paradoxes", [])
    breakdown["timestamp_manipulation"] = min(len(paradoxes) * 5, 20)

    tools = result.get("tools_detected", [])
    anti  = [t for t in tools if t.get("category") == "anti_forensic"]
    anon  = [t for t in tools if t.get("category") == "anonymization"]
    breakdown["anti_forensic_tools"] = min(len(anti) * 5, 15)
    breakdown["anonymization_tools"] = min(len(anon) * 3, 9)

    if result.get("uefi", {}).get("usb_boot_signature"):
        breakdown["uefi_boot_anomaly"] = 8

    os_conf = result.get("os_profile", {}).get("confidence", 0)
    if os_conf > 0.5:
        breakdown["offensive_os"] = int(os_conf * 8)

    return min(sum(breakdown.values()), 100), breakdown


def generate_verdict(score: int) -> str:
    if score >= 80: return "HIGH RISK — Structured attack campaign detected. Evidence tampering confirmed. Immediate escalation recommended."
    if score >= 60: return "HIGH-MEDIUM RISK — Multiple evasion indicators found. Attacker attempted to cover tracks."
    if score >= 40: return "MEDIUM RISK — Suspicious activity detected. Further forensic investigation recommended."
    if score >= 20: return "LOW-MEDIUM RISK — Some anomalies found. May be benign or early-stage activity."
    return "LOW RISK — No significant forensic indicators detected."


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ForenSight — Linux Forensic Intelligence System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py /                          # scan live system\n"
            "  python main.py /mnt/disk                  # scan mounted disk image\n"
            "  python main.py / --output report.json     # custom output path\n"
            "  python main.py / --demo                   # run demo scenario\n"
        )
    )
    parser.add_argument("target",   help="Target path (/ for live system, or mounted disk image path)")
    parser.add_argument("--output", default="forensight_report.json", help="Output JSON report path")
    parser.add_argument("--demo",   action="store_true", help="Run demo with simulated Tails scenario")
    args = parser.parse_args()
    run_scan(args.target, args.output, args.demo)