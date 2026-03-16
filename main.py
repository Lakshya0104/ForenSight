import argparse
import json
import sys
import os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
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

BANNER = """
███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗ ██╗  ██╗████████╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║  ███╗███████║   ██║   
██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║   ██║██╔══██║   ██║   
██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╔╝██║  ██║   ██║   
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
"""

def print_banner():
    console.print(f"[bold green]{BANNER}[/bold green]")
    console.print(Panel.fit(
        "[bold white]Linux Forensic Intelligence System[/bold white]\n"
        "[dim]Offensive OS Detection · Anti-Forensic Analysis · MITRE ATT&CK Mapping[/dim]\n"
        "[dim]Temporal Paradox Engine · UEFI Fingerprinting · Attacker Persona Profiling[/dim]",
        border_style="green"
    ))
    console.print()


def print_results(result: dict):
    # OS Profile
    os_p = result.get("os_profile", {})
    os_color = "red" if os_p.get("confidence", 0) > 0.5 else "yellow"
    console.print(Panel(
        f"[bold {os_color}]{os_p.get('distro', 'Unknown')}[/bold {os_color}] "
        f"[dim](confidence: {os_p.get('confidence', 0):.0%})[/dim]\n"
        + "\n".join(f"  [dim]• {e}[/dim]" for e in os_p.get("evidence", [])),
        title="[bold]OS Profile[/bold]",
        border_style=os_color
    ))

    # Tools Detected
    tools = result.get("tools_detected", [])
    if tools:
        t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold magenta")
        t.add_column("Tool", style="bold white", min_width=16)
        t.add_column("Category", style="cyan", min_width=16)
        t.add_column("State", min_width=12)
        t.add_column("Evidence", style="dim")
        for tool in tools:
            state = tool["state"]
            state_fmt = f"[red]{state}[/red]" if state == "installed" else f"[yellow]{state}[/yellow]"
            t.add_row(tool["name"], tool["category"], state_fmt, tool["evidence"])
        console.print(Panel(t, title="[bold]Tools Detected[/bold]", border_style="magenta"))

    # Evasion Score
    score = result.get("evasion_score", 0)
    breakdown = result.get("evasion_breakdown", {})
    bar_color = "red" if score >= 70 else "yellow" if score >= 40 else "green"
    filled = int(score / 5)
    bar = f"[{bar_color}]{'█' * filled}[/{bar_color}][dim]{'░' * (20 - filled)}[/dim]"
    score_lines = f"{bar}  [bold {bar_color}]{score}/100[/bold {bar_color}]\n\n"
    for k, v in breakdown.items():
        score_lines += f"  [dim]{k.replace('_', ' ').title():<28}[/dim] [bold]{v:>3}pts[/bold]\n"
    console.print(Panel(score_lines.strip(), title="[bold]Evasion Intent Score[/bold]", border_style=bar_color))

    # Temporal Paradoxes
    paradoxes = result.get("temporal_paradoxes", [])
    if paradoxes:
        pt = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold red")
        pt.add_column("Type", style="bold red", min_width=28)
        pt.add_column("File", style="white", min_width=30)
        pt.add_column("Severity", min_width=10)
        pt.add_column("Delta", style="dim")
        for p in paradoxes:
            sev = p.get("severity", "unknown")
            sev_fmt = f"[red]{sev}[/red]" if sev == "critical" else f"[yellow]{sev}[/yellow]"
            delta = f"{p.get('delta_seconds', 0):.1f}s" if "delta_seconds" in p else "—"
            pt.add_row(p.get("type", ""), p.get("file", ""), sev_fmt, delta)
        console.print(Panel(pt, title=f"[bold red]Temporal Paradoxes ({len(paradoxes)} found)[/bold red]", border_style="red"))

    # MITRE Chain
    chain = result.get("mitre_chain", [])
    if chain:
        mt = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold yellow")
        mt.add_column("Phase", style="bold yellow", min_width=18)
        mt.add_column("Technique", style="cyan", min_width=10)
        mt.add_column("Command", style="dim white")
        for c in chain:
            mt.add_row(c.get("phase", ""), c.get("technique", ""), c.get("command", ""))
        console.print(Panel(mt, title="[bold]MITRE ATT&CK Kill Chain[/bold]", border_style="yellow"))

    # Persona
    persona = result.get("persona", "Unknown")
    conf = result.get("persona_confidence", 0.0)
    console.print(Panel(
        f"[bold cyan]{persona}[/bold cyan]  [dim](confidence: {conf:.0%})[/dim]",
        title="[bold]Attacker Persona[/bold]",
        border_style="cyan"
    ))

    # UEFI
    uefi = result.get("uefi", {})
    uefi_color = "red" if uefi.get("usb_boot_signature") else "green"
    console.print(Panel(
        f"USB Boot Signature: [bold {uefi_color}]{'DETECTED' if uefi.get('usb_boot_signature') else 'NOT FOUND'}[/bold {uefi_color}]\n"
        f"Last Boot Device:   [bold]{uefi.get('last_boot_device', 'Unknown')}[/bold]\n"
        f"Evidence:           [dim]{uefi.get('firmware_evidence', '—')}[/dim]",
        title="[bold]UEFI Firmware Analysis[/bold]",
        border_style=uefi_color
    ))

    # Narrative
    console.print(Panel(
        f"[italic]{result.get('narrative', '')}[/italic]",
        title="[bold]Investigative Narrative[/bold]",
        border_style="white"
    ))

    # Verdict
    verdict = result.get("verdict", "")
    v_color = "red" if "HIGH" in verdict else "yellow" if "MEDIUM" in verdict else "green"
    console.print(Panel(
        f"[bold {v_color}]{verdict}[/bold {v_color}]",
        title="[bold]Final Verdict[/bold]",
        border_style=v_color
    ))


def run_scan(target: str, output_path: str = "forensight_report.json", demo: bool = False):
    print_banner()

    if demo:
        console.print("[bold yellow][DEMO MODE][/bold yellow] Running with simulated Tails OS scenario\n")

    result = {
        "scan_meta": {
            "tool": "ForenSight",
            "version": "1.0.0",
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "target": target,
            "mode": "demo" if demo else "live"
        }
    }

    steps = [
        ("[1/8] OS Fingerprinting",        lambda: fingerprint_os(target)),
        ("[2/8] Tool Detection",            lambda: detect_tools(target)),
        ("[3/8] Log Analysis",              lambda: analyze_logs(target)),
        ("[4/8] Timeline Reconstruction",   lambda: build_timeline(target)),
        ("[5/8] Temporal Paradox Engine",   lambda: detect_paradoxes(target)),
        ("[6/8] MITRE ATT&CK Mapping",      lambda: map_to_mitre(target)),
        ("[7/8] UEFI Fingerprinting",       lambda: fingerprint_uefi()),
        ("[8/8] Persona Classification",    lambda: classify_persona(
            result.get("tools_detected", []),
            result.get("temporal_paradoxes", [])
        )),
    ]

    keys = ["os_profile", "tools_detected", "log_analysis", "timeline",
            "temporal_paradoxes", "mitre_chain", "uefi", "_persona"]

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[bold green]{task.description}"),
        BarColumn(bar_width=30, style="green", complete_style="bright_green"),
        console=console
    ) as progress:
        task = progress.add_task("Scanning...", total=len(steps))
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
            progress.advance(task)

    result["evasion_score"], result["evasion_breakdown"] = calculate_evasion_score(result)
    result["narrative"] = generate_narrative(result)
    result["verdict"]   = generate_verdict(result["evasion_score"])

    console.print()
    print_results(result)
    export_json(result, output_path)
    console.print(f"\n[bold green]Report saved →[/bold green] [underline]{output_path}[/underline]\n")
    return result


def calculate_evasion_score(result: dict) -> tuple:
    breakdown = {
        "log_wipe": 0,
        "history_clear": 0,
        "timestamp_manipulation": 0,
        "anti_forensic_tools": 0,
        "anonymization_tools": 0,
        "uefi_boot_anomaly": 0,
        "offensive_os": 0,
    }
    log = result.get("log_analysis", {})
    if log.get("logs_cleared"):              breakdown["log_wipe"] = 25
    if log.get("history_cleared"):           breakdown["history_clear"] = 15
    if log.get("evasion_commands_found"):    breakdown["history_clear"] = min(breakdown["history_clear"] + len(log["evasion_commands_found"]) * 2, 20)

    paradoxes = result.get("temporal_paradoxes", [])
    breakdown["timestamp_manipulation"] = min(len(paradoxes) * 5, 20)

    tools = result.get("tools_detected", [])
    anti  = [t for t in tools if t.get("category") == "anti_forensic"]
    anon  = [t for t in tools if t.get("category") == "anonymization"]
    breakdown["anti_forensic_tools"]  = min(len(anti) * 5, 15)
    breakdown["anonymization_tools"]  = min(len(anon) * 3, 9)

    if result.get("uefi", {}).get("usb_boot_signature"):
        breakdown["uefi_boot_anomaly"] = 8

    os_conf = result.get("os_profile", {}).get("confidence", 0)
    if os_conf > 0.5:
        breakdown["offensive_os"] = int(os_conf * 8)

    total = min(sum(breakdown.values()), 100)
    return total, breakdown


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
        epilog="Examples:\n  python main.py /\n  python main.py /mnt/disk --output report.json\n  python main.py / --demo"
    )
    parser.add_argument("target", help="Target path (/ for live system, or mounted disk image path)")
    parser.add_argument("--output", default="forensight_report.json", help="Output JSON report path")
    parser.add_argument("--demo", action="store_true", help="Run with simulated demo data")
    args = parser.parse_args()
    run_scan(args.target, args.output, args.demo)