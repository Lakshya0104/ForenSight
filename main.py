import argparse
import json
import sys
from datetime import datetime
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

def run_scan(target: str, output_path: str = "forensight_report.json"):
    print(f"\n[ForenSight] Starting scan on: {target}")
    print("=" * 50)

    result = {
        "scan_meta": {
            "tool": "ForenSight",
            "version": "1.0.0",
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "target": target
        }
    }

    print("[1/8] OS fingerprinting...")
    result["os_profile"] = fingerprint_os(target)

    print("[2/8] Tool detection...")
    result["tools_detected"] = detect_tools(target)

    print("[3/8] Log analysis...")
    result["log_analysis"] = analyze_logs(target)

    print("[4/8] Temporal paradox detection...")
    result["temporal_paradoxes"] = detect_paradoxes(target)

    print("[5/8] MITRE ATT&CK mapping...")
    result["mitre_chain"] = map_to_mitre(target)

    print("[6/8] UEFI fingerprinting...")
    result["uefi"] = fingerprint_uefi()

    print("[7/8] Attacker persona classification...")
    tools = result["tools_detected"]
    paradoxes = result["temporal_paradoxes"]
    result["persona"], result["persona_confidence"] = classify_persona(tools, paradoxes)

    print("[8/8] Generating narrative and evasion score...")
    result["evasion_score"], result["evasion_breakdown"] = calculate_evasion_score(result)
    result["narrative"] = generate_narrative(result)
    result["verdict"] = generate_verdict(result["evasion_score"])

    export_json(result, output_path)
    print(f"\n[ForenSight] Scan complete. Report saved to: {output_path}")
    print(f"[ForenSight] Evasion Score: {result['evasion_score']}/100")
    print(f"[ForenSight] Verdict: {result['verdict']}\n")
    return result


def calculate_evasion_score(result: dict) -> tuple:
    breakdown = {
        "log_wipe": 0,
        "history_clear": 0,
        "timestamp_manipulation": 0,
        "anti_forensic_tools": 0
    }
    log = result.get("log_analysis", {})
    if log.get("logs_cleared"): breakdown["log_wipe"] = 30
    if log.get("history_cleared"): breakdown["history_clear"] = 20
    paradoxes = result.get("temporal_paradoxes", [])
    if paradoxes: breakdown["timestamp_manipulation"] = min(len(paradoxes) * 8, 25)
    tools = result.get("tools_detected", [])
    anti_forensic = [t for t in tools if t.get("category") == "anti_forensic"]
    breakdown["anti_forensic_tools"] = min(len(anti_forensic) * 4, 16)
    total = sum(breakdown.values())
    return min(total, 100), breakdown


def generate_verdict(score: int) -> str:
    if score >= 80: return "HIGH RISK — structured attack campaign detected. Evidence tampering confirmed."
    if score >= 50: return "MEDIUM RISK — suspicious activity detected. Further investigation recommended."
    if score >= 20: return "LOW RISK — some anomalies found. May be benign."
    return "CLEAN — no significant indicators found."


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ForenSight — Linux Forensic Analysis Tool")
    parser.add_argument("target", help="Target path (/ for live system, or path to mounted disk image)")
    parser.add_argument("--output", default="forensight_report.json", help="Output JSON report path")
    args = parser.parse_args()
    run_scan(args.target, args.output)