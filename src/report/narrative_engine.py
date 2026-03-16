def generate_narrative(result: dict) -> str:
    sections = []
    os_info   = result.get("os_profile", {})
    tools     = result.get("tools_detected", [])
    paradoxes = result.get("temporal_paradoxes", [])
    log       = result.get("log_analysis", {})
    evasion   = result.get("evasion_score", 0)
    persona   = result.get("persona", "Unknown")
    uefi      = result.get("uefi", {})
    mitre     = result.get("mitre_chain", [])

    # OS
    if os_info.get("distro") not in ("Unknown", None):
        sections.append(
            f"The examined system was running {os_info['distro']} "
            f"(confidence {os_info.get('confidence', 0):.0%}), an operating system "
            f"purpose-built for offensive security operations."
        )

    # Tools
    installed = [t["name"] for t in tools if t["state"] == "installed"]
    removed   = [t["name"] for t in tools if t["state"] == "removed"]
    critical  = [t["name"] for t in tools if t.get("risk") == "CRITICAL"]
    if installed:
        sections.append(
            f"Active offensive tools confirmed: {', '.join(installed)}. "
            + (f"Among these, {', '.join(critical)} are classified as CRITICAL-risk tools." if critical else "")
        )
    if removed:
        sections.append(
            f"Evidence of tool removal was found for: {', '.join(removed)}. "
            f"Deletion of tools does not erase forensic traces — package logs, "
            f"APT history, and inode residue confirm prior installation."
        )

    # Logs
    missing_count = len(log.get("missing_logs", [])) + len(log.get("wiped_logs", []))
    if missing_count > 0:
        sections.append(
            f"{missing_count} critical log file(s) were missing or wiped, "
            f"including authentication logs and system activity records. "
            f"This represents deliberate destruction of evidence."
        )
    if log.get("evasion_commands_found"):
        cmds = log["evasion_commands_found"][:3]
        sections.append(
            f"Anti-forensic commands were recovered from bash history: "
            f"{'; '.join(cmds)}. These commands were executed to destroy evidence."
        )

    # Temporal paradoxes
    critical_p = [p for p in paradoxes if p.get("severity") == "critical"]
    if critical_p:
        sections.append(
            f"{len(critical_p)} critical timestamp paradox(es) were detected. "
            f"These represent mathematically impossible filesystem states — "
            f"specifically, {critical_p[0]['type'].replace('_', ' ')} on {critical_p[0]['file']}. "
            f"This is court-admissible proof of deliberate evidence tampering."
        )

    # UEFI
    if uefi.get("usb_boot_signature"):
        sections.append(
            f"UEFI firmware analysis confirmed a USB boot event. "
            f"This signature is burned into firmware and survives a complete OS wipe — "
            f"it cannot be erased by the attacker. Boot entries found: "
            f"{', '.join(uefi.get('boot_entries', [])[:3]) or 'see full report'}."
        )

    # MITRE
    phases = list(dict.fromkeys(c["phase"] for c in mitre))
    if phases:
        sections.append(
            f"MITRE ATT&CK kill chain analysis identified activity across "
            f"{len(phases)} tactic phase(s): {' → '.join(phases)}. "
            f"This structured progression indicates a planned operation, not opportunistic activity."
        )

    # Persona + verdict
    if persona != "Unknown":
        sections.append(
            f"Attacker persona classified as: {persona}. "
            f"Evasion Intent Score: {evasion}/100."
        )

    if not sections:
        return "Insufficient forensic data to generate a narrative. Manual investigation recommended."

    return " ".join(sections)