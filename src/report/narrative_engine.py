def generate_narrative(result: dict) -> str:
    """
    VENKAT'S MODULE
    Generates a plain-language investigative narrative from scan results.
    """
    lines = []
    os_info = result.get("os_profile", {})
    tools = result.get("tools_detected", [])
    paradoxes = result.get("temporal_paradoxes", [])
    evasion = result.get("evasion_score", 0)
    persona = result.get("persona", "Unknown")
    uefi = result.get("uefi", {})

    if os_info.get("distro") != "Unknown":
        lines.append(f"This machine was running {os_info['distro']}, an offensive-purpose Linux distribution.")

    if tools:
        installed = [t["name"] for t in tools if t["state"] == "installed"]
        removed   = [t["name"] for t in tools if t["state"] == "removed"]
        if installed:
            lines.append(f"Active attack tools found: {', '.join(installed)}.")
        if removed:
            lines.append(f"Evidence of removed tools detected: {', '.join(removed)} — deletion does not erase all traces.")

    if paradoxes:
        lines.append(f"{len(paradoxes)} timestamp paradox(es) detected — filesystem timestamps were deliberately manipulated.")

    if uefi.get("usb_boot_signature"):
        lines.append(f"UEFI firmware confirms a USB boot event. This signature cannot be wiped by the OS.")

    lines.append(f"Attacker persona: {persona}. Evasion intent score: {evasion}/100.")

    return " ".join(lines) if lines else "Insufficient data for narrative generation."