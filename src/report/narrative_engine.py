import os
import json

def generate_narrative(result: dict) -> dict:
    """
    Generates two forensic reports from scan results.
    Tries Groq API first, falls back to template if no key present or call fails.
    Returns dict with 'technical', 'plain', and 'source' keys.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if api_key:
        try:
            return _generate_via_groq(result, api_key)
        except Exception as e:
            print(f"[narrative] Groq API call failed ({e}), falling back to template")
    return _generate_template(result)


def _build_evidence_summary(result: dict) -> dict:
    os_info   = result.get("os_profile", {})
    tools     = result.get("tools_detected", [])
    paradoxes = result.get("temporal_paradoxes", [])
    log       = result.get("log_analysis", {})
    evasion   = result.get("evasion_score", 0)
    persona   = result.get("persona", "Unknown")
    uefi      = result.get("uefi", {})
    mitre     = result.get("mitre_chain", [])

    return {
        "os_detected":           os_info.get("distro", "Unknown"),
        "os_confidence":         f"{os_info.get('confidence', 0):.0%}",
        "os_threat_level":       os_info.get("threat_level", "NONE"),
        "os_version":            os_info.get("version", "Unknown"),
        "tools_installed":       [t["name"] for t in tools if t["state"] == "installed"],
        "tools_ghost":           [t["name"] for t in tools if t["state"] == "removed"],
        "critical_tools":        [t["name"] for t in tools if t.get("risk") == "CRITICAL"],
        "tool_categories":       list(set(t["category"] for t in tools)),
        "logs_wiped":            log.get("logs_cleared", False),
        "history_cleared":       log.get("history_cleared", False),
        "missing_log_count":     len(log.get("missing_logs", [])) + len(log.get("wiped_logs", [])),
        "evasion_commands":      log.get("evasion_commands_found", [])[:5],
        "suspicious_commands":   log.get("suspicious_commands_found", [])[:5],
        "failed_logins":         log.get("failed_logins", 0),
        "ssh_connections":       log.get("ssh_connections", [])[:5],
        "log_coverage":          f"{log.get('log_coverage', 0):.0%}",
        "timestamp_paradoxes":   len(paradoxes),
        "critical_paradoxes":    len([p for p in paradoxes if p.get("severity") == "critical"]),
        "paradox_types":         list(set(p.get("type", "") for p in paradoxes)),
        "paradox_examples": [
            {
                "file":       p.get("file"),
                "type":       p.get("type"),
                "court_note": p.get("court_note"),
                "attacker_action": p.get("attacker_action", "")
            } for p in paradoxes[:3]
        ],
        "uefi_usb_detected":     uefi.get("usb_boot_signature", False),
        "uefi_evidence":         uefi.get("firmware_evidence", ""),
        "uefi_boot_entries":     uefi.get("boot_entries", [])[:3],
        "mitre_phases":          list(dict.fromkeys(c["phase"] for c in mitre)),
        "mitre_techniques":      [c["technique"] for c in mitre][:8],
        "mitre_commands":        [c["command"] for c in mitre][:5],
        "attacker_persona":      persona,
        "persona_confidence":    f"{result.get('persona_confidence', 0):.0%}",
        "evasion_score":         evasion,
        "verdict":               result.get("verdict", ""),
    }


def _generate_via_groq(result: dict, api_key: str) -> dict:
    from groq import Groq

    evidence = _build_evidence_summary(result)
    client   = Groq(api_key=api_key)

    prompt = f"""You are a senior digital forensics investigator writing an official case report for a Linux forensic analysis tool called ForenSight.

Based on the following evidence collected during a forensic scan, write exactly two reports.

EVIDENCE:
{json.dumps(evidence, indent=2)}

Return ONLY a valid JSON object with no additional text, no markdown, no code fences:
{{"technical": "your technical report here", "plain": "your plain language report here"}}

REPORT 1 — technical (key: "technical"):
- Written for a forensic analyst or cybersecurity expert
- Use precise technical terminology: mtime, ctime, atime, POSIX invariants, inode, NVRAM, EFI variables
- Reference specific tool names, MITRE technique IDs (e.g. T1070, T1059), attack phases
- Cite specific evidence: paradox types, log files wiped, tools found, timestamp violations
- Mention POSIX invariant violation if paradoxes exist (mtime must never exceed ctime)
- Mention UEFI NVRAM firmware evidence if USB boot was detected
- Tone: clinical, precise, evidence-based, authoritative
- Length: 5-7 sentences

REPORT 2 — plain language (key: "plain"):
- Written for a detective, judge, lawyer, or non-technical investigator
- Zero technical jargon — explain everything as if to someone with no IT background
- Use analogies: e.g. "like a security camera that records even when the thief tries to destroy evidence"
- Tell the story of what happened on this machine chronologically
- Emphasize what each piece of evidence proves legally
- Explain why the attacker's cover-up attempt failed
- Tone: clear, authoritative, compelling, accessible
- Length: 5-7 sentences

Both reports must be grounded strictly in the evidence provided. Do not invent findings not present in the evidence. If a field is empty or unknown, do not reference it."""

    chat = client.chat.completions.create(
        model="llama3-8b-8192",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a senior digital forensics investigator. "
                    "You write precise, evidence-based forensic reports. "
                    "You always respond with valid JSON only — no markdown, "
                    "no code fences, no extra text."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        max_tokens=1200,
        temperature=0.3,
    )

    raw = chat.choices[0].message.content.strip()

    # Strip markdown fences if model added them anyway
    if "```" in raw:
        parts = raw.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("{"):
                raw = part
                break

    parsed = json.loads(raw)
    return {
        "technical": parsed.get("technical", ""),
        "plain":     parsed.get("plain", ""),
        "source":    "groq-llama3"
    }


def _generate_template(result: dict) -> dict:
    os_info   = result.get("os_profile", {})
    tools     = result.get("tools_detected", [])
    paradoxes = result.get("temporal_paradoxes", [])
    log       = result.get("log_analysis", {})
    evasion   = result.get("evasion_score", 0)
    persona   = result.get("persona", "Unknown")
    uefi      = result.get("uefi", {})
    mitre     = result.get("mitre_chain", [])

    installed  = [t["name"] for t in tools if t["state"] == "installed"]
    removed    = [t["name"] for t in tools if t["state"] == "removed"]
    critical_t = [t["name"] for t in tools if t.get("risk") == "CRITICAL"]
    phases     = list(dict.fromkeys(c["phase"] for c in mitre))
    critical_p = [p for p in paradoxes if p.get("severity") == "critical"]
    high_p     = [p for p in paradoxes if p.get("severity") == "high"]
    missing    = len(log.get("missing_logs", [])) + len(log.get("wiped_logs", []))
    evasion_cmds = log.get("evasion_commands_found", [])

    # ── Technical report ─────────────────────────────────────────────────
    tech = []

    if os_info.get("distro") not in ("Unknown", None):
        tech.append(
            f"Forensic analysis identified the target system as {os_info['distro']} "
            f"(confidence: {os_info.get('confidence', 0):.0%}, "
            f"threat level: {os_info.get('threat_level', 'UNKNOWN')}), "
            f"an offensive-purpose Linux distribution with pre-installed attack tooling."
        )

    if installed or removed:
        parts = []
        if installed:
            parts.append(f"Active offensive binaries confirmed at expected filesystem paths: {', '.join(installed)}.")
        if removed:
            parts.append(
                f"Post-deletion ghost traces recovered for {', '.join(removed)} "
                f"via DPKG status database, APT history logs, and bash history residue."
            )
        if critical_t:
            parts.append(f"CRITICAL-risk tools identified: {', '.join(critical_t)}.")
        tech.append(" ".join(parts))

    if missing > 0:
        tech.append(
            f"{missing} critical system log files were absent or zero-byte "
            f"(including auth.log, syslog, wtmp), consistent with deliberate log destruction. "
            + (f"Anti-forensic commands recovered: {'; '.join(evasion_cmds[:3])}."
               if evasion_cmds else "")
        )

    if critical_p:
        p = critical_p[0]
        tech.append(
            f"{len(critical_p)} critical and {len(high_p)} high-severity timestamp "
            f"paradox(es) detected across the filesystem. "
            f"Primary violation: {p['type'].replace('_', ' ')} on {p['file']} "
            f"(delta: {p.get('delta_seconds', 0):.1f}s). "
            f"POSIX invariant breached — mtime exceeds ctime, "
            f"physically impossible on unmanipulated inodes."
        )

    if uefi.get("usb_boot_signature"):
        tech.append(
            f"UEFI NVRAM analysis via /sys/firmware/efi/efivars confirmed a USB boot event. "
            f"EFI boot variables persist in non-volatile firmware memory and "
            f"survive complete OS wipe — inaccessible to userspace deletion."
        )

    if phases:
        tech.append(
            f"MITRE ATT&CK kill chain reconstruction identified {len(phases)} tactic "
            f"phases: {' → '.join(phases)}. "
            f"Attacker persona classified as {persona} "
            f"(evasion intent score: {evasion}/100)."
        )

    # ── Plain language report ─────────────────────────────────────────────
    plain = []

    if os_info.get("distro") not in ("Unknown", None):
        plain.append(
            f"This machine was running {os_info['distro']}, an operating system "
            f"specifically built for hacking and offensive cyber operations — "
            f"it is not software anyone installs by accident."
        )

    if installed or removed:
        parts = []
        if installed:
            parts.append(
                f"Hacking tools were found actively installed on the machine: "
                f"{', '.join(installed)}."
            )
        if removed:
            parts.append(
                f"Additional tools had been deleted in an attempt to hide them — "
                f"{', '.join(removed)} — but their installation records remained "
                f"in the system's package database. Deleting a tool does not erase "
                f"the record that it was ever there."
            )
        plain.append(" ".join(parts))

    if missing > 0:
        plain.append(
            f"The machine's activity records — the logs that would normally "
            f"show everything that happened — were deliberately wiped. "
            f"{missing} critical log files were missing or emptied. "
            f"This is not an accident. It indicates a deliberate attempt "
            f"to destroy evidence before the machine was seized."
        )

    if critical_p:
        plain.append(
            f"The attacker tried to alter file timestamps to make their activity "
            f"look older than it was — similar to changing the date on a forged document. "
            f"However, the operating system automatically records the exact moment "
            f"any change is made, in a hidden field the attacker cannot modify. "
            f"This created a mathematical impossibility — "
            f"{len(critical_p)} instance(s) of proof that timestamps were deliberately falsified."
        )

    if uefi.get("usb_boot_signature"):
        plain.append(
            f"Even though the hard drive was wiped, the motherboard's built-in chip — "
            f"which works like a security camera with its own independent power — "
            f"recorded that a USB device was used to boot this machine. "
            f"This record is burned into hardware and cannot be erased by any software, "
            f"including Tails OS."
        )

    if phases:
        plain.append(
            f"Taken together, the evidence shows a planned, multi-stage operation — "
            f"not accidental or casual use. "
            f"The investigation identified activity across {len(phases)} distinct attack phases: "
            f"{', '.join(phases)}. "
            f"This level of structure proves deliberate intent. "
            f"The attacker's evasion score was {evasion} out of 100 — "
            f"meaning they tried extremely hard to cover their tracks and failed."
        )

    if not tech:
        tech = ["Insufficient forensic data for technical analysis. Manual investigation recommended."]
    if not plain:
        plain = ["Insufficient data to generate investigator summary. Manual review required."]

    return {
        "technical": " ".join(tech),
        "plain":     " ".join(plain),
        "source":    "template"
    }