import os
import json
from datetime import datetime, timezone
from collections import defaultdict

SCAN_PATHS = [
    "etc", "var/log", "root", "home", "tmp",
    "usr/bin", "usr/local/bin", "usr/sbin",
    "opt", "bin", "sbin", "var/tmp",
]

OFFENSIVE_TOOLS = {
    "nmap":        {"category": "recon",         "risk": "HIGH"},
    "masscan":     {"category": "recon",         "risk": "HIGH"},
    "metasploit":  {"category": "exploit",       "risk": "CRITICAL"},
    "msfconsole":  {"category": "exploit",       "risk": "CRITICAL"},
    "sqlmap":      {"category": "exploit",       "risk": "CRITICAL"},
    "hydra":       {"category": "brute_force",   "risk": "CRITICAL"},
    "john":        {"category": "brute_force",   "risk": "HIGH"},
    "hashcat":     {"category": "brute_force",   "risk": "HIGH"},
    "wireshark":   {"category": "sniffing",      "risk": "HIGH"},
    "tcpdump":     {"category": "sniffing",      "risk": "MEDIUM"},
    "aircrack-ng": {"category": "wireless",      "risk": "HIGH"},
    "wifite":      {"category": "wireless",      "risk": "HIGH"},
    "burpsuite":   {"category": "web_exploit",   "risk": "CRITICAL"},
    "nikto":       {"category": "web_exploit",   "risk": "HIGH"},
    "gobuster":    {"category": "web_exploit",   "risk": "HIGH"},
    "bleachbit":   {"category": "anti_forensic", "risk": "CRITICAL"},
    "shred":       {"category": "anti_forensic", "risk": "HIGH"},
    "tor":         {"category": "anonymization", "risk": "HIGH"},
    "proxychains": {"category": "anonymization", "risk": "HIGH"},
    "netcat":      {"category": "c2",            "risk": "HIGH"},
    "socat":       {"category": "c2",            "risk": "HIGH"},
    "chisel":      {"category": "c2",            "risk": "CRITICAL"},
}

MITRE_RULES = [
    {"keywords": ["nmap","masscan","netdiscover","arp-scan"],         "phase": "Recon",                "technique": "T1046", "tactic": "Discovery"},
    {"keywords": ["whois","dig ","nslookup","dnsrecon"],              "phase": "Recon",                "technique": "T1590", "tactic": "Reconnaissance"},
    {"keywords": ["theharvester","recon-ng","maltego"],               "phase": "Recon",                "technique": "T1589", "tactic": "Reconnaissance"},
    {"keywords": ["hydra","medusa","patator","crowbar"],              "phase": "Initial Access",        "technique": "T1110", "tactic": "Credential Access"},
    {"keywords": ["sqlmap","' or 1=1","union select"],               "phase": "Initial Access",        "technique": "T1190", "tactic": "Initial Access"},
    {"keywords": ["curl ","wget ","python -c","perl -e"],             "phase": "Execution",             "technique": "T1059", "tactic": "Execution"},
    {"keywords": ["chmod +x","bash -i","./exploit","bash "],          "phase": "Execution",             "technique": "T1059", "tactic": "Execution"},
    {"keywords": ["msfconsole","msfvenom","metasploit"],              "phase": "Execution",             "technique": "T1203", "tactic": "Execution"},
    {"keywords": ["crontab","cron.d","cron.daily"],                   "phase": "Persistence",           "technique": "T1053", "tactic": "Persistence"},
    {"keywords": ["systemctl enable",".service"],                     "phase": "Persistence",           "technique": "T1543", "tactic": "Persistence"},
    {"keywords": ["authorized_keys","ssh-keygen","~/.ssh/"],          "phase": "Persistence",           "technique": "T1098", "tactic": "Persistence"},
    {"keywords": ["useradd","adduser","usermod"],                     "phase": "Persistence",           "technique": "T1136", "tactic": "Persistence"},
    {"keywords": ["sudo -l","sudo su","pkexec","suid"],               "phase": "Privilege Escalation",  "technique": "T1548", "tactic": "Privilege Escalation"},
    {"keywords": ["linpeas","linenum","linux-exploit-suggester"],     "phase": "Privilege Escalation",  "technique": "T1068", "tactic": "Privilege Escalation"},
    {"keywords": ["history -c","unset histfile","export histsize=0"], "phase": "Defense Evasion",       "technique": "T1070", "tactic": "Defense Evasion"},
    {"keywords": ["bleachbit","shred ","srm ","wipe "],               "phase": "Defense Evasion",       "technique": "T1070", "tactic": "Defense Evasion"},
    {"keywords": ["iptables -f","ufw disable","setenforce 0"],        "phase": "Defense Evasion",       "technique": "T1562", "tactic": "Defense Evasion"},
    {"keywords": ["touch -t","touch -d","timestomp"],                 "phase": "Defense Evasion",       "technique": "T1070.006", "tactic": "Defense Evasion"},
    {"keywords": ["hashdump","/etc/shadow","cat /etc/passwd"],        "phase": "Credential Access",     "technique": "T1003", "tactic": "Credential Access"},
    {"keywords": ["mimikatz","lazagne","keydump"],                    "phase": "Credential Access",     "technique": "T1555", "tactic": "Credential Access"},
    {"keywords": ["scp ","rsync ","ftp ","sftp "],                    "phase": "Exfiltration",          "technique": "T1048", "tactic": "Exfiltration"},
    {"keywords": ["nc -e","ncat ","/dev/tcp/","socat"],               "phase": "Exfiltration",          "technique": "T1041", "tactic": "Exfiltration"},
    {"keywords": ["rm -rf /var/log","> /var/log","truncate"],         "phase": "Cover Tracks",          "technique": "T1070.002", "tactic": "Defense Evasion"},
    {"keywords": ["logrotate -f","cat /dev/null >"],                  "phase": "Cover Tracks",          "technique": "T1070.003", "tactic": "Defense Evasion"},
]

PERSONAS = {
    "Network Intrusion Operator": {
        "tools": ["nmap","masscan","metasploit","hydra","netcat","socat"],
        "weight": 3.0,
        "description": "Focused on network scanning, exploitation, and gaining remote shells.",
        "color": "#E24B4A"
    },
    "Data Exfiltrator": {
        "tools": ["curl","wget","netcat","socat","chisel","scp"],
        "weight": 3.0,
        "description": "Prioritizes data theft via covert channels and file transfer tools.",
        "color": "#EF9F27"
    },
    "Credential Harvester": {
        "tools": ["hydra","john","hashcat","medusa"],
        "weight": 2.5,
        "description": "Targets authentication systems — password cracking and hash dumping.",
        "color": "#D85A30"
    },
    "Web Application Attacker": {
        "tools": ["burpsuite","sqlmap","nikto","dirb","gobuster","wfuzz"],
        "weight": 2.5,
        "description": "Exploits web application vulnerabilities — SQLi, XSS, directory traversal.",
        "color": "#7F77DD"
    },
    "Wireless Attacker": {
        "tools": ["aircrack-ng","kismet","wifite","wireshark"],
        "weight": 2.0,
        "description": "Specializes in wireless network attacks — WPA cracking, deauthentication.",
        "color": "#1D9E75"
    },
    "Insider Threat": {
        "tools": ["bleachbit","secure-delete","shred","wipe","tor","proxychains"],
        "weight": 2.0,
        "description": "Evidence of deliberate cover-up behavior — anti-forensic focus.",
        "color": "#D4537E"
    },
    "Advanced Persistent Threat (APT)": {
        "tools": ["chisel","socat","tor","proxychains","metasploit"],
        "weight": 3.5,
        "description": "Long-term access maintenance — persistence mechanisms and covert C2.",
        "color": "#E24B4A"
    },
}

PHASE_ORDER = [
    "Recon", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Exfiltration", "Cover Tracks"
]

PHASE_COLORS = {
    "Recon":                "#378ADD",
    "Initial Access":       "#7F77DD",
    "Execution":            "#D85A30",
    "Persistence":          "#EF9F27",
    "Privilege Escalation": "#E24B4A",
    "Defense Evasion":      "#A32D2D",
    "Credential Access":    "#BA7517",
    "Exfiltration":         "#D4537E",
    "Cover Tracks":         "#791F1F",
}


def run_lare(target: str, paradoxes: list = None, tools_detected: list = None) -> dict:
    """
    Master LARE function — runs all three integrated modules and returns
    a unified result dict with timeline, mitre_chain, persona, and html_path.
    """
    paradoxes      = paradoxes or []
    tools_detected = tools_detected or []

    timeline   = _build_timeline(target)
    mitre      = _map_mitre(target)
    persona, persona_conf = _classify_persona(tools_detected, paradoxes)
    events     = _synthesize_events(timeline, mitre, paradoxes, tools_detected)
    html_path  = _generate_html(events, persona, persona_conf, paradoxes,
                                tools_detected, target)

    return {
        "timeline":          timeline,
        "mitre_chain":       mitre,
        "persona":           persona,
        "persona_confidence":persona_conf,
        "attack_events":     events,
        "html_report":       html_path,
        "phases_hit":        list(dict.fromkeys(e["phase"] for e in events if e.get("phase"))),
        "total_events":      len(events),
    }


def _build_timeline(target: str) -> dict:
    root   = target.rstrip("/") if target != "/" else ""
    events = []
    suspicious_files  = []
    recently_modified = []

    SUSPICIOUS_EXTS  = {".sh",".py",".pl",".rb",".php",".elf",".so",".ko",".bin"}
    SUSPICIOUS_NAMES = {"payload","backdoor","shell","exploit","hack","pwn","root","crack"}

    for scan_path in SCAN_PATHS:
        full_dir = os.path.join(root, scan_path) if root else f"/{scan_path}"
        if not os.path.exists(full_dir):
            continue
        try:
            entries = os.listdir(full_dir)
        except PermissionError:
            continue
        for fname in entries:
            fpath = os.path.join(full_dir, fname)
            try:
                s   = os.stat(fpath)
                rel = fpath.replace(root, "") if root else fpath
                ext = os.path.splitext(fname)[1].lower()
                flags = []
                if ext in SUSPICIOUS_EXTS:
                    flags.append(f"suspicious extension: {ext}")
                if any(kw in fname.lower() for kw in SUSPICIOUS_NAMES):
                    flags.append("suspicious filename")
                if s.st_size == 0 and ext not in {".log",".pid"}:
                    flags.append("zero-byte file")
                try:
                    if oct(s.st_mode).endswith("777"):
                        flags.append("world-writable (777)")
                except Exception:
                    pass
                ev = {
                    "file":       rel,
                    "atime":      datetime.utcfromtimestamp(s.st_atime).isoformat(),
                    "mtime":      datetime.utcfromtimestamp(s.st_mtime).isoformat(),
                    "ctime":      datetime.utcfromtimestamp(s.st_ctime).isoformat(),
                    "size_bytes": s.st_size,
                    "suspicious": bool(flags),
                    "flags":      flags
                }
                events.append(ev)
                if flags:
                    suspicious_files.append(rel)
            except (PermissionError, OSError):
                continue

    events.sort(key=lambda x: x["mtime"], reverse=True)
    recently_modified = [e["file"] for e in events[:20]]

    return {
        "total_files_scanned":  len(events),
        "suspicious_files_found": len(suspicious_files),
        "suspicious_files":     suspicious_files[:20],
        "recently_modified":    recently_modified,
        "recently_accessed":    sorted(events, key=lambda x: x["atime"],
                                       reverse=True)[:20],
        "full_timeline":        events[:150]
    }


def _map_mitre(target: str) -> list:
    root         = target.rstrip("/") if target != "/" else ""
    chain        = []
    seen         = set()
    history_path = os.path.join(root, "root/.bash_history") if root else "/root/.bash_history"

    if not os.path.exists(history_path):
        return chain
    try:
        lines = open(history_path, errors="ignore").read().splitlines()
    except Exception:
        return chain

    for line in lines:
        cmd = line.strip()
        if not cmd:
            continue
        cmd_lower = cmd.lower()
        for rule in MITRE_RULES:
            if any(kw.lower() in cmd_lower for kw in rule["keywords"]):
                key = f"{rule['technique']}:{cmd[:40]}"
                if key not in seen:
                    chain.append({
                        "phase":     rule["phase"],
                        "tactic":    rule["tactic"],
                        "technique": rule["technique"],
                        "command":   cmd,
                    })
                    seen.add(key)
                break

    chain.sort(key=lambda x: PHASE_ORDER.index(x["phase"])
               if x["phase"] in PHASE_ORDER else 99)
    return chain


def _classify_persona(tools: list, paradoxes: list) -> tuple:
    tool_names  = {t["name"].lower() for t in tools}
    tool_states = {t["name"].lower(): t.get("state") for t in tools}
    scores      = {}

    for persona, config in PERSONAS.items():
        score   = 0.0
        matched = []
        for t in config["tools"]:
            if t in tool_names:
                w = 1.0 if tool_states.get(t) == "installed" else 0.6
                score += w
                matched.append(t)
        if score > 0:
            scores[persona] = {"raw": score * config["weight"], "matched": matched}

    if paradoxes:
        if "Insider Threat" not in scores:
            scores["Insider Threat"] = {"raw": 0, "matched": []}
        scores["Insider Threat"]["raw"] += len(paradoxes) * 0.8

    if not scores:
        return "Unknown", 0.0

    best        = max(scores, key=lambda k: scores[k]["raw"])
    max_poss    = PERSONAS[best]["weight"] * len(PERSONAS[best]["tools"])
    confidence  = round(min(scores[best]["raw"] / max(max_poss, 1), 1.0), 2)
    return best, confidence


def _synthesize_events(timeline: dict, mitre: list,
                        paradoxes: list, tools: list) -> list:
    """
    Merges MITRE chain, paradoxes, and tool detections into a single
    chronological attack event list for LARE visualization.
    """
    events = []

    # MITRE commands become attack events
    for i, c in enumerate(mitre):
        events.append({
            "id":          f"mitre-{i}",
            "type":        "attack",
            "phase":       c["phase"],
            "tactic":      c["tactic"],
            "technique":   c["technique"],
            "title":       c["phase"],
            "description": c["command"],
            "evidence":    f"Command recovered from bash history: {c['command']}",
            "severity":    "critical" if c["phase"] in
                           ["Privilege Escalation", "Cover Tracks", "Exfiltration"]
                           else "high",
            "color":       PHASE_COLORS.get(c["phase"], "#888780"),
            "icon":        _phase_icon(c["phase"]),
        })

    # Temporal paradoxes become evidence events
    for i, p in enumerate(paradoxes[:10]):
        events.append({
            "id":          f"paradox-{i}",
            "type":        "paradox",
            "phase":       "Defense Evasion",
            "tactic":      "Timestomping",
            "technique":   "T1070.006",
            "title":       "Timestamp Paradox",
            "description": p.get("type", "").replace("_", " ").title(),
            "evidence":    p.get("court_note", ""),
            "attacker":    p.get("attacker_action", ""),
            "file":        p.get("file", ""),
            "delta":       p.get("delta_seconds", 0),
            "severity":    p.get("severity", "high"),
            "color":       "#A32D2D",
            "icon":        "clock",
        })

    # Critical tools become presence events
    for i, t in enumerate(tools):
        if t.get("risk") in ("CRITICAL", "HIGH"):
            phase = _tool_phase(t["category"])
            events.append({
                "id":          f"tool-{i}",
                "type":        "tool",
                "phase":       phase,
                "tactic":      t["category"].replace("_", " ").title(),
                "technique":   "",
                "title":       f"{t['name']} {'(active)' if t['state'] == 'installed' else '(ghost)'}",
                "description": t.get("evidence", ""),
                "evidence":    t.get("evidence", ""),
                "severity":    t.get("risk", "HIGH").lower(),
                "state":       t.get("state", "unknown"),
                "color":       "#E24B4A" if t["state"] == "installed" else "#BA7517",
                "icon":        "tool",
            })

    # Suspicious files from timeline
    for i, f in enumerate(timeline.get("suspicious_files", [])[:5]):
        events.append({
            "id":          f"file-{i}",
            "type":        "file",
            "phase":       "Execution",
            "tactic":      "Suspicious File",
            "technique":   "T1059",
            "title":       "Suspicious File",
            "description": f,
            "evidence":    f"Flagged during filesystem timeline scan: {f}",
            "severity":    "medium",
            "color":       "#D85A30",
            "icon":        "file",
        })

    # Sort by phase order
    def sort_key(e):
        phase = e.get("phase", "")
        return PHASE_ORDER.index(phase) if phase in PHASE_ORDER else 99

    events.sort(key=sort_key)
    return events


def _phase_icon(phase: str) -> str:
    return {
        "Recon":                "search",
        "Initial Access":       "unlock",
        "Execution":            "play",
        "Persistence":          "anchor",
        "Privilege Escalation": "arrow-up",
        "Defense Evasion":      "shield-off",
        "Credential Access":    "key",
        "Exfiltration":         "upload",
        "Cover Tracks":         "trash",
    }.get(phase, "alert")


def _tool_phase(category: str) -> str:
    return {
        "recon":         "Recon",
        "exploit":       "Execution",
        "brute_force":   "Initial Access",
        "sniffing":      "Recon",
        "wireless":      "Initial Access",
        "web_exploit":   "Initial Access",
        "anti_forensic": "Cover Tracks",
        "anonymization": "Defense Evasion",
        "c2":            "Exfiltration",
    }.get(category, "Execution")


def _generate_html(events: list, persona: str, persona_conf: float,
                   paradoxes: list, tools: list, target: str) -> str:
    persona_color = PERSONAS.get(persona, {}).get("color", "#888780")
    persona_desc  = PERSONAS.get(persona, {}).get("description", "")
    phases_hit    = list(dict.fromkeys(
        e["phase"] for e in events if e.get("phase") in PHASE_ORDER
    ))
    critical_count = len([e for e in events if e.get("severity") == "critical"])
    paradox_count  = len(paradoxes)
    tool_count     = len([t for t in tools if t.get("state") == "installed"])
    ghost_count    = len([t for t in tools if t.get("state") == "removed"])
    scan_time      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    events_json  = json.dumps(events,    indent=2, default=str)
    phases_json  = json.dumps(PHASE_COLORS)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ForenSight — LARE Attack Reconstruction</title>
<style>
  :root {{
    --bg:        #0a0c10;
    --bg2:       #111318;
    --bg3:       #1a1d24;
    --border:    #2a2d35;
    --text:      #e2e4e9;
    --muted:     #6b7280;
    --green:     #1D9E75;
    --red:       #E24B4A;
    --amber:     #EF9F27;
    --blue:      #378ADD;
    --purple:    #7F77DD;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.6;
  }}

  /* ── Header ── */
  .header {{
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 20px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }}
  .logo {{ font-size: 22px; font-weight: 700; color: var(--green); letter-spacing: 2px; }}
  .logo span {{ color: var(--muted); font-weight: 400; font-size: 13px; margin-left: 12px; }}
  .scan-meta {{ text-align: right; color: var(--muted); font-size: 12px; line-height: 1.8; }}

  /* ── Metric cards ── */
  .metrics {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    padding: 24px 32px 0;
  }}
  .metric {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 16px;
    text-align: center;
  }}
  .metric-val {{
    font-size: 26px;
    font-weight: 700;
    line-height: 1.2;
  }}
  .metric-label {{
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: .06em;
    margin-top: 4px;
  }}

  /* ── Persona card ── */
  .persona-card {{
    margin: 20px 32px 0;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-left: 4px solid {persona_color};
    border-radius: 10px;
    padding: 16px 20px;
    display: flex;
    align-items: center;
    gap: 20px;
  }}
  .persona-badge {{
    background: {persona_color}22;
    border: 1px solid {persona_color}55;
    color: {persona_color};
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 600;
    white-space: nowrap;
  }}
  .persona-desc {{ color: var(--muted); font-size: 13px; }}
  .persona-conf {{
    margin-left: auto;
    text-align: right;
    white-space: nowrap;
  }}
  .persona-conf-val {{
    font-size: 22px;
    font-weight: 700;
    color: {persona_color};
  }}
  .persona-conf-label {{ font-size: 11px; color: var(--muted); }}

  /* ── Kill chain strip ── */
  .chain-strip {{
    margin: 20px 32px 0;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 20px;
    display: flex;
    align-items: center;
    gap: 0;
    flex-wrap: wrap;
    gap: 4px;
  }}
  .chain-phase {{
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    opacity: 0.3;
    transition: opacity .3s;
  }}
  .chain-phase.hit {{ opacity: 1; }}
  .chain-arrow {{
    color: var(--border);
    margin: 0 2px;
    font-size: 12px;
  }}

  /* ── Section title ── */
  .section-title {{
    padding: 24px 32px 12px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--muted);
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .section-title::after {{
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }}

  /* ── Timeline ── */
  .timeline {{
    padding: 0 32px 40px;
    position: relative;
  }}
  .timeline::before {{
    content: '';
    position: absolute;
    left: 64px;
    top: 0;
    bottom: 0;
    width: 2px;
    background: linear-gradient(to bottom, var(--green), var(--border));
  }}

  .event-row {{
    display: flex;
    gap: 20px;
    margin-bottom: 12px;
    align-items: flex-start;
    opacity: 0;
    transform: translateX(-20px);
    transition: opacity .4s ease, transform .4s ease;
    cursor: pointer;
  }}
  .event-row.visible {{
    opacity: 1;
    transform: translateX(0);
  }}

  .event-index {{
    width: 32px;
    height: 32px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 700;
    flex-shrink: 0;
    margin-top: 6px;
    position: relative;
    z-index: 1;
    border: 2px solid var(--bg);
  }}

  .event-card {{
    flex: 1;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 18px;
    transition: border-color .2s, transform .2s, box-shadow .2s;
  }}
  .event-card:hover {{
    border-color: #3a3d47;
    transform: translateX(4px);
    box-shadow: 0 4px 20px rgba(0,0,0,.4);
  }}
  .event-card.expanded {{
    border-color: var(--color, var(--green));
  }}

  .event-header {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 6px;
  }}
  .event-phase-pill {{
    font-size: 11px;
    font-weight: 600;
    padding: 2px 10px;
    border-radius: 12px;
    background: var(--color, #333)22;
    color: var(--color, var(--text));
    border: 1px solid var(--color, #333)44;
  }}
  .event-type-badge {{
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 10px;
    background: var(--bg3);
    color: var(--muted);
    border: 1px solid var(--border);
    text-transform: uppercase;
    letter-spacing: .04em;
  }}
  .event-title {{
    font-size: 14px;
    font-weight: 600;
    color: var(--text);
  }}
  .event-desc {{
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 12px;
    color: var(--muted);
    background: var(--bg3);
    padding: 6px 10px;
    border-radius: 6px;
    margin-top: 6px;
    word-break: break-all;
  }}
  .event-technique {{
    font-size: 11px;
    color: var(--blue);
    margin-top: 4px;
  }}

  /* ── Expanded evidence ── */
  .event-detail {{
    display: none;
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid var(--border);
    animation: slideDown .3s ease;
  }}
  .event-detail.open {{ display: block; }}

  @keyframes slideDown {{
    from {{ opacity:0; transform: translateY(-8px); }}
    to   {{ opacity:1; transform: translateY(0); }}
  }}

  .detail-row {{
    display: flex;
    gap: 10px;
    margin-bottom: 8px;
    font-size: 12px;
  }}
  .detail-label {{
    color: var(--muted);
    min-width: 90px;
    flex-shrink: 0;
  }}
  .detail-value {{
    color: var(--text);
    word-break: break-all;
  }}
  .court-note {{
    background: #A32D2D18;
    border: 1px solid #A32D2D44;
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 12px;
    color: #F09595;
    margin-top: 8px;
    line-height: 1.5;
  }}
  .attacker-action {{
    background: #EF9F2718;
    border: 1px solid #EF9F2744;
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 12px;
    font-family: monospace;
    color: #FAC775;
    margin-top: 6px;
  }}

  .sev-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
  }}
  .sev-critical {{ background: #E24B4A22; color: #E24B4A; border: 1px solid #E24B4A44; }}
  .sev-high     {{ background: #EF9F2722; color: #EF9F27; border: 1px solid #EF9F2744; }}
  .sev-medium   {{ background: #37ADD422; color: #85B7EB; border: 1px solid #378ADD44; }}

  .expand-hint {{
    font-size: 11px;
    color: var(--muted);
    margin-top: 6px;
    display: flex;
    align-items: center;
    gap: 4px;
  }}
  .expand-hint .arrow {{
    transition: transform .3s;
    display: inline-block;
  }}
  .event-card.expanded .expand-hint .arrow {{ transform: rotate(180deg); }}

  /* ── Footer ── */
  .footer {{
    border-top: 1px solid var(--border);
    padding: 16px 32px;
    display: flex;
    justify-content: space-between;
    color: var(--muted);
    font-size: 12px;
  }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="logo">FORENSIGHT <span>· LARE Attack Reconstruction</span></div>
    <div style="color:var(--muted);font-size:12px;margin-top:4px;">
      Live Attack Reconstruction Engine — Integrated Timeline · MITRE ATT&CK · Persona
    </div>
  </div>
  <div class="scan-meta">
    <div>Target: <strong style="color:var(--text)">{target}</strong></div>
    <div>Scan time: {scan_time}</div>
    <div>ForenSight v1.0.0 · Team Cyber Nuggets</div>
  </div>
</div>

<div class="metrics">
  <div class="metric">
    <div class="metric-val" style="color:var(--red)">{len(events)}</div>
    <div class="metric-label">Attack Events</div>
  </div>
  <div class="metric">
    <div class="metric-val" style="color:var(--red)">{critical_count}</div>
    <div class="metric-label">Critical Events</div>
  </div>
  <div class="metric">
    <div class="metric-val" style="color:var(--amber)">{len(phases_hit)}</div>
    <div class="metric-label">ATT&CK Phases</div>
  </div>
  <div class="metric">
    <div class="metric-val" style="color:var(--red)">{paradox_count}</div>
    <div class="metric-label">Paradoxes</div>
  </div>
  <div class="metric">
    <div class="metric-val" style="color:var(--red)">{tool_count}</div>
    <div class="metric-label">Active Tools</div>
  </div>
  <div class="metric">
    <div class="metric-val" style="color:var(--amber)">{ghost_count}</div>
    <div class="metric-label">Ghost Traces</div>
  </div>
</div>

<div class="persona-card">
  <div class="persona-badge">{persona}</div>
  <div class="persona-desc">{persona_desc}</div>
  <div class="persona-conf">
    <div class="persona-conf-val">{persona_conf:.0%}</div>
    <div class="persona-conf-label">Confidence</div>
  </div>
</div>

<div class="chain-strip" id="chainStrip">
  {''.join(
    f'<span class="chain-phase{" hit" if p in phases_hit else ""}" '
    f'style="background:{PHASE_COLORS.get(p,"#888")}22;color:{PHASE_COLORS.get(p,"#888")}">{p}</span>'
    + ('<span class="chain-arrow">→</span>' if i < len(PHASE_ORDER)-1 else '')
    for i, p in enumerate(PHASE_ORDER)
  )}
</div>

<div class="section-title">Attack timeline — click any event to reveal evidence</div>

<div class="timeline" id="timeline">
</div>

<div class="footer">
  <div>ForenSight · LARE Report · {scan_time}</div>
  <div>{len(events)} events reconstructed across {len(phases_hit)} ATT&CK phases</div>
</div>

<script>
const events = {events_json};

function severityClass(s) {{
  if (s === 'critical') return 'sev-critical';
  if (s === 'high')     return 'sev-high';
  return 'sev-medium';
}}

function buildDetail(ev) {{
  let html = '';
  if (ev.technique) {{
    html += `<div class="detail-row">
      <span class="detail-label">Technique</span>
      <span class="detail-value" style="color:var(--blue)">${{ev.technique}} — ${{ev.tactic || ''}}</span>
    </div>`;
  }}
  if (ev.evidence) {{
    html += `<div class="detail-row">
      <span class="detail-label">Evidence</span>
      <span class="detail-value">${{ev.evidence}}</span>
    </div>`;
  }}
  if (ev.file) {{
    html += `<div class="detail-row">
      <span class="detail-label">File</span>
      <span class="detail-value" style="font-family:monospace">${{ev.file}}</span>
    </div>`;
  }}
  if (ev.delta) {{
    html += `<div class="detail-row">
      <span class="detail-label">Time delta</span>
      <span class="detail-value" style="color:var(--amber)">${{ev.delta.toFixed ? ev.delta.toFixed(2) : ev.delta}}s</span>
    </div>`;
  }}
  if (ev.state) {{
    html += `<div class="detail-row">
      <span class="detail-label">State</span>
      <span class="detail-value">${{ev.state === 'installed' ? '⚠ Active on system' : '👻 Deleted — ghost trace recovered'}}</span>
    </div>`;
  }}
  if (ev.evidence && ev.type === 'paradox') {{
    html += `<div class="court-note">Court note: ${{ev.evidence}}</div>`;
  }}
  if (ev.attacker) {{
    html += `<div class="attacker-action">Attacker action: ${{ev.attacker}}</div>`;
  }}
  return html;
}}

function renderEvents() {{
  const container = document.getElementById('timeline');
  events.forEach((ev, i) => {{
    const color   = ev.color || '#888780';
    const sevCls  = severityClass(ev.severity || 'medium');
    const detail  = buildDetail(ev);
    const row     = document.createElement('div');
    row.className = 'event-row';
    row.style.setProperty('--color', color);
    row.innerHTML = `
      <div class="event-index" style="background:${{color}}22;color:${{color}};border-color:${{color}}44">
        ${{i + 1}}
      </div>
      <div class="event-card" id="card-${{i}}" style="--color:${{color}}">
        <div class="event-header">
          <span class="event-phase-pill" style="--color:${{color}}">${{ev.phase}}</span>
          <span class="event-type-badge">${{ev.type}}</span>
          <span class="sev-badge ${{sevCls}}">${{ev.severity || 'medium'}}</span>
        </div>
        <div class="event-title">${{ev.title}}</div>
        ${{ev.description ? `<div class="event-desc">${{ev.description}}</div>` : ''}}
        ${{ev.technique ? `<div class="event-technique">${{ev.technique}} · ${{ev.tactic || ''}}</div>` : ''}}
        ${{detail ? `
          <div class="event-detail" id="detail-${{i}}">${{detail}}</div>
          <div class="expand-hint">
            <span>Click to ${{ev.type === 'paradox' ? 'see court evidence' : 'show details'}}</span>
            <span class="arrow">▼</span>
          </div>
        ` : ''}}
      </div>`;

    row.addEventListener('click', () => toggleDetail(i));
    container.appendChild(row);
  }});
}}

function toggleDetail(i) {{
  const card   = document.getElementById('card-' + i);
  const detail = document.getElementById('detail-' + i);
  if (!detail) return;
  const isOpen = detail.classList.contains('open');
  detail.classList.toggle('open', !isOpen);
  card.classList.toggle('expanded', !isOpen);
}}

function animateTimeline() {{
  const rows = document.querySelectorAll('.event-row');
  rows.forEach((row, i) => {{
    setTimeout(() => row.classList.add('visible'), i * 120);
  }});
}}

renderEvents();
setTimeout(animateTimeline, 100);
</script>
</body>
</html>"""

    output_path = "lare_report.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return os.path.abspath(output_path)