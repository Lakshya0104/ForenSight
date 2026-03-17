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
    events_json    = json.dumps(events,     indent=2, default=str)
    paradoxes_json = json.dumps(paradoxes,  indent=2, default=str)
    tools_json     = json.dumps(tools,      indent=2, default=str)
    phase_colors_json = json.dumps(PHASE_COLORS)
    personas_json  = json.dumps({k: v["color"] for k, v in PERSONAS.items()})

    # Build MITRE phase summary
    mitre_by_phase = defaultdict(list)
    for e in events:
        if e.get("type") == "attack" and e.get("phase"):
            mitre_by_phase[e["phase"]].append(e)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ForenSight — LARE</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root {{
  --bg0:      #050608;
  --bg1:      #0a0d12;
  --bg2:      #0f1318;
  --bg3:      #161b24;
  --bg4:      #1d2430;
  --border:   #1e2d3d;
  --border2:  #2a3f55;
  --text:     #c8d8e8;
  --muted:    #4a6278;
  --dim:      #2a3a4a;
  --green:    #00ff88;
  --green2:   #00cc6a;
  --red:      #ff3344;
  --red2:     #cc1122;
  --amber:    #ffaa00;
  --amber2:   #cc8800;
  --blue:     #0088ff;
  --blue2:    #0066cc;
  --cyan:     #00ddff;
  --purple:   #aa44ff;
  --critical: #ff3344;
  --high:     #ff8800;
  --medium:   #ffdd00;
  --low:      #00cc88;
  --scanline: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,255,136,0.015) 2px,
    rgba(0,255,136,0.015) 4px
  );
}}

*, *::before, *::after {{ margin:0; padding:0; box-sizing:border-box; }}

html {{ scroll-behavior: smooth; }}

body {{
  background: var(--bg0);
  color: var(--text);
  font-family: 'Rajdhani', sans-serif;
  font-size: 15px;
  line-height: 1.5;
  overflow-x: hidden;
  cursor: none;
}}

/* ── Custom cursor ── */
#cursor-dot {{
  position: fixed;
  width: 8px; height: 8px;
  background: var(--green);
  border-radius: 50%;
  pointer-events: none;
  z-index: 99999;
  transform: translate(-50%,-50%);
  transition: width .1s, height .1s, background .1s;
  box-shadow: 0 0 10px var(--green), 0 0 20px var(--green);
}}
#cursor-ring {{
  position: fixed;
  width: 32px; height: 32px;
  border: 1px solid var(--green);
  border-radius: 50%;
  pointer-events: none;
  z-index: 99998;
  transform: translate(-50%,-50%);
  transition: transform .08s ease, width .2s, height .2s, opacity .2s;
  opacity: 0.5;
}}
.cursor-trail {{
  position: fixed;
  border-radius: 50%;
  pointer-events: none;
  z-index: 99990;
  transform: translate(-50%,-50%);
  background: var(--green);
  transition: opacity .4s;
}}
body:hover #cursor-dot {{ opacity: 1; }}

/* ── Scanlines overlay ── */
body::before {{
  content: '';
  position: fixed;
  inset: 0;
  background: var(--scanline);
  pointer-events: none;
  z-index: 9999;
  opacity: 0.4;
}}

/* ── Grid background ── */
body::after {{
  content: '';
  position: fixed;
  inset: 0;
  background-image:
    linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
  pointer-events: none;
  z-index: 0;
}}

/* ── Layout ── */
.wrapper {{ position: relative; z-index: 1; }}

/* ── HERO ── */
.hero {{
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  position: relative;
  padding: 40px;
  overflow: hidden;
}}
.hero-glow {{
  position: absolute;
  width: 600px; height: 600px;
  background: radial-gradient(circle, rgba(0,255,136,0.06) 0%, transparent 70%);
  top: 50%; left: 50%;
  transform: translate(-50%,-50%);
  pointer-events: none;
  animation: pulseGlow 4s ease-in-out infinite;
}}
@keyframes pulseGlow {{
  0%,100% {{ opacity: 0.6; transform: translate(-50%,-50%) scale(1); }}
  50%      {{ opacity: 1;   transform: translate(-50%,-50%) scale(1.1); }}
}}
.hero-eyebrow {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  letter-spacing: .3em;
  color: var(--green);
  text-transform: uppercase;
  margin-bottom: 20px;
  opacity: 0;
  animation: fadeUp .6s .2s forwards;
}}
.hero-title {{
  font-family: 'Orbitron', sans-serif;
  font-size: clamp(52px, 8vw, 96px);
  font-weight: 900;
  letter-spacing: .1em;
  line-height: 1;
  color: #fff;
  text-shadow:
    0 0 40px rgba(0,255,136,0.4),
    0 0 80px rgba(0,255,136,0.15);
  opacity: 0;
  animation: fadeUp .6s .4s forwards;
}}
.hero-title span {{ color: var(--green); }}
.hero-sub {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 13px;
  color: var(--muted);
  letter-spacing: .15em;
  margin-top: 16px;
  opacity: 0;
  animation: fadeUp .6s .6s forwards;
}}
.hero-meta {{
  display: flex;
  gap: 32px;
  margin-top: 40px;
  opacity: 0;
  animation: fadeUp .6s .8s forwards;
  flex-wrap: wrap;
  justify-content: center;
}}
.hero-meta-item {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--muted);
}}
.hero-meta-item strong {{
  color: var(--text);
  display: block;
  font-size: 13px;
}}
.hero-scroll {{
  position: absolute;
  bottom: 32px;
  left: 50%;
  transform: translateX(-50%);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  opacity: 0;
  animation: fadeUp .6s 1.2s forwards;
  cursor: pointer;
}}
.hero-scroll-label {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: .2em;
  color: var(--muted);
}}
.hero-scroll-line {{
  width: 1px; height: 40px;
  background: linear-gradient(to bottom, var(--green), transparent);
  animation: scrollPulse 2s ease-in-out infinite;
}}
@keyframes scrollPulse {{
  0%,100% {{ opacity: 0.3; }}
  50%      {{ opacity: 1; }}
}}

/* ── Section ── */
.section {{
  padding: 80px 48px;
  max-width: 1400px;
  margin: 0 auto;
}}
.section-header {{
  display: flex;
  align-items: flex-end;
  gap: 20px;
  margin-bottom: 48px;
}}
.section-number {{
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  font-weight: 700;
  color: var(--green);
  letter-spacing: .2em;
  padding-bottom: 4px;
}}
.section-title {{
  font-family: 'Orbitron', sans-serif;
  font-size: 24px;
  font-weight: 700;
  color: #fff;
  letter-spacing: .08em;
}}
.section-desc {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  color: var(--muted);
  margin-top: 6px;
  letter-spacing: .05em;
  line-height: 1.6;
  max-width: 600px;
}}
.section-line {{
  flex: 1;
  height: 1px;
  background: linear-gradient(to right, var(--border2), transparent);
}}

/* ── Metrics grid ── */
.metrics-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 16px;
  margin-bottom: 60px;
}}
.metric-card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-top: 2px solid var(--accent, var(--green));
  border-radius: 4px;
  padding: 20px;
  position: relative;
  overflow: hidden;
  transition: border-color .2s, transform .2s;
}}
.metric-card::before {{
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, var(--accent, var(--green))08 0%, transparent 60%);
  pointer-events: none;
}}
.metric-card:hover {{
  transform: translateY(-2px);
  border-color: var(--accent, var(--green));
}}
.metric-val {{
  font-family: 'Orbitron', sans-serif;
  font-size: 36px;
  font-weight: 700;
  color: var(--accent, var(--green));
  line-height: 1;
  margin-bottom: 8px;
}}
.metric-label {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: .2em;
  color: var(--muted);
  text-transform: uppercase;
}}
.metric-sub {{
  font-size: 11px;
  color: var(--dim);
  margin-top: 4px;
  font-family: 'Share Tech Mono', monospace;
}}

/* ── Persona section ── */
.persona-block {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-left: 3px solid var(--p-color, var(--green));
  border-radius: 4px;
  padding: 32px 36px;
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 32px;
  align-items: center;
  margin-bottom: 20px;
}}
.persona-badge {{
  font-family: 'Orbitron', sans-serif;
  font-size: 14px;
  font-weight: 700;
  color: var(--p-color, var(--green));
  border: 1px solid var(--p-color, var(--green));
  padding: 8px 20px;
  border-radius: 2px;
  white-space: nowrap;
  text-transform: uppercase;
  letter-spacing: .1em;
}}
.persona-info-title {{
  font-size: 13px;
  color: var(--muted);
  font-family: 'Share Tech Mono', monospace;
  text-transform: uppercase;
  letter-spacing: .1em;
  margin-bottom: 8px;
}}
.persona-info-desc {{
  font-size: 15px;
  color: var(--text);
  line-height: 1.6;
}}
.persona-conf-block {{ text-align: right; }}
.persona-conf-val {{
  font-family: 'Orbitron', sans-serif;
  font-size: 42px;
  font-weight: 900;
  color: var(--p-color, var(--green));
  line-height: 1;
}}
.persona-conf-label {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: .2em;
  color: var(--muted);
  text-transform: uppercase;
  margin-top: 4px;
}}

/* ── Kill chain strip ── */
.killchain {{
  display: flex;
  align-items: center;
  gap: 0;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 16px 24px;
  overflow-x: auto;
  flex-wrap: nowrap;
  margin-bottom: 20px;
}}
.kc-phase {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  letter-spacing: .08em;
  padding: 6px 14px;
  border-radius: 2px;
  white-space: nowrap;
  opacity: 0.2;
  transition: opacity .3s, transform .2s;
  text-transform: uppercase;
}}
.kc-phase.hit {{
  opacity: 1;
  font-weight: 700;
}}
.kc-phase.hit:hover {{ transform: scale(1.05); cursor: default; }}
.kc-arrow {{ color: var(--dim); margin: 0 4px; font-size: 12px; flex-shrink: 0; }}

/* ── MITRE cards ── */
.mitre-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 16px;
  margin-bottom: 32px;
}}
.mitre-card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-top: 2px solid var(--phase-color, var(--blue));
  border-radius: 4px;
  padding: 20px;
  transition: transform .2s, border-color .2s;
}}
.mitre-card:hover {{
  transform: translateY(-2px);
  border-color: var(--phase-color, var(--blue));
}}
.mitre-phase-label {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: .15em;
  text-transform: uppercase;
  color: var(--phase-color, var(--blue));
  margin-bottom: 10px;
}}
.mitre-technique {{
  font-family: 'Orbitron', sans-serif;
  font-size: 12px;
  color: var(--cyan);
  margin-bottom: 8px;
}}
.mitre-command {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  color: var(--text);
  background: var(--bg3);
  padding: 8px 12px;
  border-radius: 3px;
  word-break: break-all;
  line-height: 1.5;
  border-left: 2px solid var(--phase-color, var(--blue));
}}

/* ── Timeline ── */
.timeline-container {{
  position: relative;
  padding-left: 60px;
}}
.timeline-spine {{
  position: absolute;
  left: 20px;
  top: 0; bottom: 0;
  width: 2px;
  background: linear-gradient(to bottom, var(--green), var(--border), transparent);
}}

.t-event {{
  position: relative;
  margin-bottom: 16px;
  opacity: 0;
  transform: translateX(-16px);
  transition: opacity .5s, transform .5s;
}}
.t-event.visible {{
  opacity: 1;
  transform: translateX(0);
}}
.t-dot {{
  position: absolute;
  left: -48px;
  top: 18px;
  width: 14px; height: 14px;
  border-radius: 50%;
  border: 2px solid var(--ev-color, var(--green));
  background: var(--bg0);
  z-index: 2;
  transition: transform .2s;
}}
.t-event:hover .t-dot {{
  transform: scale(1.4);
  background: var(--ev-color, var(--green));
  box-shadow: 0 0 12px var(--ev-color, var(--green));
}}
.t-connector {{
  position: absolute;
  left: -34px;
  top: 24px;
  width: 22px;
  height: 1px;
  background: var(--ev-color, var(--green));
  opacity: 0.4;
}}

.t-card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-left: 3px solid var(--ev-color, var(--green));
  border-radius: 4px;
  padding: 16px 20px;
  cursor: pointer;
  transition: border-color .2s, background .2s, transform .2s;
  position: relative;
  overflow: hidden;
}}
.t-card::before {{
  content: '';
  position: absolute;
  left: 0; top: 0; bottom: 0;
  width: 0;
  background: var(--ev-color, var(--green));
  opacity: 0.04;
  transition: width .3s;
}}
.t-card:hover::before, .t-card.open::before {{ width: 100%; }}
.t-card:hover, .t-card.open {{
  border-color: var(--ev-color, var(--green));
  background: var(--bg3);
}}

.t-card-header {{
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}}
.t-phase-pill {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 9px;
  letter-spacing: .12em;
  text-transform: uppercase;
  padding: 3px 10px;
  border-radius: 2px;
  background: var(--ev-color, var(--green))18;
  color: var(--ev-color, var(--green));
  border: 1px solid var(--ev-color, var(--green))33;
}}
.t-type-badge {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 9px;
  letter-spacing: .1em;
  text-transform: uppercase;
  padding: 3px 8px;
  border-radius: 2px;
  background: var(--bg4);
  color: var(--muted);
  border: 1px solid var(--border);
}}
.t-sev {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 9px;
  font-weight: 700;
  letter-spacing: .12em;
  text-transform: uppercase;
  padding: 3px 8px;
  border-radius: 2px;
  margin-left: auto;
}}
.sev-critical {{ background: var(--critical)18; color: var(--critical); border: 1px solid var(--critical)44; }}
.sev-high     {{ background: var(--high)18;     color: var(--high);     border: 1px solid var(--high)44; }}
.sev-medium   {{ background: var(--medium)18;   color: var(--medium);   border: 1px solid var(--medium)44; }}
.sev-low      {{ background: var(--low)18;      color: var(--low);      border: 1px solid var(--low)44; }}

.t-title {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 16px;
  font-weight: 600;
  color: #fff;
  margin-bottom: 4px;
}}
.t-desc {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  color: var(--muted);
  background: var(--bg3);
  padding: 6px 10px;
  border-radius: 3px;
  word-break: break-all;
  line-height: 1.6;
}}
.t-technique {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--cyan);
  margin-top: 6px;
  opacity: 0.8;
}}

/* ── Expanded evidence ── */
.t-evidence {{
  display: none;
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  animation: slideDown .25s ease;
}}
.t-evidence.open {{ display: block; }}
@keyframes slideDown {{
  from {{ opacity:0; transform: translateY(-8px); }}
  to   {{ opacity:1; transform: translateY(0); }}
}}

.ev-grid {{
  display: grid;
  grid-template-columns: 120px 1fr;
  gap: 8px 16px;
  margin-bottom: 12px;
}}
.ev-label {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .08em;
  padding-top: 2px;
}}
.ev-value {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  color: var(--text);
  word-break: break-all;
  line-height: 1.6;
}}
.court-note {{
  background: var(--critical)0d;
  border: 1px solid var(--critical)33;
  border-radius: 3px;
  padding: 12px 14px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: #ff9999;
  line-height: 1.6;
  margin-top: 10px;
}}
.court-note::before {{
  content: 'COURT NOTE  ';
  color: var(--critical);
  font-weight: 700;
  letter-spacing: .1em;
}}
.attacker-cmd {{
  background: var(--amber)0d;
  border: 1px solid var(--amber)33;
  border-radius: 3px;
  padding: 10px 14px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  color: var(--amber);
  margin-top: 8px;
  word-break: break-all;
}}
.attacker-cmd::before {{
  content: '$ ';
  opacity: 0.5;
}}

.expand-hint {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--dim);
  margin-top: 8px;
  letter-spacing: .08em;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: color .2s;
}}
.t-card:hover .expand-hint {{ color: var(--muted); }}
.expand-arrow {{
  display: inline-block;
  transition: transform .3s;
  font-size: 8px;
}}
.t-card.open .expand-arrow {{ transform: rotate(180deg); }}

/* ── Paradox section ── */
.paradox-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
  gap: 16px;
}}
.paradox-card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 20px;
  position: relative;
  overflow: hidden;
  transition: transform .2s;
}}
.paradox-card::after {{
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: var(--sev-color, var(--critical));
}}
.paradox-card:hover {{ transform: translateY(-2px); }}
.paradox-sev {{
  font-family: 'Orbitron', sans-serif;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .15em;
  text-transform: uppercase;
  color: var(--sev-color, var(--critical));
  margin-bottom: 10px;
  display: flex;
  align-items: center;
  gap: 8px;
}}
.paradox-sev::before {{
  content: '';
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--sev-color, var(--critical));
  box-shadow: 0 0 8px var(--sev-color, var(--critical));
  animation: blink 1.5s ease-in-out infinite;
}}
@keyframes blink {{
  0%,100% {{ opacity:1; }} 50% {{ opacity:0.3; }}
}}
.paradox-type {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 15px;
  font-weight: 600;
  color: #fff;
  margin-bottom: 8px;
  text-transform: capitalize;
}}
.paradox-file {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--cyan);
  background: var(--bg3);
  padding: 4px 8px;
  border-radius: 2px;
  word-break: break-all;
  margin-bottom: 10px;
}}
.paradox-delta {{
  font-family: 'Orbitron', sans-serif;
  font-size: 20px;
  font-weight: 700;
  color: var(--sev-color, var(--critical));
  margin-bottom: 10px;
}}
.paradox-court {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: #aa6666;
  line-height: 1.6;
  border-top: 1px solid var(--border);
  padding-top: 10px;
  margin-top: 10px;
}}

/* ── Tools table ── */
.tools-table {{
  width: 100%;
  border-collapse: collapse;
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
}}
.tools-table th {{
  text-align: left;
  padding: 10px 16px;
  border-bottom: 1px solid var(--border2);
  color: var(--muted);
  font-size: 10px;
  letter-spacing: .15em;
  text-transform: uppercase;
  background: var(--bg3);
}}
.tools-table td {{
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
  color: var(--text);
}}
.tools-table tr:hover td {{ background: var(--bg3); }}
.tool-name {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 15px;
  font-weight: 600;
  color: #fff;
}}
.tool-state-active {{
  color: var(--critical);
  font-size: 10px;
  letter-spacing: .1em;
  border: 1px solid var(--critical)44;
  padding: 2px 8px;
  border-radius: 2px;
  background: var(--critical)0d;
}}
.tool-state-ghost {{
  color: var(--amber);
  font-size: 10px;
  letter-spacing: .1em;
  border: 1px solid var(--amber)44;
  padding: 2px 8px;
  border-radius: 2px;
  background: var(--amber)0d;
}}
.risk-critical {{ color: var(--critical); font-weight: 700; }}
.risk-high     {{ color: var(--high); font-weight: 700; }}
.risk-medium   {{ color: var(--medium); }}
.risk-low      {{ color: var(--low); }}

/* ── Divider ── */
.section-divider {{
  width: 100%;
  height: 1px;
  background: linear-gradient(to right, transparent, var(--border2), transparent);
  margin: 0;
}}

/* ── Verdict ── */
.verdict-block {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 48px;
  text-align: center;
  position: relative;
  overflow: hidden;
}}
.verdict-block::before {{
  content: '';
  position: absolute;
  inset: 0;
  background: radial-gradient(ellipse at 50% 0%, var(--v-color, var(--red))0a 0%, transparent 60%);
  pointer-events: none;
}}
.verdict-risk {{
  font-family: 'Orbitron', sans-serif;
  font-size: clamp(28px, 4vw, 48px);
  font-weight: 900;
  color: var(--v-color, var(--red));
  text-shadow: 0 0 30px var(--v-color, var(--red))66;
  letter-spacing: .08em;
  margin-bottom: 16px;
  animation: glitch 8s infinite;
}}
@keyframes glitch {{
  0%,95%,100% {{ text-shadow: 0 0 30px var(--v-color, var(--red))66; }}
  96%  {{ text-shadow: -2px 0 var(--cyan), 2px 0 var(--critical), 0 0 30px var(--v-color, var(--red))66; }}
  97%  {{ text-shadow: 2px 0 var(--cyan), -2px 0 var(--critical), 0 0 30px var(--v-color, var(--red))66; }}
  98%  {{ text-shadow: 0 0 30px var(--v-color, var(--red))66; }}
}}
.verdict-detail {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 13px;
  color: var(--muted);
  max-width: 600px;
  margin: 0 auto 32px;
  line-height: 1.7;
}}
.verdict-stats {{
  display: flex;
  justify-content: center;
  gap: 40px;
  flex-wrap: wrap;
}}
.vstat {{
  text-align: center;
}}
.vstat-val {{
  font-family: 'Orbitron', sans-serif;
  font-size: 28px;
  font-weight: 700;
  color: var(--text);
  line-height: 1;
}}
.vstat-label {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .15em;
  margin-top: 4px;
}}

/* ── Footer ── */
.footer {{
  border-top: 1px solid var(--border);
  padding: 20px 48px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--muted);
  letter-spacing: .05em;
}}
.footer-logo {{
  font-family: 'Orbitron', sans-serif;
  font-size: 13px;
  font-weight: 700;
  color: var(--green);
  letter-spacing: .15em;
}}

/* ── Animations ── */
@keyframes fadeUp {{
  from {{ opacity:0; transform: translateY(16px); }}
  to   {{ opacity:1; transform: translateY(0); }}
}}
.reveal {{
  opacity: 0;
  transform: translateY(20px);
  transition: opacity .6s, transform .6s;
}}
.reveal.visible {{
  opacity: 1;
  transform: translateY(0);
}}

/* ── Scrollbar ── */
::-webkit-scrollbar {{ width: 4px; height: 4px; }}
::-webkit-scrollbar-track {{ background: var(--bg0); }}
::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius: 2px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--green); }}
</style>
</head>
<body>

<div id="cursor-dot"></div>
<div id="cursor-ring"></div>

<div class="wrapper">

<!-- ══ HERO ══════════════════════════════════════════════════ -->
<section class="hero">
  <div class="hero-glow"></div>
  <div class="hero-eyebrow">// LIVE ATTACK RECONSTRUCTION ENGINE</div>
  <div class="hero-title">Foren<span>Sight</span></div>
  <div class="hero-sub">LARE &nbsp;·&nbsp; MITRE ATT&CK &nbsp;·&nbsp; TEMPORAL PARADOX &nbsp;·&nbsp; ATTACKER PERSONA</div>
  <div class="hero-meta">
    <div class="hero-meta-item"><strong>{target}</strong>TARGET</div>
    <div class="hero-meta-item"><strong>{scan_time}</strong>SCAN TIME</div>
    <div class="hero-meta-item"><strong>v1.0.0</strong>VERSION</div>
    <div class="hero-meta-item"><strong>TEAM CYBER NUGGETS</strong>TEAM</div>
  </div>
  <div class="hero-scroll" onclick="document.getElementById('metrics').scrollIntoView({{behavior:'smooth'}})">
    <div class="hero-scroll-label">SCROLL TO REPORT</div>
    <div class="hero-scroll-line"></div>
  </div>
</section>

<!-- ══ METRICS ════════════════════════════════════════════════ -->
<div class="section-divider"></div>
<section class="section" id="metrics">
  <div class="section-header reveal">
    <div>
      <div class="section-number">01 &nbsp;/&nbsp; OVERVIEW</div>
      <div class="section-title">Threat Intelligence Summary</div>
      <div class="section-desc">High-level indicators extracted from the forensic scan. All metrics are derived from filesystem artifacts, bash history, package databases, and UEFI firmware.</div>
    </div>
    <div class="section-line"></div>
  </div>
  <div class="metrics-grid reveal">
    <div class="metric-card" style="--accent:var(--{'red' if critical_count > 0 else 'green'})">
      <div class="metric-val">{len(events)}</div>
      <div class="metric-label">Attack Events</div>
      <div class="metric-sub">Reconstructed from artifacts</div>
    </div>
    <div class="metric-card" style="--accent:var(--{'critical' if critical_count > 0 else 'green'})">
      <div class="metric-val">{critical_count}</div>
      <div class="metric-label">Critical Events</div>
      <div class="metric-sub">Immediate escalation required</div>
    </div>
    <div class="metric-card" style="--accent:var(--{'amber' if len(phases_hit) > 0 else 'green'})">
      <div class="metric-val">{len(phases_hit)}</div>
      <div class="metric-label">ATT&CK Phases</div>
      <div class="metric-sub">Kill chain coverage</div>
    </div>
    <div class="metric-card" style="--accent:var(--{'critical' if paradox_count > 0 else 'green'})">
      <div class="metric-val">{paradox_count}</div>
      <div class="metric-label">Paradoxes</div>
      <div class="metric-sub">Timestamp impossibilities</div>
    </div>
    <div class="metric-card" style="--accent:var(--{'red' if tool_count > 0 else 'green'})">
      <div class="metric-val">{tool_count}</div>
      <div class="metric-label">Active Tools</div>
      <div class="metric-sub">Confirmed on filesystem</div>
    </div>
    <div class="metric-card" style="--accent:var(--{'amber' if ghost_count > 0 else 'green'})">
      <div class="metric-val">{ghost_count}</div>
      <div class="metric-label">Ghost Traces</div>
      <div class="metric-sub">Deleted — residue recovered</div>
    </div>
  </div>
</section>

<!-- ══ PERSONA ════════════════════════════════════════════════ -->
<div class="section-divider"></div>
<section class="section" id="persona">
  <div class="section-header reveal">
    <div>
      <div class="section-number">02 &nbsp;/&nbsp; ATTACKER PERSONA</div>
      <div class="section-title">Threat Actor Classification</div>
      <div class="section-desc">Attacker archetype inferred from tool combination patterns, command sequences, and anti-forensic behavior. Classification uses weighted scoring across 7 persona archetypes mapped to real-world threat actor profiles.</div>
    </div>
    <div class="section-line"></div>
  </div>
  <div class="persona-block reveal" style="--p-color:{persona_color}">
    <div class="persona-badge">{persona}</div>
    <div>
      <div class="persona-info-title">Behavioral Profile</div>
      <div class="persona-info-desc">{persona_desc or 'Insufficient tool data to classify attacker archetype. More forensic artifacts required for confident classification.'}</div>
    </div>
    <div class="persona-conf-block">
      <div class="persona-conf-val">{persona_conf:.0%}</div>
      <div class="persona-conf-label">Confidence</div>
    </div>
  </div>
</section>

<!-- ══ MITRE ATT&CK ═══════════════════════════════════════════ -->
<div class="section-divider"></div>
<section class="section" id="mitre">
  <div class="section-header reveal">
    <div>
      <div class="section-number">03 &nbsp;/&nbsp; MITRE ATT&CK</div>
      <div class="section-title">Kill Chain Mapping</div>
      <div class="section-desc">Commands recovered from bash history and filesystem artifacts mapped to the MITRE ATT&CK framework. Each technique represents a confirmed tactic in the attacker's operational sequence. Phases highlighted in the chain below are those where evidence was found.</div>
    </div>
    <div class="section-line"></div>
  </div>

  <div class="killchain reveal" id="killchain">
    {''.join(
      f'<span class="kc-phase{" hit" if p in phases_hit else ""}" '
      f'style="color:{PHASE_COLORS.get(p,"#888")};background:{PHASE_COLORS.get(p,"#888")}18">{p}</span>'
      + (f'<span class="kc-arrow">→</span>' if i < len(PHASE_ORDER)-1 else '')
      for i, p in enumerate(PHASE_ORDER)
    )}
  </div>

  <div class="mitre-grid reveal" id="mitre-grid">
  </div>
</section>

<!-- ══ TIMELINE ═══════════════════════════════════════════════ -->
<div class="section-divider"></div>
<section class="section" id="timeline">
  <div class="section-header reveal">
    <div>
      <div class="section-number">04 &nbsp;/&nbsp; ATTACK TIMELINE</div>
      <div class="section-title">Reconstructed Event Sequence</div>
      <div class="section-desc">Chronological reconstruction of the attack, synthesized from MITRE ATT&CK mapping, temporal paradox detections, tool presence indicators, and filesystem timeline artifacts. Click any event card to reveal its forensic evidence and court notes.</div>
    </div>
    <div class="section-line"></div>
  </div>
  <div class="timeline-container">
    <div class="timeline-spine"></div>
    <div id="timeline-events"></div>
  </div>
</section>

<!-- ══ TEMPORAL PARADOXES ═════════════════════════════════════ -->
<div class="section-divider"></div>
<section class="section" id="paradoxes">
  <div class="section-header reveal">
    <div>
      <div class="section-number">05 &nbsp;/&nbsp; TEMPORAL PARADOX ENGINE</div>
      <div class="section-title">Timestamp Impossibilities</div>
      <div class="section-desc">Mathematically impossible filesystem timestamp combinations detected via inode analysis. Each violation represents a breach of POSIX invariants — specifically the rule that mtime must never exceed ctime on an unmanipulated file. These findings constitute court-admissible proof of deliberate evidence tampering.</div>
    </div>
    <div class="section-line"></div>
  </div>
  <div class="paradox-grid reveal" id="paradox-grid"></div>
</section>

<!-- ══ TOOLS ══════════════════════════════════════════════════ -->
<div class="section-divider"></div>
<section class="section" id="tools">
  <div class="section-header reveal">
    <div>
      <div class="section-number">06 &nbsp;/&nbsp; OFFENSIVE TOOL DETECTION</div>
      <div class="section-title">Installed &amp; Ghost Traces</div>
      <div class="section-desc">Offensive tools identified across three detection layers: active binary presence, DPKG package database records, and APT history logs. Ghost traces represent tools that were deleted — their installation records survive deletion and constitute forensic evidence of prior presence.</div>
    </div>
    <div class="section-line"></div>
  </div>
  <div class="reveal" style="background:var(--bg2);border:1px solid var(--border);border-radius:4px;overflow:hidden">
    <table class="tools-table" id="tools-table">
      <thead>
        <tr>
          <th>Tool</th>
          <th>Category</th>
          <th>Risk</th>
          <th>State</th>
          <th>Evidence</th>
        </tr>
      </thead>
      <tbody id="tools-body"></tbody>
    </table>
  </div>
</section>

<!-- ══ VERDICT ════════════════════════════════════════════════ -->
<div class="section-divider"></div>
<section class="section" id="verdict">
  <div class="section-header reveal">
    <div>
      <div class="section-number">07 &nbsp;/&nbsp; FINAL VERDICT</div>
      <div class="section-title">ForenSight Assessment</div>
      <div class="section-desc">Consolidated verdict based on all forensic indicators collected during this scan session.</div>
    </div>
    <div class="section-line"></div>
  </div>
  <div class="verdict-block reveal" id="verdict-block">
    <div class="verdict-risk" id="verdict-text">ANALYZING...</div>
    <div class="verdict-detail" id="verdict-detail"></div>
    <div class="verdict-stats">
      <div class="vstat"><div class="vstat-val" id="vs-events">{len(events)}</div><div class="vstat-label">Events</div></div>
      <div class="vstat"><div class="vstat-val" id="vs-phases">{len(phases_hit)}</div><div class="vstat-label">ATT&CK Phases</div></div>
      <div class="vstat"><div class="vstat-val" id="vs-paradoxes">{paradox_count}</div><div class="vstat-label">Paradoxes</div></div>
      <div class="vstat"><div class="vstat-val" id="vs-tools">{tool_count + ghost_count}</div><div class="vstat-label">Tools Found</div></div>
    </div>
  </div>
</section>

<div class="section-divider"></div>
<footer class="footer">
  <div class="footer-logo">FORENSIGHT</div>
  <div>LARE Report &nbsp;·&nbsp; {scan_time} &nbsp;·&nbsp; {len(events)} events across {len(phases_hit)} ATT&CK phases</div>
  <div>Team Cyber Nuggets &nbsp;·&nbsp; v1.0.0</div>
</footer>

</div>

<script>
const EVENTS    = {events_json};
const PARADOXES = {paradoxes_json};
const TOOLS     = {tools_json};
const PHASE_COLORS = {phase_colors_json};
const PERSONA_COLORS = {personas_json};

const SEV_CLASS = {{
  critical: 'sev-critical',
  high:     'sev-high',
  medium:   'sev-medium',
  low:      'sev-low',
}};

// ── Cursor trails ────────────────────────────────────────────
const dot  = document.getElementById('cursor-dot');
const ring = document.getElementById('cursor-ring');
const TRAIL_COUNT = 12;
const trails = [];
for (let i = 0; i < TRAIL_COUNT; i++) {{
  const el = document.createElement('div');
  el.className = 'cursor-trail';
  const size = Math.max(2, 8 - i * 0.5);
  el.style.cssText = `width:${{size}}px;height:${{size}}px;opacity:${{(1 - i / TRAIL_COUNT) * 0.5}}`;
  document.body.appendChild(el);
  trails.push({{ el, x: 0, y: 0 }});
}}

let mx = 0, my = 0;
document.addEventListener('mousemove', e => {{
  mx = e.clientX; my = e.clientY;
  dot.style.left  = mx + 'px';
  dot.style.top   = my + 'px';
  ring.style.left = mx + 'px';
  ring.style.top  = my + 'px';
}});

function animateTrails() {{
  let px = mx, py = my;
  trails.forEach((t, i) => {{
    t.x += (px - t.x) * (0.25 - i * 0.015);
    t.y += (py - t.y) * (0.25 - i * 0.015);
    t.el.style.left = t.x + 'px';
    t.el.style.top  = t.y + 'px';
    px = t.x; py = t.y;
  }});
  requestAnimationFrame(animateTrails);
}}
animateTrails();

document.addEventListener('mouseenter', () => {{ dot.style.opacity='1'; ring.style.opacity='0.5'; }});
document.addEventListener('mouseleave', () => {{ dot.style.opacity='0'; ring.style.opacity='0'; }});

// ── Scroll reveal ────────────────────────────────────────────
const observer = new IntersectionObserver(entries => {{
  entries.forEach(e => {{
    if (e.isIntersecting) {{
      e.target.classList.add('visible');
      observer.unobserve(e.target);
    }}
  }});
}}, {{ threshold: 0.1 }});
document.querySelectorAll('.reveal').forEach(el => observer.observe(el));

// ── Build MITRE grid ─────────────────────────────────────────
function buildMitre() {{
  const grid = document.getElementById('mitre-grid');
  const attackEvents = EVENTS.filter(e => e.type === 'attack');
  if (!attackEvents.length) {{
    grid.innerHTML = '<div style="color:var(--muted);font-family:monospace;font-size:13px;padding:20px">No MITRE techniques mapped — bash history empty or not accessible.</div>';
    return;
  }}
  attackEvents.forEach(ev => {{
    const color = PHASE_COLORS[ev.phase] || '#378ADD';
    const card  = document.createElement('div');
    card.className = 'mitre-card';
    card.style.setProperty('--phase-color', color);
    card.innerHTML = `
      <div class="mitre-phase-label">${{ev.phase}}</div>
      <div class="mitre-technique">${{ev.technique}} &nbsp;·&nbsp; ${{ev.tactic || ''}}</div>
      <div class="mitre-command">${{ev.description || '—'}}</div>`;
    grid.appendChild(card);
  }});
}}

// ── Build timeline ───────────────────────────────────────────
function sevClass(s) {{ return SEV_CLASS[s] || 'sev-medium'; }}

function buildDetail(ev) {{
  let html = '<div class="ev-grid">';
  if (ev.technique) html += `<span class="ev-label">Technique</span><span class="ev-value" style="color:var(--cyan)">${{ev.technique}} — ${{ev.tactic||''}}</span>`;
  if (ev.evidence)  html += `<span class="ev-label">Evidence</span><span class="ev-value">${{ev.evidence}}</span>`;
  if (ev.file)      html += `<span class="ev-label">File</span><span class="ev-value" style="color:var(--cyan)">${{ev.file}}</span>`;
  if (ev.state)     html += `<span class="ev-label">State</span><span class="ev-value">${{ev.state === 'installed' ? '⚠ Active binary confirmed' : '👻 Deleted — ghost trace recovered'}}</span>`;
  if (ev.delta)     html += `<span class="ev-label">Delta</span><span class="ev-value" style="color:var(--amber)">${{typeof ev.delta === 'number' ? ev.delta.toFixed(2) : ev.delta}}s</span>`;
  html += '</div>';
  if (ev.type === 'paradox' && ev.evidence) html += `<div class="court-note">${{ev.evidence}}</div>`;
  if (ev.attacker) html += `<div class="attacker-cmd">${{ev.attacker}}</div>`;
  return html;
}}

function buildTimeline() {{
  const container = document.getElementById('timeline-events');
  if (!EVENTS.length) {{
    container.innerHTML = '<div style="color:var(--muted);font-family:monospace;font-size:13px;padding:20px 0">No attack events reconstructed — run on a live Linux system with root access for full results.</div>';
    return;
  }}
  EVENTS.forEach((ev, i) => {{
    const color   = ev.color || '#00ff88';
    const detail  = buildDetail(ev);
    const hasDetail = !!(ev.evidence || ev.file || ev.attacker || ev.delta);
    const row = document.createElement('div');
    row.className = 't-event';
    row.style.setProperty('--ev-color', color);
    row.style.transitionDelay = (i * 0.05) + 's';
    row.innerHTML = `
      <div class="t-dot"></div>
      <div class="t-connector"></div>
      <div class="t-card" id="tc-${{i}}">
        <div class="t-card-header">
          <span class="t-phase-pill">${{ev.phase}}</span>
          <span class="t-type-badge">${{ev.type}}</span>
          <span class="t-sev ${{sevClass(ev.severity)}}">${{ev.severity||'medium'}}</span>
        </div>
        <div class="t-title">${{ev.title}}</div>
        ${{ev.description ? `<div class="t-desc">${{ev.description}}</div>` : ''}}
        ${{ev.technique   ? `<div class="t-technique">${{ev.technique}} &nbsp;·&nbsp; ${{ev.tactic||''}}</div>` : ''}}
        ${{hasDetail ? `
          <div class="t-evidence" id="te-${{i}}">${{detail}}</div>
          <div class="expand-hint">CLICK TO ${{ev.type==='paradox'?'REVEAL COURT EVIDENCE':'SHOW FORENSIC DETAIL'}} <span class="expand-arrow">▼</span></div>
        ` : ''}}
      </div>`;
    if (hasDetail) {{
      row.addEventListener('click', () => toggleEv(i));
    }}
    container.appendChild(row);
  }});

  setTimeout(() => {{
    document.querySelectorAll('.t-event').forEach((el, i) => {{
      setTimeout(() => el.classList.add('visible'), i * 80);
    }});
  }}, 300);
}}

function toggleEv(i) {{
  const card = document.getElementById('tc-' + i);
  const ev   = document.getElementById('te-' + i);
  if (!ev) return;
  const open = ev.classList.contains('open');
  ev.classList.toggle('open', !open);
  card.classList.toggle('open', !open);
}}

// ── Build paradox grid ───────────────────────────────────────
function buildParadoxes() {{
  const grid = document.getElementById('paradox-grid');
  if (!PARADOXES.length) {{
    grid.innerHTML = '<div style="color:var(--low);font-family:monospace;font-size:13px;padding:20px;border:1px solid var(--border);border-radius:4px;background:var(--bg2)">No timestamp paradoxes detected. All filesystem timestamps are logically consistent.</div>';
    return;
  }}
  PARADOXES.forEach(p => {{
    const sev   = p.severity || 'high';
    const color = sev==='critical' ? 'var(--critical)' : sev==='high' ? 'var(--high)' : 'var(--medium)';
    const delta = p.delta_seconds !== undefined ? Math.abs(p.delta_seconds).toFixed(2) + 's' : '—';
    const card  = document.createElement('div');
    card.className = 'paradox-card';
    card.style.setProperty('--sev-color', color);
    card.innerHTML = `
      <div class="paradox-sev">${{sev.toUpperCase()}}</div>
      <div class="paradox-type">${{(p.type||'').replace(/_/g,' ')}}</div>
      ${{p.file  ? `<div class="paradox-file">${{p.file}}</div>` : ''}}
      ${{p.delta_seconds !== undefined ? `<div class="paradox-delta">${{delta}} delta</div>` : ''}}
      ${{p.court_note ? `<div class="paradox-court">${{p.court_note}}</div>` : ''}}`;
    grid.appendChild(card);
  }});
}}

// ── Build tools table ────────────────────────────────────────
function buildTools() {{
  const tbody = document.getElementById('tools-body');
  if (!TOOLS.length) {{
    tbody.innerHTML = '<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:24px">No offensive tools detected.</td></tr>';
    return;
  }}
  TOOLS.forEach(t => {{
    const risk  = (t.risk||'UNKNOWN').toLowerCase();
    const state = t.state === 'installed'
      ? '<span class="tool-state-active">ACTIVE</span>'
      : '<span class="tool-state-ghost">GHOST</span>';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="tool-name">${{t.name}}</span></td>
      <td>${{(t.category||'').replace(/_/g,' ')}}</td>
      <td><span class="risk-${{risk}}">${{t.risk||'—'}}</span></td>
      <td>${{state}}</td>
      <td style="color:var(--muted);max-width:300px;word-break:break-all">${{t.evidence||'—'}}</td>`;
    tbody.appendChild(tr);
  }});
}}

// ── Verdict ──────────────────────────────────────────────────
function buildVerdict() {{
  const score = {len([e for e in events if e.get('severity') in ['critical','high']])} * 10;
  const vtext = document.getElementById('verdict-text');
  const vdet  = document.getElementById('verdict-detail');
  const vblock= document.getElementById('verdict-block');
  const critical = {critical_count};
  const phases   = {len(phases_hit)};

  if (critical > 0 || phases >= 4) {{
    vtext.textContent = 'HIGH RISK';
    vblock.style.setProperty('--v-color', 'var(--critical)');
    vdet.textContent  = 'Structured attack campaign detected. Multiple critical indicators confirmed. Evidence tampering identified. Immediate escalation recommended.';
  }} else if (phases >= 2) {{
    vtext.textContent = 'MEDIUM RISK';
    vblock.style.setProperty('--v-color', 'var(--amber)');
    vdet.textContent  = 'Suspicious activity detected across multiple ATT&CK phases. Further forensic investigation recommended.';
  }} else {{
    vtext.textContent = 'LOW RISK';
    vblock.style.setProperty('--v-color', 'var(--low)');
    vdet.textContent  = 'Limited indicators detected. Manual investigation recommended to confirm or rule out malicious activity.';
  }}
}}

// ── Init ─────────────────────────────────────────────────────
buildMitre();
buildTimeline();
buildParadoxes();
buildTools();
buildVerdict();
</script>
</body>
</html>"""

    output_path = "lare_report.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return os.path.abspath(output_path)