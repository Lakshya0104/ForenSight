PERSONAS = {
    "Network Intrusion Operator": {
        "tools":    ["nmap", "masscan", "metasploit", "hydra", "netcat", "socat"],
        "commands": ["nmap", "msfconsole", "hydra", "nc -e", "bash -i"],
        "weight":   3.0,
        "description": "Focused on network scanning, exploitation, and gaining remote shells"
    },
    "Data Exfiltrator": {
        "tools":    ["curl", "wget", "netcat", "socat", "chisel", "scp"],
        "commands": ["scp ", "rsync ", "curl ", "wget ", "/dev/tcp/"],
        "weight":   3.0,
        "description": "Prioritizes data theft via covert channels and file transfer tools"
    },
    "Credential Harvester": {
        "tools":    ["hydra", "john", "hashcat", "medusa"],
        "commands": ["hashdump", "/etc/shadow", "john ", "hashcat ", "hydra "],
        "weight":   2.5,
        "description": "Targets authentication systems — password cracking and hash dumping"
    },
    "Web Application Attacker": {
        "tools":    ["burpsuite", "sqlmap", "nikto", "dirb", "gobuster", "wfuzz", "commix"],
        "commands": ["sqlmap", "nikto", "dirb", "gobuster", "' or 1=1"],
        "weight":   2.5,
        "description": "Exploits web application vulnerabilities — SQLi, XSS, directory traversal"
    },
    "Wireless Attacker": {
        "tools":    ["aircrack-ng", "kismet", "wifite", "wireshark"],
        "commands": ["aircrack", "airodump", "aireplay", "wifite"],
        "weight":   2.0,
        "description": "Specializes in wireless network attacks — WPA cracking, deauthentication"
    },
    "Insider Threat": {
        "tools":    ["bleachbit", "secure-delete", "shred", "wipe", "tor", "proxychains"],
        "commands": ["bleachbit", "shred ", "srm ", "history -c", "unset histfile"],
        "weight":   2.0,
        "description": "Evidence of deliberate cover-up behavior — anti-forensic focus"
    },
    "Advanced Persistent Threat (APT)": {
        "tools":    ["chisel", "socat", "tor", "proxychains", "metasploit"],
        "commands": ["crontab", "systemctl enable", "useradd", "authorized_keys"],
        "weight":   3.5,
        "description": "Long-term access maintenance — persistence mechanisms and covert C2"
    },
}

def classify_persona(tools: list, paradoxes: list) -> tuple:
    tool_names  = {t["name"].lower() for t in tools}
    tool_states = {t["name"].lower(): t.get("state") for t in tools}
    scores = {}

    for persona, config in PERSONAS.items():
        score = 0.0
        matched_tools = []
        for t in config["tools"]:
            if t in tool_names:
                w = 1.0 if tool_states.get(t) == "installed" else 0.6
                score += w
                matched_tools.append(t)
        if score > 0:
            scores[persona] = {
                "raw": score * config["weight"],
                "matched_tools": matched_tools,
                "tool_count": len(matched_tools)
            }

    # Boost Insider Threat if paradoxes found
    if paradoxes:
        if "Insider Threat" not in scores:
            scores["Insider Threat"] = {"raw": 0, "matched_tools": [], "tool_count": 0}
        scores["Insider Threat"]["raw"] += len(paradoxes) * 0.8

    # Boost APT if persistence commands found
    if any("crontab" in str(t) or "systemctl" in str(t) for t in tools):
        if "Advanced Persistent Threat (APT)" not in scores:
            scores["Advanced Persistent Threat (APT)"] = {"raw": 0, "matched_tools": [], "tool_count": 0}
        scores["Advanced Persistent Threat (APT)"]["raw"] += 1.5

    if not scores:
        return "Unknown", 0.0

    best = max(scores, key=lambda k: scores[k]["raw"])
    max_possible = PERSONAS[best]["weight"] * len(PERSONAS[best]["tools"])
    confidence = round(min(scores[best]["raw"] / max(max_possible, 1), 1.0), 2)

    return best, confidence