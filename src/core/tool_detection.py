import os

OFFENSIVE_TOOLS = {
    "nmap":        {"category": "recon",          "paths": ["/usr/bin/nmap", "/usr/local/bin/nmap"]},
    "metasploit":  {"category": "exploit",         "paths": ["/opt/metasploit-framework", "/usr/bin/msfconsole"]},
    "wireshark":   {"category": "recon",          "paths": ["/usr/bin/wireshark", "/usr/bin/tshark"]},
    "aircrack-ng": {"category": "wireless",        "paths": ["/usr/bin/aircrack-ng"]},
    "sqlmap":      {"category": "exploit",         "paths": ["/usr/bin/sqlmap", "/usr/local/bin/sqlmap"]},
    "hydra":       {"category": "brute_force",     "paths": ["/usr/bin/hydra"]},
    "john":        {"category": "brute_force",     "paths": ["/usr/bin/john"]},
    "hashcat":     {"category": "brute_force",     "paths": ["/usr/bin/hashcat"]},
    "netcat":      {"category": "recon",          "paths": ["/usr/bin/nc", "/usr/bin/netcat"]},
    "burpsuite":   {"category": "web_exploit",     "paths": ["/usr/bin/burpsuite", "/opt/BurpSuiteCommunity"]},
    "nikto":       {"category": "web_exploit",     "paths": ["/usr/bin/nikto"]},
    "bleachbit":   {"category": "anti_forensic",   "paths": ["/usr/bin/bleachbit"]},
    "secure-delete":{"category": "anti_forensic",  "paths": ["/usr/bin/srm", "/usr/bin/sfill"]},
    "tor":         {"category": "anonymization",   "paths": ["/usr/bin/tor", "/usr/sbin/tor"]},
}

def detect_tools(target: str) -> list:
    detected = []
    root = target.rstrip("/")

    for tool_name, info in OFFENSIVE_TOOLS.items():
        for tool_path in info["paths"]:
            full_path = os.path.join(root, tool_path.lstrip("/"))
            if os.path.exists(full_path):
                detected.append({
                    "name": tool_name,
                    "category": info["category"],
                    "state": "installed",
                    "evidence": f"Binary found at {tool_path}"
                })
                break
        else:
            ghost = _check_inode_ghost(root, tool_name)
            if ghost:
                detected.append({
                    "name": tool_name,
                    "category": info["category"],
                    "state": "removed",
                    "evidence": ghost
                })

    return detected


def _check_inode_ghost(root: str, tool_name: str) -> str:
    cache_paths = [
        f"var/cache/apt/archives/{tool_name}",
        f"var/lib/dpkg/info/{tool_name}.list",
        f"var/log/dpkg.log",
    ]
    for cp in cache_paths:
        full = os.path.join(root, cp)
        if os.path.exists(full):
            try:
                if tool_name in open(full, errors="ignore").read():
                    return f"Residue found in /{cp}"
            except Exception:
                pass
    return ""