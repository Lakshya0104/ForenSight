import os
import re

OFFENSIVE_TOOLS = {
    # Recon
    "nmap":           {"category": "recon",          "paths": ["/usr/bin/nmap", "/usr/local/bin/nmap"], "risk": "HIGH"},
    "masscan":        {"category": "recon",          "paths": ["/usr/bin/masscan"],                     "risk": "HIGH"},
    "netdiscover":    {"category": "recon",          "paths": ["/usr/bin/netdiscover"],                 "risk": "MEDIUM"},
    "recon-ng":       {"category": "recon",          "paths": ["/usr/bin/recon-ng"],                    "risk": "HIGH"},
    "maltego":        {"category": "recon",          "paths": ["/usr/bin/maltego"],                     "risk": "HIGH"},
    "theharvester":   {"category": "recon",          "paths": ["/usr/bin/theharvester"],                "risk": "HIGH"},
    # Exploitation
    "metasploit":     {"category": "exploit",        "paths": ["/opt/metasploit-framework", "/usr/bin/msfconsole"], "risk": "CRITICAL"},
    "sqlmap":         {"category": "exploit",        "paths": ["/usr/bin/sqlmap"],                      "risk": "CRITICAL"},
    "beef-xss":       {"category": "exploit",        "paths": ["/usr/bin/beef-xss", "/usr/share/beef-xss"], "risk": "CRITICAL"},
    "exploit-db":     {"category": "exploit",        "paths": ["/usr/bin/searchsploit"],                "risk": "HIGH"},
    "commix":         {"category": "exploit",        "paths": ["/usr/bin/commix"],                      "risk": "HIGH"},
    # Password attacks
    "hydra":          {"category": "brute_force",    "paths": ["/usr/bin/hydra"],                       "risk": "CRITICAL"},
    "john":           {"category": "brute_force",    "paths": ["/usr/bin/john"],                        "risk": "HIGH"},
    "hashcat":        {"category": "brute_force",    "paths": ["/usr/bin/hashcat"],                     "risk": "HIGH"},
    "medusa":         {"category": "brute_force",    "paths": ["/usr/bin/medusa"],                      "risk": "HIGH"},
    "crunch":         {"category": "brute_force",    "paths": ["/usr/bin/crunch"],                      "risk": "MEDIUM"},
    # Sniffing
    "wireshark":      {"category": "sniffing",       "paths": ["/usr/bin/wireshark", "/usr/bin/tshark"], "risk": "HIGH"},
    "tcpdump":        {"category": "sniffing",       "paths": ["/usr/bin/tcpdump"],                     "risk": "MEDIUM"},
    "ettercap":       {"category": "sniffing",       "paths": ["/usr/bin/ettercap"],                    "risk": "HIGH"},
    "dsniff":         {"category": "sniffing",       "paths": ["/usr/bin/dsniff"],                      "risk": "HIGH"},
    # Wireless
    "aircrack-ng":    {"category": "wireless",       "paths": ["/usr/bin/aircrack-ng"],                 "risk": "HIGH"},
    "kismet":         {"category": "wireless",       "paths": ["/usr/bin/kismet"],                      "risk": "HIGH"},
    "wifite":         {"category": "wireless",       "paths": ["/usr/bin/wifite"],                      "risk": "HIGH"},
    # Web
    "burpsuite":      {"category": "web_exploit",    "paths": ["/usr/bin/burpsuite", "/opt/BurpSuiteCommunity"], "risk": "CRITICAL"},
    "nikto":          {"category": "web_exploit",    "paths": ["/usr/bin/nikto"],                       "risk": "HIGH"},
    "dirb":           {"category": "web_exploit",    "paths": ["/usr/bin/dirb"],                        "risk": "MEDIUM"},
    "gobuster":       {"category": "web_exploit",    "paths": ["/usr/bin/gobuster"],                    "risk": "HIGH"},
    "wfuzz":          {"category": "web_exploit",    "paths": ["/usr/bin/wfuzz"],                       "risk": "HIGH"},
    # Anti-forensic
    "bleachbit":      {"category": "anti_forensic",  "paths": ["/usr/bin/bleachbit"],                   "risk": "CRITICAL"},
    "secure-delete":  {"category": "anti_forensic",  "paths": ["/usr/bin/srm", "/usr/bin/sfill"],       "risk": "CRITICAL"},
    "shred":          {"category": "anti_forensic",  "paths": ["/usr/bin/shred"],                       "risk": "HIGH"},
    "wipe":           {"category": "anti_forensic",  "paths": ["/usr/bin/wipe"],                        "risk": "HIGH"},
    "timestomp":      {"category": "anti_forensic",  "paths": ["/usr/bin/timestomp"],                   "risk": "CRITICAL"},
    # Anonymization
    "tor":            {"category": "anonymization",  "paths": ["/usr/bin/tor", "/usr/sbin/tor"],        "risk": "HIGH"},
    "proxychains":    {"category": "anonymization",  "paths": ["/usr/bin/proxychains", "/usr/bin/proxychains4"], "risk": "HIGH"},
    "anonsurf":       {"category": "anonymization",  "paths": ["/usr/bin/anonsurf"],                    "risk": "HIGH"},
    # C2 / Backdoors
    "netcat":         {"category": "c2",             "paths": ["/usr/bin/nc", "/usr/bin/netcat", "/bin/nc"], "risk": "HIGH"},
    "socat":          {"category": "c2",             "paths": ["/usr/bin/socat"],                       "risk": "HIGH"},
    "chisel":         {"category": "c2",             "paths": ["/usr/bin/chisel", "/opt/chisel"],       "risk": "CRITICAL"},
    # Forensics (attacker using forensic tools against the victim)
    "volatility":     {"category": "memory_forensic","paths": ["/usr/bin/volatility", "/usr/bin/vol"],  "risk": "HIGH"},
    "foremost":       {"category": "data_recovery",  "paths": ["/usr/bin/foremost"],                    "risk": "MEDIUM"},
    "binwalk":        {"category": "reversing",      "paths": ["/usr/bin/binwalk"],                     "risk": "MEDIUM"},
}

def detect_tools(target: str) -> list:
    root = target.rstrip("/") if target != "/" else ""
    detected = []
    checked = set()

    for tool_name, info in OFFENSIVE_TOOLS.items():
        found = False
        for tool_path in info["paths"]:
            full_path = os.path.join(root, tool_path.lstrip("/")) if root else tool_path
            if os.path.exists(full_path):
                size = 0
                try:
                    size = os.path.getsize(full_path)
                except Exception:
                    pass
                detected.append({
                    "name": tool_name,
                    "category": info["category"],
                    "risk": info["risk"],
                    "state": "installed",
                    "path": tool_path,
                    "size_bytes": size,
                    "evidence": f"Binary confirmed at {tool_path} ({size} bytes)"
                })
                found = True
                break

        if not found and tool_name not in checked:
            ghost = _check_ghost_traces(root, tool_name)
            if ghost:
                detected.append({
                    "name": tool_name,
                    "category": info["category"],
                    "risk": info["risk"],
                    "state": "removed",
                    "path": "unknown (deleted)",
                    "size_bytes": 0,
                    "evidence": ghost
                })
            checked.add(tool_name)

    detected.sort(key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["risk"], 4),
        x["state"] == "removed"
    ))
    return detected


def _check_ghost_traces(root: str, tool_name: str) -> str:
    traces = []

    # DPKG log
    dpkg_log = os.path.join(root, "var/log/dpkg.log") if root else "/var/log/dpkg.log"
    if os.path.exists(dpkg_log):
        try:
            content = open(dpkg_log, errors="ignore").read()
            if tool_name in content:
                lines = [l for l in content.splitlines() if tool_name in l]
                traces.append(f"dpkg.log: {lines[-1].strip()}")
        except Exception:
            pass

    # APT history
    apt_history = os.path.join(root, "var/log/apt/history.log") if root else "/var/log/apt/history.log"
    if os.path.exists(apt_history):
        try:
            content = open(apt_history, errors="ignore").read()
            if tool_name in content:
                traces.append(f"APT history references {tool_name}")
        except Exception:
            pass

    # DPKG info file list
    dpkg_info = os.path.join(root, f"var/lib/dpkg/info/{tool_name}.list") if root else f"/var/lib/dpkg/info/{tool_name}.list"
    if os.path.exists(dpkg_info):
        traces.append(f"DPKG info file exists: /var/lib/dpkg/info/{tool_name}.list")

    # Bash history
    bash_history = os.path.join(root, "root/.bash_history") if root else "/root/.bash_history"
    if os.path.exists(bash_history):
        try:
            content = open(bash_history, errors="ignore").read()
            if tool_name in content:
                traces.append(f"Found in bash history")
        except Exception:
            pass

    return " | ".join(traces) if traces else ""