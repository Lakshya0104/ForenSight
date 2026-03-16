import os
import json
import subprocess
from datetime import datetime, timezone

TOOL_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "tool_db.json")
TOOL_DB_PATH = os.path.normpath(TOOL_DB_PATH)

WINDOWS_OFFENSIVE_TOOLS = {
    # Credential dumping
    "mimikatz":        {"category": "credential-access",   "risk": "CRITICAL"},
    "mimikatz.exe":    {"category": "credential-access",   "risk": "CRITICAL"},
    "wce.exe":         {"category": "credential-access",   "risk": "CRITICAL"},
    "pwdump":          {"category": "credential-access",   "risk": "CRITICAL"},
    "fgdump":          {"category": "credential-access",   "risk": "CRITICAL"},
    # Recon
    "nmap":            {"category": "recon",               "risk": "HIGH"},
    "nmap.exe":        {"category": "recon",               "risk": "HIGH"},
    "masscan":         {"category": "recon",               "risk": "HIGH"},
    "sharphound":      {"category": "recon",               "risk": "CRITICAL"},
    "sharphound.exe":  {"category": "recon",               "risk": "CRITICAL"},
    "bloodhound":      {"category": "recon",               "risk": "CRITICAL"},
    # Exploitation
    "metasploit":      {"category": "exploitation",        "risk": "CRITICAL"},
    "msfconsole":      {"category": "exploitation",        "risk": "CRITICAL"},
    "cobalt strike":   {"category": "exploitation",        "risk": "CRITICAL"},
    "cobaltstrike":    {"category": "exploitation",        "risk": "CRITICAL"},
    "havoc":           {"category": "exploitation",        "risk": "CRITICAL"},
    "sliver":          {"category": "exploitation",        "risk": "CRITICAL"},
    "covenant":        {"category": "exploitation",        "risk": "CRITICAL"},
    # Post exploitation
    "powersploit":     {"category": "post-exploitation",   "risk": "CRITICAL"},
    "empire":          {"category": "post-exploitation",   "risk": "CRITICAL"},
    "rubeus.exe":      {"category": "post-exploitation",   "risk": "CRITICAL"},
    "certify.exe":     {"category": "post-exploitation",   "risk": "CRITICAL"},
    "sharpup.exe":     {"category": "post-exploitation",   "risk": "CRITICAL"},
    "seatbelt.exe":    {"category": "post-exploitation",   "risk": "HIGH"},
    "winpeas.exe":     {"category": "post-exploitation",   "risk": "HIGH"},
    "winpeas.bat":     {"category": "post-exploitation",   "risk": "HIGH"},
    # Lateral movement
    "psexec.exe":      {"category": "lateral-movement",    "risk": "CRITICAL"},
    "paexec.exe":      {"category": "lateral-movement",    "risk": "CRITICAL"},
    "wmiexec":         {"category": "lateral-movement",    "risk": "CRITICAL"},
    "crackmapexec":    {"category": "lateral-movement",    "risk": "CRITICAL"},
    # Sniffing
    "wireshark":       {"category": "sniffing",            "risk": "HIGH"},
    "wireshark.exe":   {"category": "sniffing",            "risk": "HIGH"},
    "rawcap.exe":      {"category": "sniffing",            "risk": "HIGH"},
    # Anti-forensic
    "eraser":          {"category": "anti-forensic",       "risk": "CRITICAL"},
    "cipher.exe":      {"category": "anti-forensic",       "risk": "HIGH"},
    "sdelete.exe":     {"category": "anti-forensic",       "risk": "CRITICAL"},
    "ccleaner":        {"category": "anti-forensic",       "risk": "HIGH"},
    "bleachbit":       {"category": "anti-forensic",       "risk": "CRITICAL"},
    # Brute force
    "hydra.exe":       {"category": "brute-force",         "risk": "CRITICAL"},
    "hashcat.exe":     {"category": "brute-force",         "risk": "HIGH"},
    "john.exe":        {"category": "brute-force",         "risk": "HIGH"},
    # C2 / RATs
    "nc.exe":          {"category": "c2",                  "risk": "HIGH"},
    "ncat.exe":        {"category": "c2",                  "risk": "HIGH"},
    "netcat.exe":      {"category": "c2",                  "risk": "HIGH"},
    "socat.exe":       {"category": "c2",                  "risk": "HIGH"},
    # Tunneling
    "ngrok.exe":       {"category": "tunneling",           "risk": "HIGH"},
    "chisel.exe":      {"category": "tunneling",           "risk": "CRITICAL"},
    "ligolo":          {"category": "tunneling",           "risk": "CRITICAL"},
    # Anonymization
    "tor.exe":         {"category": "anonymization",       "risk": "HIGH"},
    "proxifier":       {"category": "anonymization",       "risk": "HIGH"},
}

WINDOWS_SCAN_PATHS = [
    "C:\\Tools",
    "C:\\Windows\\Temp",
    "C:\\Temp",
    "C:\\ProgramData",
    "C:\\Users\\Public",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
]

KALI_CATEGORIES = [
    "kali-tools-top10",
    "kali-tools-information-gathering",
    "kali-tools-vulnerability",
    "kali-tools-web",
    "kali-tools-database",
    "kali-tools-passwords",
    "kali-tools-wireless",
    "kali-tools-reverse-engineering",
    "kali-tools-exploitation",
    "kali-tools-sniffing-spoofing",
    "kali-tools-post-exploitation",
    "kali-tools-forensics",
    "kali-tools-reporting",
    "kali-tools-social-engineering",
    "kali-tools-hardware",
    "kali-tools-crypto-stego",
    "kali-tools-fuzzing",
    "kali-tools-802-11",
    "kali-tools-bluetooth",
    "kali-tools-rfid",
    "kali-tools-voip",
]

CATEGORY_RISK = {
    "top10":                "CRITICAL",
    "exploitation":         "CRITICAL",
    "passwords":            "CRITICAL",
    "post-exploitation":    "CRITICAL",
    "reverse-engineering":  "CRITICAL",
    "vulnerability":        "HIGH",
    "web":                  "HIGH",
    "sniffing-spoofing":    "HIGH",
    "social-engineering":   "HIGH",
    "wireless":             "HIGH",
    "802-11":               "HIGH",
    "bluetooth":            "HIGH",
    "rfid":                 "HIGH",
    "voip":                 "HIGH",
    "information-gathering":"MEDIUM",
    "database":             "MEDIUM",
    "fuzzing":              "MEDIUM",
    "forensics":            "MEDIUM",
    "crypto-stego":         "MEDIUM",
    "hardware":             "MEDIUM",
    "reporting":            "LOW",
}

STATIC_FALLBACK = {
    "nmap":           {"category": "information-gathering", "risk": "HIGH"},
    "masscan":        {"category": "information-gathering", "risk": "HIGH"},
    "metasploit-framework": {"category": "exploitation",   "risk": "CRITICAL"},
    "msfconsole":     {"category": "exploitation",         "risk": "CRITICAL"},
    "sqlmap":         {"category": "web",                  "risk": "CRITICAL"},
    "hydra":          {"category": "passwords",            "risk": "CRITICAL"},
    "john":           {"category": "passwords",            "risk": "HIGH"},
    "hashcat":        {"category": "passwords",            "risk": "HIGH"},
    "aircrack-ng":    {"category": "wireless",             "risk": "HIGH"},
    "wireshark":      {"category": "sniffing-spoofing",    "risk": "HIGH"},
    "burpsuite":      {"category": "web",                  "risk": "CRITICAL"},
    "nikto":          {"category": "web",                  "risk": "HIGH"},
    "gobuster":       {"category": "web",                  "risk": "HIGH"},
    "wfuzz":          {"category": "web",                  "risk": "HIGH"},
    "dirb":           {"category": "web",                  "risk": "MEDIUM"},
    "netcat":         {"category": "post-exploitation",    "risk": "HIGH"},
    "socat":          {"category": "post-exploitation",    "risk": "HIGH"},
    "chisel":         {"category": "post-exploitation",    "risk": "CRITICAL"},
    "bleachbit":      {"category": "anti_forensic",        "risk": "CRITICAL"},
    "shred":          {"category": "anti_forensic",        "risk": "HIGH"},
    "tor":            {"category": "information-gathering","risk": "HIGH"},
    "proxychains":    {"category": "information-gathering","risk": "HIGH"},
    "wifite":         {"category": "wireless",             "risk": "HIGH"},
    "kismet":         {"category": "wireless",             "risk": "HIGH"},
    "ettercap":       {"category": "sniffing-spoofing",    "risk": "HIGH"},
    "tcpdump":        {"category": "sniffing-spoofing",    "risk": "MEDIUM"},
    "medusa":         {"category": "passwords",            "risk": "HIGH"},
    "volatility":     {"category": "forensics",            "risk": "HIGH"},
    "autopsy":        {"category": "forensics",            "risk": "MEDIUM"},
    "binwalk":        {"category": "reverse-engineering",  "risk": "MEDIUM"},
    "ghidra":         {"category": "reverse-engineering",  "risk": "MEDIUM"},
    "radare2":        {"category": "reverse-engineering",  "risk": "HIGH"},
    "maltego":        {"category": "information-gathering","risk": "HIGH"},
    "recon-ng":       {"category": "information-gathering","risk": "HIGH"},
    "theharvester":   {"category": "information-gathering","risk": "HIGH"},
    "commix":         {"category": "web",                  "risk": "HIGH"},
    "beef-xss":       {"category": "exploitation",         "risk": "CRITICAL"},
    "searchsploit":   {"category": "exploitation",         "risk": "HIGH"},
    "setoolkit":      {"category": "social-engineering",   "risk": "CRITICAL"},
    "responder":      {"category": "sniffing-spoofing",    "risk": "CRITICAL"},
    "impacket":       {"category": "post-exploitation",    "risk": "CRITICAL"},
    "crackmapexec":   {"category": "post-exploitation",    "risk": "CRITICAL"},
    "evil-winrm":     {"category": "post-exploitation",    "risk": "CRITICAL"},
    "bloodhound":     {"category": "post-exploitation",    "risk": "CRITICAL"},
    "powersploit":    {"category": "post-exploitation",    "risk": "CRITICAL"},
}


def _infer_risk(category_suffix: str) -> str:
    for key, risk in CATEGORY_RISK.items():
        if key in category_suffix:
            return risk
    return "MEDIUM"


def _parse_apt_depends(category: str) -> dict:
    tools = {}
    try:
        result = subprocess.run(
            [
                "apt-cache", "depends",
                "--recurse",
                "--no-recommends",
                "--no-suggests",
                "--no-conflicts",
                "--no-breaks",
                "--no-replaces",
                "--no-enhances",
                category
            ],
            capture_output=True, text=True, timeout=60
        )
        suffix = category.replace("kali-tools-", "")
        risk   = _infer_risk(suffix)

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("|") or line.startswith("<") or line.startswith("kali"):
                continue
            line = line.replace("Depends:", "").replace("PreDepends:", "").strip()
            if not line or line.startswith("lib") or " " in line:
                continue
            tools[line] = {
                "category": suffix,
                "risk":     risk,
                "source":   "kali-apt",
                "meta_pkg": category,
            }
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return tools


def refresh_tool_db(verbose: bool = False) -> dict:
    """
    Pull latest offensive tool list from Kali apt meta-packages.
    Falls back gracefully on non-Kali systems.
    Returns the full DB dict.
    """
    all_tools = {}
    success   = 0

    for category in KALI_CATEGORIES:
        tools = _parse_apt_depends(category)
        if tools:
            success += 1
            all_tools.update(tools)
        if verbose:
            status = f"✓ {len(tools)}" if tools else "✗ skipped"
            print(f"  {category:<45} {status}")

    # Always merge static fallback so core tools are always present
    for tool, info in STATIC_FALLBACK.items():
        if tool not in all_tools:
            all_tools[tool] = {**info, "source": "static-fallback"}

    db = {
        "updated":        datetime.now(timezone.utc).isoformat(),
        "tool_count":     len(all_tools),
        "categories_hit": success,
        "source":         "kali-apt" if success > 0 else "static-fallback",
        "tools":          all_tools,
    }

    with open(TOOL_DB_PATH, "w") as f:
        json.dump(db, f, indent=2)

    return db


def load_tool_db() -> dict:
    """
    Load tool DB from cache file.
    Auto-falls back to static dict if no DB file exists.
    """
    if os.path.exists(TOOL_DB_PATH):
        try:
            with open(TOOL_DB_PATH) as f:
                db = json.load(f)
            return db.get("tools", STATIC_FALLBACK)
        except Exception:
            pass
    return STATIC_FALLBACK


def get_db_meta() -> dict:
    """Return metadata about the current tool DB."""
    if os.path.exists(TOOL_DB_PATH):
        try:
            with open(TOOL_DB_PATH) as f:
                db = json.load(f)
            return {
                "exists":     True,
                "updated":    db.get("updated", "unknown"),
                "tool_count": db.get("tool_count", 0),
                "source":     db.get("source", "unknown"),
            }
        except Exception:
            pass
    return {
        "exists":     False,
        "updated":    "never",
        "tool_count": len(STATIC_FALLBACK),
        "source":     "static-fallback",
    }