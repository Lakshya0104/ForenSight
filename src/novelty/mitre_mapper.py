import os

MITRE_RULES = [
    {"keywords": ["nmap", "masscan", "netdiscover"],   "phase": "Recon",       "technique": "T1046"},
    {"keywords": ["hydra", "john", "hashcat"],         "phase": "Recon",       "technique": "T1110"},
    {"keywords": ["curl", "wget", "python -c"],        "phase": "Execution",   "technique": "T1059"},
    {"keywords": ["chmod +x", "bash ", "./"],          "phase": "Execution",   "technique": "T1059"},
    {"keywords": ["crontab", "systemctl enable"],      "phase": "Persistence", "technique": "T1053"},
    {"keywords": ["ssh-keygen", "authorized_keys"],    "phase": "Persistence", "technique": "T1098"},
    {"keywords": ["history -c", "shred", "rm -rf /var/log", "bleachbit"], "phase": "Cover Tracks", "technique": "T1070"},
]

def map_to_mitre(target: str) -> list:
    """
    TANVEE'S MODULE
    Maps bash history commands to MITRE ATT&CK phases and techniques.
    """
    root = target.rstrip("/")
    chain = []
    history_path = os.path.join(root, "root/.bash_history")

    if not os.path.exists(history_path):
        return chain

    try:
        with open(history_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return chain

    for line in lines:
        cmd = line.strip().lower()
        if not cmd:
            continue
        for rule in MITRE_RULES:
            if any(kw in cmd for kw in rule["keywords"]):
                chain.append({
                    "phase": rule["phase"],
                    "technique": rule["technique"],
                    "command": line.strip(),
                })
                break

    return chain