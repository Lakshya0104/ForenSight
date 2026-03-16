import os
import re

MITRE_RULES = [
    # Recon
    {"keywords": ["nmap", "masscan", "netdiscover", "arp-scan", "unicornscan"], "phase": "Recon", "technique": "T1046", "tactic": "Discovery"},
    {"keywords": ["whois", "dig ", "nslookup", "dnsrecon", "dnsenum"],          "phase": "Recon", "technique": "T1590", "tactic": "Reconnaissance"},
    {"keywords": ["theharvester", "recon-ng", "maltego", "shodan"],              "phase": "Recon", "technique": "T1589", "tactic": "Reconnaissance"},
    # Initial Access
    {"keywords": ["hydra", "medusa", "patator", "crowbar"],                      "phase": "Initial Access",  "technique": "T1110", "tactic": "Credential Access"},
    {"keywords": ["phishing", "setoolkit", "social-engineer"],                   "phase": "Initial Access",  "technique": "T1566", "tactic": "Initial Access"},
    {"keywords": ["sqlmap", "' or 1=1", "union select"],                        "phase": "Initial Access",  "technique": "T1190", "tactic": "Initial Access"},
    # Execution
    {"keywords": ["curl ", "wget ", "python -c", "perl -e", "ruby -e"],         "phase": "Execution",       "technique": "T1059", "tactic": "Execution"},
    {"keywords": ["chmod +x", "bash -i", "./exploit", "bash "],                 "phase": "Execution",       "technique": "T1059", "tactic": "Execution"},
    {"keywords": ["msfconsole", "msfvenom", "metasploit"],                      "phase": "Execution",       "technique": "T1203", "tactic": "Execution"},
    # Persistence
    {"keywords": ["crontab", "cron.d", "cron.daily"],                           "phase": "Persistence",     "technique": "T1053", "tactic": "Persistence"},
    {"keywords": ["systemctl enable", "service enable", ".service"],            "phase": "Persistence",     "technique": "T1543", "tactic": "Persistence"},
    {"keywords": ["authorized_keys", "ssh-keygen", "~/.ssh/"],                  "phase": "Persistence",     "technique": "T1098", "tactic": "Persistence"},
    {"keywords": ["useradd", "adduser", "usermod"],                             "phase": "Persistence",     "technique": "T1136", "tactic": "Persistence"},
    # Privilege Escalation
    {"keywords": ["sudo -l", "sudo su", "pkexec", "suid"],                      "phase": "Privilege Escalation", "technique": "T1548", "tactic": "Privilege Escalation"},
    {"keywords": ["linpeas", "linenum", "linux-exploit-suggester"],             "phase": "Privilege Escalation", "technique": "T1068", "tactic": "Privilege Escalation"},
    # Defense Evasion
    {"keywords": ["history -c", "unset histfile", "export histsize=0"],        "phase": "Defense Evasion", "technique": "T1070", "tactic": "Defense Evasion"},
    {"keywords": ["bleachbit", "shred ", "srm ", "wipe "],                     "phase": "Defense Evasion", "technique": "T1070", "tactic": "Defense Evasion"},
    {"keywords": ["iptables -f", "ufw disable", "setenforce 0"],               "phase": "Defense Evasion", "technique": "T1562", "tactic": "Defense Evasion"},
    {"keywords": ["timestomp", "touch -t", "touch -d"],                        "phase": "Defense Evasion", "technique": "T1070.006", "tactic": "Defense Evasion"},
    # Credential Access
    {"keywords": ["hashdump", "/etc/shadow", "cat /etc/passwd"],               "phase": "Credential Access", "technique": "T1003", "tactic": "Credential Access"},
    {"keywords": ["mimikatz", "lazagne", "keydump"],                           "phase": "Credential Access", "technique": "T1555", "tactic": "Credential Access"},
    # Exfiltration
    {"keywords": ["scp ", "rsync ", "ftp ", "sftp "],                          "phase": "Exfiltration",    "technique": "T1048", "tactic": "Exfiltration"},
    {"keywords": ["nc -e", "ncat ", "/dev/tcp/", "socat"],                     "phase": "Exfiltration",    "technique": "T1041", "tactic": "Exfiltration"},
    # Cover Tracks
    {"keywords": ["rm -rf /var/log", "> /var/log", "truncate"],                "phase": "Cover Tracks",    "technique": "T1070.002", "tactic": "Defense Evasion"},
    {"keywords": ["logrotate -f", "cat /dev/null >"],                          "phase": "Cover Tracks",    "technique": "T1070.003", "tactic": "Defense Evasion"},
]

def map_to_mitre(target: str) -> list:
    root = target.rstrip("/") if target != "/" else ""
    chain = []
    seen_techniques = set()

    history_path = os.path.join(root, "root/.bash_history") if root else "/root/.bash_history"
    lines = []
    if os.path.exists(history_path):
        try:
            lines = open(history_path, errors="ignore").read().splitlines()
        except Exception:
            pass

    for line in lines:
        cmd = line.strip()
        if not cmd:
            continue
        cmd_lower = cmd.lower()
        for rule in MITRE_RULES:
            if any(kw.lower() in cmd_lower for kw in rule["keywords"]):
                key = f"{rule['technique']}:{cmd[:40]}"
                if key not in seen_techniques:
                    chain.append({
                        "phase":     rule["phase"],
                        "tactic":    rule["tactic"],
                        "technique": rule["technique"],
                        "command":   cmd,
                    })
                    seen_techniques.add(key)
                break

    phase_order = ["Recon","Initial Access","Execution","Persistence",
                   "Privilege Escalation","Defense Evasion","Credential Access","Exfiltration","Cover Tracks"]
    chain.sort(key=lambda x: phase_order.index(x["phase"]) if x["phase"] in phase_order else 99)
    return chain