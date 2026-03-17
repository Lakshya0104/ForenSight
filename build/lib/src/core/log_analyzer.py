import os
import re
from datetime import datetime

CRITICAL_LOGS = {
    "var/log/auth.log":    "Authentication events (SSH, sudo, login failures)",
    "var/log/syslog":      "General system activity",
    "var/log/kern.log":    "Kernel messages",
    "var/log/messages":    "General messages (RHEL/CentOS)",
    "var/log/wtmp":        "Login/logout history (binary)",
    "var/log/btmp":        "Failed login attempts (binary)",
    "var/log/lastlog":     "Last login per user (binary)",
    "var/log/secure":      "Security events (RHEL/CentOS)",
    "var/log/faillog":     "Failed authentication log",
    "var/log/apt/history.log": "Package install/remove history",
    "var/log/dpkg.log":    "Package manager log",
}

EVASION_COMMANDS = [
    "history -c", "history -w /dev/null", "unset HISTFILE",
    "export HISTSIZE=0", "export HISTFILESIZE=0",
    "rm -rf /var/log", "shred /var/log",
    "> /var/log/auth.log", "> /var/log/syslog",
    "truncate -s 0", "bleachbit", "wipe",
    "srm ", "sfill ", "dd if=/dev/zero",
    "logrotate -f", "cat /dev/null >",
]

SUSPICIOUS_COMMANDS = [
    "wget ", "curl ", "chmod +x", "python -c", "perl -e", "ruby -e",
    "bash -i", "nc -e", "ncat ", "socat ",
    "/dev/tcp/", "/dev/udp/",
    "base64 -d", "echo * | base64",
    "iptables -F", "ufw disable",
    "passwd root", "useradd ", "usermod ",
    "crontab -e", "at now", "systemctl enable",
    "ssh-keygen", "authorized_keys",
    "pkill ", "kill -9",
]

def analyze_logs(target: str) -> dict:
    root = target.rstrip("/") if target != "/" else ""

    result = {
        "logs_cleared": False,
        "history_cleared": False,
        "missing_logs": [],
        "wiped_logs": [],
        "evasion_commands_found": [],
        "suspicious_commands_found": [],
        "failed_logins": 0,
        "sudo_attempts": 0,
        "ssh_connections": [],
        "log_coverage": 0.0,
    }

    present = 0
    for log_path, description in CRITICAL_LOGS.items():
        full_path = os.path.join(root, log_path) if root else f"/{log_path}"
        if not os.path.exists(full_path):
            result["missing_logs"].append({"path": f"/{log_path}", "description": description})
            result["logs_cleared"] = True
        else:
            size = os.path.getsize(full_path)
            if size == 0:
                result["wiped_logs"].append({"path": f"/{log_path}", "description": description, "note": "File exists but is empty"})
                result["logs_cleared"] = True
            else:
                present += 1
                _parse_log(full_path, result)

    result["log_coverage"] = round(present / len(CRITICAL_LOGS), 2)

    # Bash history analysis
    for hist_path in ["root/.bash_history", "home/*/.bash_history"]:
        full = os.path.join(root, hist_path.split("*")[0]) if root else f"/{hist_path.split('*')[0]}"
        actual = os.path.join(root, "root/.bash_history") if root else "/root/.bash_history"
        if os.path.exists(actual):
            try:
                content = open(actual, errors="ignore").read()
                lines = content.splitlines()
                if len(content.strip()) == 0:
                    result["history_cleared"] = True
                for line in lines:
                    l = line.strip().lower()
                    for cmd in EVASION_COMMANDS:
                        if cmd.lower() in l and cmd not in result["evasion_commands_found"]:
                            result["evasion_commands_found"].append(line.strip())
                            result["history_cleared"] = True
                    for cmd in SUSPICIOUS_COMMANDS:
                        if cmd.lower() in l and line.strip() not in result["suspicious_commands_found"]:
                            result["suspicious_commands_found"].append(line.strip())
            except Exception:
                pass
        else:
            result["history_cleared"] = True

    return result


def _parse_log(path: str, result: dict):
    try:
        content = open(path, errors="ignore").read()
        result["failed_logins"]  += len(re.findall(r"(?:Failed password|authentication failure|FAILED LOGIN)", content, re.I))
        result["sudo_attempts"]  += len(re.findall(r"sudo:", content))
        ssh_ips = re.findall(r"Accepted (?:password|publickey) for \w+ from ([\d.]+)", content)
        result["ssh_connections"].extend(ssh_ips)
    except Exception:
        pass