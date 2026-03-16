import os

CRITICAL_LOGS = [
    "var/log/auth.log",
    "var/log/syslog",
    "var/log/kern.log",
    "var/log/messages",
    "var/log/wtmp",
    "var/log/btmp",
    "var/log/lastlog",
]

BASH_HISTORY_PATHS = [
    "root/.bash_history",
    "home/*/.bash_history",
]

EVASION_COMMANDS = [
    "history -c", "history -w /dev/null",
    "rm -rf /var/log", "shred", "wipe",
    "> /var/log", "truncate", "unset HISTFILE",
    "export HISTSIZE=0", "bleachbit",
]

def analyze_logs(target: str) -> dict:
    root = target.rstrip("/")
    result = {
        "logs_cleared": False,
        "history_cleared": False,
        "missing_logs": [],
        "evasion_commands_found": [],
        "suspicious_entries": []
    }

    for log in CRITICAL_LOGS:
        full_path = os.path.join(root, log)
        if not os.path.exists(full_path):
            result["missing_logs"].append(f"/{log}")
            result["logs_cleared"] = True
        else:
            size = os.path.getsize(full_path)
            if size == 0:
                result["missing_logs"].append(f"/{log} (empty — likely wiped)")
                result["logs_cleared"] = True

    history_path = os.path.join(root, "root/.bash_history")
    if os.path.exists(history_path):
        try:
            with open(history_path, "r", errors="ignore") as f:
                history = f.read()
            if len(history.strip()) == 0:
                result["history_cleared"] = True
            for cmd in EVASION_COMMANDS:
                if cmd in history:
                    result["evasion_commands_found"].append(cmd)
                    result["history_cleared"] = True
        except Exception:
            pass
    else:
        result["history_cleared"] = True

    return result