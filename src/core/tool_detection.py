import os
import platform
from src.core.tool_db import load_tool_db

COMMON_BIN_PATHS = [
    "/usr/bin", "/usr/local/bin", "/usr/sbin",
    "/usr/local/sbin", "/bin", "/sbin",
    "/opt", "/usr/share",
]

def detect_tools(target: str) -> list:
    """
    Auto-detects platform and routes to correct detection engine.
    Linux → apt/dpkg/filesystem scan
    Windows → winget/chocolatey/filesystem scan
    """
    if platform.system().lower() == "windows" and target not in ("/", ""):
        from src.core.windows_tool_detection import detect_tools_windows
        return detect_tools_windows(target)

    # Linux path — existing logic
    root    = target.rstrip("/") if target != "/" else ""
    tool_db = load_tool_db()
    detected = []
    checked  = set()

    for tool_name, info in tool_db.items():
        if tool_name in checked:
            continue
        checked.add(tool_name)

        found = False
        for bin_dir in COMMON_BIN_PATHS:
            full = os.path.join(root, bin_dir.lstrip("/"), tool_name) if root \
                   else os.path.join(bin_dir, tool_name)
            if os.path.exists(full):
                try:
                    size = os.path.getsize(full)
                except Exception:
                    size = 0
                detected.append({
                    "name":       tool_name,
                    "category":   info.get("category", "unknown"),
                    "risk":       info.get("risk", "MEDIUM"),
                    "state":      "installed",
                    "path":       os.path.join(bin_dir, tool_name),
                    "size_bytes": size,
                    "evidence":   f"Binary confirmed at {bin_dir}/{tool_name} ({size} bytes)"
                })
                found = True
                break

        if not found:
            for base in ["/opt", "/usr/share"]:
                full = os.path.join(root, base.lstrip("/"), tool_name) if root \
                       else os.path.join(base, tool_name)
                if os.path.exists(full):
                    detected.append({
                        "name":       tool_name,
                        "category":   info.get("category", "unknown"),
                        "risk":       info.get("risk", "MEDIUM"),
                        "state":      "installed",
                        "path":       f"{base}/{tool_name}",
                        "size_bytes": 0,
                        "evidence":   f"Directory/binary found at {base}/{tool_name}"
                    })
                    found = True
                    break

        if not found:
            ghost = _check_ghost_traces(root, tool_name)
            if ghost:
                detected.append({
                    "name":       tool_name,
                    "category":   info.get("category", "unknown"),
                    "risk":       info.get("risk", "MEDIUM"),
                    "state":      "removed",
                    "path":       "unknown (deleted)",
                    "size_bytes": 0,
                    "evidence":   ghost
                })

    risk_order  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    state_order = {"installed": 0, "removed": 1}
    detected.sort(key=lambda x: (
        risk_order.get(x.get("risk", "LOW"), 3),
        state_order.get(x.get("state", "removed"), 1)
    ))
    return detected


def _check_ghost_traces(root: str, tool_name: str) -> str:
    traces = []

    dpkg_log = os.path.join(root, "var/log/dpkg.log") if root else "/var/log/dpkg.log"
    if os.path.exists(dpkg_log):
        try:
            content = open(dpkg_log, errors="ignore").read()
            if tool_name in content:
                lines = [l for l in content.splitlines() if tool_name in l]
                if lines:
                    traces.append(f"dpkg.log: {lines[-1].strip()[:80]}")
        except Exception:
            pass

    apt_hist = os.path.join(root, "var/log/apt/history.log") if root else "/var/log/apt/history.log"
    if os.path.exists(apt_hist):
        try:
            content = open(apt_hist, errors="ignore").read()
            if tool_name in content:
                traces.append(f"APT history references {tool_name}")
        except Exception:
            pass

    dpkg_info = os.path.join(root, f"var/lib/dpkg/info/{tool_name}.list") if root \
                else f"/var/lib/dpkg/info/{tool_name}.list"
    if os.path.exists(dpkg_info):
        traces.append(f"DPKG info file exists: /var/lib/dpkg/info/{tool_name}.list")

    bash_hist = os.path.join(root, "root/.bash_history") if root else "/root/.bash_history"
    if os.path.exists(bash_hist):
        try:
            content = open(bash_hist, errors="ignore").read()
            if tool_name in content:
                traces.append(f"Referenced in bash history")
        except Exception:
            pass

    return " | ".join(traces) if traces else ""