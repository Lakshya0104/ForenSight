import os
import subprocess
import platform
from src.core.tool_db import WINDOWS_OFFENSIVE_TOOLS, WINDOWS_SCAN_PATHS, STATIC_FALLBACK

def is_windows() -> bool:
    return platform.system().lower() == "windows"


def detect_tools_windows(target: str) -> list:
    """
    Windows tool detection — three layers:
    1. Filesystem path scan for known offensive tool names
    2. Winget installed packages
    3. Chocolatey installed packages
    """
    detected = []
    seen     = set()

    # Layer 1 — Filesystem scan
    fs_hits = _scan_filesystem(target)
    for hit in fs_hits:
        if hit["name"] not in seen:
            detected.append(hit)
            seen.add(hit["name"])

    # Layer 2 — Winget
    winget_hits = _check_winget()
    for hit in winget_hits:
        if hit["name"] not in seen:
            detected.append(hit)
            seen.add(hit["name"])

    # Layer 3 — Chocolatey
    choco_hits = _check_chocolatey()
    for hit in choco_hits:
        if hit["name"] not in seen:
            detected.append(hit)
            seen.add(hit["name"])

    # Sort by risk
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    detected.sort(key=lambda x: risk_order.get(x.get("risk", "LOW"), 3))
    return detected


def _scan_filesystem(target: str) -> list:
    detected = []
    root     = target if target != "/" else ""

    scan_paths = WINDOWS_SCAN_PATHS if is_windows() else []

    # Also scan user dirs dynamically
    if is_windows():
        users_dir = os.path.join(root, "Users") if root else "C:\\Users"
        if os.path.exists(users_dir):
            for user in os.listdir(users_dir):
                for sub in ["Downloads", "Desktop", "Documents", "AppData\\Local\\Temp"]:
                    scan_paths.append(os.path.join(users_dir, user, sub))

    for scan_path in scan_paths:
        full_path = os.path.join(root, scan_path.lstrip("/\\")) if root else scan_path
        if not os.path.exists(full_path):
            continue
        try:
            for fname in os.listdir(full_path):
                fname_lower = fname.lower()
                fpath       = os.path.join(full_path, fname)
                for tool_name, info in WINDOWS_OFFENSIVE_TOOLS.items():
                    if fname_lower == tool_name.lower() or fname_lower.startswith(tool_name.lower().rstrip(".exe")):
                        try:
                            size = os.path.getsize(fpath)
                        except Exception:
                            size = 0
                        detected.append({
                            "name":       fname,
                            "category":   info["category"],
                            "risk":       info["risk"],
                            "state":      "installed",
                            "path":       fpath,
                            "size_bytes": size,
                            "evidence":   f"Binary found at {fpath} ({size} bytes)"
                        })
                        break
        except PermissionError:
            continue
        except Exception:
            continue

    return detected


def _check_winget() -> list:
    detected = []
    try:
        result = subprocess.run(
            ["winget", "list"],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="ignore"
        )
        for line in result.stdout.splitlines():
            line_lower = line.lower()
            for tool_name, info in WINDOWS_OFFENSIVE_TOOLS.items():
                clean = tool_name.lower().replace(".exe", "")
                if clean in line_lower and len(clean) > 3:
                    detected.append({
                        "name":     tool_name,
                        "category": info["category"],
                        "risk":     info["risk"],
                        "state":    "installed",
                        "path":     "winget package",
                        "size_bytes": 0,
                        "evidence": f"Found in winget installed packages: {line.strip()[:80]}"
                    })
                    break
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return detected


def _check_chocolatey() -> list:
    detected = []
    try:
        result = subprocess.run(
            ["choco", "list", "--local-only"],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="ignore"
        )
        for line in result.stdout.splitlines():
            line_lower = line.lower()
            for tool_name, info in WINDOWS_OFFENSIVE_TOOLS.items():
                clean = tool_name.lower().replace(".exe", "")
                if clean in line_lower and len(clean) > 3:
                    detected.append({
                        "name":     tool_name,
                        "category": info["category"],
                        "risk":     info["risk"],
                        "state":    "installed",
                        "path":     "chocolatey package",
                        "size_bytes": 0,
                        "evidence": f"Found in Chocolatey installed packages: {line.strip()[:80]}"
                    })
                    break
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return detected