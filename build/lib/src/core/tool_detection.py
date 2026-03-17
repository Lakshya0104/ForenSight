import os
import platform
from src.core.tool_db import load_tool_db

COMMON_BIN_PATHS = [
    "/usr/bin", "/usr/local/bin", "/usr/sbin",
    "/usr/local/sbin", "/bin", "/sbin",
]

DEEP_SCAN_PATHS = [
    "/opt", "/usr/share",
]


def detect_tools(target: str) -> list:
    if platform.system().lower() == "windows" and target not in ("/", ""):
        from src.core.windows_tool_detection import detect_tools_windows
        return detect_tools_windows(target)

    root    = target.rstrip("/") if target != "/" else ""
    tool_db = load_tool_db()
    detected = []

    # ── Step 1: Build installed set from filesystem in ONE pass ──────────
    # List every file in every bin dir once, store in a set
    # Then O(1) lookup per tool instead of O(paths) exists() calls
    installed_binaries = {}   # name → full_path
    installed_dirs     = {}   # name → full_path (for /opt, /usr/share)

    for bin_dir in COMMON_BIN_PATHS:
        full_dir = os.path.join(root, bin_dir.lstrip("/")) if root else bin_dir
        if not os.path.exists(full_dir):
            continue
        try:
            for fname in os.listdir(full_dir):
                if fname not in installed_binaries:
                    installed_binaries[fname] = os.path.join(full_dir, fname)
        except PermissionError:
            continue
        except Exception:
            continue

    for base in DEEP_SCAN_PATHS:
        full_base = os.path.join(root, base.lstrip("/")) if root else base
        if not os.path.exists(full_base):
            continue
        try:
            for fname in os.listdir(full_base):
                if fname not in installed_dirs:
                    installed_dirs[fname] = os.path.join(full_base, fname)
        except PermissionError:
            continue
        except Exception:
            continue

    # ── Step 2: Load ghost trace sources once ────────────────────────────
    dpkg_log_content  = _read_file(root, "var/log/dpkg.log")
    apt_hist_content  = _read_file(root, "var/log/apt/history.log")
    bash_hist_content = _read_file(root, "root/.bash_history")
    dpkg_info_dir     = _get_dpkg_info_dir(root)

    # ── Step 3: Cross-reference tool DB against collected sets ───────────
    seen = set()
    for tool_name, info in tool_db.items():
        if tool_name in seen:
            continue
        seen.add(tool_name)

        # Binary found in bin dirs
        if tool_name in installed_binaries:
            fpath = installed_binaries[tool_name]
            try:
                size = os.path.getsize(fpath)
            except Exception:
                size = 0
            detected.append({
                "name":       tool_name,
                "category":   info.get("category", "unknown"),
                "risk":       info.get("risk", "MEDIUM"),
                "state":      "installed",
                "path":       fpath.replace(root, "") if root else fpath,
                "size_bytes": size,
                "evidence":   f"Binary confirmed ({size} bytes)"
            })
            continue

        # Found in /opt or /usr/share
        if tool_name in installed_dirs:
            fpath = installed_dirs[tool_name]
            detected.append({
                "name":       tool_name,
                "category":   info.get("category", "unknown"),
                "risk":       info.get("risk", "MEDIUM"),
                "state":      "installed",
                "path":       fpath.replace(root, "") if root else fpath,
                "size_bytes": 0,
                "evidence":   f"Found in {fpath.replace(root,'') if root else fpath}"
            })
            continue

        # Ghost trace check — string search in pre-loaded content
        ghost = _check_ghost_fast(
            tool_name,
            dpkg_log_content,
            apt_hist_content,
            bash_hist_content,
            dpkg_info_dir
        )
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

    # Sort: CRITICAL installed → HIGH installed → CRITICAL ghost → etc.
    risk_order  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    state_order = {"installed": 0, "removed": 1}
    detected.sort(key=lambda x: (
        state_order.get(x.get("state", "removed"), 1),
        risk_order.get(x.get("risk", "LOW"), 3)
    ))
    return detected


def _read_file(root: str, rel_path: str) -> str:
    full = os.path.join(root, rel_path) if root else f"/{rel_path}"
    if not os.path.exists(full):
        return ""
    try:
        return open(full, errors="ignore").read()
    except Exception:
        return ""


def _get_dpkg_info_dir(root: str) -> set:
    """Return set of tool names that have a dpkg info file."""
    dpkg_dir = os.path.join(root, "var/lib/dpkg/info") if root else "/var/lib/dpkg/info"
    names    = set()
    if not os.path.exists(dpkg_dir):
        return names
    try:
        for fname in os.listdir(dpkg_dir):
            # fname looks like "nmap.list" or "nmap:amd64.list"
            base = fname.split(".")[0].split(":")[0]
            names.add(base)
    except Exception:
        pass
    return names


def _check_ghost_fast(
    tool_name: str,
    dpkg_log: str,
    apt_hist: str,
    bash_hist: str,
    dpkg_info_names: set
) -> str:
    """
    Fast ghost detection using pre-loaded file contents.
    All string searches on in-memory strings — no disk I/O.
    """
    traces = []

    if dpkg_log and tool_name in dpkg_log:
        lines = [l for l in dpkg_log.splitlines() if tool_name in l]
        if lines:
            traces.append(f"dpkg.log: {lines[-1].strip()[:80]}")

    if apt_hist and tool_name in apt_hist:
        traces.append(f"APT history references {tool_name}")

    if tool_name in dpkg_info_names:
        traces.append(f"DPKG info file: /var/lib/dpkg/info/{tool_name}.list")

    if bash_hist and tool_name in bash_hist:
        traces.append(f"Referenced in bash history")

    return " | ".join(traces) if traces else ""