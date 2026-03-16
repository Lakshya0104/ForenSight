import os
from datetime import datetime

IMPORTANT_PATHS = [
    "etc", "var/log", "root", "home",
    "tmp", "var/tmp", "usr/bin", "usr/local/bin",
    "opt", "bin", "sbin", "usr/sbin",
]

SUSPICIOUS_EXTENSIONS = {".sh", ".py", ".pl", ".rb", ".elf", ".so", ".ko"}
SUSPICIOUS_NAMES = {"payload", "backdoor", "shell", "exploit", "hack", "pwn", "root", "crack"}

def build_timeline(target: str) -> dict:
    root = target.rstrip("/") if target != "/" else ""
    events = []
    suspicious_files = []
    recently_modified = []
    recently_accessed = []

    for scan_path in IMPORTANT_PATHS:
        full_dir = os.path.join(root, scan_path) if root else f"/{scan_path}"
        if not os.path.exists(full_dir):
            continue
        try:
            entries = os.listdir(full_dir)
        except PermissionError:
            continue

        for fname in entries:
            fpath = os.path.join(full_dir, fname)
            try:
                s = os.stat(fpath)
                rel = fpath.replace(root, "") if root else fpath
                ext = os.path.splitext(fname)[1].lower()
                name_lower = fname.lower()

                event = {
                    "file": rel,
                    "atime": datetime.utcfromtimestamp(s.st_atime).isoformat(),
                    "mtime": datetime.utcfromtimestamp(s.st_mtime).isoformat(),
                    "ctime": datetime.utcfromtimestamp(s.st_ctime).isoformat(),
                    "size_bytes": s.st_size,
                    "suspicious": False,
                    "flags": []
                }

                # Flag suspicious files
                if ext in SUSPICIOUS_EXTENSIONS:
                    event["suspicious"] = True
                    event["flags"].append(f"suspicious extension: {ext}")
                if any(kw in name_lower for kw in SUSPICIOUS_NAMES):
                    event["suspicious"] = True
                    event["flags"].append("suspicious filename keyword")
                if s.st_size == 0 and ext not in {".log", ".pid"}:
                    event["flags"].append("zero-byte file")
                try:
                    mode = oct(s.st_mode)
                    if mode.endswith("777"):
                        event["flags"].append("world-writable (777)")
                        event["suspicious"] = True
                except Exception:
                    pass

                events.append(event)
                if event["suspicious"]:
                    suspicious_files.append(rel)

            except (PermissionError, OSError):
                continue

    events.sort(key=lambda x: x["mtime"], reverse=True)
    recently_modified = [e["file"] for e in events[:20]]
    recently_accessed = sorted(events, key=lambda x: x["atime"], reverse=True)
    recently_accessed = [e["file"] for e in recently_accessed[:20]]

    return {
        "total_files_scanned": len(events),
        "suspicious_files_found": len(suspicious_files),
        "suspicious_files": suspicious_files[:20],
        "recently_modified": recently_modified,
        "recently_accessed": recently_accessed[:20],
        "full_timeline": events[:150]
    }