import os
import stat

def build_timeline(target: str) -> list:
    root = target.rstrip("/")
    events = []

    SCAN_PATHS = [
        "etc", "var/log", "root", "home",
        "tmp", "usr/bin", "opt"
    ]

    for scan_path in SCAN_PATHS:
        full_dir = os.path.join(root, scan_path)
        if not os.path.exists(full_dir):
            continue
        for fname in os.listdir(full_dir):
            fpath = os.path.join(full_dir, fname)
            try:
                s = os.stat(fpath)
                events.append({
                    "file": fpath.replace(root, ""),
                    "atime": s.st_atime,
                    "mtime": s.st_mtime,
                    "ctime": s.st_ctime,
                    "size": s.st_size
                })
            except Exception:
                pass

    events.sort(key=lambda x: x["mtime"], reverse=True)
    return events[:100]