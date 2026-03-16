import os

def detect_paradoxes(target: str) -> list:
    """
    TANVEE'S MODULE
    Detects logically impossible timestamp combinations across the filesystem.
    Returns list of paradox dicts matching sample_output.json schema.
    """
    root = target.rstrip("/")
    paradoxes = []

    SCAN_PATHS = ["etc", "var/log", "root", "home", "tmp", "usr/bin"]

    for scan_path in SCAN_PATHS:
        full_dir = os.path.join(root, scan_path)
        if not os.path.exists(full_dir):
            continue
        for fname in os.listdir(full_dir):
            fpath = os.path.join(full_dir, fname)
            try:
                s = os.stat(fpath)
                rel_path = fpath.replace(root, "")

                # Rule 1: mtime > ctime (impossible on unmanipulated files)
                if s.st_mtime > s.st_ctime:
                    paradoxes.append({
                        "type": "mtime_exceeds_ctime",
                        "file": rel_path,
                        "mtime": s.st_mtime,
                        "ctime": s.st_ctime,
                        "delta_seconds": round(s.st_mtime - s.st_ctime, 2),
                        "severity": "critical"
                    })

                # Rule 2: zero-byte file with recent mtime (wiped file)
                if s.st_size == 0 and s.st_mtime > (s.st_ctime + 60):
                    paradoxes.append({
                        "type": "wiped_file_timestamp",
                        "file": rel_path,
                        "mtime": s.st_mtime,
                        "ctime": s.st_ctime,
                        "severity": "high"
                    })

            except Exception:
                pass

    return paradoxes