import os
from datetime import datetime

SCAN_PATHS = [
    "etc", "var/log", "root", "home", "tmp",
    "usr/bin", "usr/local/bin", "opt", "bin", "sbin"
]

def detect_paradoxes(target: str) -> list:
    root = target.rstrip("/") if target != "/" else ""
    paradoxes = []

    for scan_path in SCAN_PATHS:
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
                at, mt, ct = s.st_atime, s.st_mtime, s.st_ctime

                # Rule 1: mtime > ctime (impossible — content changed without metadata update)
                if mt > ct + 1.0:
                    paradoxes.append({
                        "type": "mtime_exceeds_ctime",
                        "description": "File content modified AFTER metadata — physically impossible without timestomping",
                        "file": rel,
                        "mtime": datetime.utcfromtimestamp(mt).isoformat(),
                        "ctime": datetime.utcfromtimestamp(ct).isoformat(),
                        "delta_seconds": round(mt - ct, 3),
                        "severity": "critical",
                        "court_note": "Violation of POSIX invariant: mtime <= ctime on unmanipulated files"
                    })

                # Rule 2: atime < ctime (file accessed before it was created)
                if at < ct - 60:
                    paradoxes.append({
                        "type": "atime_before_creation",
                        "description": "File was accessed before it was created — impossible without manipulation",
                        "file": rel,
                        "atime": datetime.utcfromtimestamp(at).isoformat(),
                        "ctime": datetime.utcfromtimestamp(ct).isoformat(),
                        "delta_seconds": round(ct - at, 3),
                        "severity": "critical",
                        "court_note": "Access timestamp predates creation — evidence of retroactive timestomping"
                    })

                # Rule 3: All timestamps identical (tool set them all at once)
                if abs(at - mt) < 0.001 and abs(mt - ct) < 0.001 and abs(at - ct) < 0.001:
                    if s.st_size > 1024:
                        paradoxes.append({
                            "type": "all_timestamps_identical",
                            "description": "All three timestamps are identical on a non-trivial file — hallmark of timestamp-setting tools",
                            "file": rel,
                            "timestamp": datetime.utcfromtimestamp(mt).isoformat(),
                            "file_size": s.st_size,
                            "delta_seconds": 0.0,
                            "severity": "high",
                            "court_note": "Probability of natural identical timestamps approaches zero on files > 1KB"
                        })

                # Rule 4: Zero-byte file with future mtime
                now = datetime.utcnow().timestamp()
                if s.st_size == 0 and mt > now:
                    paradoxes.append({
                        "type": "future_timestamp",
                        "description": "File has a modification time in the future",
                        "file": rel,
                        "mtime": datetime.utcfromtimestamp(mt).isoformat(),
                        "delta_seconds": round(mt - now, 3),
                        "severity": "high",
                        "court_note": "Future timestamps indicate deliberate timestamp manipulation"
                    })

                # Rule 5: mtime before filesystem epoch (Unix time 0 or negative)
                if mt < 0 or ct < 0:
                    paradoxes.append({
                        "type": "pre_epoch_timestamp",
                        "description": "Timestamp is before Unix epoch (1970-01-01) — impossible on real files",
                        "file": rel,
                        "mtime": str(mt),
                        "delta_seconds": abs(mt),
                        "severity": "critical",
                        "court_note": "Pre-epoch timestamps are physically impossible and indicate direct inode manipulation"
                    })

            except (PermissionError, OSError):
                continue

    paradoxes.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2}.get(x["severity"], 3))
    return paradoxes