import os
from datetime import datetime, timezone

SCAN_PATHS = [
    "etc", "var/log", "root", "home", "tmp",
    "usr/bin", "usr/local/bin", "usr/sbin",
    "opt", "bin", "sbin", "var/tmp",
    "var/lib/dpkg", "var/cache/apt"
]

# These paths are managed by package managers — round timestamps are normal
# Only flag mtime > ctime here, never round timestamps
SYSTEM_PATHS = {
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/lib", "/lib", "/usr/share",
    "/var/lib/dpkg", "/var/cache/apt",
    "/etc/alternatives"
}

# Only scan these file types for timestamp paradoxes
INTERESTING_EXTENSIONS = {
    ".sh", ".py", ".pl", ".rb", ".php",
    ".elf", ".so", ".ko", ".bin",
    ".log", ".conf", ".cfg", ".txt",
    ".json", ".xml", ".csv",
    ""  # no extension (binaries, scripts)
}

SEVERITY_WEIGHTS = {
    "mtime_exceeds_ctime":      {"severity": "critical", "score": 10},
    "atime_before_creation":    {"severity": "critical", "score": 10},
    "all_timestamps_identical": {"severity": "high",     "score": 6},
    "future_timestamp":         {"severity": "high",     "score": 8},
    "pre_epoch_timestamp":      {"severity": "critical", "score": 10},
    "suspicious_round_mtime":   {"severity": "medium",   "score": 4},
    "zero_byte_recent_mtime":   {"severity": "high",     "score": 6},
}


def _is_system_path(filepath: str) -> bool:
    for sp in SYSTEM_PATHS:
        if filepath.startswith(sp):
            return True
    return False


def _is_interesting_file(fname: str, fpath: str) -> bool:
    ext = os.path.splitext(fname)[1].lower()
    return ext in INTERESTING_EXTENSIONS


def detect_paradoxes(target: str) -> list:
    root  = target.rstrip("/") if target != "/" else ""
    now   = datetime.now(timezone.utc).timestamp()
    found = []
    seen  = set()

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
            if fpath in seen:
                continue
            seen.add(fpath)

            try:
                s   = os.stat(fpath)
                rel = fpath.replace(root, "") if root else fpath
                at  = s.st_atime
                mt  = s.st_mtime
                ct  = s.st_ctime

                at_str = datetime.utcfromtimestamp(at).isoformat()
                mt_str = datetime.utcfromtimestamp(mt).isoformat()
                ct_str = datetime.utcfromtimestamp(ct).isoformat()

                is_sys = _is_system_path(rel)

                # ── Rule 1: mtime > ctime ─────────────────────────────────
                # THE real paradox. Fires everywhere — system or not.
                # This is the only rule that fires on system paths.
                if mt > ct + 1.0:
                    meta = SEVERITY_WEIGHTS["mtime_exceeds_ctime"]
                    found.append({
                        "type":           "mtime_exceeds_ctime",
                        "description":    "File content timestamp is NEWER than metadata timestamp — physically impossible without timestomping",
                        "file":           rel,
                        "mtime":          mt_str,
                        "ctime":          ct_str,
                        "atime":          at_str,
                        "delta_seconds":  round(mt - ct, 3),
                        "severity":       meta["severity"],
                        "threat_score":   meta["score"],
                        "court_note":     "POSIX invariant violation: mtime MUST be <= ctime on unmanipulated files. This file was timestomped.",
                        "attacker_action": f"Attacker ran: touch -m -t {datetime.utcfromtimestamp(mt).strftime('%Y%m%d%H%M')} {rel}"
                    })

                # Skip noisy rules for system-managed paths
                if is_sys:
                    continue

                # ── Rule 2: atime before ctime ────────────────────────────
                # Only on non-system files — user files, scripts, tmp, home
                if at < ct - 120 and not is_sys:
                    meta = SEVERITY_WEIGHTS["atime_before_creation"]
                    found.append({
                        "type":           "atime_before_creation",
                        "description":    "File was accessed BEFORE it was created — retroactive access is impossible",
                        "file":           rel,
                        "atime":          at_str,
                        "ctime":          ct_str,
                        "delta_seconds":  round(ct - at, 3),
                        "severity":       meta["severity"],
                        "threat_score":   meta["score"],
                        "court_note":     "Access timestamp predates creation timestamp. Attacker set atime to a date before the file existed.",
                        "attacker_action": f"Attacker manipulated atime to appear as if file existed before {ct_str}"
                    })

                # ── Rule 3: All timestamps identical ──────────────────────
                # Only on non-system files AND must be large enough to matter
                # AND must be in suspicious locations (tmp, home, opt, root)
                suspicious_dirs = ["/tmp", "/var/tmp", "/home", "/root", "/opt"]
                in_suspicious   = any(rel.startswith(d) for d in suspicious_dirs)

                if (in_suspicious and
                    abs(at - mt) < 0.001 and
                    abs(mt - ct) < 0.001 and
                    s.st_size > 4096):
                    meta = SEVERITY_WEIGHTS["all_timestamps_identical"]
                    found.append({
                        "type":           "all_timestamps_identical",
                        "description":    "All three timestamps are identical on a non-trivial file in a suspicious location — hallmark of timestomp tools",
                        "file":           rel,
                        "timestamp":      mt_str,
                        "file_size_bytes":s.st_size,
                        "delta_seconds":  0.0,
                        "severity":       meta["severity"],
                        "threat_score":   meta["score"],
                        "court_note":     f"Statistical impossibility: all timestamps identical on {s.st_size}-byte file in {rel.split('/')[1]}. Tools like timestomp set all timestamps simultaneously.",
                        "attacker_action": "Attacker ran: timestomp or touch -amt on this file"
                    })

                # ── Rule 4: Future timestamp ──────────────────────────────
                if mt > now + 60:
                    meta = SEVERITY_WEIGHTS["future_timestamp"]
                    found.append({
                        "type":           "future_timestamp",
                        "description":    "Modification timestamp is set in the future — impossible without deliberate manipulation",
                        "file":           rel,
                        "mtime":          mt_str,
                        "current_time":   datetime.utcfromtimestamp(now).isoformat(),
                        "delta_seconds":  round(mt - now, 3),
                        "severity":       meta["severity"],
                        "threat_score":   meta["score"],
                        "court_note":     "Future timestamps cannot occur naturally. Attacker set timestamp ahead of real time to confuse timeline reconstruction.",
                        "attacker_action": f"Attacker set mtime to future date: {mt_str}"
                    })

                # ── Rule 5: Pre-epoch timestamp ───────────────────────────
                if mt < 0 or ct < 0 or at < 0:
                    meta = SEVERITY_WEIGHTS["pre_epoch_timestamp"]
                    found.append({
                        "type":           "pre_epoch_timestamp",
                        "description":    "Timestamp is before Unix epoch (1970-01-01) — direct inode manipulation",
                        "file":           rel,
                        "mtime":          str(mt),
                        "ctime":          str(ct),
                        "delta_seconds":  abs(min(mt, ct, at)),
                        "severity":       meta["severity"],
                        "threat_score":   meta["score"],
                        "court_note":     "Pre-epoch timestamps require direct raw inode editing. This is extreme evidence tampering.",
                        "attacker_action": "Attacker used raw disk editor to directly modify inode timestamps"
                    })

                # ── Rule 6: Suspicious round mtime ───────────────────────
                # Only in user-controlled dirs, only large files, only
                # if ctime is significantly different (proving it was set)
                mt_dt = datetime.utcfromtimestamp(mt)
                if (in_suspicious and
                    mt_dt.hour == 0 and mt_dt.minute == 0 and mt_dt.second == 0 and
                    s.st_size > 4096 and
                    abs(mt - ct) > 300):   # ctime must differ by 5+ mins
                    meta = SEVERITY_WEIGHTS["suspicious_round_mtime"]
                    found.append({
                        "type":           "suspicious_round_mtime",
                        "description":    "Modification time is exactly midnight with significant ctime divergence — manually set timestamp",
                        "file":           rel,
                        "mtime":          mt_str,
                        "ctime":          ct_str,
                        "file_size_bytes":s.st_size,
                        "delta_seconds":  round(abs(mt - ct), 3),
                        "severity":       meta["severity"],
                        "threat_score":   meta["score"],
                        "court_note":     "Midnight timestamps with ctime divergence indicate manual timestamp setting via touch command.",
                        "attacker_action": f"Attacker ran: touch -m -t {mt_dt.strftime('%Y%m%d')}0000 {rel}"
                    })

                # ── Rule 7: Zero-byte log wipe ────────────────────────────
                # Only actual log files, not just any zero-byte file
                log_indicators = ["auth", "syslog", "kern", "messages",
                                   "secure", "wtmp", "btmp", "lastlog", "history"]
                is_log = any(indicator in fname.lower() for indicator in log_indicators)

                if (is_log and s.st_size == 0 and abs(mt - ct) < 10):
                    meta = SEVERITY_WEIGHTS["zero_byte_recent_mtime"]
                    found.append({
                        "type":           "zero_byte_recent_mtime",
                        "description":    "Log file truncated to zero bytes — deliberate evidence destruction",
                        "file":           rel,
                        "mtime":          mt_str,
                        "ctime":          ct_str,
                        "file_size_bytes":0,
                        "delta_seconds":  round(abs(mt - ct), 3),
                        "severity":       meta["severity"],
                        "threat_score":   meta["score"],
                        "court_note":     "Named log file reduced to zero bytes. The act of wiping updated both mtime and ctime simultaneously, proving deliberate destruction.",
                        "attacker_action": f"Attacker ran: cat /dev/null > {rel}  or  truncate -s 0 {rel}"
                    })

            except (PermissionError, OSError, ValueError):
                continue

    # Sort: critical first, then by threat score descending
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    found.sort(key=lambda x: (
        severity_order.get(x.get("severity", "low"), 3),
        -x.get("threat_score", 0)
    ))

    return found


def get_paradox_summary(paradoxes: list) -> dict:
    if not paradoxes:
        return {
            "total":             0,
            "critical":          0,
            "high":              0,
            "medium":            0,
            "total_threat_score":0,
            "most_severe_file":  None,
            "verdict":           "No timestamp anomalies detected"
        }
    critical    = [p for p in paradoxes if p.get("severity") == "critical"]
    high        = [p for p in paradoxes if p.get("severity") == "high"]
    medium      = [p for p in paradoxes if p.get("severity") == "medium"]
    total_score = sum(p.get("threat_score", 0) for p in paradoxes)
    return {
        "total":             len(paradoxes),
        "critical":          len(critical),
        "high":              len(high),
        "medium":            len(medium),
        "total_threat_score":total_score,
        "most_severe_file":  paradoxes[0].get("file") if paradoxes else None,
        "verdict": (
            "CONFIRMED TAMPERING — multiple critical timestamp violations detected"
            if critical else
            "LIKELY TAMPERING — high-severity timestamp anomalies found"
            if high else
            "SUSPICIOUS — timestamp anomalies require investigation"
        )
    }