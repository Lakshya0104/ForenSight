import os
from datetime import datetime, timezone

SCAN_PATHS = [
    "etc", "var/log", "root", "home", "tmp",
    "usr/bin", "usr/local/bin", "usr/sbin",
    "opt", "bin", "sbin", "var/tmp",
    "var/lib/dpkg", "var/cache/apt"
]

SEVERITY_WEIGHTS = {
    "mtime_exceeds_ctime":      {"severity": "critical", "score": 10},
    "atime_before_creation":    {"severity": "critical", "score": 10},
    "all_timestamps_identical": {"severity": "high",     "score": 6},
    "future_timestamp":         {"severity": "high",     "score": 8},
    "pre_epoch_timestamp":      {"severity": "critical", "score": 10},
    "suspicious_round_mtime":   {"severity": "medium",   "score": 4},
    "zero_byte_recent_mtime":   {"severity": "high",     "score": 6},
}

def detect_paradoxes(target: str) -> list:
    root   = target.rstrip("/") if target != "/" else ""
    now    = datetime.now(timezone.utc).timestamp()
    found  = []
    seen   = set()

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

                # ── Rule 1: mtime > ctime ─────────────────────────────────
                # The crown jewel. Content modified after metadata changed.
                # Physically impossible without timestomping.
                if mt > ct + 1.0:
                    meta = SEVERITY_WEIGHTS["mtime_exceeds_ctime"]
                    found.append({
                        "type":        "mtime_exceeds_ctime",
                        "description": "File content timestamp is NEWER than metadata timestamp — physically impossible without timestomping",
                        "file":        rel,
                        "mtime":       mt_str,
                        "ctime":       ct_str,
                        "atime":       at_str,
                        "delta_seconds": round(mt - ct, 3),
                        "severity":    meta["severity"],
                        "threat_score":meta["score"],
                        "court_note":  "POSIX invariant violation: mtime MUST be <= ctime on unmanipulated files. This file was timestomped.",
                        "attacker_action": f"Attacker ran: touch -m -t {datetime.utcfromtimestamp(mt).strftime('%Y%m%d%H%M')} {rel}"
                    })

                # ── Rule 2: atime before ctime by significant margin ───────
                # File accessed before it was created — impossible.
                if at < ct - 120:
                    meta = SEVERITY_WEIGHTS["atime_before_creation"]
                    found.append({
                        "type":        "atime_before_creation",
                        "description": "File was accessed BEFORE it was created — retroactive access is impossible",
                        "file":        rel,
                        "atime":       at_str,
                        "ctime":       ct_str,
                        "delta_seconds": round(ct - at, 3),
                        "severity":    meta["severity"],
                        "threat_score":meta["score"],
                        "court_note":  "Access timestamp predates creation timestamp. Attacker set atime to a date before the file existed.",
                        "attacker_action": f"Attacker manipulated atime to appear as if file existed before {ct_str}"
                    })

                # ── Rule 3: All three timestamps identical on large file ───
                # Tools like timestomp set all three at once.
                # Probability of natural occurrence on files > 1KB: near zero.
                if (abs(at - mt) < 0.001 and
                    abs(mt - ct) < 0.001 and
                    abs(at - ct) < 0.001 and
                    s.st_size > 1024):
                    meta = SEVERITY_WEIGHTS["all_timestamps_identical"]
                    found.append({
                        "type":        "all_timestamps_identical",
                        "description": "All three timestamps are identical on a non-trivial file — hallmark of timestomp tools",
                        "file":        rel,
                        "timestamp":   mt_str,
                        "file_size_bytes": s.st_size,
                        "delta_seconds": 0.0,
                        "severity":    meta["severity"],
                        "threat_score":meta["score"],
                        "court_note":  f"Statistical impossibility: all timestamps identical on {s.st_size}-byte file. Tools like timestomp set all timestamps simultaneously.",
                        "attacker_action": "Attacker ran: timestomp or touch -amt on this file"
                    })

                # ── Rule 4: Future timestamp ──────────────────────────────
                # Timestamp set ahead of current time.
                if mt > now + 60:
                    meta = SEVERITY_WEIGHTS["future_timestamp"]
                    found.append({
                        "type":        "future_timestamp",
                        "description": "Modification timestamp is set in the future — impossible without deliberate manipulation",
                        "file":        rel,
                        "mtime":       mt_str,
                        "current_time":datetime.utcfromtimestamp(now).isoformat(),
                        "delta_seconds": round(mt - now, 3),
                        "severity":    meta["severity"],
                        "threat_score":meta["score"],
                        "court_note":  "Future timestamps cannot occur naturally. Attacker set timestamp ahead of real time to confuse timeline reconstruction.",
                        "attacker_action": f"Attacker set mtime to future date: {mt_str}"
                    })

                # ── Rule 5: Pre-epoch timestamp ───────────────────────────
                # Before Unix time 0 (1970-01-01). Physically impossible.
                if mt < 0 or ct < 0 or at < 0:
                    meta = SEVERITY_WEIGHTS["pre_epoch_timestamp"]
                    found.append({
                        "type":        "pre_epoch_timestamp",
                        "description": "Timestamp is before Unix epoch (1970-01-01) — direct inode manipulation",
                        "file":        rel,
                        "mtime":       str(mt),
                        "ctime":       str(ct),
                        "delta_seconds": abs(min(mt, ct, at)),
                        "severity":    meta["severity"],
                        "threat_score":meta["score"],
                        "court_note":  "Pre-epoch timestamps require direct raw inode editing. This is extreme evidence tampering.",
                        "attacker_action": "Attacker used raw disk editor to directly modify inode timestamps"
                    })

                # ── Rule 6: Suspiciously round mtime ─────────────────────
                # touch -t sets exact times — often round numbers like
                # 2020-01-01 00:00:00 which never occur naturally.
                mt_dt = datetime.utcfromtimestamp(mt)
                if (mt_dt.hour == 0 and mt_dt.minute == 0 and
                    mt_dt.second == 0 and s.st_size > 512):
                    meta = SEVERITY_WEIGHTS["suspicious_round_mtime"]
                    found.append({
                        "type":        "suspicious_round_mtime",
                        "description": "Modification time is exactly midnight — characteristic of manually set timestamps",
                        "file":        rel,
                        "mtime":       mt_str,
                        "file_size_bytes": s.st_size,
                        "delta_seconds": 0.0,
                        "severity":    meta["severity"],
                        "threat_score":meta["score"],
                        "court_note":  "Naturally occurring file modifications virtually never land exactly at 00:00:00. This timestamp was set manually.",
                        "attacker_action": f"Attacker ran: touch -m -t {mt_dt.strftime('%Y%m%d')}0000 {rel}"
                    })

                # ── Rule 7: Zero-byte file with recent mtime ──────────────
                # File was wiped (truncated to zero) but mtime updated —
                # classic log wipe signature.
                if (s.st_size == 0 and
                    mt > ct - 5 and
                    any(log in fname for log in ["log", "auth", "syslog", "history", "wtmp"])):
                    meta = SEVERITY_WEIGHTS["zero_byte_recent_mtime"]
                    found.append({
                        "type":        "zero_byte_recent_mtime",
                        "description": "Log file truncated to zero bytes — deliberate evidence destruction",
                        "file":        rel,
                        "mtime":       mt_str,
                        "ctime":       ct_str,
                        "file_size_bytes": 0,
                        "delta_seconds": round(abs(mt - ct), 3),
                        "severity":    meta["severity"],
                        "threat_score":meta["score"],
                        "court_note":  "File is a log with zero bytes — wiped. The act of wiping updated mtime, proving deliberate destruction.",
                        "attacker_action": f"Attacker ran: cat /dev/null > {rel}  or  truncate -s 0 {rel}"
                    })

            except (PermissionError, OSError, ValueError):
                continue

    # Sort by severity then threat score
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    found.sort(key=lambda x: (
        severity_order.get(x.get("severity", "low"), 3),
        -x.get("threat_score", 0)
    ))

    return found


def get_paradox_summary(paradoxes: list) -> dict:
    if not paradoxes:
        return {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "total_threat_score": 0,
            "most_severe_file": None,
            "verdict": "No timestamp anomalies detected"
        }

    critical = [p for p in paradoxes if p.get("severity") == "critical"]
    high     = [p for p in paradoxes if p.get("severity") == "high"]
    medium   = [p for p in paradoxes if p.get("severity") == "medium"]
    total_score = sum(p.get("threat_score", 0) for p in paradoxes)

    return {
        "total":             len(paradoxes),
        "critical":          len(critical),
        "high":              len(high),
        "medium":            len(medium),
        "total_threat_score":total_score,
        "most_severe_file":  paradoxes[0].get("file") if paradoxes else None,
        "verdict":           (
            "CONFIRMED TAMPERING — multiple critical timestamp violations detected"
            if critical else
            "LIKELY TAMPERING — high-severity timestamp anomalies found"
            if high else
            "SUSPICIOUS — timestamp anomalies require investigation"
        )
    }