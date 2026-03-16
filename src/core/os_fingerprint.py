import os
import re

OFFENSIVE_DISTROS = {
    "kali":       {"distro": "Kali Linux",    "confidence": 0.97, "threat": "CRITICAL"},
    "parrot":     {"distro": "Parrot OS",     "confidence": 0.94, "threat": "CRITICAL"},
    "blackarch":  {"distro": "BlackArch",     "confidence": 0.95, "threat": "CRITICAL"},
    "tails":      {"distro": "Tails",         "confidence": 0.99, "threat": "CRITICAL"},
    "whonix":     {"distro": "Whonix",        "confidence": 0.93, "threat": "HIGH"},
    "backbox":    {"distro": "BackBox",       "confidence": 0.90, "threat": "HIGH"},
    "pentoo":     {"distro": "Pentoo",        "confidence": 0.88, "threat": "HIGH"},
    "deft":       {"distro": "DEFT Linux",    "confidence": 0.85, "threat": "MEDIUM"},
    "remnux":     {"distro": "REMnux",        "confidence": 0.86, "threat": "HIGH"},
    "dracos":     {"distro": "Dracos Linux",  "confidence": 0.84, "threat": "HIGH"},
    "cyborg":     {"distro": "Cyborg Hawk",   "confidence": 0.83, "threat": "HIGH"},
    "bugtraq":    {"distro": "Bugtraq",       "confidence": 0.82, "threat": "HIGH"},
}

RELEASE_FILES = [
    "etc/os-release", "etc/lsb-release", "etc/issue",
    "etc/issue.net", "etc/debian_version",
    "etc/kali-release", "etc/parrot-release",
    "etc/blackarch-release", "etc/tails-release",
]

OFFENSIVE_PACKAGES = [
    "metasploit-framework", "aircrack-ng", "sqlmap",
    "burpsuite", "maltego", "beef-xss", "social-engineer-toolkit",
    "volatility", "autopsy", "foremost",
]

def fingerprint_os(target: str) -> dict:
    root = target.rstrip("/") if target != "/" else ""
    evidence = []
    detected_distro = "Unknown"
    confidence = 0.0
    threat_level = "NONE"
    version = "Unknown"
    kernel = "Unknown"
    package_count = 0

    # Check release files
    for rel_file in RELEASE_FILES:
        full_path = os.path.join(root, rel_file) if root else f"/{rel_file}"
        if os.path.exists(full_path):
            try:
                content = open(full_path, errors="ignore").read().lower()
                for key, info in OFFENSIVE_DISTROS.items():
                    if key in content:
                        detected_distro = info["distro"]
                        confidence = info["confidence"]
                        threat_level = info["threat"]
                        evidence.append(f"Release file /{rel_file} identifies system as {info['distro']}")
                        ver_match = re.search(r'version[_id]*\s*=\s*["\']?([^\s"\']+)', content)
                        if ver_match:
                            version = ver_match.group(1).strip()
                        break
            except Exception:
                pass

    # Check GRUB config
    for grub_path in ["boot/grub/grub.cfg", "boot/grub2/grub.cfg"]:
        full = os.path.join(root, grub_path) if root else f"/{grub_path}"
        if os.path.exists(full):
            try:
                content = open(full, errors="ignore").read().lower()
                for key, info in OFFENSIVE_DISTROS.items():
                    if key in content:
                        evidence.append(f"GRUB bootloader references {info['distro']}")
                        if confidence < info["confidence"] - 0.1:
                            detected_distro = info["distro"]
                            confidence = info["confidence"] - 0.1
                            threat_level = info["threat"]
            except Exception:
                pass

    # Check for pre-installed offensive packages
    dpkg_path = os.path.join(root, "var/lib/dpkg/status") if root else "/var/lib/dpkg/status"
    if os.path.exists(dpkg_path):
        try:
            dpkg_content = open(dpkg_path, errors="ignore").read().lower()
            found_pkgs = [p for p in OFFENSIVE_PACKAGES if p in dpkg_content]
            if found_pkgs:
                package_count = len(found_pkgs)
                evidence.append(f"Offensive packages in DPKG: {', '.join(found_pkgs[:5])}")
                if confidence == 0.0:
                    confidence = min(0.4 + len(found_pkgs) * 0.05, 0.75)
                    detected_distro = "Unknown (offensive tools installed)"
                    threat_level = "HIGH"
        except Exception:
            pass

    # Kernel version
    proc_version = os.path.join(root, "proc/version") if root else "/proc/version"
    if os.path.exists(proc_version):
        try:
            kernel = open(proc_version, errors="ignore").read().strip()[:80]
            evidence.append(f"Kernel: {kernel}")
        except Exception:
            pass

    # Hostname
    hostname_path = os.path.join(root, "etc/hostname") if root else "/etc/hostname"
    if os.path.exists(hostname_path):
        try:
            hostname = open(hostname_path, errors="ignore").read().strip()
            evidence.append(f"Hostname: {hostname}")
            if any(k in hostname.lower() for k in ["kali", "parrot", "hack", "pwn", "tails"]):
                evidence.append(f"Hostname '{hostname}' is consistent with offensive system naming")
                confidence = min(confidence + 0.05, 1.0)
        except Exception:
            pass

    if not evidence:
        evidence.append("No offensive OS markers detected")

    return {
        "distro": detected_distro,
        "version": version,
        "kernel": kernel,
        "confidence": round(confidence, 2),
        "threat_level": threat_level,
        "offensive_packages_found": package_count,
        "evidence": evidence
    }