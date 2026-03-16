import os

OFFENSIVE_DISTROS = {
    "kali": {"distro": "Kali Linux", "confidence": 0.95},
    "parrot": {"distro": "Parrot OS", "confidence": 0.93},
    "blackarch": {"distro": "BlackArch", "confidence": 0.94},
    "tails": {"distro": "Tails", "confidence": 0.97},
    "whonix": {"distro": "Whonix", "confidence": 0.91},
    "backbox": {"distro": "BackBox", "confidence": 0.88},
}

RELEASE_FILES = [
    "/etc/os-release",
    "/etc/lsb-release",
    "/etc/issue",
    "/etc/kali-release",
    "/etc/parrot-release",
]

def fingerprint_os(target: str) -> dict:
    evidence = []
    detected_distro = "Unknown"
    confidence = 0.0

    for rel_file in RELEASE_FILES:
        full_path = os.path.join(target.rstrip("/"), rel_file.lstrip("/"))
        if os.path.exists(full_path):
            try:
                with open(full_path, "r", errors="ignore") as f:
                    content = f.read().lower()
                for key, info in OFFENSIVE_DISTROS.items():
                    if key in content:
                        detected_distro = info["distro"]
                        confidence = info["confidence"]
                        evidence.append(f"Found {rel_file} containing '{key}'")
                        break
            except Exception:
                pass

    grub_path = os.path.join(target.rstrip("/"), "boot/grub/grub.cfg")
    if os.path.exists(grub_path):
        try:
            with open(grub_path, "r", errors="ignore") as f:
                grub_content = f.read().lower()
            for key in OFFENSIVE_DISTROS:
                if key in grub_content:
                    evidence.append(f"GRUB config references '{key}'")
                    if confidence == 0.0:
                        detected_distro = OFFENSIVE_DISTROS[key]["distro"]
                        confidence = 0.75
        except Exception:
            pass

    if not evidence:
        evidence.append("No offensive distro markers found")

    return {
        "distro": detected_distro,
        "confidence": confidence,
        "evidence": evidence
    }