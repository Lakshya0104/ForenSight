import os

EFI_PATHS = [
    "/sys/firmware/efi/efivars",
    "/sys/firmware/efi",
    "/boot/efi",
]

def fingerprint_uefi() -> dict:
    """
    VENKAT'S MODULE
    Reads UEFI firmware variables to detect USB boot signatures
    and boot history that survives OS wipes.
    """
    result = {
        "usb_boot_signature": False,
        "last_boot_device": "Unknown",
        "boot_entries": [],
        "firmware_evidence": "No EFI data accessible"
    }

    efi_vars_path = "/sys/firmware/efi/efivars"
    if not os.path.exists(efi_vars_path):
        result["firmware_evidence"] = "EFI vars not accessible (run as root on Linux)"
        return result

    try:
        entries = os.listdir(efi_vars_path)
        boot_entries = [e for e in entries if e.startswith("Boot")]
        result["boot_entries"] = boot_entries[:10]

        usb_indicators = [e for e in entries if "usb" in e.lower() or "removable" in e.lower()]
        if usb_indicators:
            result["usb_boot_signature"] = True
            result["last_boot_device"] = "USB"
            result["firmware_evidence"] = f"USB boot indicators found: {usb_indicators[:3]}"
    except PermissionError:
        result["firmware_evidence"] = "Permission denied — re-run as root"
    except Exception as e:
        result["firmware_evidence"] = f"Error reading EFI vars: {str(e)}"

    return result