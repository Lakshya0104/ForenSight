"""
forensight — Linux Forensic Intelligence System
Entry point for the `forensight` CLI command.

Usage:
    forensight /                        scan live system
    forensight /mnt/disk                scan mounted disk image
    forensight / -o report.json         custom output path
    forensight / --serve                live dashboard at localhost:5000
    forensight / --verbose              full paradox table
    forensight / --update-db            refresh tool DB from Kali apt
    forensight / --demo                 demo mode (simulated Tails scenario)
    forensight / --serve --update-db    update DB + live dashboard
"""

import argparse
import os
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="forensight",
        description=(
            "ForenSight — Linux Forensic Intelligence System\n"
            "Team Cyber Nuggets  ·  v1.0.0"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  forensight /                          # scan live system\n"
            "  forensight /mnt/disk                  # scan mounted disk image\n"
            "  forensight / -o report.json           # custom output path\n"
            "  forensight / --serve                  # live dashboard at localhost:5000\n"
            "  forensight / --verbose                # full paradox table\n"
            "  forensight / --update-db              # refresh tool DB from Kali apt\n"
            "  forensight / --demo                   # simulated Tails scenario\n"
            "  forensight / --serve --update-db      # update DB + dashboard\n"
            "\n"
            "SSH workflow (two-laptop demo):\n"
            "  ssh kali@192.168.x.x          # connect to seized machine\n"
            "  forensight / --serve          # scan + stream to browser\n"
            "  # Open http://192.168.x.x:5000 on investigator laptop\n"
        )
    )

    parser.add_argument(
        "target",
        help="Target path — use / for live system, or path to mounted disk image"
    )
    parser.add_argument(
        "-o", "--output",
        default="forensight_report.json",
        metavar="FILE",
        help="Output JSON report path (default: forensight_report.json)"
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start live dashboard at localhost:5000"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full paradox table and extended output"
    )
    parser.add_argument(
        "--update-db",
        dest="update_db",
        action="store_true",
        help="Refresh tool database from Kali apt repos (~30s, run once)"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with simulated Tails OS attack scenario"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        metavar="PORT",
        help="Dashboard port (default: 5000)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ForenSight v1.0.0 — Team Cyber Nuggets"
    )

    args = parser.parse_args()

    # Ensure we're running from the ForenSight directory so all imports resolve
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    # Import and run the scan
    try:
        from main import run_scan
    except ImportError as e:
        print(f"\n[forensight] Import error: {e}")
        print("[forensight] Make sure you installed with: pip install -e .")
        sys.exit(1)

    run_scan(
        target    = args.target,
        output_path = args.output,
        demo      = args.demo,
        verbose   = args.verbose,
        update_db = args.update_db,
        serve     = args.serve,
    )


if __name__ == "__main__":
    main()