# ForenSight

A Python-based forensic analysis tool built exclusively for Linux environments.
Designed for investigators facing offensive and privacy-focused systems.

## Team Cyber Nuggets
- Jyothir Adithya V B — Core engine + OS/tool detection
- Lakshya S — Dashboard UI + evasion scoring
- Potnuru Tanvee Satya — Temporal Paradox Engine + MITRE mapping
- Pasam Venkat Pavan — UEFI fingerprinting + persona + report

## Usage
```bash
python main.py /          # scan live system
python main.py /mnt/disk  # scan mounted disk image
python main.py / --output report.json
```

## Project Structure
```
src/
  core/        → OS fingerprint, tool detection, log analysis, timeline
  novelty/     → Temporal paradox, MITRE mapper, UEFI, persona
  report/      → JSON export, PDF generator, narrative engine
  ui/          → Dashboard (Lakshya)
tests/
main.py
```