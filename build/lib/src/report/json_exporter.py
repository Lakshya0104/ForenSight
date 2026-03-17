import json
import os

def export_json(result: dict, output_path: str) -> None:
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"[ForenSight] JSON report exported: {output_path}")