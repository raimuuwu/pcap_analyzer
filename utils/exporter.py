import json
import sys
from typing import Dict, Any


def export_to_json(data: Dict[str, Any], filepath: str) -> bool:
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"[+] Successfully exported report to: {filepath}")
        return True
    except Exception as e:
        print(f"[!] Failed to export report to {filepath}: {e}", file=sys.stderr)
        return False