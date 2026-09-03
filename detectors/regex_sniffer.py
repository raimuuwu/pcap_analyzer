import re
from typing import Optional, Dict, Any

import config



def check_sensitive_data(parsed_pkt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    payload = parsed_pkt.get("payload")

    if not payload:
        return None

    for label, pattern in config.SENSITIVE_PATTERNS.items():
        match = re.search(pattern, payload, re.IGNORECASE)
        if match:
            extracted_value = match.group(1) if match.groups() else match.group(0)

            return {
                "type": "Sensitive Data Leak",
                "category": label,
                "extracted_data": extracted_value,
                "details": f"Detected potential leakage of {label}: {extracted_value}"
            }

    return None