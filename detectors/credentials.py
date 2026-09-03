import re
import base64
from typing import Optional, Dict, Any

import config


def check_credentials(parsed_pkt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    payload = parsed_pkt.get("payload")
    if not payload:
        return None

    basic_auth_match = re.search(config.BASIC_AUTH_PATTERN, payload, re.IGNORECASE)
    if basic_auth_match:
        encoded_creds = basic_auth_match.group(1)
        try:
            decoded_creds = base64.b64decode(encoded_creds).decode("utf-8", errors="ignore")
        except Exception:
            decoded_creds = encoded_creds

        return {
            "type": "Cleartext Credentials",
            "subtype": "Basic Auth",
            "extracted_data": decoded_creds,
            "details": f"Found Basic Authentication credentials: {decoded_creds}"
        }

    matched_params = re.findall(config.POST_PARAMS_PATTERN, payload, re.IGNORECASE)
    if matched_params:
        return {
            "type": "Cleartext Credentials",
            "subtype": "Form Parameter",
            "extracted_data": matched_params,
            "details": f"Found potential sensitive data in parameters: {matched_params}"
        }

    return None