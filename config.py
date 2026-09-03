UNENCRYPTED_PORTS = {
    80: "HTTP",
    21: "FTP",
    23: "TELNET",
    110: "POP3",
    143: "IMAP",
    8080: "HTTP Alternate"
}

HTTP_SIGNATURES = ["HTTP/1.", "GET ", "POST ", "HEAD ", "PUT ", "DELETE "]

BASIC_AUTH_PATTERN = r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)"
POST_PARAMS_PATTERN = r"(?:username|user|login|pass|password|pwd|secret|token)=([^&\s]+)"

EMAIL_PATTERN = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
CARD_PATTERN = r"\b(?:\d[ -]*?){13,16}\b"
API_TOKEN_PATTERN = r"(?:api[_-]?key|access[_-]?token|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,})['\"]?"

SENSITIVE_PATTERNS = {
    "Email Address": EMAIL_PATTERN,
    "Credit Card Number": CARD_PATTERN,
    "API Token / Key": API_TOKEN_PATTERN
}