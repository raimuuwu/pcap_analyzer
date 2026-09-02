from typing import Optional, Dict, Any

UNENCRYPTED_PORTS = {
    80: "HTTP",
    8080: "HTTP-Alt",
    21: "FTP",
    23: "Telnet",
    110: "POP3",
    143: "IMAP",
}

HTTP_SIGNATURES = ["HTTP/1.", "GET ", "POST ", "HEAD ", "PUT ", "DELETE "]


def check_unencrypted(parsed_pkt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    sport = parsed_pkt.get("src_port")
    dport = parsed_pkt.get("dst_port")
    payload = parsed_pkt.get("payload")

    detected_protocol = None
    matched_port = None

    if sport in UNENCRYPTED_PORTS:
        detected_protocol = UNENCRYPTED_PORTS[sport]
        matched_port = sport
    elif dport in UNENCRYPTED_PORTS:
        detected_protocol = UNENCRYPTED_PORTS[dport]
        matched_port = dport

    if not detected_protocol and payload:
        if any(sig in payload for sig in HTTP_SIGNATURES):
            detected_protocol = "HTTP (Payload Detected)"
            matched_port = dport or sport

    if not detected_protocol:
        return None

    return {
        "type": "Unencrypted Protocol",
        "protocol": detected_protocol,
        "port": matched_port,
        "details": f"Insecure traffic detected on port {matched_port} ({detected_protocol}).",
    }