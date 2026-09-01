import scapy.all as scapy
from typing import Optional, Dict, Any

def parse_packet(pkt: scapy.Packet) -> Optional[Dict[str, Any]]:
    if not pkt.haslayer(scapy.IP):
        return None

    # L3 attributes (IP layer)
    sip = pkt[scapy.IP].src
    dip = pkt[scapy.IP].dst
    plen = len(pkt)

    # L4 attributes (Transport layer)
    if pkt.haslayer(scapy.TCP):
        ptype = "TCP"
        sport = pkt[scapy.TCP].sport
        dport = pkt[scapy.TCP].dport
    elif pkt.haslayer(scapy.UDP):
        ptype = "UDP"
        sport = pkt[scapy.UDP].sport
        dport = pkt[scapy.UDP].dport
    else:
        ptype = "OTHER"
        sport = None
        dport = None

    # L7 payload (Application layer raw bytes)
    if pkt.haslayer(scapy.Raw):
        payload = pkt[scapy.Raw].load.decode('utf-8', errors='ignore')
    else:
        payload = None
        
    return {
        "src_ip": sip,
        "dst_ip": dip,
        "length": plen,
        "protocol": ptype,
        "src_port": sport,
        "dst_port": dport,
        "payload": payload
    }