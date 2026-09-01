from pathlib import Path
from typing import Union
import scapy.all as scapy

VALID_EXTENSIONS = {".pcap", ".pcapng"}


def validate_path(file_path: Union[str, Path]) -> Path:
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File does not exist: {path}")

    if path.suffix.lower() not in VALID_EXTENSIONS:
        raise ValueError(
            f"Invalid file extension: {path.suffix}. Expected one of {VALID_EXTENSIONS}")

    return path


def read_pcap_file(file_path: Union[str, Path]) -> scapy.PacketList:
    validated_path = validate_path(file_path)

    try:
        packets = scapy.rdpcap(str(validated_path))
        return packets
    except Exception as e:
        raise ValueError(f"Error reading PCAP file: {e}")


def live_capture(count: int = 0, iface: str = None) -> scapy.PacketList:
    try:
        print(
            f"Starting live capture on interface '{iface or 'default'}' (packet limit: {count})...")
        packets = scapy.sniff(iface=iface, count=count)
        return packets
    except Exception as e:
        raise RuntimeError(
            f"Failed to capture live traffic: {e}. Ensure you have Admin privileges / Npcap installed.")