from pathlib import Path
from typing import Union
import scapy.all as scapy
from typing import Optional, Callable
import sys

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


def live_capture(callback: Callable, interface: Optional[str] = None, count: int = 0) -> None:

    print(f"[*] Starting live capture on interface: {interface or 'Default'}...")
    print("[*] Press Ctrl+C to stop capturing and view statistics.\n")

    try:
        scapy.sniff(
            iface=interface,
            prn=callback,
            store=False,
            count=count
        )
    except KeyboardInterrupt:
        print("\n[*] Live capture stopped by user (Ctrl+C).")
    except Exception as e:
        print(f"\n[!] Error during live capture: {e}", file=sys.stderr)