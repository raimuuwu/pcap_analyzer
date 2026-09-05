import argparse
import sys
from typing import Any

from core.parser import parse_packet
from core.capture import read_pcap_file, live_capture
from core.stats import StatsTracker
from detectors.unencrypted import check_unencrypted
from detectors.credentials import check_credentials
from detectors.regex_sniffer import check_sensitive_data
from utils.exporter import export_to_json


def process_single_packet(raw_pkt: Any, tracker: StatsTracker) -> None:
    parsed = parse_packet(raw_pkt)
    if not parsed:
        return

    alert = (
        check_unencrypted(parsed) or
        check_credentials(parsed) or
        check_sensitive_data(parsed)
    )

    tracker.update(parsed, alert)
    if alert:
        print(f"[ALERT!] {alert.get('type')}: {alert.get('details')}")


def main():
    parser = argparse.ArgumentParser(
        description="PCAP Traffic Analyzer & Sensitive Data Sniffer"
    )
    
    parser.add_argument("-f", "--file", type=str, help="Path to PCAP file for analysis")
    parser.add_argument("-l", "--live", action="store_true", help="Enable live traffic capture mode")
    parser.add_argument("-if", "--interface", type=str, help="Network interface for live capture (WILL BE ADDED LATER)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture in live mode (default: 0 = infinite)")
    parser.add_argument("-o", "--output", type=str, help="Path to JSON file to export the final analysis report")

    args = parser.parse_args()

    if not args.file and not args.live:
        parser.print_help()
        print("\n[!] Error: Please specify either --file or --live mode.")
        sys.exit(1)

    tracker = StatsTracker()

    if args.file:
        print(f"[*] Reading and analyzing PCAP file: {args.file}...\n")
        packets = read_pcap_file(args.file)
        for pkt in packets:
            process_single_packet(pkt, tracker)

    elif args.live:
        live_capture(
            callback=lambda pkt: process_single_packet(pkt, tracker),
            interface=args.interface,
            count=args.count
        )

    summary = tracker.get_summary()

    print("\n" + "=" * 50)
    print("ANALYSIS SUMMARY")
    print("=" * 50)
    print(f"Total Packets Processed: {summary['total_packets']}")
    print(f"Total Data Transferred: {summary['total_mb']} MB ({summary['total_bytes']} bytes)")
    print(f"Top 5 Source IPs: {summary['top_src_ips']}")
    print(f"Top 5 Destination IPs: {summary['top_dst_ips']}")
    print(f"Top 5 Ports Used: {summary['top_ports']}")
    print(f"Alerts Summary: {summary['alerts_summary']}")
    print("=" * 50)

    if args.output:
        export_to_json(summary, args.output)


if __name__ == "__main__":
    main()