from core.capture import read_pcap_file
from core.parser import parse_packet

packets = read_pcap_file("samples/cmp_IR_sequence_OpenSSL-Cryptlib.pcap")

for pkt in packets[:5]:
    parsed_data = parse_packet(pkt)
    if parsed_data:
        print(parsed_data)