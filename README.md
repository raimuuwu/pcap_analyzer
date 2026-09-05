# PCAP Traffic Analyzer & Sensitive Data Sniffer
A lightweight, Python-based CLI tool designed to analyze network traffic (`.pcap` files) and capture live packets. It parses network layers, identifies unencrypted communication, and extracts sensitive data leaks using Scapy and Regular Expressions.

## **Core Features**
* **Traffic Parsing**: Processes offline PCAP files and captures live network traffic.
* **Security Detection**: Identifies unencrypted protocols (HTTP, FTP, Telnet, POP3, IMAP).
* **Credential Sniffing**: Extracts cleartext credentials from HTTP Basic Auth headers and POST form parameters.
* **Data Leak Detection**: Uses configured Regex rules to find exposed email addresses, credit card numbers, and API tokens.
* **Statistics & Reporting**: Tracks packet counts, data transfer, top IPs/ports, and exports a summarized JSON report.

## **Usage**
* `python main.py --help` - displays available functions and arguments
* `python main.py -f \path\to\your\file.pcap` - runs analysis on chosen .pcap file
* `python main.py -l -c *n*` - starts live capture mode; optional "-c" for package count limit (default unlimited)
* `python main.py -o \path\to\your\file.json` - exports all captured data into .json file
* `python main.py -if` - live capture with an TUI interface (not implemented yet)
**For more info use --help**

## **Acknowledgments**
This project was developed as an educational portfolio piece to practice network analysis, object-oriented programming, and Python best practices. I want to explicitly acknowledge the assistance of AI, which acted as technical mentor and architectural guide throughout the entire development of this program.
