from collections import Counter
from typing import Dict, Any, Optional


class StatsTracker:
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0

        self.src_ips = Counter()
        self.dst_ips = Counter()
        self.ports = Counter()
        self.alerts_by_type = Counter()

    def update(self, parsed_pkt: Dict[str, Any], alert: Optional[Dict[str, Any]] = None) -> None:
        self.total_packets += 1
        self.total_bytes += parsed_pkt.get("length", 0)

        src_ip = parsed_pkt.get("src_ip")
        if src_ip:
            self.src_ips[src_ip] += 1

        dst_ip = parsed_pkt.get("dst_ip")
        if dst_ip:
            self.dst_ips[dst_ip] += 1

        src_port = parsed_pkt.get("src_port")
        if src_port:
            self.ports[src_port] += 1

        dst_port = parsed_pkt.get("dst_port")
        if dst_port:
            self.ports[dst_port] += 1

        if alert:
            alert_type = alert.get("type", "Unknown Alert")
            self.alerts_by_type[alert_type] += 1

    def get_summary(self) -> Dict[str, Any]:
        total_mb = round(self.total_bytes / (1024 * 1024), 2)

        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_mb": total_mb,
            "top_src_ips": self.src_ips.most_common(5),
            "top_dst_ips": self.dst_ips.most_common(5),
            "top_ports": self.ports.most_common(5),
            "alerts_summary": dict(self.alerts_by_type)
        }