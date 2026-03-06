from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from parsers.access_parser import AccessEvent


@dataclass
class SummaryAggregator:
    topn_size: int
    window_start: datetime | None = None
    window_end: datetime | None = None

    access_total: int = 0
    accepted_total: int = 0
    rejected_total: int = 0
    tcp_total: int = 0
    udp_total: int = 0

    unique_email: set[str] = field(default_factory=set)
    unique_src_ip: set[str] = field(default_factory=set)

    dst_counter: Counter[str] = field(default_factory=Counter)
    route_counter: Counter[str] = field(default_factory=Counter)

    def ingest(self, event: AccessEvent) -> None:
        if self.window_start is None:
            self.window_start = event.timestamp
        self.window_end = event.timestamp

        self.access_total += 1
        if event.status == "accepted":
            self.accepted_total += 1
            if event.proto == "tcp":
                self.tcp_total += 1
            elif event.proto == "udp":
                self.udp_total += 1

            if event.dst_host:
                self.dst_counter[event.dst_host] += 1
            if event.route_tag:
                self.route_counter[event.route_tag] += 1
            if event.email:
                self.unique_email.add(event.email)
            if event.src_ip:
                self.unique_src_ip.add(event.src_ip)
        elif event.status == "rejected":
            self.rejected_total += 1
            if event.src_ip:
                self.unique_src_ip.add(event.src_ip)

    def flush(
        self,
        node_id: str,
        reconnect_suspects_count: int = 0,
        fail_patterns_count: int = 0,
        fail_occurrences_total: int = 0,
    ) -> dict | None:
        if self.window_start is None or self.window_end is None:
            return None

        payload = {
            "event_type": "node_summary",
            "node_id": node_id,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "access_total": self.access_total,
            "accepted_total": self.accepted_total,
            "rejected_total": self.rejected_total,
            "unique_email": len(self.unique_email),
            "unique_src_ip": len(self.unique_src_ip),
            "tcp_total": self.tcp_total,
            "udp_total": self.udp_total,
            "top_dst_domains": self.dst_counter.most_common(self.topn_size),
            "top_route_tags": self.route_counter.most_common(self.topn_size),
            "route_split": _route_split(self.route_counter),
            "reconnect_suspects_count": reconnect_suspects_count,
            "fail_patterns_count": fail_patterns_count,
            "fail_occurrences_total": fail_occurrences_total,
        }
        self.__init__(topn_size=self.topn_size)
        return payload


def _route_split(route_counter: Counter[str]) -> dict[str, int]:
    out = {"DIRECT": 0, "BLOCK": 0, "ru-reality2": 0, "OTHER": 0}
    for raw, n in route_counter.items():
        if ">> DIRECT" in raw:
            out["DIRECT"] += n
        elif "-> BLOCK" in raw:
            out["BLOCK"] += n
        elif "-> ru-reality2" in raw:
            out["ru-reality2"] += n
        else:
            out["OTHER"] += n
    return out
