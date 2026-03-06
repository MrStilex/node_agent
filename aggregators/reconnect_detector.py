from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from parsers.access_parser import AccessEvent


@dataclass
class _EmailState:
    events: deque[tuple[datetime, str | None, int | None, str | None]] = field(default_factory=deque)
    dst_counter: Counter[str] = field(default_factory=Counter)


class ReconnectDetector:
    def __init__(self, window_sec: int, threshold: int) -> None:
        self.window = timedelta(seconds=window_sec)
        self.window_sec = window_sec
        self.threshold = threshold
        self._by_email: dict[str, _EmailState] = defaultdict(_EmailState)
        self._cooldown_until: dict[str, datetime] = {}

    def ingest(self, event: AccessEvent, node_id: str) -> list[dict]:
        if event.status != "accepted" or not event.email:
            return []

        st = self._by_email[event.email]
        st.events.append((event.timestamp, event.src_ip, event.src_port, event.dst_host))
        if event.dst_host:
            st.dst_counter[event.dst_host] += 1

        self._evict_old(st, event.timestamp)
        count = len(st.events)

        if count <= self.threshold:
            return []

        cd = self._cooldown_until.get(event.email)
        if cd and event.timestamp < cd:
            return []

        self._cooldown_until[event.email] = event.timestamp + self.window

        src_ips = {x[1] for x in st.events if x[1]}
        src_ports = {x[2] for x in st.events if x[2]}
        top_dst = st.dst_counter.most_common(1)
        window_start = event.timestamp - self.window
        severity = "crit" if count >= (self.threshold * 2) else "warn"

        return [
            {
                "event_type": "reconnect_suspect",
                "node_id": node_id,
                "email": event.email,
                "window": self.window_sec,
                "window_start": window_start.isoformat(),
                "window_end": event.timestamp.isoformat(),
                "severity": severity,
                "reconnect_count": count,
                "unique_src_ip": len(src_ips),
                "unique_src_port": len(src_ports),
                "top_dst": top_dst[0][0] if top_dst else None,
            }
        ]

    def _evict_old(self, st: _EmailState, now: datetime) -> None:
        cutoff = now - self.window
        while st.events and st.events[0][0] < cutoff:
            _, _, _, dst = st.events.popleft()
            if dst:
                st.dst_counter[dst] -= 1
                if st.dst_counter[dst] <= 0:
                    del st.dst_counter[dst]
