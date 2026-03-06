from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from parsers.error_parser import ErrorEvent


@dataclass
class _DedupEntry:
    first_seen: datetime
    last_seen: datetime
    occurrences: int = 0
    emails: set[str] = field(default_factory=set)
    src_ips: set[str] = field(default_factory=set)
    dst_counter: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    proto_counter: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    route_counter: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    sample: str = ""
    severity: str = "info"


class FailAggregator:
    def __init__(self, fail_window_sec: int, dedup_window_sec: int) -> None:
        self.fail_window_sec = fail_window_sec
        self.dedup_window = timedelta(seconds=dedup_window_sec)
        self._bucket_start: datetime | None = None
        self._entries: dict[tuple[str, str, str, str], _DedupEntry] = {}

    def ingest(
        self,
        event: ErrorEvent,
        email: str | None = None,
        route_tag: str | None = None,
    ) -> None:
        if self._bucket_start is None:
            self._bucket_start = self._floor_ts(event.timestamp)

        key = (
            event.pattern,
            event.proto or "",
            event.dst_host or "",
            route_tag or "",
        )

        e = self._entries.get(key)
        if e is None:
            e = _DedupEntry(first_seen=event.timestamp, last_seen=event.timestamp)
            self._entries[key] = e

        if event.timestamp - e.last_seen > self.dedup_window:
            e.first_seen = event.timestamp
            e.occurrences = 0
            e.emails.clear()
            e.src_ips.clear()
            e.dst_counter.clear()
            e.proto_counter.clear()
            e.route_counter.clear()

        e.last_seen = event.timestamp
        e.occurrences += 1
        e.sample = e.sample or event.sample
        e.severity = max(e.severity, event.severity, key=_severity_rank)

        if email:
            e.emails.add(email)
        if event.src_ip:
            e.src_ips.add(event.src_ip)
        if event.dst_host:
            e.dst_counter[event.dst_host] += 1
        if event.proto:
            e.proto_counter[event.proto] += 1
        if route_tag:
            e.route_counter[route_tag] += 1

    def flush(self, node_id: str, ts: datetime) -> list[dict]:
        if self._bucket_start is None:
            return []

        current_bucket = self._floor_ts(ts)
        if current_bucket <= self._bucket_start:
            return []

        window_start = self._bucket_start
        window_end = self._bucket_start + timedelta(seconds=self.fail_window_sec)

        out: list[dict] = []
        window = self.fail_window_sec
        for (pattern, proto, dst, _), entry in self._entries.items():
            top_dst = _top1(entry.dst_counter)
            top_proto = _top1(entry.proto_counter)
            route_tag = _top1(entry.route_counter)
            affected_scope = _affected_scope(len(entry.emails), len(entry.src_ips))
            fingerprint = "|".join(
                [
                    pattern,
                    top_proto or proto or "na",
                    top_dst or dst or "na",
                ]
            )

            out.append(
                {
                    "event_type": "fail_event",
                    "node_id": node_id,
                    "ts": entry.last_seen.isoformat(),
                    "window": window,
                    "window_start": window_start.isoformat(),
                    "window_end": window_end.isoformat(),
                    "pattern": pattern,
                    "fingerprint": fingerprint,
                    "severity": entry.severity,
                    "occurrences": entry.occurrences,
                    "unique_email": len(entry.emails),
                    "unique_src_ip": len(entry.src_ips),
                    "affected_scope": affected_scope,
                    "top_dst": top_dst,
                    "proto": top_proto,
                    "route_tag": route_tag,
                    "sample": entry.sample,
                }
            )

        self._bucket_start = current_bucket
        self._entries.clear()
        return out

    def _floor_ts(self, ts: datetime) -> datetime:
        s = int(ts.timestamp())
        s = s - (s % self.fail_window_sec)
        return datetime.fromtimestamp(s, tz=ts.tzinfo)


def _top1(counter: dict[str, int]) -> str | None:
    if not counter:
        return None
    return sorted(counter.items(), key=lambda x: x[1], reverse=True)[0][0]


def _severity_rank(sev: str) -> int:
    return {"info": 0, "warn": 1, "critical": 2}.get(sev, 0)


def _affected_scope(unique_email: int, unique_src_ip: int) -> str:
    if unique_email > 0:
        return "user"
    if unique_src_ip > 0:
        return "ip"
    return "node"
