from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from parsers.access_parser import AccessEvent
from parsers.error_parser import ErrorEvent


@dataclass
class _Ctx:
    ts: datetime
    email: str | None
    route_tag: str | None


class AccessContextResolver:
    def __init__(self, lookback_sec: int = 120) -> None:
        self.lookback = timedelta(seconds=lookback_sec)
        self._idx: dict[tuple[str, str, str], deque[_Ctx]] = defaultdict(deque)

    def ingest(self, ev: AccessEvent) -> None:
        if ev.status != "accepted" or not ev.src_ip or not ev.dst_host or not ev.proto:
            return
        key = (ev.src_ip, ev.dst_host, ev.proto)
        q = self._idx[key]
        q.append(_Ctx(ts=ev.timestamp, email=ev.email, route_tag=ev.route_tag))
        self._evict_old(q, ev.timestamp)

    def resolve(self, ev: ErrorEvent) -> tuple[str | None, str | None]:
        if not ev.src_ip or not ev.dst_host or not ev.proto:
            return None, None
        key = (ev.src_ip, ev.dst_host, ev.proto)
        q = self._idx.get(key)
        if not q:
            return None, None

        cutoff = ev.timestamp - self.lookback
        while q and q[0].ts < cutoff:
            q.popleft()
        if not q:
            return None, None

        ctx = q[-1]
        return ctx.email, ctx.route_tag

    def _evict_old(self, q: deque[_Ctx], now: datetime) -> None:
        cutoff = now - self.lookback
        while q and q[0].ts < cutoff:
            q.popleft()
