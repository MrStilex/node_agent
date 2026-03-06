from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


_TS_FMT = "%Y/%m/%d %H:%M:%S.%f"
_BASE_RE = re.compile(r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+) .*?\[(?P<rid>\d+)\] (?P<msg>.*)$")
_SRC_RE = re.compile(r"from (?:tcp:)?(?P<ip>\d+\.\d+\.\d+\.\d+):\d+")
_DST_RE = re.compile(r"(?:tcp|udp):(?P<dst>[^: ]+):\d+")
_PROTO_RE = re.compile(r"\b(?P<proto>tcp|udp):")


@dataclass
class ErrorEvent:
    timestamp: datetime
    pattern: str
    severity: str
    rid: Optional[str]
    src_ip: Optional[str]
    dst_host: Optional[str]
    proto: Optional[str]
    sample: str


PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("failed_outbound", re.compile(r"failed to process outbound traffic", re.I), "warn"),
    ("connection_reset", re.compile(r"connection reset by peer", re.I), "warn"),
    ("invalid_request", re.compile(r"invalid request address", re.I), "warn"),
    ("xtls_udp_rejected", re.compile(r"XTLS rejected UDP/443 traffic", re.I), "warn"),
    ("timeout", re.compile(r"context deadline exceeded|i/o timeout|timed out", re.I), "warn"),
    ("tls_error", re.compile(r"tls|bad certificate|reality verification failed", re.I), "warn"),
    ("dns_error", re.compile(r"nxdomain|servfail|no such host", re.I), "warn"),
]

EXCLUDE_PATTERNS = [
    re.compile(r"received request for", re.I),
    re.compile(r"connection opened to", re.I),
]


def parse_error_line(line: str) -> Optional[ErrorEvent]:
    line = line.strip()
    if not line:
        return None

    for rx in EXCLUDE_PATTERNS:
        if rx.search(line):
            return None

    base = _BASE_RE.match(line)
    if not base:
        return None

    ts = datetime.strptime(base.group("ts"), _TS_FMT)
    rid = base.group("rid")
    msg = base.group("msg")

    src_ip = None
    src_m = _SRC_RE.search(msg)
    if src_m:
        src_ip = src_m.group("ip")

    dst_host = None
    dst_m = _DST_RE.search(msg)
    if dst_m:
        dst_host = dst_m.group("dst")
    proto = None
    proto_m = _PROTO_RE.search(msg)
    if proto_m:
        proto = proto_m.group("proto")

    for name, rx, sev in PATTERNS:
        if rx.search(msg):
            return ErrorEvent(ts, name, sev, rid, src_ip, dst_host, proto, line)

    if "connection ends > EOF" in msg:
        return ErrorEvent(ts, "other", "info", rid, src_ip, dst_host, proto, line)

    return None
