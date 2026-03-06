from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


_TS_FMT = "%Y/%m/%d %H:%M:%S.%f"

_ACCEPT_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"from (?P<src>(?:tcp:)?[^ ]+) accepted "
    r"(?P<proto>tcp|udp):(?P<dst_host>[^: ]+):(?P<dst_port>\d+) "
    r"\[(?P<route>[^\]]+)\](?: email: (?P<email>\S+))?$"
)

_REJECT_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"from (?P<src>(?:tcp:)?[^ ]+) rejected\s+(?P<reason>.+)$"
)

_SRC_IP_PORT_RE = re.compile(r"^(?:tcp:)?(?P<ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)$")


@dataclass
class AccessEvent:
    timestamp: datetime
    status: str
    src_ip: Optional[str]
    src_port: Optional[int]
    proto: Optional[str]
    dst_host: Optional[str]
    dst_port: Optional[int]
    email: Optional[str]
    route_tag: Optional[str]
    reason: Optional[str] = None


def parse_access_line(line: str) -> Optional[AccessEvent]:
    line = line.strip()
    if not line:
        return None

    m = _ACCEPT_RE.match(line)
    if m:
        src_ip, src_port = _parse_src(m.group("src"))
        return AccessEvent(
            timestamp=datetime.strptime(m.group("ts"), _TS_FMT),
            status="accepted",
            src_ip=src_ip,
            src_port=src_port,
            proto=m.group("proto"),
            dst_host=m.group("dst_host"),
            dst_port=int(m.group("dst_port")),
            email=m.group("email"),
            route_tag=m.group("route"),
        )

    m = _REJECT_RE.match(line)
    if m:
        src_ip, src_port = _parse_src(m.group("src"))
        return AccessEvent(
            timestamp=datetime.strptime(m.group("ts"), _TS_FMT),
            status="rejected",
            src_ip=src_ip,
            src_port=src_port,
            proto=None,
            dst_host=None,
            dst_port=None,
            email=None,
            route_tag=None,
            reason=m.group("reason"),
        )

    return None


def _parse_src(src: str) -> tuple[Optional[str], Optional[int]]:
    m = _SRC_IP_PORT_RE.match(src)
    if not m:
        return None, None
    return m.group("ip"), int(m.group("port"))
