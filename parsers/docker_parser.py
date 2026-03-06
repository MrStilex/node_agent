from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class NodeIncident:
    timestamp: datetime
    incident_type: str
    severity: str
    sample: str


INCIDENT_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("spawn_error", re.compile(r"SPAWN_ERROR", re.I), "critical"),
    ("rn_001", re.compile(r"RN-001", re.I), "critical"),
    ("stats_econnrefused", re.compile(r"ECONNREFUSED.*127\.0\.0\.1:61000", re.I), "warn"),
    ("process_crash", re.compile(r"process .*?(crash|exited|killed)|Xray processes killed", re.I), "critical"),
    ("container_restart", re.compile(r"\[Entrypoint\] Starting entrypoint script", re.I), "warn"),
]


def parse_docker_line(line: str) -> Optional[NodeIncident]:
    line = line.strip()
    if not line:
        return None

    now = datetime.now(timezone.utc)
    for itype, rx, sev in INCIDENT_PATTERNS:
        if rx.search(line):
            return NodeIncident(timestamp=now, incident_type=itype, severity=sev, sample=line)
    return None
