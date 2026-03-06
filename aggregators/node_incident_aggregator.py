from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from parsers.docker_parser import NodeIncident


@dataclass
class _IncidentState:
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    last_emitted: datetime | None = None


class NodeIncidentAggregator:
    def __init__(self, dedup_window_sec: int = 30) -> None:
        self.dedup_window = timedelta(seconds=dedup_window_sec)
        self._states: dict[str, _IncidentState] = {}

    def ingest(self, incident: NodeIncident, node_id: str) -> list[dict]:
        fp = _fingerprint(incident)
        st = self._states.get(fp)
        if st is None:
            st = _IncidentState(first_seen=incident.timestamp, last_seen=incident.timestamp, occurrences=0)
            self._states[fp] = st

        st.last_seen = incident.timestamp
        st.occurrences += 1

        if st.last_emitted and incident.timestamp - st.last_emitted < self.dedup_window:
            return []

        st.last_emitted = incident.timestamp
        return [
            {
                "event_type": "node_incident",
                "node_id": node_id,
                "ts": incident.timestamp.isoformat(),
                "incident_type": incident.incident_type,
                "severity": incident.severity,
                "fingerprint": fp,
                "occurrences": st.occurrences,
                "first_seen": st.first_seen.isoformat(),
                "last_seen": st.last_seen.isoformat(),
                "sample": incident.sample,
            }
        ]


def _fingerprint(incident: NodeIncident) -> str:
    return incident.incident_type
