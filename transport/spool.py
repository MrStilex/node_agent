from __future__ import annotations

import json
import uuid
from pathlib import Path


class Spool:
    def __init__(self, spool_dir: Path, schema_version: str = "1.0") -> None:
        self.spool_dir = spool_dir
        self.schema_version = schema_version
        self.spool_dir.mkdir(parents=True, exist_ok=True)

    def put(self, event: dict) -> None:
        event = dict(event)
        event.setdefault("schema_version", self.schema_version)
        tmp = self.spool_dir / f"{uuid.uuid4().hex}.tmp"
        dst = self.spool_dir / f"{uuid.uuid4().hex}.json"
        tmp.write_text(json.dumps(event, ensure_ascii=True), encoding="utf-8")
        tmp.rename(dst)

    def put_many(self, events: list[dict]) -> None:
        for e in events:
            self.put(e)

    def get_batch(self, batch_size: int) -> list[tuple[Path, dict]]:
        items: list[tuple[Path, dict]] = []
        for p in sorted(self.spool_dir.glob("*.json"))[:batch_size]:
            try:
                obj = json.loads(p.read_text(encoding="utf-8"))
                items.append((p, obj))
            except Exception:
                p.unlink(missing_ok=True)
        return items

    def ack(self, paths: list[Path]) -> None:
        for p in paths:
            p.unlink(missing_ok=True)
