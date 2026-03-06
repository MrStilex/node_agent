from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request


logger = logging.getLogger(__name__)


class Sender:
    def __init__(self, collector_url: str, timeout_sec: int = 5, collector_token: str = "") -> None:
        self.collector_url = collector_url
        self.timeout_sec = timeout_sec
        self.collector_token = collector_token

    def send_batch(self, events: list[dict]) -> bool:
        if not events:
            return True

        body = json.dumps(events, ensure_ascii=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.collector_token:
            headers["Authorization"] = f"Bearer {self.collector_token}"

        req = urllib.request.Request(
            self.collector_url,
            data=body,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                if not 200 <= resp.status < 300:
                    logger.warning("Ingest returned status=%s", resp.status)
                return 200 <= resp.status < 300
        except urllib.error.HTTPError as exc:
            try:
                body_text = exc.read().decode("utf-8", errors="replace")
            except Exception:
                body_text = "<unavailable>"
            logger.warning("Ingest returned status=%s body=%s", exc.code, body_text[:500])
            return False
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            logger.exception("Failed to send events to collector")
            return False
