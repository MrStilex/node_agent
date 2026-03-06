from __future__ import annotations

import json
import urllib.error
import urllib.request


class Sender:
    def __init__(self, collector_url: str, timeout_sec: int = 5, collector_token: str = "") -> None:
        self.collector_url = collector_url
        self.timeout_sec = timeout_sec
        self.collector_token = collector_token

    def send_batch(self, events: list[dict]) -> bool:
        if not events:
            return True

        body = json.dumps({"events": events}, ensure_ascii=True).encode("utf-8")
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
                return 200 <= resp.status < 300
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            return False
