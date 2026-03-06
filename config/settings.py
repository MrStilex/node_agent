from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    node_id: str
    schema_version: str = "1.0"

    heartbeat_interval: int = 60
    summary_interval: int = 60
    fail_window: int = 30
    reconnect_window: int = 300
    reconnect_threshold: int = 30
    fail_dedup_window: int = 15
    context_lookback_sec: int = 120
    incident_dedup_window_sec: int = 30
    topn_size: int = 10
    spool_dir: Path = Path("/var/lib/node-agent/spool")

    access_log_path: Path = Path("/var/log/remnanode/access.log")
    error_log_path: Path = Path("/var/log/remnanode/error.log")
    docker_container_name: str = "remnanode"

    collector_url: str = "http://127.0.0.1:8080/ingest"
    collector_token: str = ""
    send_batch_size: int = 200
    send_interval: int = 5
    request_timeout_sec: int = 5


    @staticmethod
    def from_env() -> "Settings":
        node_id = os.getenv("NODE_ID", "")
        if not node_id:
            raise ValueError("NODE_ID is required")

        return Settings(
            node_id=node_id,
            schema_version=os.getenv("SCHEMA_VERSION", "1.0"),
            heartbeat_interval=int(os.getenv("HEARTBEAT_INTERVAL", "60")),
            summary_interval=int(os.getenv("SUMMARY_INTERVAL", "60")),
            fail_window=int(os.getenv("FAIL_WINDOW", "30")),
            reconnect_window=int(os.getenv("RECONNECT_WINDOW", "300")),
            reconnect_threshold=int(os.getenv("RECONNECT_THRESHOLD", "30")),
            fail_dedup_window=int(os.getenv("FAIL_DEDUP_WINDOW", "15")),
            context_lookback_sec=int(os.getenv("CONTEXT_LOOKBACK_SEC", "120")),
            incident_dedup_window_sec=int(os.getenv("INCIDENT_DEDUP_WINDOW_SEC", "30")),
            topn_size=int(os.getenv("TOPN_SIZE", "10")),
            spool_dir=Path(os.getenv("SPOOL_DIR", "/var/lib/node-agent/spool")),
            access_log_path=Path(os.getenv("ACCESS_LOG_PATH", "/var/log/remnanode/access.log")),
            error_log_path=Path(os.getenv("ERROR_LOG_PATH", "/var/log/remnanode/error.log")),
            docker_container_name=os.getenv("DOCKER_CONTAINER_NAME", "remnanode"),
            collector_url=os.getenv("COLLECTOR_URL", os.getenv("INGEST_URL", "http://127.0.0.1:8080/ingest")),
            collector_token=os.getenv("COLLECTOR_TOKEN", os.getenv("INGEST_TOKEN", "")),
            send_batch_size=int(os.getenv("SEND_BATCH_SIZE", "200")),
            send_interval=int(os.getenv("SEND_INTERVAL", "5")),
            request_timeout_sec=int(os.getenv("REQUEST_TIMEOUT_SEC", "5")),
        )
