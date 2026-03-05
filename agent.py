#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import re
import signal
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import requests

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None

AGENT_VERSION = "1.0.0"

ACCESS_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+from\s+"
    r"(?:(?:tcp:)?(?P<src_ip>[^: ]+):(?P<src_port>\d+))\s+accepted\s+"
    r"(?P<dst_proto>tcp|udp):(?P<dst_host>[^ :]+):(?P<dst_port>\d+)"
    r".*?\bemail:\s*(?P<email>\S+)\s*$"
)

ERROR_TS_RE = re.compile(r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)")
ERROR_RECEIVED_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\[(?P<level>[^\]]+)\]\s+"
    r"(?:\[(?P<rid>\d+)\]\s+)?proxy/vless/inbound: received request for "
    r"(?P<dst_proto>tcp|udp):(?P<dst_host>[^ :]+):(?P<dst_port>\d+)"
)
ERROR_EOF_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\[(?P<level>[^\]]+)\]\s+"
    r"(?:\[(?P<rid>\d+)\]\s+)?app/proxyman/inbound: connection ends > EOF"
)
REALITY_MISMATCH_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\[(?P<level>[^\]]+)\]\s+"
    r"transport/internet/tcp: REALITY: processed invalid connection from "
    r"(?P<src_ip>[^: ]+):(?P<src_port>\d+): server name mismatch"
)
ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
DOCKER_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")


@dataclass
class Config:
    node_id: str
    ingest_url: str
    ingest_token: str
    send_batch_max: int
    send_interval_sec: int
    heartbeat_interval_sec: int
    summary_interval_sec: int
    summary_window_sec: int
    reconnect_window_sec: int
    reconnect_warn_threshold: int
    reconnect_crit_threshold: int
    reconnect_cooldown_sec: int
    fail_dedup_window_sec: int
    fail_msg_maxlen: int
    log_access_path: str
    log_error_path: str
    docker_incidents_enabled: bool
    docker_container_name: str
    spool_dir: str
    spool_max_events: int
    spool_drop_policy: str
    log_level: str
    line_dedup_window_sec: int
    read_from_start: bool
    request_timeout_sec: int

    @staticmethod
    def from_env() -> "Config":
        if load_dotenv is not None:
            load_dotenv()

        def env_int(name: str, default: int) -> int:
            raw = os.getenv(name, str(default)).strip()
            try:
                return int(raw)
            except ValueError as exc:
                raise ValueError(f"Invalid integer for {name}: {raw}") from exc

        def env_bool(name: str, default: bool) -> bool:
            raw = os.getenv(name, "1" if default else "0").strip().lower()
            return raw in {"1", "true", "yes", "on"}

        cfg = Config(
            node_id=os.getenv("NODE_ID", "fi-1").strip(),
            ingest_url=os.getenv("INGEST_URL", "").strip(),
            ingest_token=os.getenv("INGEST_TOKEN", "").strip(),
            send_batch_max=env_int("SEND_BATCH_MAX", 100),
            send_interval_sec=env_int("SEND_INTERVAL_SEC", 2),
            heartbeat_interval_sec=env_int("HEARTBEAT_INTERVAL_SEC", 60),
            summary_interval_sec=env_int("SUMMARY_INTERVAL_SEC", 60),
            summary_window_sec=env_int("SUMMARY_WINDOW_SEC", 60),
            reconnect_window_sec=env_int("RECONNECT_WINDOW_SEC", 300),
            reconnect_warn_threshold=env_int("RECONNECT_WARN_THRESHOLD", 30),
            reconnect_crit_threshold=env_int("RECONNECT_CRIT_THRESHOLD", 60),
            reconnect_cooldown_sec=env_int("RECONNECT_COOLDOWN_SEC", 300),
            fail_dedup_window_sec=env_int("FAIL_DEDUP_WINDOW_SEC", 10),
            fail_msg_maxlen=env_int("FAIL_MSG_MAXLEN", 300),
            log_access_path=os.getenv("LOG_ACCESS_PATH", "/var/log/remnanode/access.log").strip(),
            log_error_path=os.getenv("LOG_ERROR_PATH", "/var/log/remnanode/error.log").strip(),
            docker_incidents_enabled=env_bool("DOCKER_INCIDENTS_ENABLED", True),
            docker_container_name=os.getenv("DOCKER_CONTAINER_NAME", "remnanode").strip(),
            spool_dir=os.getenv("SPOOL_DIR", "/var/lib/remna-agent/spool").strip(),
            spool_max_events=env_int("SPOOL_MAX_EVENTS", 200000),
            spool_drop_policy=os.getenv("SPOOL_DROP_POLICY", "drop_oldest").strip(),
            log_level=os.getenv("LOG_LEVEL", "INFO").strip().upper(),
            line_dedup_window_sec=env_int("LINE_DEDUP_WINDOW_SEC", 30),
            read_from_start=env_bool("READ_FROM_START", False),
            request_timeout_sec=env_int("REQUEST_TIMEOUT_SEC", 10),
        )
        if cfg.spool_drop_policy not in {"drop_oldest", "drop_newest"}:
            raise ValueError("SPOOL_DROP_POLICY must be drop_oldest or drop_newest")
        if not cfg.ingest_url:
            raise ValueError("INGEST_URL is required")
        if not cfg.ingest_token:
            raise ValueError("INGEST_TOKEN is required")
        return cfg


def now_epoch() -> float:
    return time.time()


def to_iso(ts_epoch: float | None) -> str | None:
    if ts_epoch is None:
        return None
    return datetime.fromtimestamp(ts_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def parse_xray_ts(raw: str) -> float | None:
    try:
        dt = datetime.strptime(raw, "%Y/%m/%d %H:%M:%S.%f")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def parse_docker_ts(raw: str) -> float | None:
    try:
        fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in raw else "%Y-%m-%d %H:%M:%S"
        dt = datetime.strptime(raw, fmt)
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def safe_msg(msg: str, max_len: int) -> str:
    msg = " ".join(msg.strip().split())
    if len(msg) <= max_len:
        return msg
    return msg[: max_len - 3] + "..."


def normalize_for_fp(msg: str) -> str:
    msg = re.sub(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+", "TS", msg)
    msg = re.sub(r"\b\d+\b", "N", msg)
    msg = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b", "IPPORT", msg)
    msg = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP", msg)
    msg = " ".join(msg.split())
    return msg


def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="replace")).hexdigest()


class SQLiteSpool:
    def __init__(self, path: Path, max_events: int, drop_policy: str) -> None:
        self.path = path
        self.max_events = max_events
        self.drop_policy = drop_policy
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "created_at REAL NOT NULL, "
            "payload TEXT NOT NULL"
            ")"
        )
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_id ON events(id)")
        self.conn.commit()
        self.cached_count = self._count_db()
        self.dropped_newest = 0
        self.dropped_oldest = 0

    def _count_db(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM events")
        row = cur.fetchone()
        return int(row[0] if row else 0)

    def count(self) -> int:
        with self.lock:
            return self.cached_count

    def enqueue(self, event: dict[str, Any]) -> bool:
        payload = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
        with self.lock:
            if self.cached_count >= self.max_events:
                if self.drop_policy == "drop_newest":
                    self.dropped_newest += 1
                    return False
                overflow = self.cached_count - self.max_events + 1
                self.conn.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)",
                    (overflow,),
                )
                self.conn.commit()
                self.cached_count = max(0, self.cached_count - overflow)
                self.dropped_oldest += overflow
            self.conn.execute(
                "INSERT INTO events(created_at,payload) VALUES(?,?)",
                (now_epoch(), payload),
            )
            self.conn.commit()
            self.cached_count += 1
            return True

    def pop_batch(self, limit: int) -> list[tuple[int, dict[str, Any]]]:
        with self.lock:
            cur = self.conn.execute(
                "SELECT id, payload FROM events ORDER BY id ASC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
        out: list[tuple[int, dict[str, Any]]] = []
        for row_id, payload in rows:
            try:
                out.append((int(row_id), json.loads(payload)))
            except json.JSONDecodeError:
                logging.exception("Invalid JSON payload in spool id=%s; dropping", row_id)
                self.ack([int(row_id)])
        return out

    def ack(self, ids: list[int]) -> None:
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        with self.lock:
            self.conn.execute(f"DELETE FROM events WHERE id IN ({placeholders})", ids)
            self.conn.commit()
            self.cached_count = max(0, self.cached_count - len(ids))


class RecentLineDeduper:
    def __init__(self, window_sec: int) -> None:
        self.window_sec = window_sec
        self.lock = threading.Lock()
        self.dq: deque[tuple[float, str]] = deque()
        self.seen: set[str] = set()

    def should_accept(self, key: str, ts_epoch: float) -> bool:
        with self.lock:
            self._prune(ts_epoch)
            if key in self.seen:
                return False
            self.seen.add(key)
            self.dq.append((ts_epoch, key))
            return True

    def _prune(self, now_ts: float) -> None:
        limit = now_ts - self.window_sec
        while self.dq and self.dq[0][0] < limit:
            _, key = self.dq.popleft()
            self.seen.discard(key)


@dataclass
class BurstBucket:
    first_ts: float
    last_ts: float
    count: int
    payload: dict[str, Any]


class BurstDeduper:
    def __init__(self, window_sec: int) -> None:
        self.window_sec = window_sec
        self.lock = threading.Lock()
        self.buckets: dict[str, BurstBucket] = {}

    def add(self, key: str, payload: dict[str, Any], event_ts: float) -> list[dict[str, Any]]:
        ready: list[dict[str, Any]] = []
        with self.lock:
            bucket = self.buckets.get(key)
            if bucket is None:
                self.buckets[key] = BurstBucket(event_ts, event_ts, 1, payload)
                return ready
            if event_ts - bucket.last_ts <= self.window_sec:
                bucket.last_ts = event_ts
                bucket.count += 1
                return ready
            ready.append(self._emit_and_remove(key))
            self.buckets[key] = BurstBucket(event_ts, event_ts, 1, payload)
        return [r for r in ready if r is not None]

    def flush_expired(self, now_ts: float) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        with self.lock:
            stale_keys = [k for k, v in self.buckets.items() if now_ts - v.last_ts > self.window_sec]
            for key in stale_keys:
                emitted = self._emit_and_remove(key)
                if emitted is not None:
                    out.append(emitted)
        return out

    def flush_all(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        with self.lock:
            keys = list(self.buckets.keys())
            for key in keys:
                emitted = self._emit_and_remove(key)
                if emitted is not None:
                    out.append(emitted)
        return out

    def _emit_and_remove(self, key: str) -> dict[str, Any] | None:
        bucket = self.buckets.pop(key, None)
        if bucket is None:
            return None
        event = dict(bucket.payload)
        event["count"] = bucket.count
        return event


class SlidingState:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.lock = threading.Lock()
        self.last_seen_access_ts: float | None = None
        self.last_seen_error_ts: float | None = None
        self.summary_events: deque[dict[str, Any]] = deque()
        self.reconnect_events: deque[dict[str, Any]] = deque()
        self.reconnect_cooldown: dict[str, float] = {}

    def mark_access_seen(self, ts_epoch: float) -> None:
        with self.lock:
            self.last_seen_access_ts = ts_epoch

    def mark_error_seen(self, ts_epoch: float) -> None:
        with self.lock:
            self.last_seen_error_ts = ts_epoch

    def add_summary(self, kind: str, ts_epoch: float, **extra: Any) -> None:
        with self.lock:
            self.summary_events.append({"ts": ts_epoch, "kind": kind, **extra})
            self._prune_summary_locked(ts_epoch)

    def add_reconnect_item(self, ts_epoch: float, email: str, src_ip: str, src_port: str) -> None:
        with self.lock:
            self.reconnect_events.append(
                {"ts": ts_epoch, "email": email, "src_ip": src_ip, "src_port": src_port}
            )
            self._prune_reconnect_locked(ts_epoch)

    def maybe_reconnect_suspect(self, ts_epoch: float, email: str) -> dict[str, Any] | None:
        with self.lock:
            self._prune_reconnect_locked(ts_epoch)
            items = [x for x in self.reconnect_events if x["email"] == email]
            accepted_count = len(items)
            if accepted_count < self.cfg.reconnect_warn_threshold:
                return None
            last_emit = self.reconnect_cooldown.get(email)
            if last_emit is not None and ts_epoch - last_emit < self.cfg.reconnect_cooldown_sec:
                return None
            unique_ports = {x["src_port"] for x in items}
            unique_ips = {x["src_ip"] for x in items}
            severity = "critical" if accepted_count >= self.cfg.reconnect_crit_threshold else "warning"
            self.reconnect_cooldown[email] = ts_epoch
            sample_src_ip = items[-1]["src_ip"] if items else None
            self.summary_events.append({"ts": ts_epoch, "kind": "reconnect_suspect", "email": email})
            self._prune_summary_locked(ts_epoch)
            return {
                "event_type": "reconnect_suspect",
                "severity": severity,
                "node_id": self.cfg.node_id,
                "ts": to_iso(ts_epoch),
                "email_id": email,
                "accepted_count_window": accepted_count,
                "unique_src_ports_window": len(unique_ports),
                "unique_src_ips_window": len(unique_ips),
                "sample_src_ip": sample_src_ip,
                "window_sec": self.cfg.reconnect_window_sec,
            }

    def build_summary(self, ts_epoch: float) -> dict[str, Any]:
        with self.lock:
            self._prune_summary_locked(ts_epoch)
            events = list(self.summary_events)

        accepted_total = 0
        unique_emails: set[str] = set()
        reconnect_suspects_count = 0
        error_counts_by_type: dict[str, int] = defaultdict(int)
        reality_sni_mismatch_total = 0
        eof_total = 0
        received_request_total = 0

        for item in events:
            kind = item["kind"]
            if kind == "accepted":
                accepted_total += 1
                if item.get("email"):
                    unique_emails.add(str(item["email"]))
            elif kind == "reconnect_suspect":
                reconnect_suspects_count += 1
            elif kind == "received_request":
                received_request_total += 1
            elif kind == "fail":
                fail_type = str(item.get("fail_type", "other"))
                error_counts_by_type[fail_type] += 1
                if fail_type == "reality_sni_mismatch":
                    reality_sni_mismatch_total += 1
                if fail_type == "eof":
                    eof_total += 1

        return {
            "event_type": "node_summary",
            "node_id": self.cfg.node_id,
            "ts": to_iso(ts_epoch),
            "window_sec": self.cfg.summary_window_sec,
            "accepted_total": accepted_total,
            "unique_emails": len(unique_emails),
            "reconnect_suspects_count": reconnect_suspects_count,
            "error_counts_by_type": dict(error_counts_by_type),
            "reality_sni_mismatch_total": reality_sni_mismatch_total,
            "eof_total": eof_total,
            "received_request_total": received_request_total,
        }

    def build_heartbeat(self, ts_epoch: float, queue_size: int) -> dict[str, Any]:
        with self.lock:
            last_access = self.last_seen_access_ts
            last_error = self.last_seen_error_ts

        def lag(last: float | None) -> int | None:
            if last is None:
                return None
            return max(0, int(ts_epoch - last))

        return {
            "event_type": "node_heartbeat",
            "node_id": self.cfg.node_id,
            "ts": to_iso(ts_epoch),
            "last_seen_access_ts": to_iso(last_access),
            "last_seen_error_ts": to_iso(last_error),
            "access_lag_sec": lag(last_access),
            "error_lag_sec": lag(last_error),
            "queue_size": queue_size,
            "agent_version": AGENT_VERSION,
        }

    def _prune_summary_locked(self, now_ts: float) -> None:
        cutoff = now_ts - self.cfg.summary_window_sec
        while self.summary_events and self.summary_events[0]["ts"] < cutoff:
            self.summary_events.popleft()

    def _prune_reconnect_locked(self, now_ts: float) -> None:
        cutoff = now_ts - self.cfg.reconnect_window_sec
        while self.reconnect_events and self.reconnect_events[0]["ts"] < cutoff:
            self.reconnect_events.popleft()


class ResilientTailer(threading.Thread):
    def __init__(
        self,
        path: str,
        source_name: str,
        on_line: Callable[[str], None],
        stop_event: threading.Event,
        start_at_end: bool,
        poll_sec: float = 0.5,
    ) -> None:
        super().__init__(daemon=True, name=f"tail-{source_name}")
        self.path = path
        self.source_name = source_name
        self.on_line = on_line
        self.stop_event = stop_event
        self.start_at_end = start_at_end
        self.poll_sec = poll_sec
        self.file_obj = None
        self.inode = None
        self.offset = 0
        self.first_open_done = False

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self._tick()
            except Exception:
                logging.exception("Tailer error for %s", self.path)
                time.sleep(1)

    def _tick(self) -> None:
        path = Path(self.path)
        if not path.exists():
            time.sleep(self.poll_sec)
            return

        st = path.stat()
        inode = st.st_ino
        size = st.st_size

        if self.file_obj is None or self.inode != inode:
            self._open_file(inode, size)
        elif size < self.offset:
            logging.info("Detected truncate for %s (copytruncate); rewinding to 0", self.path)
            self.file_obj.seek(0)
            self.offset = 0

        assert self.file_obj is not None
        line = self.file_obj.readline()
        if not line:
            time.sleep(self.poll_sec)
            return

        self.offset = self.file_obj.tell()
        self.on_line(line.rstrip("\n"))

    def _open_file(self, inode: int, size: int) -> None:
        if self.file_obj is not None:
            try:
                self.file_obj.close()
            except Exception:
                pass

        self.file_obj = open(self.path, "r", encoding="utf-8", errors="replace")
        self.inode = inode
        if not self.first_open_done and self.start_at_end:
            self.offset = size
            self.file_obj.seek(size)
        else:
            self.offset = 0
            self.file_obj.seek(0)
        self.first_open_done = True
        logging.info("Opened %s (inode=%s, offset=%s)", self.path, self.inode, self.offset)


class SenderThread(threading.Thread):
    def __init__(self, cfg: Config, spool: SQLiteSpool, stop_event: threading.Event) -> None:
        super().__init__(daemon=True, name="sender")
        self.cfg = cfg
        self.spool = spool
        self.stop_event = stop_event
        self.session = requests.Session()
        self.backoff_sec = 1

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                batch = self.spool.pop_batch(self.cfg.send_batch_max)
                if not batch:
                    self.backoff_sec = 1
                    time.sleep(self.cfg.send_interval_sec)
                    continue

                ids = [x[0] for x in batch]
                payload = [x[1] for x in batch]
                ok = self._send(payload)
                if ok:
                    self.spool.ack(ids)
                    self.backoff_sec = 1
                else:
                    sleep_for = min(60, self.backoff_sec)
                    logging.warning("Send failed, keeping %d events in spool, retry in %ss", len(batch), sleep_for)
                    time.sleep(sleep_for)
                    self.backoff_sec = min(60, self.backoff_sec * 2)
            except Exception:
                logging.exception("Sender loop error")
                time.sleep(2)

    def _send(self, events: list[dict[str, Any]]) -> bool:
        headers = {
            "Authorization": f"Bearer {self.cfg.ingest_token}",
            "Content-Type": "application/json",
        }
        try:
            resp = self.session.post(
                self.cfg.ingest_url,
                headers=headers,
                data=json.dumps(events, ensure_ascii=True),
                timeout=(3.05, self.cfg.request_timeout_sec),
            )
            if 200 <= resp.status_code < 300:
                logging.debug("Sent %d events, status=%s", len(events), resp.status_code)
                return True
            logging.warning("Ingest returned status=%s body=%s", resp.status_code, resp.text[:300])
            return False
        except requests.RequestException:
            logging.exception("HTTP send exception")
            return False


class DockerIncidentReader(threading.Thread):
    def __init__(
        self,
        cfg: Config,
        stop_event: threading.Event,
        on_line: Callable[[str], None],
    ) -> None:
        super().__init__(daemon=True, name="docker-incidents")
        self.cfg = cfg
        self.stop_event = stop_event
        self.on_line = on_line

    def run(self) -> None:
        while not self.stop_event.is_set():
            proc = None
            try:
                cmd = [
                    "docker",
                    "logs",
                    "-f",
                    "--since",
                    "2m",
                    self.cfg.docker_container_name,
                ]
                logging.info("Starting docker incident reader: %s", " ".join(cmd))
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                assert proc.stdout is not None
                for raw in proc.stdout:
                    if self.stop_event.is_set():
                        break
                    line = raw.rstrip("\n")
                    self.on_line(line)
                if proc.poll() is None:
                    proc.terminate()
            except Exception:
                logging.exception("docker logs reader failed")
            finally:
                if proc is not None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            if not self.stop_event.is_set():
                time.sleep(5)


class Agent:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        Path(cfg.spool_dir).mkdir(parents=True, exist_ok=True)
        self.spool = SQLiteSpool(Path(cfg.spool_dir) / "spool.db", cfg.spool_max_events, cfg.spool_drop_policy)
        self.state = SlidingState(cfg)
        self.stop_event = threading.Event()
        self.line_deduper = RecentLineDeduper(cfg.line_dedup_window_sec)
        self.fail_deduper = BurstDeduper(cfg.fail_dedup_window_sec)
        self.incident_deduper = BurstDeduper(cfg.fail_dedup_window_sec)
        self.sender = SenderThread(cfg, self.spool, self.stop_event)
        self.threads: list[threading.Thread] = []

    def run(self) -> None:
        self._start_threads()
        next_heartbeat = now_epoch() + self.cfg.heartbeat_interval_sec
        next_summary = now_epoch() + self.cfg.summary_interval_sec

        while not self.stop_event.is_set():
            try:
                now_ts = now_epoch()
                for ev in self.fail_deduper.flush_expired(now_ts):
                    self._enqueue(ev)
                for ev in self.incident_deduper.flush_expired(now_ts):
                    self._enqueue(ev)

                if now_ts >= next_heartbeat:
                    hb = self.state.build_heartbeat(now_ts, self.spool.count())
                    self._enqueue(hb)
                    next_heartbeat = now_ts + self.cfg.heartbeat_interval_sec

                if now_ts >= next_summary:
                    summary = self.state.build_summary(now_ts)
                    self._enqueue(summary)
                    next_summary = now_ts + self.cfg.summary_interval_sec

                time.sleep(1)
            except KeyboardInterrupt:
                break
            except Exception:
                logging.exception("Main loop error")
                time.sleep(1)

        self.shutdown()

    def shutdown(self) -> None:
        self.stop_event.set()
        for ev in self.fail_deduper.flush_all():
            self._enqueue(ev)
        for ev in self.incident_deduper.flush_all():
            self._enqueue(ev)

        for t in self.threads:
            t.join(timeout=2)
        self.sender.join(timeout=5)

    def _start_threads(self) -> None:
        self.sender.start()
        access_tailer = ResilientTailer(
            path=self.cfg.log_access_path,
            source_name="access",
            on_line=self._handle_access_line,
            stop_event=self.stop_event,
            start_at_end=not self.cfg.read_from_start,
        )
        error_tailer = ResilientTailer(
            path=self.cfg.log_error_path,
            source_name="error",
            on_line=self._handle_error_line,
            stop_event=self.stop_event,
            start_at_end=not self.cfg.read_from_start,
        )
        access_tailer.start()
        error_tailer.start()
        self.threads.extend([access_tailer, error_tailer])

        if self.cfg.docker_incidents_enabled:
            docker_reader = DockerIncidentReader(
                cfg=self.cfg,
                stop_event=self.stop_event,
                on_line=self._handle_docker_line,
            )
            docker_reader.start()
            self.threads.append(docker_reader)

    def _enqueue(self, event: dict[str, Any]) -> None:
        ok = self.spool.enqueue(event)
        if not ok:
            logging.error(
                "Spool full, event dropped by policy=%s type=%s",
                self.cfg.spool_drop_policy,
                event.get("event_type"),
            )

    def _handle_access_line(self, line: str) -> None:
        if not line:
            return
        ts_epoch = now_epoch()
        m = ACCESS_RE.match(line)
        if not m:
            return

        parsed_ts = parse_xray_ts(m.group("ts"))
        if parsed_ts is not None:
            ts_epoch = parsed_ts

        dedup_key = f"access:{m.group('ts')}:{sha1_hex(line)}"
        if not self.line_deduper.should_accept(dedup_key, now_epoch()):
            return

        email = m.group("email")
        src_ip = m.group("src_ip")
        src_port = m.group("src_port")

        self.state.mark_access_seen(ts_epoch)
        self.state.add_summary("accepted", ts_epoch, email=email)
        self.state.add_reconnect_item(ts_epoch, email=email, src_ip=src_ip, src_port=src_port)

        suspect = self.state.maybe_reconnect_suspect(ts_epoch, email)
        if suspect is not None:
            self._enqueue(suspect)

    def _handle_error_line(self, line: str) -> None:
        if not line:
            return

        ts_epoch = now_epoch()
        ts_match = ERROR_TS_RE.match(line)
        if ts_match:
            parsed_ts = parse_xray_ts(ts_match.group("ts"))
            if parsed_ts is not None:
                ts_epoch = parsed_ts

        dedup_key = f"error:{ts_match.group('ts') if ts_match else 'na'}:{sha1_hex(line)}"
        if not self.line_deduper.should_accept(dedup_key, now_epoch()):
            return

        self.state.mark_error_seen(ts_epoch)

        if ERROR_RECEIVED_RE.match(line):
            self.state.add_summary("received_request", ts_epoch)

        fail_type, extras = self._classify_error_fail(line)
        if fail_type is None:
            return

        self.state.add_summary("fail", ts_epoch, fail_type=fail_type)
        msg_short = safe_msg(line, self.cfg.fail_msg_maxlen)
        norm = normalize_for_fp(line)
        fp = sha1_hex(f"error:{fail_type}:{norm}")
        event = {
            "event_type": "fail_event",
            "fail_type": fail_type,
            "ts": to_iso(ts_epoch),
            "node_id": self.cfg.node_id,
            "msg_short": msg_short,
            "fingerprint": fp,
            "count": 1,
        }
        event.update(extras)
        burst_key = f"fail:{fail_type}:{fp}"
        for ready in self.fail_deduper.add(burst_key, event, ts_epoch):
            self._enqueue(ready)

    def _classify_error_fail(self, line: str) -> tuple[str | None, dict[str, Any]]:
        m_reality = REALITY_MISMATCH_RE.match(line)
        if m_reality:
            return (
                "reality_sni_mismatch",
                {
                    "src_ip": m_reality.group("src_ip"),
                    "src_port": int(m_reality.group("src_port")),
                    "reason": "server name mismatch",
                },
            )

        lower = line.lower()
        if "connection ends > eof" in lower:
            return "eof", {}
        if any(x in lower for x in ["deadline exceeded", "i/o timeout", "timed out", "timeout"]):
            return "timeout", {}
        if any(x in lower for x in ["connection reset", "reset by peer", "broken pipe"]):
            return "reset", {}
        if any(x in lower for x in ["bad certificate", "tls", "handshake"]):
            return "tls", {}
        if any(x in lower for x in ["no such host", "servfail", "nxdomain"]):
            return "dns", {}

        return None, {}

    def _handle_docker_line(self, raw_line: str) -> None:
        if not raw_line:
            return

        line = ANSI_RE.sub("", raw_line)
        lower = line.lower()

        incident_type = None
        if "spawn_error: xray" in lower:
            incident_type = "SPAWN_ERROR"
        elif "rn-001" in lower:
            incident_type = "RN-001"
        elif "econnrefused" in lower:
            incident_type = "ECONNREFUSED"
        elif "not all dependencies are resolved" in lower:
            incident_type = "deps_unresolved"
        elif "failed to get system stats" in lower:
            incident_type = "stats_api_down"

        if incident_type is None:
            return

        ts_epoch = now_epoch()
        m_ts = DOCKER_TS_RE.match(line)
        if m_ts:
            parsed_ts = parse_docker_ts(m_ts.group("ts"))
            if parsed_ts is not None:
                ts_epoch = parsed_ts

        dedup_key = f"docker:{incident_type}:{m_ts.group('ts') if m_ts else 'na'}:{sha1_hex(line)}"
        if not self.line_deduper.should_accept(dedup_key, now_epoch()):
            return

        msg_short = safe_msg(line, self.cfg.fail_msg_maxlen)
        fp = sha1_hex(f"incident:{incident_type}:{normalize_for_fp(line)}")
        event = {
            "event_type": "node_incident",
            "incident_type": incident_type,
            "ts": to_iso(ts_epoch),
            "node_id": self.cfg.node_id,
            "msg_short": msg_short,
            "fingerprint": fp,
            "count": 1,
        }
        burst_key = f"incident:{incident_type}:{fp}"
        for ready in self.incident_deduper.add(burst_key, event, ts_epoch):
            self._enqueue(ready)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(threadName)s %(message)s",
    )


def main() -> None:
    cfg = Config.from_env()
    configure_logging(cfg.log_level)
    logging.info("Starting remna-agent v%s node_id=%s", AGENT_VERSION, cfg.node_id)

    agent = Agent(cfg)

    def _graceful_stop(signum: int, _frame: Any) -> None:
        logging.info("Signal received: %s", signum)
        agent.stop_event.set()

    signal.signal(signal.SIGTERM, _graceful_stop)
    signal.signal(signal.SIGINT, _graceful_stop)

    agent.run()
    logging.info("Agent stopped")


if __name__ == "__main__":
    main()
