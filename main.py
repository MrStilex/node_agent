from __future__ import annotations

import os
import select
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from aggregators.context_resolver import AccessContextResolver
from aggregators.fail_aggregator import FailAggregator
from aggregators.node_incident_aggregator import NodeIncidentAggregator
from aggregators.reconnect_detector import ReconnectDetector
from aggregators.summary_aggregator import SummaryAggregator
from config.settings import Settings
from parsers.access_parser import parse_access_line
from parsers.docker_parser import parse_docker_line
from parsers.error_parser import parse_error_line
from transport.sender import Sender
from transport.spool import Spool


@dataclass
class FileFollower:
    path: Path
    offset: int = 0
    inode: int | None = None
    fh: object | None = None
    start_at_end: bool = True

    def open_if_needed(self) -> None:
        if self.fh is None:
            self.fh = self.path.open("r", encoding="utf-8", errors="replace")
            st = self.path.stat()
            self.inode = st.st_ino
            if self.start_at_end and self.offset == 0:
                self.fh.seek(0, os.SEEK_END)
                self.offset = self.fh.tell()
                self.start_at_end = False
            else:
                self.fh.seek(self.offset)

    def read_new_lines(self) -> list[str]:
        if not self.path.exists():
            return []

        st = self.path.stat()
        if self.inode is not None and st.st_ino != self.inode:
            self._reopen_from_start()
        elif st.st_size < self.offset:
            # copytruncate
            self._reopen_from_start()

        self.open_if_needed()
        assert self.fh is not None

        lines: list[str] = []
        while True:
            line = self.fh.readline()
            if not line:
                break
            self.offset = self.fh.tell()
            lines.append(line.rstrip("\n"))
        return lines

    def _reopen_from_start(self) -> None:
        if self.fh is not None:
            self.fh.close()
        self.fh = None
        self.offset = 0
        self.inode = None


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_xray_version(container: str) -> str:
    cmd = ["docker", "exec", container, "xray", "version"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=3)
        first = out.splitlines()[0] if out else "unknown"
        return first.strip()
    except Exception:
        return "unknown"


def get_container_uptime_sec(container: str) -> int:
    cmd = ["docker", "inspect", "-f", "{{.State.StartedAt}}", container]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=3).strip()
        started = datetime.fromisoformat(out.replace("Z", "+00:00"))
        return int((datetime.now(timezone.utc) - started).total_seconds())
    except Exception:
        return 0


def get_cpu_mem_usage() -> tuple[float, float]:
    cpu = os.getloadavg()[0]
    mem_total = 1.0
    mem_avail = 0.0
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = float(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_avail = float(line.split()[1])
    except Exception:
        pass
    mem_usage = 0.0 if mem_total == 0 else round((1 - mem_avail / mem_total) * 100, 2)
    return round(cpu, 2), mem_usage


def compute_log_lag_sec(paths: list[Path]) -> int:
    mtimes = []
    now = time.time()
    for p in paths:
        if p.exists():
            mtimes.append(now - p.stat().st_mtime)
    if not mtimes:
        return 0
    return int(min(mtimes))


def make_heartbeat(settings: Settings) -> dict:
    cpu, mem = get_cpu_mem_usage()
    lag = compute_log_lag_sec([settings.access_log_path, settings.error_log_path])
    return {
        "event_type": "node_heartbeat",
        "node_id": settings.node_id,
        "ts": iso_now(),
        "agent_version": "2.0.0",
        "xray_version": get_xray_version(settings.docker_container_name),
        "container_uptime_sec": get_container_uptime_sec(settings.docker_container_name),
        "cpu_usage": cpu,
        "mem_usage": mem,
        "log_lag_sec": lag,
        "status": "ok" if lag < 120 else "degraded",
    }


def start_docker_logs(container: str) -> subprocess.Popen:
    cmd = ["docker", "logs", "-f", "--since", "5s", container]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )


def run() -> None:
    settings = Settings.from_env()

    access_f = FileFollower(settings.access_log_path)
    error_f = FileFollower(settings.error_log_path)

    summary = SummaryAggregator(topn_size=settings.topn_size)
    ctx_resolver = AccessContextResolver(lookback_sec=settings.context_lookback_sec)
    reconnect = ReconnectDetector(settings.reconnect_window, settings.reconnect_threshold)
    fail_agg = FailAggregator(settings.fail_window, settings.fail_dedup_window)
    incident_agg = NodeIncidentAggregator(dedup_window_sec=settings.incident_dedup_window_sec)

    spool = Spool(settings.spool_dir, schema_version=settings.schema_version)
    sender = Sender(
        settings.collector_url,
        settings.request_timeout_sec,
        collector_token=settings.collector_token,
    )

    docker_proc = start_docker_logs(settings.docker_container_name)
    summary_reconnect_suspects_count = 0
    summary_fail_patterns: set[str] = set()
    summary_fail_occurrences_total = 0

    last_hb = time.time()
    last_summary = time.time()
    last_send = time.time()

    while True:
        now = datetime.now()

        for line in access_f.read_new_lines():
            ev = parse_access_line(line)
            if not ev:
                continue
            summary.ingest(ev)
            ctx_resolver.ingest(ev)
            for rc in reconnect.ingest(ev, settings.node_id):
                spool.put(rc)
                summary_reconnect_suspects_count += 1

        for line in error_f.read_new_lines():
            ev = parse_error_line(line)
            if not ev:
                continue
            email, route_tag = ctx_resolver.resolve(ev)
            fail_agg.ingest(ev, email=email, route_tag=route_tag)

        if docker_proc.stdout is not None:
            rlist, _, _ = select.select([docker_proc.stdout], [], [], 0)
            if rlist:
                dline = docker_proc.stdout.readline()
                if dline:
                    inc = parse_docker_line(dline)
                    if inc:
                        spool.put_many(incident_agg.ingest(inc, settings.node_id))

        fail_events = fail_agg.flush(settings.node_id, now)
        if fail_events:
            spool.put_many(fail_events)
            for e in fail_events:
                summary_fail_patterns.add(e["pattern"])
                summary_fail_occurrences_total += int(e["occurrences"])

        if time.time() - last_hb >= settings.heartbeat_interval:
            spool.put(make_heartbeat(settings))
            last_hb = time.time()

        if time.time() - last_summary >= settings.summary_interval:
            s = summary.flush(
                settings.node_id,
                reconnect_suspects_count=summary_reconnect_suspects_count,
                fail_patterns_count=len(summary_fail_patterns),
                fail_occurrences_total=summary_fail_occurrences_total,
            )
            if s:
                spool.put(s)
            summary_reconnect_suspects_count = 0
            summary_fail_patterns.clear()
            summary_fail_occurrences_total = 0
            last_summary = time.time()

        if time.time() - last_send >= settings.send_interval:
            batch = spool.get_batch(settings.send_batch_size)
            if batch:
                ok = sender.send_batch([x[1] for x in batch])
                if ok:
                    spool.ack([x[0] for x in batch])
            last_send = time.time()

        if docker_proc.poll() is not None:
            docker_proc = start_docker_logs(settings.docker_container_name)

        time.sleep(0.5)


if __name__ == "__main__":
    run()
