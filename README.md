# remna-agent
Problem-first node telemetry agent for Remnawave/Xray.

## What it sends
- `node_heartbeat` every `HEARTBEAT_INTERVAL_SEC`
- `node_summary` every `SUMMARY_INTERVAL_SEC` over `SUMMARY_WINDOW_SEC`
- `reconnect_suspect` (threshold/cooldown-based)
- `fail_event` (classified from `error.log`, burst-deduped)
- `node_incident` (optional, from `docker logs remnanode`, burst-deduped)

## Files
- `agent.py`
- `requirements.txt`
- `.env.example`
- `remna-agent.service`
- `install.sh`

## One-Line Install
```bash
curl -fsSL https://raw.githubusercontent.com/MrStilex/node_agent/main/install.sh | \
sudo NODE_ID=fi-1 \
INGEST_URL=https://logs.lalala001.ru/ingest \
INGEST_TOKEN=replace_me \
FORCE_WRITE_ENV=1 \
bash
```

If `curl` is unavailable, the same works with `wget -qO- ... | sudo ... bash`.

## Install (Ubuntu 24.04)
```bash
sudo mkdir -p /opt/remna-agent /opt/remna-agent/spool
sudo cp agent.py requirements.txt .env.example install.sh /opt/remna-agent/
sudo cp .env.example /opt/remna-agent/.env

cd /opt/remna-agent
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Create service user
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin remna-agent || true
sudo chown -R remna-agent:remna-agent /opt/remna-agent
```

## Grant log read access (required)
Current logs are often `600 root:root`, so non-root agent cannot read them without ACL/group.

Option A (ACL, recommended):
```bash
sudo apt-get update && sudo apt-get install -y acl
sudo setfacl -m u:remna-agent:r /var/log/remnanode/access.log /var/log/remnanode/error.log
sudo setfacl -d -m u:remna-agent:r /var/log/remnanode
```

Option B (group-based via logrotate create), adjust your logrotate policy accordingly.

## Configure
Edit `/opt/remna-agent/.env`:
```env
NODE_ID=fi-1
INGEST_URL=https://stats.example.com/ingest
INGEST_TOKEN=...
```

All supported keys are listed in `.env.example`.

You can also let the installer create `.env` directly in `/opt/remna-agent` with your values:
```bash
sudo NODE_ID=fi-1 \
  INGEST_URL=https://logs.lalala001.ru/ingest \
  INGEST_TOKEN=replace_me \
  FORCE_WRITE_ENV=1 \
  bash install.sh
```

## Install and start systemd
```bash
sudo cp remna-agent.service /etc/systemd/system/remna-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now remna-agent
sudo systemctl status remna-agent --no-pager
```

## Runtime checks
```bash
journalctl -u remna-agent -f
sudo -u remna-agent /opt/remna-agent/.venv/bin/python /opt/remna-agent/agent.py
```

## Event model details
### `node_heartbeat`
```json
{
  "event_type": "node_heartbeat",
  "node_id": "fi-1",
  "ts": "2026-03-05T17:40:00Z",
  "last_seen_access_ts": "2026-03-05T17:39:58.123456Z",
  "last_seen_error_ts": "2026-03-05T17:39:58.456789Z",
  "access_lag_sec": 2,
  "error_lag_sec": 2,
  "queue_size": 0,
  "agent_version": "1.0.0"
}
```

### `node_summary`
```json
{
  "event_type": "node_summary",
  "node_id": "fi-1",
  "ts": "2026-03-05T17:40:00Z",
  "window_sec": 60,
  "accepted_total": 120,
  "unique_emails": 3,
  "reconnect_suspects_count": 1,
  "error_counts_by_type": {"eof": 95, "reality_sni_mismatch": 2},
  "reality_sni_mismatch_total": 2,
  "eof_total": 95,
  "received_request_total": 118
}
```

### `reconnect_suspect`
```json
{
  "event_type": "reconnect_suspect",
  "severity": "warning",
  "node_id": "fi-1",
  "ts": "2026-03-05T17:40:00Z",
  "email_id": "53",
  "accepted_count_window": 45,
  "unique_src_ports_window": 44,
  "unique_src_ips_window": 1,
  "sample_src_ip": "85.249.31.185",
  "window_sec": 300
}
```

### `fail_event`
```json
{
  "event_type": "fail_event",
  "fail_type": "reality_sni_mismatch",
  "ts": "2026-03-05T17:13:40.649072Z",
  "node_id": "fi-1",
  "msg_short": "2026/03/05 ... REALITY: processed invalid connection ... server name mismatch",
  "fingerprint": "5a3d...",
  "count": 3,
  "src_ip": "195.178.110.162",
  "src_port": 41978,
  "reason": "server name mismatch"
}
```

### `node_incident`
```json
{
  "event_type": "node_incident",
  "incident_type": "RN-001",
  "ts": "2026-03-02T13:24:30.000Z",
  "node_id": "fi-1",
  "msg_short": "... code: 'RN-001' ...",
  "fingerprint": "b92f...",
  "count": 5
}
```

## Batch transport format
Agent sends JSON array in one POST to `INGEST_URL`:
```json
[
  {"event_type":"node_heartbeat","node_id":"fi-1","ts":"..."},
  {"event_type":"node_summary","node_id":"fi-1","ts":"..."},
  {"event_type":"fail_event","node_id":"fi-1","ts":"...","fail_type":"eof","count":14}
]
```

Headers:
- `Authorization: Bearer <INGEST_TOKEN>`
- `Content-Type: application/json`

## Reliability behavior
- Disk queue: SQLite at `${SPOOL_DIR}/spool.db`
- If network fails: events remain in spool and retry with exponential backoff
- Spool limit enforced by `SPOOL_MAX_EVENTS`
- Drop policy configurable: `drop_oldest` or `drop_newest`
- Tailing handles logrotate `copytruncate` via inode/size tracking
- Short-window line dedup by `(source + ts + hash(line))`
- Burst dedup for fail/incidents with `FAIL_DEDUP_WINDOW_SEC`
