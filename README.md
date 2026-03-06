# remna-agent

Problem-first telemetry agent for Remnawave/Xray nodes.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/MrStilex/node_agent/main/install.sh | \
sudo NODE_ID=fi-1 \
INGEST_URL=https://logs.lalala001.ru/ingest \
INGEST_TOKEN=replace_me \
FORCE_WRITE_ENV=1 \
bash
```

What the installer does:

- installs files into `/opt/remna-agent`
- creates `/opt/remna-agent/.env`
- creates `/opt/remna-agent/.venv`
- creates `/opt/remna-agent/spool`
- installs `/etc/systemd/system/remna-agent.service`
- configures log read access for `/var/log/remnanode/*.log`

## Paths

- app directory: `/opt/remna-agent`
- config: `/opt/remna-agent/.env`
- spool: `/opt/remna-agent/spool`
- service: `/etc/systemd/system/remna-agent.service`

## Configuration

Main settings are stored in `/opt/remna-agent/.env`.

Minimal required values:

```env
NODE_ID=fi-1
INGEST_URL=https://logs.lalala001.ru/ingest
INGEST_TOKEN=replace_me
```

After changing config:

```bash
sudo systemctl restart remna-agent
```

## systemd

Start:

```bash
sudo systemctl start remna-agent
```

Stop:

```bash
sudo systemctl stop remna-agent
```

Restart:

```bash
sudo systemctl restart remna-agent
```

Enable on boot:

```bash
sudo systemctl enable remna-agent
```

Disable on boot:

```bash
sudo systemctl disable remna-agent
```

Status:

```bash
sudo systemctl status remna-agent --no-pager
```

## Logs

Agent logs:

```bash
journalctl -u remna-agent -f
```

Recent agent logs:

```bash
journalctl -u remna-agent --no-pager -n 100
```

Xray logs used by the agent:

- `/var/log/remnanode/access.log`
- `/var/log/remnanode/error.log`

## Update

Run the installer again:

```bash
curl -fsSL https://raw.githubusercontent.com/MrStilex/node_agent/main/install.sh | \
sudo NODE_ID=fi-1 \
INGEST_URL=https://logs.lalala001.ru/ingest \
INGEST_TOKEN=replace_me \
FORCE_WRITE_ENV=1 \
bash
```
