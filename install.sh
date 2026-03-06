#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/remna-agent}"
ETC_DIR="${ETC_DIR:-$APP_DIR}"
STATE_DIR="${STATE_DIR:-$APP_DIR}"
SPOOL_DIR="${SPOOL_DIR:-$STATE_DIR/spool}"
SERVICE_NAME="${SERVICE_NAME:-remna-agent}"
SERVICE_USER="${SERVICE_USER:-remna-agent}"
SERVICE_GROUP="${SERVICE_GROUP:-remna-agent}"
ENV_FILE="${ENV_FILE:-$ETC_DIR/.env}"
LOG_DIR="${LOG_DIR:-/var/log/remnanode}"
ACCESS_LOG="${ACCESS_LOG:-$LOG_DIR/access.log}"
ERROR_LOG="${ERROR_LOG:-$LOG_DIR/error.log}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
AUTO_START="${AUTO_START:-1}"
FORCE_WRITE_ENV="${FORCE_WRITE_ENV:-0}"
REPO_OWNER="${REPO_OWNER:-MrStilex}"
REPO_NAME="${REPO_NAME:-node_agent}"
REPO_REF="${REPO_REF:-main}"
RAW_BASE_URL="${RAW_BASE_URL:-https://raw.githubusercontent.com/$REPO_OWNER/$REPO_NAME/$REPO_REF}"
BOOTSTRAP_DIR=""

log() {
  printf '[install] %s\n' "$*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 1
  }
}

download_file() {
  local src="$1"
  local dst="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$src" -o "$dst"
    return 0
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO "$dst" "$src"
    return 0
  fi

  echo "Neither curl nor wget is available" >&2
  exit 1
}

prepare_sources() {
  if [ -f "$SRC_DIR/agent.py" ] && [ -f "$SRC_DIR/requirements.txt" ] && [ -f "$SRC_DIR/remna-agent.service" ] && [ -f "$SRC_DIR/.env.example" ]; then
    return 0
  fi

  BOOTSTRAP_DIR="$(mktemp -d)"
  SRC_DIR="$BOOTSTRAP_DIR"
  log "Downloading installer payload from $RAW_BASE_URL"
  download_file "$RAW_BASE_URL/agent.py" "$SRC_DIR/agent.py"
  download_file "$RAW_BASE_URL/requirements.txt" "$SRC_DIR/requirements.txt"
  download_file "$RAW_BASE_URL/remna-agent.service" "$SRC_DIR/remna-agent.service"
  download_file "$RAW_BASE_URL/.env.example" "$SRC_DIR/.env.example"
}

ensure_venv_support() {
  local probe_dir
  probe_dir="$(mktemp -d)"

  if "$PYTHON_BIN" -m venv "$probe_dir/venv-check" >/dev/null 2>&1; then
    rm -rf "$probe_dir"
    return 0
  fi

  rm -rf "$probe_dir"
  log "Installing python3-venv package"
  apt-get update
  apt-get install -y python3-venv
}

safe_install_acl() {
  if command -v setfacl >/dev/null 2>&1; then
    return 0
  fi

  log "Installing acl package"
  apt-get update
  apt-get install -y acl
}

ensure_user_group() {
  if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    log "Creating group $SERVICE_GROUP"
    groupadd --system "$SERVICE_GROUP"
  fi

  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    log "Creating user $SERVICE_USER"
    useradd --system --gid "$SERVICE_GROUP" --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  fi

  if getent group docker >/dev/null 2>&1; then
    log "Adding $SERVICE_USER to docker group"
    usermod -aG docker "$SERVICE_USER"
  fi
}

install_files() {
  log "Creating directories"
  mkdir -p "$APP_DIR" "$ETC_DIR" "$SPOOL_DIR"

  log "Installing application files"
  install -m 0644 "$SRC_DIR/agent.py" "$APP_DIR/agent.py"
  install -m 0644 "$SRC_DIR/requirements.txt" "$APP_DIR/requirements.txt"
  install -m 0644 "$SRC_DIR/remna-agent.service" "/etc/systemd/system/$SERVICE_NAME.service"

  if [ ! -f "$ENV_FILE" ] || [ "$FORCE_WRITE_ENV" = "1" ]; then
    log "Creating env file at $ENV_FILE"
    install -m 0640 "$SRC_DIR/.env.example" "$ENV_FILE"
  else
    log "Keeping existing env file at $ENV_FILE"
  fi

  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$STATE_DIR"
  chmod 0750 "$STATE_DIR" "$SPOOL_DIR"
  chmod 0755 "$APP_DIR"
  chmod 0640 "$ENV_FILE"
}

write_env_overrides() {
  [ -f "$ENV_FILE" ] || return 0

  if [ -n "${NODE_ID:-}" ]; then
    sed -i "s|^NODE_ID=.*$|NODE_ID=$NODE_ID|" "$ENV_FILE"
  fi

  if [ -n "${INGEST_URL:-}" ]; then
    sed -i "s|^INGEST_URL=.*$|INGEST_URL=$INGEST_URL|" "$ENV_FILE"
  fi

  if [ -n "${INGEST_TOKEN:-}" ]; then
    sed -i "s|^INGEST_TOKEN=.*$|INGEST_TOKEN=$INGEST_TOKEN|" "$ENV_FILE"
  fi

  sed -i "s|^SPOOL_DIR=.*$|SPOOL_DIR=$SPOOL_DIR|" "$ENV_FILE"
}

setup_venv() {
  need_cmd "$PYTHON_BIN"
  ensure_venv_support

  if [ -d "$APP_DIR/.venv" ] && [ ! -x "$APP_DIR/.venv/bin/pip" ]; then
    log "Detected incomplete virtualenv, recreating it"
    rm -rf "$APP_DIR/.venv"
  fi

  if [ ! -d "$APP_DIR/.venv" ]; then
    log "Creating virtualenv"
    "$PYTHON_BIN" -m venv "$APP_DIR/.venv"
  fi

  log "Installing Python dependencies"
  "$APP_DIR/.venv/bin/pip" install --upgrade pip
  "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
}

setup_log_access() {
  safe_install_acl

  if [ -f "$ACCESS_LOG" ] || [ -f "$ERROR_LOG" ]; then
    log "Granting ACL read access to log files"
    [ -f "$ACCESS_LOG" ] && setfacl -m "u:$SERVICE_USER:r" "$ACCESS_LOG"
    [ -f "$ERROR_LOG" ] && setfacl -m "u:$SERVICE_USER:r" "$ERROR_LOG"
  else
    log "Log files not present yet, skipping direct file ACL"
  fi

  if [ -d "$LOG_DIR" ]; then
    log "Granting directory traverse/read ACL on $LOG_DIR"
    setfacl -m "u:$SERVICE_USER:rx" "$LOG_DIR"
    setfacl -d -m "u:$SERVICE_USER:rx" "$LOG_DIR" || true
  fi
}

env_is_configured() {
  [ -f "$ENV_FILE" ] || return 1

  local ingest_url ingest_token
  ingest_url="$(sed -n 's/^INGEST_URL=//p' "$ENV_FILE" | tail -n 1)"
  ingest_token="$(sed -n 's/^INGEST_TOKEN=//p' "$ENV_FILE" | tail -n 1)"

  [ -n "$ingest_url" ] || return 1
  [ -n "$ingest_token" ] || return 1
  [ "$ingest_url" != "https://stats.example.com/ingest" ] || return 1
  [ "$ingest_token" != "replace_me" ] || return 1
}

manage_service() {
  log "Reloading systemd"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"

  if [ "$AUTO_START" != "1" ]; then
    log "AUTO_START=$AUTO_START, skipping service start"
    return 0
  fi

  if ! env_is_configured; then
    log "Env file still contains placeholder ingest settings; skipping service start"
    return 0
  fi

  log "Restarting service"
  systemctl restart "$SERVICE_NAME"
  systemctl --no-pager --full status "$SERVICE_NAME"
}

main() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
  fi

  prepare_sources
  ensure_user_group
  install_files
  write_env_overrides
  setup_venv
  setup_log_access
  manage_service

  if [ -n "$BOOTSTRAP_DIR" ] && [ -d "$BOOTSTRAP_DIR" ]; then
    rm -rf "$BOOTSTRAP_DIR"
  fi

  log "Done"
  log "Env file: $ENV_FILE"
  log "Service: $SERVICE_NAME"
}

main "$@"
