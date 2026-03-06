#!/usr/bin/env bash
set -euo pipefail

REPO_DEFAULT="MrStilex/node_agent"
BRANCH_DEFAULT="main"

REPO="${REPO:-$REPO_DEFAULT}"
BRANCH="${BRANCH:-$BRANCH_DEFAULT}"

WORKDIR="$(mktemp -d /tmp/node-agent-install.XXXXXX)"
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

log() { echo "[node-agent-bootstrap] $*"; }

if ! command -v curl >/dev/null 2>&1; then
  echo "[ERR] curl is required" >&2
  exit 1
fi
if ! command -v tar >/dev/null 2>&1; then
  echo "[ERR] tar is required" >&2
  exit 1
fi
if ! command -v bash >/dev/null 2>&1; then
  echo "[ERR] bash is required" >&2
  exit 1
fi

URL="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}"
log "downloading ${URL}"

curl -fsSL "$URL" -o "$WORKDIR/repo.tar.gz"
mkdir -p "$WORKDIR/src"
tar -xzf "$WORKDIR/repo.tar.gz" -C "$WORKDIR/src" --strip-components=1

if [[ ! -x "$WORKDIR/src/install.sh" ]]; then
  chmod +x "$WORKDIR/src/install.sh" 2>/dev/null || true
fi

if [[ ! -f "$WORKDIR/src/install.sh" ]]; then
  echo "[ERR] install.sh not found in downloaded repository" >&2
  exit 1
fi

log "running installer"
exec bash "$WORKDIR/src/install.sh"
