#!/usr/bin/env bash
# Clavis installer.
#
# Root rights are needed ONCE per workstation: the script builds the
# binaries, creates the clavis system user, installs configs and systemd
# units, then enables the services. Everything the agent does afterwards
# happens as the unprivileged clavis user (FUSE via fusermount3).
#
# Usage:
#   sudo ./deploy/install.sh [--with-agent] [--with-keyserver] [--key-file PATH]
#
# Options:
#   --with-agent       install and enable the agent service (default)
#   --with-keyserver   install and enable the Key Server service
#   --key-file PATH    copy an existing 32-byte key file (hex) into the
#                      agent config; otherwise a random key is generated
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root (sudo)" >&2
  exit 1
fi

WITH_AGENT=1
WITH_KEYSERVER=0
KEY_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-agent) WITH_AGENT=1 ;;
    --with-keyserver) WITH_KEYSERVER=1 ;;
    --key-file) KEY_FILE="$2"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
  shift
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-/usr/local}"
ETC_DIR="${ETC_DIR:-/etc/clavis}"
SECURE_DIR="${SECURE_DIR:-/opt/clavis/data}"
MOUNT_POINT="${MOUNT_POINT:-/home/clavis-secure}"
VERSION="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo dev)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "==> building binaries"
cd "$ROOT"
export PATH="$PATH:/usr/local/go/bin"
LDFLAGS="-s -w \
  -X github.com/clavis/clavis/internal/version.Version=0.1.0 \
  -X github.com/clavis/clavis/internal/version.Commit=$VERSION \
  -X github.com/clavis/clavis/internal/version.Date=$DATE"
go build -ldflags "$LDFLAGS" -o /tmp/clavis-agent-build ./agent
go build -ldflags "$LDFLAGS" -o /tmp/clavis-server-build ./server

echo "==> creating system user"
id clavis &>/dev/null || useradd --system --home-dir /var/lib/clavis --shell /usr/sbin/nologin clavis

echo "==> preparing directories"
install -d -m 0755 "$PREFIX/bin"
install -d -m 0644 "$ETC_DIR"
install -d -m 0750 -o clavis -g clavis "$SECURE_DIR"
install -d -m 0750 -o clavis -g clavis "$MOUNT_POINT"
install -d -m 0750 -o clavis -g clavis /var/lib/clavis/tokens
install -d -m 0750 -o clavis -g clavis /var/log/clavis

echo "==> installing binaries"
install -m 0755 /tmp/clavis-agent-build "$PREFIX/bin/clavis-agent"
install -m 0755 /tmp/clavis-server-build "$PREFIX/bin/clavis-server"
rm -f /tmp/clavis-agent-build /tmp/clavis-server-build

echo "==> installing configuration"
if [[ ! -f "$ETC_DIR/settings.yaml" ]]; then
  sed -e "s|/opt/cybertrust/data|$SECURE_DIR|" \
      -e "s|/home/alex/Clavis|$MOUNT_POINT|" \
      -e "s|/etc/clavis/agent.key|$ETC_DIR/agent.key|" \
      "$ROOT/settings.yaml" > "$ETC_DIR/settings.yaml"
fi
[[ ! -f "$ETC_DIR/server.yaml" ]] && cp "$ROOT/server.yaml" "$ETC_DIR/server.yaml" || true

if [[ -n "$KEY_FILE" ]]; then
  install -m 0600 -o clavis -g clavis "$KEY_FILE" "$ETC_DIR/agent.key"
  sed -i "s|agent.key|agent.key|" "$ETC_DIR/settings.yaml" # keep default path
elif [[ ! -f "$ETC_DIR/agent.key" ]]; then
  # Generate a random 32-byte hex key for local (non-server) setups.
  (umask 077; printf '%s\n' "$(head -c 32 /dev/urandom | xxd -p -c 64)" > "$ETC_DIR/agent.key")
fi
chown clavis:clavis "$ETC_DIR/agent.key"
chmod 0600 "$ETC_DIR/agent.key"

echo "==> installing systemd units"
install -m 0644 "$ROOT/deploy/systemd/clavis-agent.service" /etc/systemd/system/
install -m 0644 "$ROOT/deploy/systemd/clavis-keyserver.service" /etc/systemd/system/
systemctl daemon-reload

if [[ "$WITH_KEYSERVER" == "1" ]]; then
  echo "==> enabling Key Server"
  systemctl enable --now clavis-keyserver.service
fi
if [[ "$WITH_AGENT" == "1" ]]; then
  echo "==> enabling agent"
  systemctl enable --now clavis-agent.service
fi

cat <<EOF

Clavis installed.

  agent   : $PREFIX/bin/clavis-agent   (unit: clavis-agent.service)
  server  : $PREFIX/bin/clavis-server  (unit: clavis-keyserver.service)
  config  : $ETC_DIR/settings.yaml , $ETC_DIR/server.yaml
  key     : $ETC_DIR/agent.key
  data    : $SECURE_DIR (encrypted files)
  mount   : $MOUNT_POINT (decrypted view)

Check the agent:
  journalctl -u clavis-agent -f
  ls -la $MOUNT_POINT

One workstation = installed package + protected folder. Done.
EOF