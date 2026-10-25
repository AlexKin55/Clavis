#!/usr/bin/env bash
# Build Clavis distribution packages (.deb and .rpm) for the three
# components: clavis-agent, clavis-server, clavis-postgres.
#
# Requirements:
#   - Go toolchain (GO, default: go on PATH)
#   - nfpm (NFPM, default: $HOME/go/bin/nfpm) — go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
#
# Usage:  ./packaging/build.sh [VERSION]
# Output: clavis/dist/*.deb, clavis/dist/*.rpm
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GO="${GO:-go}"
command -v "$GO" >/dev/null 2>&1 || GO="/usr/local/go/bin/go"
NFPM="${NFPM:-$HOME/go/bin/nfpm}"
VERSION="${1:-0.1.0}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w \
  -X github.com/clavis/clavis/internal/version.Version=${VERSION} \
  -X github.com/clavis/clavis/internal/version.Commit=${COMMIT} \
  -X github.com/clavis/clavis/internal/version.Date=${BUILD_DATE}"

echo "==> staging"
rm -rf packaging/stage dist
mkdir -p packaging/stage/agent packaging/stage/server packaging/stage/common dist

echo "==> building binaries"
"$GO" build -ldflags "$LDFLAGS" -o packaging/stage/agent/clavis-agent ./agent
"$GO" build -tags gui -ldflags "$LDFLAGS" -o packaging/stage/agent/clavis-gui ./gui
"$GO" build -ldflags "$LDFLAGS" -o packaging/stage/server/clavis-server ./server

echo "==> preparing packaged configs"
# The packaged agent config uses the packaged mount point.
sed -e 's|/home/alex/Clavis|/home/clavis-secure|' settings.yaml > packaging/stage/common/settings.yaml
cp server.yaml packaging/stage/common/server.yaml

echo "==> making scripts executable"
chmod +x packaging/scripts/*.sh packaging/scripts/*.postinstall packaging/scripts/*.postremove

echo "==> building packages"
declare -A TARGETS=(
  [clavis-agent.deb.yaml]=dist/clavis-agent_${VERSION}_amd64.deb
  [clavis-agent.rpm.yaml]=dist/clavis-agent-${VERSION}-1.x86_64.rpm
  [clavis-server.deb.yaml]=dist/clavis-server_${VERSION}_amd64.deb
  [clavis-server.rpm.yaml]=dist/clavis-server-${VERSION}-1.x86_64.rpm
  [clavis-postgres.deb.yaml]=dist/clavis-postgres_${VERSION}_amd64.deb
  [clavis-postgres.rpm.yaml]=dist/clavis-postgres-${VERSION}-1.x86_64.rpm
)
for cfg in "${!TARGETS[@]}"; do
  base="${cfg%.yaml}"          # clavis-server.rpm
  fmt="${base##*.}"            # rpm
  fname="${TARGETS[$cfg]}"
  echo "  - $fname ($fmt)"
  "$NFPM" package -f "packaging/$cfg" -p "$fmt" -t "$fname"
done

echo
echo "Packages:"
ls -lh dist/
echo
echo "Install on Debian/Ubuntu:   sudo dpkg -i dist/clavis-*_${VERSION}_amd64.deb"
echo "Install on RPM systems:     sudo zypper in dist/clavis-*-${VERSION}-1.x86_64.rpm"
