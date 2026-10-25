#!/usr/bin/env bash
# Build Clavis distribution packages (.deb and .rpm) for the three
# components: clavis-agent, clavis-server, clavis-postgres.
#
# Formats & distributions:
#   - deb : Debian/Ubuntu (Debian-based) — single artifact per component
#   - rpm : built per distribution family (openSUSE, Fedora/RHEL-like),
#           artifact names carry the family suffix, and the per-family
#           dependency names are selected via CL_RPM_DIST templating.
#
# Requirements:
#   - Go toolchain (GO, default: go on PATH)
#   - nfpm (NFPM, default: $HOME/go/bin/nfpm) — go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
#
# Usage:  ./packaging/build.sh [VERSION]
# Output: clavis/dist/
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

echo "==> building deb packages (Debian/Ubuntu)"
for cfg in packaging/clavis-*.deb.yaml; do
  comp="$(basename "$cfg" .deb.yaml)"
  fname="dist/${comp}_${VERSION}_amd64.deb"
  echo "  - $fname"
  "$NFPM" package -f "$cfg" -p deb -t "$fname"
done

echo "==> building rpm packages (per distribution family)"
for cfg in packaging/clavis-*.rpm.yaml; do
  base="$(basename "$cfg" .yaml)"    # clavis-agent.opensuse.rpm
  stem="${base%.rpm}"                # clavis-agent.opensuse
  dist="${stem##*.}"                 # opensuse (or fedora)
  comp="${stem%.$dist}"              # clavis-agent
  fname="dist/${comp}-${VERSION}-1.${dist}.x86_64.rpm"
  echo "  - $fname ($dist)"
  "$NFPM" package -f "$cfg" -p rpm -t "$fname"
done

echo
echo "Packages:"
ls -lh dist/
echo
echo "Install on Debian/Ubuntu:   sudo dpkg -i dist/clavis-*_${VERSION}_amd64.deb"
echo "Install on openSUSE:        sudo zypper in dist/clavis-*-${VERSION}-1.opensuse.x86_64.rpm"
echo "Install on Fedora/RHEL:     sudo dnf install dist/clavis-*-${VERSION}-1.fedora.x86_64.rpm"
