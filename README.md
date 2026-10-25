# Clavis Agent

Clavis is a next-generation DLP agent: transparent file encryption via FUSE,
remote key and policy management (Key Server), a Firejail sandbox and
RBA (Risk-Based Authentication). The code is written in Go; the full
implementation plan is in [`../docs/plan-go.md`](../docs/plan-go.md).

> Current status: **Phase 0** (project skeleton). The FUSE backend will be
> added in Phase 2.

## Repository layout

```
clavis/
├── agent/                  # agent entry point (CMD)
├── server/                 # Key Server entry point (planned)
├── internal/
│   ├── app/                # initialization, graceful shutdown, health
│   ├── config/             # settings.yaml loading + validation
│   ├── crypto/             # file header (UUID/nonce), AES-CTR, key getters
│   ├── fuse/               # FUSE mirror with on-the-fly encryption
│   ├── interceptor/        # access policy: firejail/root/whitelist + audit
│   ├── keyclient/          # Key Server client: mTLS, policies, TTL cache
│   ├── logging/            # slog + rotation (lumberjack)
│   ├── sandbox/            # Firejail sandbox (net/print/sound lockdown)
│   ├── subject/            # calling process identity from /proc
│   └── version/            # build version (ldflags)
├── scripts/                # helper scripts
├── tests/                  # e2e tests (to be added)
└── settings.yaml           # sample configuration
```

## Requirements

- Go >= 1.27 (`/usr/local/go/bin/go` if not in PATH)
- Linux; for FUSE mounting: `fusermount3` (fuse3 package)

## Build and checks

Go ships with its own build system, so no Makefile is used — everything is
done with `go` commands:

```bash
# build the binary into bin/clavis-agent
go build -o bin/clavis-agent ./agent

# build with version info (version/commit/date via -ldflags)
go build -ldflags "-X github.com/clavis/clavis/internal/version.Version=0.1.0" \
  -o bin/clavis-agent ./agent

# unit tests
go test ./...

# static analysis
go vet ./...
golangci-lint run   # requires golangci-lint v2 (go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0)

# run the agent with the sample settings
go run ./agent -config settings.yaml

# run an application inside the Firejail sandbox (double security perimeter)
go run ./agent open gedit /home/alex/Clavis/report.txt
```

## Configuration

Settings are provided in a YAML file (default `settings.yaml`), see the
sample in [`settings.yaml`](settings.yaml). Key parameters:

| Parameter | Description |
|---|---|
| `agent.id` | unique agent ID |
| `agent.health_listen` | HTTP `/healthz` address (empty disables it) |
| `crypto.key_file` | local key material file (hex or raw 16/24/32 bytes) |
| `crypto.algorithm` | default algorithm for new documents |
| `policy.allow_uid0` | allow root without further checks |
| `policy.allow_firejail` | allow Firejail-sandboxed processes |
| `policy.whitelist` | sanctioned executable names (e.g. `["libreoffice"]`) |
| `server.url` | Key Server base URL (mTLS); empty = local key file |
| `server.ca_file` / `cert_file` / `key_file` | mTLS credentials |
| `server.timeout_seconds` | Key Server request timeout |
| `fuse.directory` | directory of the encrypted files (must exist) |
| `fuse.mount_point` | mount point (created automatically) |
| `fuse.options` | FUSE arguments |
| `log.file` / `log.size` / `log.count` / `log.level` | rotating log journal |

## Liveness check

```bash
curl -s http://127.0.0.1:8901/healthz   # -> ok
```

Shutdown: `SIGINT`/`SIGTERM` stop the agent gracefully (Phase 2 will add a
clean FUSE unmount).