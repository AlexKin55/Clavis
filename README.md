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
│   ├── logging/            # slog + rotation (lumberjack)
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
```

## Configuration

Settings are provided in a YAML file (default `settings.yaml`), see the
sample in [`settings.yaml`](settings.yaml). Key parameters:

| Parameter | Description |
|---|---|
| `agent.id` | unique agent ID |
| `agent.health_listen` | HTTP `/healthz` address (empty disables it) |
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