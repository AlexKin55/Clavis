# Clavis Agent

Clavis is a next-generation DLP agent: transparent file encryption via FUSE,
remote key and policy management (Key Server), a Firejail sandbox and
RBA (Risk-Based Authentication). The code is written in Go; the full
implementation plan is in [`../docs/plan-go.md`](../docs/plan-go.md).

> Status: full v1+v2 pipeline implemented (crypto, FUSE, access control,
> Key Server client/server, sandbox, tokens, e2e relay, packaging).
>
> Documentation: [ARCHITECTURE](docs/ARCHITECTURE.md) ·
> [SECURITY](docs/SECURITY.md) · [v2 crypto model](../docs/crypto-model-v2.md)

## Repository layout

```
clavis/
├── agent/                  # agent entry point (CMD)
├── server/                 # Key Server entry point (CMD)
├── internal/
│   ├── app/                # initialization, graceful shutdown, health
│   ├── config/             # settings.yaml loading + validation
│   ├── crypto/             # file header (UUID/nonce), AES-CTR, key getters
│   ├── fuse/               # FUSE mirror with on-the-fly encryption
│   ├── interceptor/        # access policy: firejail/root/whitelist + audit
│   ├── keyclient/          # Key Server client: mTLS, policies, TTL cache
│   ├── keyserver/          # Key Server API: issue/revoke/policy/audit
│   ├── logging/            # slog + rotation (lumberjack)
│   ├── sandbox/            # Firejail sandbox (net/print/sound lockdown)
│   ├── subject/            # calling process identity from /proc
│   ├── token/              # PKCS#11 hardware token (wrapped document keys)
│   └── version/            # build version (ldflags)
├── scripts/                # helper scripts
├── tests/                  # integration/e2e tests (mirrored layout)
│   ├── fuse/               # real FUSE mount tests
│   ├── e2e/                # relay + direct key exchange tests
│   └── keyserver/          # Key Server HTTP API tests
├── postgres/               # shared PostgreSQL service (compose + schema)
├── settings.yaml           # agent sample configuration
└── server.yaml             # Key Server sample configuration
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

# Key Server (central key issuance, revocation, audit)
go run ./server -config server.yaml
```

## Tests layout

Go requires unit tests to live next to the code they test (same package,
white-box access), so they stay in the packages. Integration and
end-to-end tests (real mounts, HTTP servers, relay exchanges) are kept
separately in [`tests/`](tests/) with a mirrored directory structure and
use only the public API.

## Key Server cluster (shared database)

All Key Server instances connect to **one shared PostgreSQL** database
(see [`postgres/`](postgres/)), so agents, reader keys, revocations,
policies and the audit trail are identical on every server — the database
itself is the source of truth. Each server also accepts a comma-separated
`peers` list and health-checks the other instances.

Schema (in [`postgres/schema.sql`](postgres/schema.sql)):

| Table | Contents |
|---|---|
| `clavis_agents` | agents, reader keys (AS), owner ids, revocations |
| `clavis_documents` | document policies, TTL, revocations |
| `clavis_e2e_sessions` | rendezvous for direct key exchange |
| `clavis_peer_state` | observed health of peer instances |
| `clavis_audit` | who/when/where access events |

Every table carries a `server_id` column: the identity of the Key Server
instance (generated once at install time, `server-xxxx`, persisted in
`server.yaml → id_file`) that produced the row, so records can be
attributed across the cluster.

```yaml
# server.yaml (on every instance)
db_url: "postgres://clavis:...@db-host:5432/clavis"
peers: "https://ks2.example.com:8443,https://ks3.example.com:8443"
# server identity created on first start (0600); stamped into every row
# this instance writes in the shared PostgreSQL tables
id_file: "/var/lib/clavis/server-id"
```

## Offline access (local SQLite cache)

Once the agent fetches a reader key (AS) from a Key Server and successfully
opens a document, the key is stored in the local SQLite database
(`crypto.local_cache_db`), wrapped under the local master key A. Later
openings read the key from the cache first, so documents keep working
**without network**. Cache misses fall back to the Key Server.

## Multi-server failover (agent side)

`server.url` accepts several Key Server addresses separated by commas
(e.g. `https://ks1.example.com,https://ks2.example.com`). The agent:

- registers a **reader key (AS) per server** during identity registration
  (each server gets its own S/nonce-derived AS);
- on every operation (issue, reader-key, e2e session) tries the servers
  in order and uses the **first healthy one**;
- skips unreachable servers at registration and retries them on the next
  start — the rest of the list keeps the agent working.

## Desktop GUI (Fyne)

The optional desktop panel [`gui/`](gui/) lets the user:

- pick the **sharing mode for new documents** (Proxy / End-to-end); the
  FUSE agent reads the same preference for every created file;
- check for **end-to-end access requests** and answer with a modal dialog
  ("give the decryption key or refuse"); approval is performed by the
  agent (holder of the identity) via its localhost API (`agent.ui_listen`).

Because Fyne needs CGO and system graphics headers (libgl1-mesa-dev,
libwayland-dev on Linux; mingw on Windows), the GUI is built with an
explicit tag:

```bash
go build -tags gui -o bin/clavis-gui ./gui
./bin/clavis-gui                       # connects to 127.0.0.1:8902
```

The tag keeps `go build ./...` and the test suite free of the GUI
toolchain.

## Benchmarks

```bash
go test ./internal/crypto/ -bench=. -benchtime=1x
go test ./internal/fuse/ -bench=. -benchtime=1x
```

## Roadmap

Implemented:

- FUSE transparent encryption (v1 and v2 formats), AES-CTR random access
- access control: Firejail/root/whitelist policy, audit trail
- Key Server: issue, revocation, policies, temporary keys, PostgreSQL
- v2 model: owner keys, wrapped DK, signatures, ownership change on edit
- e2e mode: relay + direct AS exchange, sandbox Firejail runner, PKCS#11
- packaging: systemd units, installer, benchmarks

Planned (per request, kept for later):

- Phase 6: RBA (location, behavior metrics, risk heuristics)
- Phase 8: OS integrity monitoring

## Deployment

Root rights are needed once per workstation. [`deploy/install.sh`](deploy/install.sh)
builds the binaries, creates the `clavis` system user, prepares the
directories (encrypted store, mount point, token blobs, logs), generates
(or imports, via `--key-file`) the 32-byte key and installs the systemd
units.

```bash
sudo ./deploy/install.sh                   # agent only
sudo ./deploy/install.sh --with-keyserver  # agent + Key Server
```

Systemd units: [`clavis-agent.service`](deploy/systemd/clavis-agent.service)
(mounts the secure FUSE filesystem as the unprivileged `clavis` user) and
[`clavis-keyserver.service`](deploy/systemd/clavis-keyserver.service).
Configuration lives in `/etc/clavis/settings.yaml` and
`/etc/clavis/server.yaml`.

A new workstation = install the package + point `fuse.directory` at the
protected folder.

## Configuration

Settings are provided in a YAML file (default `settings.yaml`), see the
sample in [`settings.yaml`](settings.yaml). Key parameters:

| Parameter | Description |
|---|---|
| `agent.id` | optional display label; if empty, a random id (`agent-xxxx`) is generated at install and persisted in the identity file |
| `agent.health_listen` | HTTP `/healthz` address (empty disables it) |
| `agent.ui_listen` | localhost GUI API address (mode, e2e approval) |
| `crypto.key_file` | local key material file (hex or raw 16/24/32 bytes) |
| `crypto.algorithm` | default algorithm for new documents |
| `crypto.local_cache_db` | SQLite path for cached reader keys (offline access) |
| `policy.allow_uid0` | allow root without further checks |
| `policy.allow_firejail` | allow Firejail-sandboxed processes |
| `policy.whitelist` | sanctioned executable names (e.g. `["libreoffice"]`) |
| `server.url` | Key Server URLs, comma separated (failover order) |
| `server.ca_file` / `cert_file` / `key_file` | mTLS credentials |
| `server.timeout_seconds` | Key Server request timeout |
| `server.relay_addr` | e2e relay addresses, comma separated |
| `token.module_path` | PKCS#11 module (token becomes the key source) |
| `token.token_label` / `pin` / `wrap_key_label` | token session settings |
| `token.generate_wrap_key` | create the wrapping key on first use |
| `token.blobs_dir` | storage of token-wrapped document keys |
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