# Clavis — Architecture overview

Clavis protects documents at rest (transparent encryption through FUSE)
and controls who can read or modify them (Key Server policies, Firejail
sandbox, owner signatures).

## Module map

```
clavis/
├── agent/            # executable: FUSE agent + `clavis open` sandbox runner
├── server/           # executable: Key Server (API + e2e relay)
├── internal/
│   ├── crypto/       # formats v1/v2, AES-CTR, RFC3394 KeyWrap, HKDF, Ed25519
│   ├── fuse/         # FUSE mirror with on-the-fly encrypt/decrypt
│   ├── subject/      # process identity from /proc (firejail detection)
│   ├── interceptor/  # access policy (root/firejail/whitelist) + audit log
│   ├── keyclient/    # Key Server client (issue, register, reader-key, e2e)
│   ├── keyserver/    # Key Server handlers + store (memory/PostgreSQL)
│   ├── e2e/          # relay + direct X25519 key exchange
│   ├── agentid/      # agent identity/registration persistence
│   ├── sandbox/      # Firejail profiles and runner
│   ├── token/        # PKCS#11 hardware token (wrapped document keys)
│   ├── config/       # YAML settings
│   ├── notify/       # in-memory notification bus for the desktop GUI
│   └── logging/      # slog + rotation
├── tests/            # integration/e2e (mirrored layout)
└── deploy/           # systemd units, installer, SQL schema
```

## Data flow: proxy mode

```
application (whitelisted / firejail)
        │ open/create
        ▼
fuse.SecureRoot ──► interceptor (subject from kernel caller)
        │ allowed
        ▼
fuse (v2 header) ──® reader-key provider
        ├── proxy: keyclient.ReaderKey(owner) ─► keyserver → AS stored in PG
        └── e2e:   session → relay → direct OwnerShare/PeerReceive → AS
        ▼
unwrap DK (RFC3394 under AS) → AES-CTR decryption on the fly
```

## Data flow: ownership change

Editing a foreign v2 document re-encrypts it at Release: new DK', header
owner = editor, AS' = editor reader key, signature by the editor; the
document UUID is preserved.

## Key Server API

- `POST /api/v1/agents/register` → agent_id, S, nonce
- `POST /api/v1/agents/reader-key` — store AS
- `GET  /api/v1/agents/{owner}/reader-key` → AS + pub_sig
- `POST /api/v1/keys/issue` (v1 compatibility)
- `POST /api/v1/keys/revoke`, `POST /api/v1/agents/revoke`
- `PUT  /api/v1/documents/{uuid}/policy`
- `POST /api/v1/e2e/sessions` — rendezvous for direct exchange
- `GET  /api/v1/audit`, `GET /api/v1/documents`, `GET /healthz`

## Desktop UI and notifications

The agent exposes a localhost HTTP API (`agent.ui_listen`, default
`127.0.0.1:8902`) consumed by the Fyne control panel (`gui/`, build tag
`gui`):

- `GET/POST /api/mode` — per-file sharing mode for new documents
- `GET /api/e2e/pending`, `POST /api/e2e/approve` — end-to-end access approval
- `GET /api/notifications` — recent GUI notifications

When opening a document fails because of key material problems (owner has
no key, a returned key is unusable, or the key servers are unreachable),
`fuse.Notifier` forwards the failure to
`notify.Bus`; the GUI polls `/api/notifications` and surfaces new events as
system notifications (identifying "no key for the document" vs "no access
to the key servers / offline").

## Deployment

See [README](../README.md) → Deployment and
[deploy/install.sh](../deploy/install.sh); security model in
[SECURITY.md](SECURITY.md).