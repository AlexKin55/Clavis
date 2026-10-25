# Clavis — Security notes

This document describes the security model of Clavis, the key hierarchy,
threats and operational recommendations.

## Key hierarchy

| Key | Where it lives | Purpose |
|---|---|---|
| **A** (master key, 32B) | agent workstation (`identity_file`, mode 0600); never leaves | root of the owner identity |
| **Ed25519 key pair** | same identity file | signs documents; the signature makes the reader key strictly read-only |
| **S** (server public key) | public, distributed at registration | input for reader-key derivation |
| **AS** (reader key) = `HKDF-SHA256(A‖SigPub, nonceServer‖S, "clavis-reader-key")` | registered on the Key Server (PostgreSQL) | unwraps document keys (read access only) |
| **DK** (document key, 32B) | never stored: wrapped under AS inside the v2 header | encrypts the document payload (AES-256-CTR) |
| **Session key (e2e)** | ephemeral, derived from X25519 ECDH + HKDF + AES-GCM | transports AS directly between agents |

Property: the server knows only AS; it cannot forge documents (no owner
signature) and never learns A. E2e mode additionally keeps AS off the
server (relay carries only the encrypted rendezvous payload).

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Stolen laptop / flash drive | files on disk are ciphertext; without AS/A the payload is useless (see `tests/crypto/security_test.go`) |
| Server compromise | AS present, but master keys A and signatures remain local; attacker can read (as sanctioned agents) but not modify or forge |
| Unauthorized application | FUSE open/create gated by `internal/interceptor` (root/firejail/whitelist) |
| Network exfiltration of data | Firejail `--net=none`; documents useless without keys anyway |
| Revocation bypass | reader-key issuance denied for revoked agents; client cache honors TTL and revocation hook |
| Malicious edits | document signature by the owner; editing a foreign document re-encrypts it to the editor (owner change) |

## Operational recommendations

- Run the Key Server with **mutual TLS** (`tls.ca_file` set) and a
  **PostgreSQL** backend (`db_url`); keep `signing_key_file` on a
  protected volume (0600).
- Enforce a client-side policy [`policy`](settings.yaml): allow only
  Firejail-sandboxed processes and a minimal whitelist.
- The agent's `identity_file` is your long-term secret: back it up safely,
  protect with filesystem permissions, and rotate by re-encrypting
  documents (owner change).
- Keep the token PIN and mTLS keys out of version control.
- TTLs: prefer short reader-key TTLs so revocation propagates quickly.

## Current limitations (roadmap)

- Key cache lives in process memory with TTL; zeroization and memory
  hardening (mlock) are future work.
- PostgreSQL store persists reader keys in plaintext columns; a production
  option is to wrap AS under an HSM/PKCS#11 master key (the wrap/unwrap
  primitives already exist in `internal/token`).
- RBA (Phase 6) and OS integrity (Phase 8) are planned but not implemented
  yet; until then the interceptor's deny-by-default remains the primary
  access control.