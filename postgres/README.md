# Clavis shared PostgreSQL

One shared PostgreSQL database is the source of truth for the Key Server
cluster. All server instances connect to it with the same `db_url`, so the
data (agents, reader keys, revocations, audit trail, policies) is
consistent across all of them without any custom replication.

## Start the shared database

```bash
docker compose -f postgres/compose.yml up -d
docker compose -f postgres/compose.yml ps   # wait for healthy
```

Defaults: user `clavis`, password `change-me`, database `clavis`,
port `5432` on localhost (see [compose.yml](compose.yml)).

## DSN

```
postgres://clavis:change-me@127.0.0.1:5432/clavis?sslmode=disable
```

## Point every Key Server at it

In each server's `server.yaml`:

```yaml
listen: "0.0.0.0:8443"
db_url: "postgres://clavis:change-me@127.0.0.1:5432/clavis?sslmode=disable"
peers: "https://ks2.example.com:8443,https://ks3.example.com:8443"
```

- `db_url` — the shared database (identical on every instance);
- `peers` — comma separated addresses of the other instances; the server
  probes their `/healthz` for coordination (data stays consistent via the
  shared DB itself).

## Schema

[`schema.sql`](schema.sql) is mounted into the container as an init
script and is also applied automatically by the Key Server on startup.