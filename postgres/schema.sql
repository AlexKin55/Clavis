-- Clavis shared PostgreSQL schema.
--
-- Applied automatically by the Key Server on start (db_url set) and
-- mounted as an init script in postgres/compose.yml. All Key Server
-- instances share this database, keeping agents, reader keys and the
-- audit trail consistent across the cluster.

CREATE TABLE IF NOT EXISTS clavis_agents (
	agent_id     text PRIMARY KEY,
	device_id    text NOT NULL DEFAULT '',
	pub_sig      bytea NOT NULL,
	owner_key_id text NOT NULL UNIQUE,
	nonce_server bytea NOT NULL,
	reader_key   bytea,
	revoked      boolean NOT NULL DEFAULT false,
	created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clavis_audit (
	id       bigserial PRIMARY KEY,
	ts       timestamptz NOT NULL DEFAULT now(),
	agent_id text NOT NULL DEFAULT '',
	document text NOT NULL DEFAULT '',
	allowed  boolean NOT NULL DEFAULT false,
	reason   text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS clavis_audit_ts_idx ON clavis_audit (ts DESC);
CREATE INDEX IF NOT EXISTS clavis_agents_owner_idx ON clavis_agents (owner_key_id);