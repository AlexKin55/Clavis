package keyserver

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore persists agents and the audit trail in PostgreSQL.
// v1 document records keep the in-memory behavior (the v2 model removes
// document keys from the server entirely).
type PostgresStore struct {
	*MemoryStore
	pool *pgxpool.Pool
}

// NewPostgresStore connects to PostgreSQL, ensures the schema and returns
// the store.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("keyserver: connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("keyserver: ping postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaDDL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("keyserver: init schema: %w", err)
	}
	return &PostgresStore{MemoryStore: NewMemoryStore(), pool: pool}, nil
}

// Close releases the connection pool.
func (p *PostgresStore) Close() {
	p.pool.Close()
}

// CreateE2ESession keeps rendezvous records in memory (session-level data).
func (p *PostgresStore) CreateE2ESession(ownerKeyID, peerAgentID string) (E2ESession, error) {
	return p.MemoryStore.CreateE2ESession(ownerKeyID, peerAgentID)
}

// GetE2ESession returns the rendezvous from memory.
func (p *PostgresStore) GetE2ESession(sessionID string) (E2ESession, bool) {
	return p.MemoryStore.GetE2ESession(sessionID)
}

// EnsureAgent registers the agent id if unknown.
func (p *PostgresStore) EnsureAgent(id string) {
	if _, err := p.pool.Exec(context.Background(),
		`INSERT INTO clavis_agents (agent_id, pub_sig, owner_key_id, nonce_server)
		 VALUES ($1, ''::bytea, $1, ''::bytea)
		 ON CONFLICT (agent_id) DO NOTHING`, id); err != nil {
		return // best effort; the v2 registration path is authoritative
	}
}

// AgentRevoked reports whether the agent was revoked.
func (p *PostgresStore) AgentRevoked(id string) bool {
	var revoked bool
	if err := p.pool.QueryRow(context.Background(),
		`SELECT COALESCE(revoked, false) FROM clavis_agents WHERE agent_id = $1`, id).Scan(&revoked); err != nil {
		return false
	}
	return revoked
}

// RevokeAgent revokes an agent by ID.
func (p *PostgresStore) RevokeAgent(id string) {
	_, _ = p.pool.Exec(context.Background(),
		`UPDATE clavis_agents SET revoked = true WHERE agent_id = $1`, id)
}

// RegisterAgent creates or updates the v2 agent registration.
func (p *PostgresStore) RegisterAgent(rec AgentRecord) error {
	if rec.AgentID == "" || rec.OwnerKeyID == "" {
		return fmt.Errorf("keyserver: agent_id and owner_key_id are required")
	}
	_, err := p.pool.Exec(context.Background(),
		`INSERT INTO clavis_agents (agent_id, device_id, pub_sig, owner_key_id, nonce_server)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (owner_key_id)
		 DO UPDATE SET device_id = EXCLUDED.device_id, nonce_server = EXCLUDED.nonce_server`,
		rec.AgentID, rec.DeviceID, rec.PubSig, rec.OwnerKeyID, rec.NonceServer)
	if err != nil {
		return fmt.Errorf("keyserver: register agent: %w", err)
	}
	return nil
}

// AgentByID returns the agent record.
func (p *PostgresStore) AgentByID(id string) (*AgentRecord, bool) {
	return p.scanAgent(`SELECT agent_id, device_id, pub_sig, owner_key_id, nonce_server, reader_key, revoked FROM clavis_agents WHERE agent_id = $1`, id)
}

// AgentByOwnerKeyID returns the agent by its owner identifier.
func (p *PostgresStore) AgentByOwnerKeyID(ownerKeyID string) (*AgentRecord, bool) {
	return p.scanAgent(`SELECT agent_id, device_id, pub_sig, owner_key_id, nonce_server, reader_key, revoked FROM clavis_agents WHERE owner_key_id = $1`, ownerKeyID)
}

func (p *PostgresStore) scanAgent(query, arg string) (*AgentRecord, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var rec AgentRecord
	var readerKey []byte
	err := p.pool.QueryRow(ctx, query, arg).Scan(
		&rec.AgentID, &rec.DeviceID, &rec.PubSig, &rec.OwnerKeyID,
		&rec.NonceServer, &readerKey, &rec.Revoked,
	)
	if err != nil {
		return nil, false
	}
	rec.ReaderKey = readerKey
	rec.CreatedAt = time.Now()
	return &rec, true
}

// SetReaderKey stores the agent's reader key (AS).
func (p *PostgresStore) SetReaderKey(ownerKeyID string, readerKey []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tag, err := p.pool.Exec(ctx,
		`UPDATE clavis_agents SET reader_key = $2 WHERE owner_key_id = $1`, ownerKeyID, readerKey)
	if err != nil {
		return fmt.Errorf("keyserver: set reader key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("keyserver: agent with owner key id %q not found", ownerKeyID)
	}
	return nil
}

// AddAudit appends an audit record to PostgreSQL.
func (p *PostgresStore) AddAudit(e AuditEntry) {
	_, _ = p.pool.Exec(context.Background(),
		`INSERT INTO clavis_audit (agent_id, document, allowed, reason) VALUES ($1, $2, $3, $4)`,
		e.AgentID, e.Document, e.Allowed, e.Reason)
}

// ListAudit returns up to limit latest audit entries.
func (p *PostgresStore) ListAudit(limit int) []AuditEntry {
	if limit <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := p.pool.Query(ctx,
		`SELECT ts, agent_id, document, allowed, reason FROM clavis_audit ORDER BY ts DESC LIMIT $1`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Time, &e.AgentID, &e.Document, &e.Allowed, &e.Reason); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

// schemaDDL is the minimal PostgreSQL schema (also shipped as
// deploy/schema.sql for manual setup).
const schemaDDL = `
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
`
