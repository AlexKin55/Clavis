package keyserver

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clavis/clavis/internal/keyclient"
)

func randRead(b []byte) (int, error) { return rand.Read(b) }

// PostgresStore persists all Key Server state in the shared PostgreSQL
// database: agents, reader keys, audit trail, e2e sessions, document
// policies and peer health. Because every server instance writes to the
// same database, the cluster is automatically consistent.
type PostgresStore struct {
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
	return &PostgresStore{pool: pool}, nil
}

// Close releases the connection pool.
func (p *PostgresStore) Close() { p.pool.Close() }

// ---------------------------------------------------------------- agents

// EnsureAgent registers the agent id if unknown.
func (p *PostgresStore) EnsureAgent(id string) {
	_, _ = p.pool.Exec(context.Background(),
		`INSERT INTO clavis_agents (agent_id, pub_sig, owner_key_id, nonce_server)
		 VALUES ($1, ''::bytea, $1, ''::bytea)
		 ON CONFLICT (agent_id) DO NOTHING`, id)
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

// ------------------------------------------------------------- documents

// EnsureDocument returns the document, creating it on first access.
func (p *PostgresStore) EnsureDocument(uuid string, defaultPolicies keyclient.Policies, defaultTTL time.Duration) (*Document, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if doc, ok := p.Document(uuid); ok {
		return doc, nil
	}
	key := make([]byte, 32)
	if _, err := randRead(key); err != nil {
		return nil, fmt.Errorf("keyserver: generate document key: %w", err)
	}
	policies, _ := json.Marshal(defaultPolicies)
	ttlSec := int64(defaultTTL / time.Second)
	if ttlSec <= 0 {
		ttlSec = 3600
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO clavis_documents (uuid, key, policies, ttl_seconds)
		 VALUES ($1, $2, $3::jsonb, $4)
		 ON CONFLICT (uuid) DO UPDATE SET owner_key_id = EXCLUDED.owner_key_id`,
		uuid, key, policies, ttlSec)
	if err != nil {
		return nil, fmt.Errorf("keyserver: ensure document: %w", err)
	}
	doc, _ := p.Document(uuid)
	return doc, nil
}

// Document returns the document by UUID.
func (p *PostgresStore) Document(uuid string) (*Document, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var d Document
	var policies []byte
	var ttlSec int64
	err := p.pool.QueryRow(ctx,
		`SELECT uuid, key, policies, ttl_seconds, revoked FROM clavis_documents WHERE uuid = $1`, uuid).
		Scan(&d.UUID, &d.Key, &policies, &ttlSec, &d.Revoked)
	if err != nil {
		return nil, false
	}
	if err := json.Unmarshal(policies, &d.Policies); err != nil {
		return nil, false
	}
	d.TTL = time.Duration(ttlSec) * time.Second
	return &d, true
}

// SetPolicy updates the policies and TTL of a document.
func (p *PostgresStore) SetPolicy(uuid string, policies keyclient.Policies, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := json.Marshal(policies)
	if err != nil {
		return err
	}
	ttlSec := int64(ttl / time.Second)
	tag, err := p.pool.Exec(ctx,
		`UPDATE clavis_documents SET policies = $2::jsonb, ttl_seconds = $3 WHERE uuid = $1`,
		uuid, data, ttlSec)
	if err != nil {
		return fmt.Errorf("keyserver: set policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("keyserver: document %q not found", uuid)
	}
	return nil
}

// RevokeDocument revokes a document for all agents.
func (p *PostgresStore) RevokeDocument(uuid string) {
	_, _ = p.pool.Exec(context.Background(),
		`INSERT INTO clavis_documents (uuid, key, policies, ttl_seconds, revoked)
		 VALUES ($1, ''::bytea, '{}'::jsonb, 3600, true)
		 ON CONFLICT (uuid) DO UPDATE SET revoked = true`, uuid)
}

// Documents lists all registered documents.
func (p *PostgresStore) Documents() []*Document {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := p.pool.Query(ctx,
		`SELECT uuid, key, policies, ttl_seconds, revoked FROM clavis_documents`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []*Document
	for rows.Next() {
		var d Document
		var policies []byte
		var ttlSec int64
		if err := rows.Scan(&d.UUID, &d.Key, &policies, &ttlSec, &d.Revoked); err != nil {
			continue
		}
		if err := json.Unmarshal(policies, &d.Policies); err != nil {
			continue
		}
		d.TTL = time.Duration(ttlSec) * time.Second
		out = append(out, &d)
	}
	return out
}

// ------------------------------------------------------------ e2e sessions

// CreateE2ESession records a rendezvous for the e2e relay.
func (p *PostgresStore) CreateE2ESession(ownerKeyID, peerAgentID string) (E2ESession, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session := E2ESession{
		SessionID:   "e2e-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		OwnerKeyID:  ownerKeyID,
		PeerAgentID: peerAgentID,
		CreatedAt:   time.Now(),
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO clavis_e2e_sessions (session_id, owner_key_id, peer_agent_id)
		 VALUES ($1, $2, $3) ON CONFLICT (session_id) DO NOTHING`,
		session.SessionID, ownerKeyID, peerAgentID)
	if err != nil {
		return E2ESession{}, fmt.Errorf("keyserver: create e2e session: %w", err)
	}
	return session, nil
}

// GetE2ESession returns the rendezvous by id.
func (p *PostgresStore) GetE2ESession(sessionID string) (E2ESession, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var s E2ESession
	err := p.pool.QueryRow(ctx,
		`SELECT owner_key_id, peer_agent_id FROM clavis_e2e_sessions WHERE session_id = $1`, sessionID).
		Scan(&s.OwnerKeyID, &s.PeerAgentID)
	if err != nil {
		return E2ESession{}, false
	}
	s.SessionID = sessionID
	return s, true
}

// ---------------------------------------------------------------- peers

// RecordPeerStatus stores the latest observed health of a peer.
func (p *PostgresStore) RecordPeerStatus(peer string, alive bool) {
	now := time.Now()
	if alive {
		_, _ = p.pool.Exec(context.Background(),
			`INSERT INTO clavis_peer_state (peer, last_seen, last_ok) VALUES ($1, $2, $2)
			 ON CONFLICT (peer) DO UPDATE SET last_seen = EXCLUDED.last_seen, last_ok = EXCLUDED.last_ok`,
			peer, now)
		return
	}
	_, _ = p.pool.Exec(context.Background(),
		`INSERT INTO clavis_peer_state (peer, last_seen) VALUES ($1, $2)
		 ON CONFLICT (peer) DO UPDATE SET last_seen = EXCLUDED.last_seen`,
		peer, now)
}

// PeerStates returns the observed health states of all peers.
func (p *PostgresStore) PeerStates() []PeerState {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := p.pool.Query(ctx, `SELECT peer, last_seen, COALESCE(last_ok, last_seen) FROM clavis_peer_state`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []PeerState
	for rows.Next() {
		var st PeerState
		if err := rows.Scan(&st.Peer, &st.LastSeen, &st.LastOK); err != nil {
			continue
		}
		out = append(out, st)
	}
	return out
}

// ---------------------------------------------------------------- audit

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

// schemaDDL is the PostgreSQL schema (also shipped as postgres/schema.sql
// and deploy/schema.sql for manual setup).
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
CREATE TABLE IF NOT EXISTS clavis_documents (
	uuid         text PRIMARY KEY,
	owner_key_id text NOT NULL DEFAULT '',
	key          bytea NOT NULL DEFAULT ''::bytea,
	policies     jsonb NOT NULL DEFAULT '{}'::jsonb,
	ttl_seconds  bigint NOT NULL DEFAULT 3600,
	revoked      boolean NOT NULL DEFAULT false,
	created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS clavis_e2e_sessions (
	session_id   text PRIMARY KEY,
	owner_key_id text NOT NULL,
	peer_agent_id text NOT NULL DEFAULT '',
	created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS clavis_peer_state (
	peer      text PRIMARY KEY,
	last_seen timestamptz NOT NULL,
	last_ok   timestamptz
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
`
