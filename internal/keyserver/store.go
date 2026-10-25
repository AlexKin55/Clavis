package keyserver

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/clavis/clavis/internal/keyclient"
)

// Document is a protected document known to the Key Server. The key is
// generated on first issuance and then served deterministically for the
// lifetime of the document, so all agents decrypt with the same material.
type Document struct {
	UUID      string
	Key       []byte
	Policies  keyclient.Policies
	TTL       time.Duration
	Revoked   bool
	CreatedAt time.Time
}

// Agent is a registered agent (identified by its client certificate CN
// or the Agent-ID header).
type Agent struct {
	ID      string
	Revoked bool
}

// AuditEntry records one key issuance decision.
type AuditEntry struct {
	Time     time.Time
	AgentID  string
	Document string
	Allowed  bool
	Reason   string
}

// Store holds the Key Server state. The default implementation keeps the
// data in memory; a PostgreSQL backed store can implement the same
// surface later.
type Store struct {
	mu        sync.RWMutex
	documents map[string]*Document
	agents    map[string]*Agent
	audit     []AuditEntry
}

// NewStore creates an empty in-memory store.
func NewStore() *Store {
	return &Store{
		documents: make(map[string]*Document),
		agents:    make(map[string]*Agent),
	}
}

// EnsureDocument returns the document, creating it (with a fresh random
// key and the given default policies/TTL) on first access.
func (s *Store) EnsureDocument(uuid string, defaultPolicies keyclient.Policies, defaultTTL time.Duration) (*Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if doc, ok := s.documents[uuid]; ok {
		return doc, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("keyserver: generate document key: %w", err)
	}
	doc := &Document{
		UUID:      uuid,
		Key:       key,
		Policies:  defaultPolicies,
		TTL:       defaultTTL,
		CreatedAt: time.Now(),
	}
	s.documents[uuid] = doc
	return doc, nil
}

// Document returns the document by UUID.
func (s *Store) Document(uuid string) (*Document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	doc, ok := s.documents[uuid]
	return doc, ok
}

// SetPolicy updates the policies and TTL of a document.
func (s *Store) SetPolicy(uuid string, policies keyclient.Policies, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	doc, ok := s.documents[uuid]
	if !ok {
		return fmt.Errorf("keyserver: document %q not found", uuid)
	}
	doc.Policies = policies
	doc.TTL = ttl
	return nil
}

// RevokeDocument revokes a document for all agents.
func (s *Store) RevokeDocument(uuid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if doc, ok := s.documents[uuid]; ok {
		doc.Revoked = true
	} else {
		s.documents[uuid] = &Document{UUID: uuid, Revoked: true}
	}
}

// RevokeAgent revokes an agent by ID.
func (s *Store) RevokeAgent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if agent, ok := s.agents[id]; ok {
		agent.Revoked = true
	} else {
		s.agents[id] = &Agent{ID: id, Revoked: true}
	}
}

// EnsureAgent registers the agent if unknown. Revoked agents keep their
// revoked flag.
func (s *Store) EnsureAgent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.agents[id]; !ok {
		s.agents[id] = &Agent{ID: id}
	}
}

// AgentRevoked reports whether the agent was revoked.
func (s *Store) AgentRevoked(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, ok := s.agents[id]
	return ok && agent.Revoked
}

// AddAudit appends an audit record.
func (s *Store) AddAudit(e AuditEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, e)
}

// ListAudit returns up to limit latest audit entries (most recent first).
func (s *Store) ListAudit(limit int) []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		return nil
	}
	n := len(s.audit)
	if limit > n {
		limit = n
	}
	out := make([]AuditEntry, limit)
	for i := 0; i < limit; i++ {
		out[i] = s.audit[n-1-i]
	}
	return out
}

// Documents lists all registered documents (for ListKeys).
func (s *Store) Documents() []*Document {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Document, 0, len(s.documents))
	for _, d := range s.documents {
		out = append(out, d)
	}
	return out
}
