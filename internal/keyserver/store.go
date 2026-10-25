package keyserver

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/clavis/clavis/internal/keyclient"
)

// Document is a protected document known to the Key Server. In v1 mode a
// document key may exist; in the v2 model documents carry no keys on the
// server (only owner reader keys are stored).
type Document struct {
	UUID      string
	Key       []byte
	Policies  keyclient.Policies
	TTL       time.Duration
	Revoked   bool
	CreatedAt time.Time
}

// AgentRecord is the v2 registration record of an agent.
type AgentRecord struct {
	// AgentID is the server-assigned agent identifier.
	AgentID string
	// DeviceID is the installer-provided device identifier.
	DeviceID string
	// PubSig is the agent public signature key (Ed25519).
	PubSig []byte
	// OwnerKeyID is the 16-byte owner identifier derived from PubSig.
	OwnerKeyID string
	// NonceServer is the per-agent registration nonce.
	NonceServer []byte
	// ReaderKey (AS) is the registered read-only wrapper key.
	ReaderKey []byte
	// Revoked denies further reader-key issuance.
	Revoked bool
	// CreatedAt is the registration time.
	CreatedAt time.Time
}

// AuditEntry records one decision (v1 issuance or v2 reader-key events).
type AuditEntry struct {
	Time     time.Time
	AgentID  string
	Document string
	Allowed  bool
	Reason   string
}

// E2ESession describes a meeting point created by the reader agent.
type E2ESession struct {
	SessionID   string
	OwnerKeyID  string
	PeerAgentID string
	CreatedAt   time.Time
}

// PeerState is the observed health state of a peer Key Server instance.
type PeerState struct {
	Peer     string
	LastSeen time.Time
	LastOK   time.Time
}

// Store is the Key Server persistence surface. Implementations: MemoryStore
// (tests/dev) and PostgresStore (production).
type Store interface {
	// --- documents (v1 compatibility, policy management) ---
	EnsureDocument(uuid string, defaultPolicies keyclient.Policies, defaultTTL time.Duration) (*Document, error)
	Document(uuid string) (*Document, bool)
	SetPolicy(uuid string, policies keyclient.Policies, ttl time.Duration) error
	RevokeDocument(uuid string)
	Documents() []*Document

	// --- agents (v2) ---
	EnsureAgent(id string)
	AgentRevoked(id string) bool
	RevokeAgent(id string)
	RegisterAgent(rec AgentRecord) error
	AgentByID(id string) (*AgentRecord, bool)
	AgentByOwnerKeyID(ownerKeyID string) (*AgentRecord, bool)
	SetReaderKey(ownerKeyID string, readerKey []byte) error

	// --- audit ---
	AddAudit(e AuditEntry)
	ListAudit(limit int) []AuditEntry

	// --- e2e sessions ---
	CreateE2ESession(ownerKeyID, peerAgentID string) (E2ESession, error)
	GetE2ESession(sessionID string) (E2ESession, bool)
	GetE2ESessionsByOwner(ownerKeyID string) []E2ESession

	// --- peer health (cluster coordination) ---
	RecordPeerStatus(peer string, alive bool)
	PeerStates() []PeerState
}

// MemoryStore is the default in-memory implementation.
type MemoryStore struct {
	mu        sync.RWMutex
	documents map[string]*Document
	agents    map[string]*AgentRecord // key: AgentID
	byOwner   map[string]string       // ownerKeyID -> AgentID
	audit     []AuditEntry
	e2e       map[string]*E2ESession // sessionID -> session
	peers     map[string]*PeerState  // peer addr -> state
}

// NewMemoryStore creates an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		documents: make(map[string]*Document),
		agents:    make(map[string]*AgentRecord),
		byOwner:   make(map[string]string),
		e2e:       make(map[string]*E2ESession),
		peers:     make(map[string]*PeerState),
	}
}

// NewStore is an alias kept for compatibility.
func NewStore() *MemoryStore { return NewMemoryStore() }

// EnsureDocument returns the document, creating it on first access.
func (s *MemoryStore) EnsureDocument(uuid string, defaultPolicies keyclient.Policies, defaultTTL time.Duration) (*Document, error) {
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
func (s *MemoryStore) Document(uuid string) (*Document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	doc, ok := s.documents[uuid]
	return doc, ok
}

// SetPolicy updates the policies and TTL of a document.
func (s *MemoryStore) SetPolicy(uuid string, policies keyclient.Policies, ttl time.Duration) error {
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
func (s *MemoryStore) RevokeDocument(uuid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if doc, ok := s.documents[uuid]; ok {
		doc.Revoked = true
	} else {
		s.documents[uuid] = &Document{UUID: uuid, Revoked: true}
	}
}

// Documents lists all registered documents.
func (s *MemoryStore) Documents() []*Document {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Document, 0, len(s.documents))
	for _, d := range s.documents {
		out = append(out, d)
	}
	return out
}

// EnsureAgent registers the agent id if unknown (v1 flows).
func (s *MemoryStore) EnsureAgent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.agents[id]; !ok {
		s.agents[id] = &AgentRecord{AgentID: id, CreatedAt: time.Now()}
	}
}

// AgentRevoked reports whether the agent was revoked.
func (s *MemoryStore) AgentRevoked(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, ok := s.agents[id]
	return ok && agent.Revoked
}

// RevokeAgent revokes an agent by ID.
func (s *MemoryStore) RevokeAgent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if agent, ok := s.agents[id]; ok {
		agent.Revoked = true
	} else {
		s.agents[id] = &AgentRecord{AgentID: id, Revoked: true}
	}
}

// RegisterAgent creates or updates the v2 agent registration.
func (s *MemoryStore) RegisterAgent(rec AgentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rec.AgentID == "" || rec.OwnerKeyID == "" {
		return fmt.Errorf("keyserver: agent_id and owner_key_id are required")
	}
	if existing, ok := s.agents[rec.AgentID]; ok {
		// Keep revoked state.
		rec.Revoked = existing.Revoked
	}
	rec.CreatedAt = time.Now()
	s.agents[rec.AgentID] = &rec
	s.byOwner[rec.OwnerKeyID] = rec.AgentID
	return nil
}

// AgentByID returns the agent record.
func (s *MemoryStore) AgentByID(id string) (*AgentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.agents[id]
	return rec, ok
}

// AgentByOwnerKeyID returns the agent by its owner identifier.
func (s *MemoryStore) AgentByOwnerKeyID(ownerKeyID string) (*AgentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agentID, ok := s.byOwner[ownerKeyID]
	if !ok {
		return nil, false
	}
	rec, ok := s.agents[agentID]
	return rec, ok
}

// SetReaderKey stores the agent's reader key (AS).
func (s *MemoryStore) SetReaderKey(ownerKeyID string, readerKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	agentID, ok := s.byOwner[ownerKeyID]
	if !ok {
		return fmt.Errorf("keyserver: agent with owner key id %q not found", ownerKeyID)
	}
	rec := s.agents[agentID]
	rec.ReaderKey = append([]byte(nil), readerKey...)
	return nil
}

// AddAudit appends an audit record.
func (s *MemoryStore) AddAudit(e AuditEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, e)
}

// CreateE2ESession records a rendezvous for the e2e relay.
func (s *MemoryStore) CreateE2ESession(ownerKeyID, peerAgentID string) (E2ESession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return E2ESession{}, fmt.Errorf("keyserver: session id: %w", err)
	}
	session := E2ESession{
		SessionID:   "e2e-" + fmt.Sprintf("%x", buf),
		OwnerKeyID:  ownerKeyID,
		PeerAgentID: peerAgentID,
		CreatedAt:   time.Now(),
	}
	s.e2e[session.SessionID] = &session
	return session, nil
}

// GetE2ESession returns the rendezvous by id.
func (s *MemoryStore) GetE2ESession(sessionID string) (E2ESession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.e2e[sessionID]
	if !ok {
		return E2ESession{}, false
	}
	return *session, true
}

// GetE2ESessionsByOwner returns all rendezvous awaiting the owner.
func (s *MemoryStore) GetE2ESessionsByOwner(ownerKeyID string) []E2ESession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []E2ESession
	for _, session := range s.e2e {
		if session.OwnerKeyID == ownerKeyID {
			out = append(out, *session)
		}
	}
	return out
}

// RecordPeerStatus stores the latest observed health of a peer.
func (s *MemoryStore) RecordPeerStatus(peer string, alive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	st, ok := s.peers[peer]
	if !ok {
		st = &PeerState{Peer: peer}
		s.peers[peer] = st
	}
	st.LastSeen = now
	if alive {
		st.LastOK = now
	}
}

// PeerStates returns the observed health states of all peers.
func (s *MemoryStore) PeerStates() []PeerState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]PeerState, 0, len(s.peers))
	for _, st := range s.peers {
		out = append(out, *st)
	}
	return out
}

// ListAudit returns up to limit latest audit entries (most recent first).
func (s *MemoryStore) ListAudit(limit int) []AuditEntry {
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
