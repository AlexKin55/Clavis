// Package keyserver implements the Key Server API that the agent client
// (internal/keyclient) talks to: key issuance for documents, revocation,
// policy management and the audit trail. TLS/mTLS is applied at the
// http.Server level; the handler extracts the client identity from the
// peer certificate or the X-Agent-ID header.
package keyserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/clavis/clavis/internal/keyclient"
)

// DefaultAPIPath is the key issuance endpoint (must match keyclient).
const DefaultAPIPath = "/api/v1/keys/issue"

// Config tunes the Key Server behavior.
type Config struct {
	// DefaultPolicies are granted to a document at first issuance.
	DefaultPolicies keyclient.Policies
	// DefaultTTL bounds the issued keys unless overridden per document.
	DefaultTTL time.Duration
	// ServerKey is the server's public Ed25519 key handed out to agents
	// during registration (used as the S input for reader-key derivation).
	ServerKey ed25519.PublicKey
}

// Server is the Key Server HTTP handler.
type Server struct {
	store Store
	cfg   Config
}

// NewServer creates the Key Server handler.
func NewServer(cfg Config, store Store) *Server {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = time.Hour
	}
	if store == nil {
		store = NewMemoryStore()
	}
	return &Server{store: store, cfg: cfg}
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST "+DefaultAPIPath, s.handleIssue)
	mux.HandleFunc("POST /api/v1/keys/revoke", s.handleRevokeDocument)
	mux.HandleFunc("PUT /api/v1/documents/{uuid}/policy", s.handleSetPolicy)
	mux.HandleFunc("GET /api/v1/documents", s.handleListDocuments)
	mux.HandleFunc("GET /api/v1/audit", s.handleAudit)
	mux.HandleFunc("POST /api/v1/agents/register", s.handleRegisterAgent)
	mux.HandleFunc("POST /api/v1/agents/revoke", s.handleRevokeAgent)

	// v2 registration and reader-key API.
	mux.HandleFunc("POST /api/v1/agents/reader-key", s.handleSetReaderKey)
	mux.HandleFunc("GET /api/v1/agents/{owner_key_id}/reader-key", s.handleGetReaderKey)

	// e2e rendezvous.
	mux.HandleFunc("POST /api/v1/e2e/sessions", s.handleCreateE2ESession)
	mux.HandleFunc("GET /api/v1/e2e/pending", s.handlePendingE2ESessions)

	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type issueResponse struct {
	Key        string             `json:"key"`
	TTLSeconds int64              `json:"ttl_seconds"`
	Policies   keyclient.Policies `json:"policies"`
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req keyclient.IssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DocumentUUID == "" {
		writeError(w, http.StatusBadRequest, "document_uuid is required")
		return
	}

	agentID := agentIDFromRequest(r)
	if agentID == "" {
		agentID = "(unknown)"
	}
	s.store.EnsureAgent(agentID)

	// Deny revoked agents immediately ("one click" revocation).
	if s.store.AgentRevoked(agentID) {
		s.store.AddAudit(AuditEntry{
			Time: time.Now(), AgentID: agentID,
			Document: req.DocumentUUID, Allowed: false, Reason: "agent revoked",
		})
		writeError(w, http.StatusForbidden, "agent revoked")
		return
	}

	// The document key is deterministic: created once, served identically.
	doc, err := s.store.EnsureDocument(req.DocumentUUID, s.cfg.DefaultPolicies, s.cfg.DefaultTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store failure")
		return
	}
	if doc.Revoked {
		s.store.AddAudit(AuditEntry{
			Time: time.Now(), AgentID: agentID,
			Document: req.DocumentUUID, Allowed: false, Reason: "document revoked",
		})
		writeError(w, http.StatusForbidden, "document revoked")
		return
	}

	s.store.AddAudit(AuditEntry{
		Time: time.Now(), AgentID: agentID,
		Document: req.DocumentUUID, Allowed: true, Reason: "key issued",
	})

	writeJSON(w, http.StatusOK, issueResponse{
		Key:        hex.EncodeToString(doc.Key),
		TTLSeconds: int64(doc.TTL / time.Second),
		Policies:   doc.Policies,
	})
}

type revokeDocumentRequest struct {
	DocumentUUID string `json:"document_uuid"`
}

func (s *Server) handleRevokeDocument(w http.ResponseWriter, r *http.Request) {
	var req revokeDocumentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DocumentUUID == "" {
		writeError(w, http.StatusBadRequest, "document_uuid is required")
		return
	}
	s.store.RevokeDocument(req.DocumentUUID)
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

type setPolicyRequest struct {
	Policies   keyclient.Policies `json:"policies"`
	TTLSeconds int64              `json:"ttl_seconds"`
}

func (s *Server) handleSetPolicy(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if uuid == "" {
		writeError(w, http.StatusBadRequest, "uuid is required")
		return
	}

	var req setPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.Policies.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = s.cfg.DefaultTTL
	}
	if err := s.store.SetPolicy(uuid, req.Policies, ttl); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"updated": true})
}

type documentView struct {
	UUID       string             `json:"uuid"`
	TTLSeconds int64              `json:"ttl_seconds"`
	Revoked    bool               `json:"revoked"`
	Policies   keyclient.Policies `json:"policies"`
}

func (s *Server) handleListDocuments(w http.ResponseWriter, _ *http.Request) {
	docs := s.store.Documents()
	view := make([]documentView, 0, len(docs))
	for _, d := range docs {
		view = append(view, documentView{
			UUID:       d.UUID,
			TTLSeconds: int64(d.TTL / time.Second),
			Revoked:    d.Revoked,
			Policies:   d.Policies,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"documents": view})
}

type auditView struct {
	Time     string `json:"time"`
	AgentID  string `json:"agent_id"`
	Document string `json:"document"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason"`
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	entries := s.store.ListAudit(limit)
	view := make([]auditView, 0, len(entries))
	for _, e := range entries {
		view = append(view, auditView{
			Time:     e.Time.Format(time.RFC3339),
			AgentID:  e.AgentID,
			Document: e.Document,
			Allowed:  e.Allowed,
			Reason:   e.Reason,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": view})
}

type registerAgentRequest struct {
	DeviceID string `json:"device_id"`
	PubSig   []byte `json:"pub_sig"`
}

type registerAgentResponse struct {
	AgentID         string `json:"agent_id"`
	PublicKeyServer string `json:"public_key_server"`
	NonceServer     string `json:"nonce_server"`
}

func (s *Server) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	var req registerAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.PubSig) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "invalid pub_sig length")
		return
	}
	if len(s.cfg.ServerKey) != ed25519.PublicKeySize {
		writeError(w, http.StatusInternalServerError, "server key not configured")
		return
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		writeError(w, http.StatusInternalServerError, "nonce generation failed")
		return
	}
	owner := sha256.Sum256(req.PubSig)
	ownerKeyID := hex.EncodeToString(owner[:16])
	agentID := newAgentID()

	if err := s.store.RegisterAgent(AgentRecord{
		AgentID:     agentID,
		DeviceID:    req.DeviceID,
		PubSig:      req.PubSig,
		OwnerKeyID:  ownerKeyID,
		NonceServer: nonce,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.store.AddAudit(AuditEntry{
		Time: time.Now(), AgentID: agentID,
		Document: "-", Allowed: true, Reason: "agent registered",
	})

	writeJSON(w, http.StatusOK, registerAgentResponse{
		AgentID:         agentID,
		PublicKeyServer: hex.EncodeToString(s.cfg.ServerKey),
		NonceServer:     hex.EncodeToString(nonce),
	})
}

type setReaderKeyRequest struct {
	AgentID   string `json:"agent_id"`
	ReaderKey []byte `json:"reader_key"`
}

func (s *Server) handleSetReaderKey(w http.ResponseWriter, r *http.Request) {
	var req setReaderKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rec, ok := s.store.AgentByID(req.AgentID)
	if !ok {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if len(req.ReaderKey) < 16 {
		writeError(w, http.StatusBadRequest, "reader_key too short")
		return
	}
	if err := s.store.SetReaderKey(rec.OwnerKeyID, req.ReaderKey); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.store.AddAudit(AuditEntry{
		Time: time.Now(), AgentID: req.AgentID,
		Document: "-", Allowed: true, Reason: "reader key registered",
	})
	writeJSON(w, http.StatusOK, map[string]bool{"stored": true})
}

func (s *Server) handleGetReaderKey(w http.ResponseWriter, r *http.Request) {
	ownerKeyID := r.PathValue("owner_key_id")
	if ownerKeyID == "" {
		writeError(w, http.StatusBadRequest, "owner_key_id is required")
		return
	}

	rec, ok := s.store.AgentByOwnerKeyID(ownerKeyID)
	if !ok {
		s.store.AddAudit(AuditEntry{
			Time: time.Now(), AgentID: agentIDFromRequest(r),
			Document: ownerKeyID, Allowed: false, Reason: "owner not found",
		})
		writeError(w, http.StatusNotFound, "owner not found")
		return
	}
	if rec.Revoked {
		s.store.AddAudit(AuditEntry{
			Time: time.Now(), AgentID: agentIDFromRequest(r),
			Document: ownerKeyID, Allowed: false, Reason: "owner agent revoked",
		})
		writeError(w, http.StatusForbidden, "agent revoked")
		return
	}
	if len(rec.ReaderKey) == 0 {
		s.store.AddAudit(AuditEntry{
			Time: time.Now(), AgentID: agentIDFromRequest(r),
			Document: ownerKeyID, Allowed: false, Reason: "reader key not registered",
		})
		writeError(w, http.StatusNotFound, "reader key not registered")
		return
	}

	s.store.AddAudit(AuditEntry{
		Time: time.Now(), AgentID: agentIDFromRequest(r),
		Document: ownerKeyID, Allowed: true, Reason: "reader key issued",
	})
	// Return the owner's public signature key as well, so the reading
	// agent can verify the document signature.
	writeJSON(w, http.StatusOK, map[string]string{
		"reader_key": hex.EncodeToString(rec.ReaderKey),
		"pub_sig":    hex.EncodeToString(rec.PubSig),
	})
}

// handlePendingE2ESessions returns sessions awaiting the given owner.
func (s *Server) handlePendingE2ESessions(w http.ResponseWriter, r *http.Request) {
	owner := r.URL.Query().Get("owner_key_id")
	if owner == "" {
		writeError(w, http.StatusBadRequest, "owner_key_id is required")
		return
	}
	type pendingView struct {
		SessionID string `json:"session_id"`
		PeerAgent string `json:"peer_agent_id"`
	}
	sessions := s.store.GetE2ESessionsByOwner(owner)
	out := make([]pendingView, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, pendingView{SessionID: s.SessionID, PeerAgent: s.PeerAgentID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": out})
}

// handleCreateE2ESession creates a rendezvous for the direct key exchange.
func (s *Server) handleCreateE2ESession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OwnerKeyID  string `json:"owner_key_id"`
		PeerAgentID string `json:"peer_agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.OwnerKeyID == "" {
		writeError(w, http.StatusBadRequest, "owner_key_id is required")
		return
	}
	session, err := s.store.CreateE2ESession(req.OwnerKeyID, req.PeerAgentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"session_id":    session.SessionID,
		"owner_key_id":  session.OwnerKeyID,
		"peer_agent_id": session.PeerAgentID,
	})
}

// newAgentID returns a server-assigned agent identifier.
func newAgentID() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("ag-%x", buf) // best effort
	}
	return "ag-" + hex.EncodeToString(buf)
}

type revokeAgentRequest struct {
	AgentID string `json:"agent_id"`
}

func (s *Server) handleRevokeAgent(w http.ResponseWriter, r *http.Request) {
	var req revokeAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id is required")
		return
	}
	s.store.RevokeAgent(req.AgentID)
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// agentIDFromRequest takes the client identity from the X-Agent-ID header
// or, with mTLS, from the client certificate common name.
func agentIDFromRequest(r *http.Request) string {
	if id := r.Header.Get("X-Agent-ID"); id != "" {
		return id
	}
	if r.TLS != nil {
		for _, cert := range r.TLS.PeerCertificates {
			if cn := cert.Subject.CommonName; cn != "" {
				return cn
			}
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
