package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/clavis/clavis/internal/crypto"
	"github.com/clavis/clavis/internal/e2e"
	"github.com/clavis/clavis/internal/keyclient"
	"github.com/clavis/clavis/internal/logging"
	"github.com/clavis/clavis/internal/mode"
)

// UIServer is the agent's localhost API consumed by the desktop GUI
// (Fyne). It exposes the per-file default sharing mode and the e2e
// approval flow: the GUI asks, the agent performs the cryptographic
// exchange (it holds the identity).
type UIServer struct {
	listen   string
	mode     *mode.Manager
	multi    *keyclient.MultiClient
	relays   []string
	identity *crypto.AgentIdentity
	agentID  string
	logger   *logging.Logger
	server   *http.Server
}

// NewUIServer creates the local GUI API server.
func NewUIServer(listen string, mgr *mode.Manager, multi *keyclient.MultiClient, relays []string, identity *crypto.AgentIdentity, agentID string, logger *logging.Logger) *UIServer {
	return &UIServer{
		listen:   listen,
		mode:     mgr,
		multi:    multi,
		relays:   relays,
		identity: identity,
		agentID:  agentID,
		logger:   logger,
	}
}

// Start binds the listener and serves the API.
func (s *UIServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/mode", s.handleGetMode)
	mux.HandleFunc("POST /api/mode", s.handleSetMode)
	mux.HandleFunc("GET /api/e2e/pending", s.handlePending)
	mux.HandleFunc("POST /api/e2e/approve", s.handleApprove)

	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("ui listen %q: %w", s.listen, err)
	}
	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("ui server failed", "error", err)
		}
	}()
	s.logger.Info("ui server listening", "addr", s.listen)
	return nil
}

// Stop shuts the API server down.
func (s *UIServer) Stop() {
	if s.server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.server.Shutdown(ctx)
}

func (s *UIServer) handleGetMode(w http.ResponseWriter, _ *http.Request) {
	name, _ := mode.String(s.mode.Get())
	writeUIJSON(w, http.StatusOK, map[string]string{"mode": name})
}

func (s *UIServer) handleSetMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeUIError(w, http.StatusBadRequest, "invalid body")
		return
	}
	m, ok := mode.Parse(req.Mode)
	if !ok {
		writeUIError(w, http.StatusBadRequest, "unknown mode")
		return
	}
	if err := s.mode.Set(m); err != nil {
		writeUIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeUIJSON(w, http.StatusOK, map[string]bool{"updated": true})
}

func (s *UIServer) handlePending(w http.ResponseWriter, _ *http.Request) {
	if s.multi == nil || s.identity == nil {
		writeUIJSON(w, http.StatusOK, map[string]any{"pending": []keyclient.PendingE2ESession{}})
		return
	}
	ownerID := s.identity.OwnerKeyID()
	owner := hex.EncodeToString(ownerID[:])
	sessions, err := s.multi.PendingE2ESessions(context.Background(), owner)
	if err != nil {
		writeUIError(w, http.StatusBadGateway, err.Error())
		return
	}
	if sessions == nil {
		sessions = []keyclient.PendingE2ESession{}
	}
	writeUIJSON(w, http.StatusOK, map[string]any{"pending": sessions})
}

func (s *UIServer) handleApprove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeUIError(w, http.StatusBadRequest, "session_id is required")
		return
	}
	if s.identity == nil {
		writeUIError(w, http.StatusConflict, "agent identity not configured")
		return
	}
	relay := relayFor(s.relays, s.multi.LastSuccessIndex())
	if relay == "" {
		writeUIError(w, http.StatusConflict, "no e2e relay configured")
		return
	}
	as, err := s.identity.UnifiedReaderKey()
	if err != nil {
		writeUIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	conn, err := e2e.Dial(relay, req.SessionID, e2e.RoleOwner, s.agentID)
	if err != nil {
		writeUIError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer func() { _ = conn.Close() }()

	if err := e2e.OwnerShare(conn, as, s.identity.PublicSignatureKey()); err != nil {
		writeUIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeUIJSON(w, http.StatusOK, map[string]bool{"granted": true})
}

func writeUIJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeUIError(w http.ResponseWriter, status int, message string) {
	writeUIJSON(w, status, map[string]string{"error": message})
}
