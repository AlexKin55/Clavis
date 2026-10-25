// Package e2e implements the end-to-end sharing mode: the Key Server only
// organizes a relay (a "meeting point") between the document owner and a
// peer agent; the actual reader key (AS) is exchanged directly between the
// two agents over a session-encrypted channel, so the server never sees
// the key material.
package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Role identifies the side of an e2e session.
type Role string

// Session roles.
const (
	// RoleOwner is the document owner (sends the reader key).
	RoleOwner Role = "owner"
	// RolePeer is the reader agent (receives the reader key).
	RolePeer Role = "peer"
)

// handshake identifies a relay connection.
type handshake struct {
	SessionID string `json:"session_id"`
	Role      Role   `json:"role"`
	AgentID   string `json:"agent_id"`
}

// Dial connects to the relay server and performs the initial handshake.
// The returned connection is a raw bidirectional pipe to the counterpart.
func Dial(relayAddr, sessionID string, role Role, agentID string) (net.Conn, error) {
	conn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("e2e: dial relay: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(handshake{
		SessionID: sessionID,
		Role:      role,
		AgentID:   agentID,
	}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("e2e: handshake: %w", err)
	}
	return conn, nil
}

// RelayServer pairs connections with the same session id and pipes raw
// bytes between them. It never inspects the payload after the handshake.
type RelayServer struct {
	mu      sync.Mutex
	waiting map[string]net.Conn
	ln      net.Listener
}

// NewRelayServer starts listening on addr (e.g. ":0" for a random port).
func NewRelayServer(addr string) (*RelayServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("e2e: listen relay: %w", err)
	}
	return &RelayServer{
		waiting: make(map[string]net.Conn),
		ln:      ln,
	}, nil
}

// Addr returns the listening address.
func (s *RelayServer) Addr() string { return s.ln.Addr().String() }

// Serve accepts connections until closed.
func (s *RelayServer) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// Close stops the relay.
func (s *RelayServer) Close() error { return s.ln.Close() }

func (s *RelayServer) handle(conn net.Conn) {
	var handShake handshake
	if err := json.NewDecoder(conn).Decode(&handShake); err != nil {
		_ = conn.Close()
		return
	}

	s.mu.Lock()
	if peer, ok := s.waiting[handShake.SessionID]; ok {
		delete(s.waiting, handShake.SessionID)
		s.mu.Unlock()
		pipe(peer, conn)
		return
	}
	s.waiting[handShake.SessionID] = conn
	s.mu.Unlock()

	// Keep the waiting slot from leaking forever.
	time.AfterFunc(defaultWaitTimeout, func() {
		s.mu.Lock()
		if c, ok := s.waiting[handShake.SessionID]; ok && c == conn {
			delete(s.waiting, handShake.SessionID)
			_ = c.Close()
		}
		s.mu.Unlock()
	})
}

const defaultWaitTimeout = 30 * time.Second

func pipe(a, b net.Conn) {
	// Fire-and-forget: transfers run in the background. When one
	// direction finishes (EOF/error), both connections are closed so the
	// opposite copy terminates as well and no goroutine lingers.
	go func() {
		_, _ = io.Copy(a, b)
		_ = a.Close()
		_ = b.Close()
	}()
	go func() {
		_, _ = io.Copy(b, a)
		_ = b.Close()
		_ = a.Close()
	}()
}
