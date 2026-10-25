package keyclient

import (
	"context"
	"fmt"
	"sync"
)

// KeyIssuer is the minimal interface the key cache needs. Both Client and
// MultiClient implement it.
type KeyIssuer interface {
	IssueKey(ctx context.Context, req IssueRequest) (*IssueResponse, error)
}

// MultiClient tries a list of Key Server clients in order and stops at
// the first one that answers. This makes the agent resilient to a server
// becoming unavailable: the next healthy server in the list is used.
type MultiClient struct {
	mu          sync.Mutex
	clients     []*Client
	lastSuccess int
}

// NewMultiClient builds a failover client over the given servers.
func NewMultiClient(clients []*Client) *MultiClient {
	return &MultiClient{clients: clients, lastSuccess: -1}
}

// Client returns the underlying client at index i (nil when out of range).
func (m *MultiClient) Client(i int) *Client {
	if i < 0 || i >= len(m.clients) {
		return nil
	}
	return m.clients[i]
}

// Length returns the number of configured servers.
func (m *MultiClient) Length() int { return len(m.clients) }

// LastSuccessIndex returns the index of the last server that answered.
func (m *MultiClient) LastSuccessIndex() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastSuccess
}

// IssueKey implements KeyIssuer with failover across all servers.
func (m *MultiClient) IssueKey(ctx context.Context, req IssueRequest) (*IssueResponse, error) {
	var lastErr error
	for i, c := range m.clients {
		if c == nil {
			continue
		}
		resp, err := c.IssueKey(ctx, req)
		if err == nil {
			m.mu.Lock()
			m.lastSuccess = i
			m.mu.Unlock()
			return resp, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("keyclient: all %d servers failed: %w", len(m.clients), lastErr)
}

// Register tries registration on every server and returns the first
// success. Note: real multi-server registration is done per-server by
// the caller via RegisterAt.
func (m *MultiClient) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var lastErr error
	for i, c := range m.clients {
		if c == nil {
			continue
		}
		resp, err := c.Register(ctx, req)
		if err == nil {
			m.mu.Lock()
			m.lastSuccess = i
			m.mu.Unlock()
			return resp, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("keyclient: all %d servers failed to register: %w", len(m.clients), lastErr)
}

// RegisterAt registers with the exact server at index i (used to build a
// per-server AS table).
func (m *MultiClient) RegisterAt(ctx context.Context, i int, req RegisterRequest) (*RegisterResponse, error) {
	c := m.Client(i)
	if c == nil {
		return nil, fmt.Errorf("keyclient: server index %d out of range", i)
	}
	resp, err := c.Register(ctx, req)
	if err == nil {
		m.mu.Lock()
		m.lastSuccess = i
		m.mu.Unlock()
	}
	return resp, err
}

// SetReaderKey stores the reader key on the first responding server.
func (m *MultiClient) SetReaderKey(ctx context.Context, req SetReaderKeyRequest) error {
	var lastErr error
	for i, c := range m.clients {
		if c == nil {
			continue
		}
		err := c.SetReaderKey(ctx, req)
		if err == nil {
			m.mu.Lock()
			m.lastSuccess = i
			m.mu.Unlock()
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("keyclient: all %d servers failed to store reader key: %w", len(m.clients), lastErr)
}

// SetReaderKeyAt stores the reader key on the exact server at index i.
func (m *MultiClient) SetReaderKeyAt(ctx context.Context, i int, req SetReaderKeyRequest) error {
	c := m.Client(i)
	if c == nil {
		return fmt.Errorf("keyclient: server index %d out of range", i)
	}
	return c.SetReaderKey(ctx, req)
}

// ReaderKey requests the reader key from the first server that answers.
func (m *MultiClient) ReaderKey(ctx context.Context, ownerKeyID string) (ReaderMaterial, error) {
	var lastErr error
	for i, c := range m.clients {
		if c == nil {
			continue
		}
		mat, err := c.ReaderKey(ctx, ownerKeyID)
		if err == nil {
			m.mu.Lock()
			m.lastSuccess = i
			m.mu.Unlock()
			return mat, nil
		}
		lastErr = err
	}
	return ReaderMaterial{}, fmt.Errorf("keyclient: all %d servers failed to issue reader key: %w", len(m.clients), lastErr)
}

// PendingE2ESessions lists rendezvous awaiting the owner from the first
// server that answers.
func (m *MultiClient) PendingE2ESessions(ctx context.Context, ownerKeyID string) ([]PendingE2ESession, error) {
	var lastErr error
	for i, c := range m.clients {
		if c == nil {
			continue
		}
		sessions, err := c.PendingE2ESessions(ctx, ownerKeyID)
		if err == nil {
			m.mu.Lock()
			m.lastSuccess = i
			m.mu.Unlock()
			return sessions, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("keyclient: all %d servers failed to list pending sessions: %w", len(m.clients), lastErr)
}

// CreateE2ESession requests a rendezvous from the first server that
// answers.
func (m *MultiClient) CreateE2ESession(ctx context.Context, ownerKeyID, peerAgentID string) (*E2ESession, error) {
	var lastErr error
	for i, c := range m.clients {
		if c == nil {
			continue
		}
		session, err := c.CreateE2ESession(ctx, ownerKeyID, peerAgentID)
		if err == nil {
			m.mu.Lock()
			m.lastSuccess = i
			m.mu.Unlock()
			return session, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("keyclient: all %d servers failed to create e2e session: %w", len(m.clients), lastErr)
}
