// Package agentapi is a minimal HTTP client for the agent's localhost
// GUI API (internal/app/ui.go). It lets the desktop GUI read the sharing
// mode, list pending end-to-end requests and approve them. The package is
// deliberately toolkit-free so the flow logic can be tested with plain
// test doubles.
package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PendingE2ESession mirrors the agent's /api/e2e/pending response item.
type PendingE2ESession struct {
	SessionID string `json:"session_id"`
	PeerAgent string `json:"peer_agent_id"`
}

// Client talks to the agent's localhost UI API.
type Client struct {
	base string
	http *http.Client
}

// NewClient creates the client. base is e.g. "http://127.0.0.1:8902".
func NewClient(base string) *Client {
	if base == "" {
		base = "http://127.0.0.1:8902"
	}
	return &Client{
		base: base,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// PendingE2ESessions lists rendezvous awaiting the owner's approval.
func (c *Client) PendingE2ESessions(ctx context.Context) ([]PendingE2ESession, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/e2e/pending", nil)
	if err != nil {
		return nil, fmt.Errorf("agentapi: build pending request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agentapi: pending request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agentapi: pending: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("agentapi: read pending: %w", err)
	}
	var out struct {
		Pending []PendingE2ESession `json:"pending"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("agentapi: decode pending: %w", err)
	}
	if out.Pending == nil {
		out.Pending = []PendingE2ESession{}
	}
	return out.Pending, nil
}

// ApproveE2ESession grants the end-to-end key to the peer by approving
// the rendezvous (the agent performs the cryptographic exchange).
func (c *Client) ApproveE2ESession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return errors.New("agentapi: session id is required")
	}
	payload, err := json.Marshal(map[string]string{"session_id": sessionID})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/e2e/approve", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("agentapi: build approve request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("agentapi: approve request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agentapi: approve: HTTP %s", resp.Status)
	}
	return nil
}
