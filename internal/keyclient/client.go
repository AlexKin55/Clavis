package keyclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// issuePath is the Key Server endpoint for key issuance.
const issuePath = "/api/v1/keys/issue"

// v2 API paths.
const (
	registerPath     = "/api/v1/agents/register"
	setReaderKeyPath = "/api/v1/agents/reader-key"
	readerKeyPrefix  = "/api/v1/agents/"
	readerKeySuffix  = "/reader-key"
)

// Client talks to the Key Server over TLS/mTLS.
type Client struct {
	baseURL string
	httpc   *http.Client
	agentID string
}

// TLSConfig pins the files for mutual TLS.
type TLSConfig struct {
	// CAFile is the CA that signed the server certificate.
	CAFile string
	// CertFile is the agent client certificate.
	CertFile string
	// KeyFile is the private key of the agent certificate.
	KeyFile string
}

// NewTLSConfig loads the CA and client certificate/key pair for mTLS.
func NewTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if cfg.CAFile != "" {
		ca, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("keyclient: read ca file: %w", err)
		}
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("keyclient: no certificates found in %q", cfg.CAFile)
		}
	}

	tlsCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("keyclient: load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

// NewClient creates a Key Server client. The timeout bounds each request.
func NewClient(baseURL string, tlsCfg *tls.Config, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	return &Client{
		baseURL: baseURL,
		httpc:   &http.Client{Timeout: timeout, Transport: transport},
	}
}

// SetAgentID sets the agent identity sent in the X-Agent-ID header.
// The server records it in the audit trail (with mTLS the certificate
// CN is used instead).
func (c *Client) SetAgentID(id string) {
	c.agentID = id
}

// IssueKey requests the key for the document.
func (c *Client) IssueKey(ctx context.Context, req IssueRequest) (*IssueResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("keyclient: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+issuePath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("keyclient: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.agentID != "" {
		httpReq.Header.Set("X-Agent-ID", c.agentID)
	}

	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("keyclient: request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, newServerError(resp.StatusCode, resp.Body)
	}

	var out IssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("keyclient: decode response: %w", err)
	}
	if out.Key == "" {
		return nil, errors.New("keyclient: empty key in response")
	}
	if _, err := hex.DecodeString(out.Key); err != nil {
		return nil, fmt.Errorf("keyclient: invalid key encoding: %w", err)
	}
	if err := out.Policies.Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

// Register performs the v2 agent registration and returns the server
// public key S and the registration nonce.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("keyclient: marshal registration: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+registerPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("keyclient: build registration: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.agentID != "" {
		httpReq.Header.Set("X-Agent-ID", c.agentID)
	}

	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("keyclient: registration failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, newServerError(resp.StatusCode, resp.Body)
	}

	var out RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("keyclient: decode registration: %w", err)
	}
	return &out, nil
}

// SetReaderKey stores the agent's reader key (AS) on the server.
func (c *Client) SetReaderKey(ctx context.Context, req SetReaderKeyRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("keyclient: marshal reader key: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+setReaderKeyPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("keyclient: build reader key request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.agentID != "" {
		httpReq.Header.Set("X-Agent-ID", c.agentID)
	}

	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("keyclient: set reader key failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return newServerError(resp.StatusCode, resp.Body)
	}
	return nil
}

// ReaderMaterial is the owner's read-only key pair material: the reader
// key AS (unwrap document keys) and the owner's public signature key.
type ReaderMaterial struct {
	ReaderKey []byte
	PubSig    []byte
}

// E2ESession is a rendezvous created for the direct key exchange.
type E2ESession struct {
	SessionID   string `json:"session_id"`
	OwnerKeyID  string `json:"owner_key_id"`
	PeerAgentID string `json:"peer_agent_id"`
}

// ReaderKey requests the read-only wrapper key (AS) and the owner's
// public signature key.
func (c *Client) ReaderKey(ctx context.Context, ownerKeyID string) (ReaderMaterial, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+readerKeyPrefix+ownerKeyID+readerKeySuffix, nil)
	if err != nil {
		return ReaderMaterial{}, fmt.Errorf("keyclient: build reader key request: %w", err)
	}
	if c.agentID != "" {
		httpReq.Header.Set("X-Agent-ID", c.agentID)
	}

	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return ReaderMaterial{}, fmt.Errorf("keyclient: reader key request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return ReaderMaterial{}, newServerError(resp.StatusCode, resp.Body)
	}

	var out struct {
		ReaderKey string `json:"reader_key"`
		PubSig    string `json:"pub_sig"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ReaderMaterial{}, fmt.Errorf("keyclient: decode reader key: %w", err)
	}
	as, err := hex.DecodeString(out.ReaderKey)
	if err != nil {
		return ReaderMaterial{}, fmt.Errorf("keyclient: invalid reader key encoding: %w", err)
	}
	pub, err := hex.DecodeString(out.PubSig)
	if err != nil {
		return ReaderMaterial{}, fmt.Errorf("keyclient: invalid pub_sig encoding: %w", err)
	}
	return ReaderMaterial{ReaderKey: as, PubSig: pub}, nil
}

// CreateE2ESession asks the Key Server for a rendezvous point for the
// direct (end-to-end) key exchange.
func (c *Client) CreateE2ESession(ctx context.Context, ownerKeyID, peerAgentID string) (*E2ESession, error) {
	body, err := json.Marshal(map[string]string{
		"owner_key_id":  ownerKeyID,
		"peer_agent_id": peerAgentID,
	})
	if err != nil {
		return nil, fmt.Errorf("keyclient: marshal e2e session: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/e2e/sessions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("keyclient: build e2e session: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.agentID != "" {
		httpReq.Header.Set("X-Agent-ID", c.agentID)
	}
	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("keyclient: e2e session failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, newServerError(resp.StatusCode, resp.Body)
	}
	var out E2ESession
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("keyclient: decode e2e session: %w", err)
	}
	return &out, nil
}

type serverError struct {
	status int
	body   string
}

func (e *serverError) Error() string {
	return fmt.Sprintf("keyclient: server responded %d: %s", e.status, e.body)
}

func newServerError(status int, body io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(body, 4096))
	if err != nil {
		data = []byte("<unreadable>")
	}
	return &serverError{status: status, body: string(data)}
}
