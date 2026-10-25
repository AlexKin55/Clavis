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

// serverError is a non-OK Key Server response.
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
