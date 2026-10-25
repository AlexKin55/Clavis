// Command server runs the Clavis Key Server: central key issuance,
// revocation, policy management and the audit trail. The API is served
// over HTTP(S); with a CA configured, agents are authenticated with
// mutual TLS (their client certificate CN becomes the agent ID).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/clavis/clavis/internal/keyclient"
	"github.com/clavis/clavis/internal/keyserver"
	"github.com/clavis/clavis/internal/version"
)

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("clavis-server", flag.ContinueOnError)
	configPath := fs.String("config", "server.yaml", "path to server YAML config")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println(version.String())
		return 0
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	store := keyserver.NewStore()
	handler := keyserver.NewServer(keyserver.Config{
		DefaultPolicies: keyclient.Policies{ReadWrite: true},
		DefaultTTL:      time.Duration(cfg.DefaultTTLSeconds) * time.Second,
	}, store).Handler()

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		return 1
	}

	if cfg.TLS.CertFile != "" {
		tlsCfg, err := serverTLS(cfg.TLS)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tls:", err)
			_ = ln.Close()
			return 1
		}
		httpServer.TLSConfig = tlsCfg
	}

	serveErr := make(chan error, 1)
	go func() {
		if cfg.TLS.CertFile != "" {
			serveErr <- httpServer.ServeTLS(ln, cfg.TLS.CertFile, cfg.TLS.KeyFile)
			return
		}
		serveErr <- httpServer.Serve(ln)
	}()
	fmt.Printf("clavis key server listening on %s\n", cfg.Listen)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintln(os.Stderr, "shutdown:", err)
			return 1
		}
		return 0
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "server:", err)
			return 1
		}
		return 0
	}
}

// serverTLS builds the mTLS configuration. When tls.ca_file is set, agents
// must present a certificate signed by one of the listed CAs.
func serverTLS(cfg TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.CAFile != "" {
		pool := x509.NewCertPool()
		ca, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("no certificates in ca file %q", cfg.CAFile)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}
