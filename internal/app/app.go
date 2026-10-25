// Package app wires the agent together: configuration loading, logging,
// health checking and graceful shutdown.
//
// Later phases will initialize the FUSE filesystem, the Key Server client,
// the Firejail sandbox and the RBA module here.
package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/clavis/clavis/internal/agentid"
	"github.com/clavis/clavis/internal/cache"
	"github.com/clavis/clavis/internal/config"
	"github.com/clavis/clavis/internal/crypto"
	"github.com/clavis/clavis/internal/e2e"
	"github.com/clavis/clavis/internal/fuse"
	"github.com/clavis/clavis/internal/interceptor"
	"github.com/clavis/clavis/internal/keyclient"
	"github.com/clavis/clavis/internal/logging"
	"github.com/clavis/clavis/internal/mode"
	"github.com/clavis/clavis/internal/token"
	"github.com/clavis/clavis/internal/version"
)

const shutdownTimeout = 5 * time.Second

// Run starts the agent and blocks until ctx is canceled (SIGINT/SIGTERM)
// or a fatal initialization error occurs.
func Run(ctx context.Context, cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	logger, err := logging.Init(&cfg.Log)
	if err != nil {
		return fmt.Errorf("init logging: %w", err)
	}
	defer func() {
		_ = logger.Close()
	}()

	logger.Info("starting clavis",
		"version", version.String(),
		"config", cfgPath,
		"agent_id", cfg.Agent.ID,
	)

	if err := prepareMountPoint(cfg.Fuse.MountPoint); err != nil {
		return err
	}
	if cfg.Crypto.KeyFile == "" {
		return errors.New("crypto.key_file is required for the fuse mount")
	}

	var (
		identity    *crypto.AgentIdentity
		serverPub   []byte
		serverNonce []byte
		readerKeys  fuse.ReaderKeyProvider
		relays      []string
		multi       *keyclient.MultiClient
	)
	var keyGetter crypto.KeyGetter = crypto.NewFileKeyGetter(cfg.Crypto.KeyFile)
	if cfg.Server.URL != "" {
		tlsCfg, err := keyclient.NewTLSConfig(keyclient.TLSConfig{
			CAFile:   cfg.Server.CAFile,
			CertFile: cfg.Server.CertFile,
			KeyFile:  cfg.Server.KeyFile,
		})
		if err != nil {
			return fmt.Errorf("key server tls: %w", err)
		}
		// Multiple servers may be configured (comma separated): the agent
		// registers a reader key (AS) per server and fails over to the
		// next healthy one.
		urls := splitCSV(cfg.Server.URL)
		relays = splitCSV(cfg.Server.RelayAddr)
		if len(urls) == 0 {
			return errors.New("server.url must not be empty")
		}
		clientTimeout := time.Duration(cfg.Server.TimeoutSeconds) * time.Second
		clients := make([]*keyclient.Client, 0, len(urls))
		for _, u := range urls {
			client := keyclient.NewClient(u, tlsCfg, clientTimeout)
			client.SetAgentID(cfg.Agent.ID)
			clients = append(clients, client)
		}
		multi = keyclient.NewMultiClient(clients)
		keyGetter = keyclient.NewGetter(multi, keyclient.NewCache())

		// v2: persistent agent identity + registration + reader keys
		// on every configured server.
		if cfg.Crypto.IdentityFile == "" {
			return errors.New("crypto.identity_file is required with a key server")
		}
		state, err := agentid.LoadOrCreate(cfg.Crypto.IdentityFile)
		if err != nil {
			return fmt.Errorf("agent identity: %w", err)
		}
		if err := agentid.EnsureRegistered(ctx, multi, urls, state, cfg.Crypto.IdentityFile); err != nil {
			return fmt.Errorf("agent registration: %w", err)
		}
		identity, err = state.Identity()
		if err != nil {
			return fmt.Errorf("agent identity: %w", err)
		}
		if serverPub, err = state.ServerPub(); err != nil {
			return err
		}
		if serverNonce, err = state.ServerNonceBytes(); err != nil {
			return err
		}
		readerKeys = routerReaderKeys{
			multi:   multi,
			relays:  relays,
			agentID: cfg.Agent.ID,
		}

		// Offline cache: remember fetched reader keys in SQLite (wrapped
		// under the local master key A) so documents open without network.
		if cfg.Crypto.LocalCacheDB != "" {
			if err := os.MkdirAll(filepath.Dir(cfg.Crypto.LocalCacheDB), 0o700); err != nil {
				logger.Warn("local cache dir", "error", err)
			}
			disk, err := cache.Open(cfg.Crypto.LocalCacheDB, identity.MasterKey)
			if err != nil {
				logger.Warn("offline cache disabled", "path", cfg.Crypto.LocalCacheDB, "error", err)
			} else {
				defer func() { _ = disk.Close() }()
				readerKeys = &cachedReaderKeys{inner: readerKeys, store: disk}
				logger.Info("offline cache enabled", "path", cfg.Crypto.LocalCacheDB)
			}
		}
		logger.Info("using key servers", "urls", urls, "count", len(urls))
	} else if cfg.Token.ModulePath != "" {
		backend, err := token.Open(token.Config{
			ModulePath:      cfg.Token.ModulePath,
			TokenLabel:      cfg.Token.TokenLabel,
			PIN:             cfg.Token.PIN,
			WrapKeyLabel:    cfg.Token.WrapKeyLabel,
			GenerateWrapKey: cfg.Token.GenerateWrapKey,
		})
		if err != nil {
			return fmt.Errorf("token: %w", err)
		}
		defer func() {
			_ = backend.Close()
		}()
		keyGetter = token.NewGetter(backend, cfg.Token.BlobsDir)
		logger.Info("using hardware token", "module", cfg.Token.ModulePath)
	}

	// Sharing mode for new documents, writable from the desktop GUI.
	modeMgr, _ := mode.Open("")
	modeProvider := func() crypto.Mode { return modeMgr.Get() }

	if cfg.Agent.UIListen != "" && identity != nil && multi != nil {
		ui := NewUIServer(cfg.Agent.UIListen, modeMgr, multi, relays, identity, cfg.Agent.ID, logger)
		if err := ui.Start(); err != nil {
			logger.Warn("ui server disabled", "error", err)
		} else {
			defer ui.Stop()
		}
	}

	policy := interceptor.NewPolicy(interceptor.Config{
		AllowUID0:     cfg.Policy.AllowUID0,
		AllowFirejail: cfg.Policy.AllowFirejail,
		Whitelist:     cfg.Policy.Whitelist,
	}, logger.Logger)

	server, err := fuse.Mount(fuse.MountConfig{
		SourceDir:    cfg.Fuse.Directory,
		MountPoint:   cfg.Fuse.MountPoint,
		Options:      cfg.Fuse.Options,
		KeyGetter:    keyGetter,
		Interceptor:  policy,
		Logger:       logger.Logger,
		Identity:     identity,
		ServerPub:    serverPub,
		ServerNonce:  serverNonce,
		DefaultMode:  crypto.ModeProxy,
		ModeProvider: modeProvider,
		ReaderKeys:   readerKeys,
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := fuse.Unmount(server); err != nil {
			logger.Error("fuse unmount failed", "error", err)
		}
	}()

	health := newHealthServer(cfg.Agent.HealthListen, logger)
	if err := health.start(); err != nil {
		return err
	}
	defer health.stop()

	<-ctx.Done()
	logger.Info("shutdown signal received, stopping agent")
	return nil
}

// routerReaderKeys adapts the failover key-server client and the e2e
// relays to fuse.ReaderKeyProvider. Proxy-mode documents resolve the
// reader key through the first healthy server; e2e-mode documents
// exchange it directly through the relay of the last healthy server.
type routerReaderKeys struct {
	multi   *keyclient.MultiClient
	relays  []string
	agentID string
}

// ReaderKey implements fuse.ReaderKeyProvider.
func (r routerReaderKeys) ReaderKey(ctx context.Context, ownerKeyID [16]byte, mode crypto.Mode) ([]byte, []byte, error) {
	ownerHex := hex.EncodeToString(ownerKeyID[:])
	if mode == crypto.ModeE2E {
		relayAddr := relayFor(r.relays, r.multi.LastSuccessIndex())
		if relayAddr == "" {
			return nil, nil, errors.New("e2e mode requires server.relay_addr")
		}
		session, err := r.multi.CreateE2ESession(ctx, ownerHex, r.agentID)
		if err != nil {
			return nil, nil, err
		}
		conn, err := e2e.Dial(relayAddr, session.SessionID, e2e.RolePeer, r.agentID)
		if err != nil {
			return nil, nil, err
		}
		defer func() { _ = conn.Close() }()
		return e2e.PeerReceive(conn)
	}

	m, err := r.multi.ReaderKey(ctx, ownerHex)
	return m.ReaderKey, m.PubSig, err
}

// relayFor picks the relay for the last healthy server index, falling
// back to the first configured relay.
func relayFor(relays []string, index int) string {
	if index >= 0 && index < len(relays) {
		return relays[index]
	}
	if len(relays) > 0 {
		return relays[0]
	}
	return ""
}

// cachedReaderKeys serves a previously fetched reader key from the local
// SQLite cache first (offline), otherwise delegates to the inner provider
// and stores the successful result.
type cachedReaderKeys struct {
	inner fuse.ReaderKeyProvider
	store *cache.Store
}

// ReaderKey implements fuse.ReaderKeyProvider.
func (c *cachedReaderKeys) ReaderKey(ctx context.Context, ownerKeyID [16]byte, mode crypto.Mode) ([]byte, []byte, error) {
	if as, pub, ok := c.store.Get(ownerKeyID); ok {
		return as, pub, nil
	}
	as, pub, err := c.inner.ReaderKey(ctx, ownerKeyID, mode)
	if err != nil {
		return nil, nil, err
	}
	_ = c.store.Put(ownerKeyID, as, pub)
	return as, pub, nil
}

// splitCSV splits a comma-separated list into trimmed non-empty entries.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// prepareMountPoint makes sure the mount point directory exists.
// Unlike the protected directory (which must exist beforehand), the mount
// point is created automatically if missing.
func prepareMountPoint(mountPoint string) error {
	if mountPoint == "" {
		return errors.New("fuse.mount_point must not be empty")
	}
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		return fmt.Errorf("create mount point %q: %w", mountPoint, err)
	}
	return nil
}

// healthServer is a minimal HTTP server for liveness checks.
type healthServer struct {
	listen string
	logger *logging.Logger
	server *http.Server
}

func newHealthServer(listen string, logger *logging.Logger) *healthServer {
	return &healthServer{listen: listen, logger: logger}
}

func (h *healthServer) start() error {
	if h.listen == "" {
		h.logger.Info("health server disabled")
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	ln, err := net.Listen("tcp", h.listen)
	if err != nil {
		return fmt.Errorf("listen health %q: %w", h.listen, err)
	}

	h.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() {
		if err := h.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.logger.Error("health server failed", "error", err)
		}
	}()
	h.logger.Info("health server listening", "addr", h.listen)
	return nil
}

func (h *healthServer) stop() {
	if h.server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := h.server.Shutdown(ctx); err != nil {
		h.logger.Error("health server shutdown", "error", err)
	}
}
