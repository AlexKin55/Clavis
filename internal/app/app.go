// Package app wires the agent together: configuration loading, logging,
// health checking and graceful shutdown.
//
// Later phases will initialize the FUSE filesystem, the Key Server client,
// the Firejail sandbox and the RBA module here.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/clavis/clavis/internal/config"
	"github.com/clavis/clavis/internal/logging"
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

	// The FUSE filesystem initialization will be added in phase 2 (internal/fuse).
	logger.Info("fuse backend not yet implemented: skipping mount",
		"directory", cfg.Fuse.Directory,
		"mount_point", cfg.Fuse.MountPoint,
		"options", cfg.Fuse.Options,
	)

	health := newHealthServer(cfg.Agent.HealthListen, logger)
	if err := health.start(); err != nil {
		return err
	}
	defer health.stop()

	<-ctx.Done()
	logger.Info("shutdown signal received, stopping agent")
	return nil
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
