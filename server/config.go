package main

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the Key Server process configuration.
type Config struct {
	// Listen is the listen address (e.g. "0.0.0.0:8443").
	Listen string `yaml:"listen"`
	// DefaultTTLSeconds is the key lifetime granted on first issuance.
	DefaultTTLSeconds int `yaml:"default_ttl_seconds"`
	// DBURL, when set, enables the PostgreSQL store (agents + audit).
	DBURL string `yaml:"db_url"`
	// TLS enables mutual TLS (agent client certificates enforced).
	TLS TLSConfig `yaml:"tls"`
	// SigningKeyFile is the path to the 32-byte seed of the server's
	// Ed25519 key S (created on first run). Its public part and the
	// registration nonce are handed to agents (reader-key derivation).
	SigningKeyFile string `yaml:"signing_key_file"`
}

// TLSConfig holds TLS/mTLS settings.
type TLSConfig struct {
	// CertFile is the server certificate.
	CertFile string `yaml:"cert_file"`
	// KeyFile is the server private key.
	KeyFile string `yaml:"key_file"`
	// CAFile holds the client-certificate CAs. When set, agents must
	// present a valid client certificate (mTLS).
	CAFile string `yaml:"ca_file"`
}

// DefaultConfig returns the defaults.
func DefaultConfig() *Config {
	return &Config{
		Listen:            "127.0.0.1:8443",
		DefaultTTLSeconds: 3600,
	}
}

// LoadConfig reads and validates the server configuration.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server config %q: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse server config %q: %w", path, err)
	}
	if cfg.Listen == "" {
		return nil, fmt.Errorf("listen must not be empty")
	}
	if cfg.DefaultTTLSeconds <= 0 {
		cfg.DefaultTTLSeconds = 3600
	}
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile == "" {
		return nil, fmt.Errorf("tls.key_file is required with tls.cert_file")
	}
	return cfg, nil
}
