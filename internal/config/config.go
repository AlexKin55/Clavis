// Package config loads and validates agent settings from a YAML file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the root settings structure of the agent.
type Config struct {
	Agent AgentConfig `yaml:"agent"`
	Fuse  FuseConfig  `yaml:"fuse"`
	Log   LogConfig   `yaml:"log"`
}

// AgentConfig holds agent identity and service parameters.
type AgentConfig struct {
	// ID is a unique agent identifier (same as agent.id in the C++ prototype).
	ID string `yaml:"id"`
	// HealthListen is the address of the HTTP /healthz endpoint
	// (e.g. "127.0.0.1:8901"). An empty string disables the health server.
	HealthListen string `yaml:"health_listen"`
}

// FuseConfig holds FUSE mount parameters (maps to fuse.* in C++).
type FuseConfig struct {
	// Directory is the physical location of the encrypted files.
	Directory string `yaml:"directory"`
	// MountPoint is where the user sees decrypted files.
	MountPoint string `yaml:"mount_point"`
	// Options are FUSE arguments (e.g. -f -d -o auto_unmount,allow_other).
	Options []string `yaml:"options"`
}

// LogConfig holds logging parameters.
type LogConfig struct {
	// File is the log file path. Empty means logs go to stderr only.
	File string `yaml:"file"`
	// Size is the maximum file size before rotation, e.g. "5MB".
	// Suffixes KB, MB, GB are supported; a bare number means bytes.
	Size string `yaml:"size"`
	// Count is the number of rotated log files to keep.
	Count int `yaml:"count"`
	// Level is the log level: trace, debug, info, warn, error.
	Level string `yaml:"level"`
}

// Default returns a configuration with default values.
func Default() *Config {
	return &Config{
		Agent: AgentConfig{
			ID:           "clavis-001",
			HealthListen: "127.0.0.1:8901",
		},
		Fuse: FuseConfig{
			Directory:  "/opt/clavis/data",
			MountPoint: "/home/alex/Clavis",
			Options: []string{
				"-f",
				"-d",
				"-o", "auto_unmount,allow_other",
			},
		},
		Log: LogConfig{
			Size:  "5MB",
			Count: 3,
			Level: "debug",
		},
	}
}

// Load reads the YAML file at path and returns the configuration.
// Missing keys are filled with default values; the result is then validated.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read settings file %q: %w", path, err)
	}

	cfg := Default()
	if err := parse(data, cfg); err != nil {
		return nil, fmt.Errorf("parse settings file %q: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid settings file %q: %w", path, err)
	}
	return cfg, nil
}

// parse unmarshals YAML data on top of the default values.
func parse(data []byte, cfg *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			// An empty file is acceptable: defaults remain in place.
			return nil
		}
		return err
	}
	return nil
}

// Validate checks the required configuration parameters.
func (c *Config) Validate() error {
	if c.Agent.ID == "" {
		return errors.New("agent.id must not be empty")
	}
	if c.Fuse.Directory == "" {
		return errors.New("fuse.directory must not be empty")
	}
	if c.Fuse.MountPoint == "" {
		return errors.New("fuse.mount_point must not be empty")
	}

	// The protected directory must exist (mirrors the C++ main.cpp check).
	dir := filepath.Clean(c.Fuse.Directory)
	if fi, err := os.Stat(dir); err != nil {
		return fmt.Errorf("fuse.directory %q is not accessible: %w", dir, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("fuse.directory %q is not a directory", dir)
	}
	return nil
}
