// Package logging initializes the agent's slog logger with rotating
// log files (equivalent to the spdlog rotating_file_sink in the C++ prototype).
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/clavis/clavis/internal/config"
)

// Logger combines a slog logger with resources that need to be closed
// on shutdown (e.g. the log file).
type Logger struct {
	*slog.Logger
	closer io.Closer
}

// Close properly closes the log file.
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// Init builds the logger from the given configuration.
//
// If config.Log.File is set, records are written to the file with rotation
// (size and backup count come from the config); otherwise stderr is used.
func Init(cfg *config.LogConfig) (*Logger, error) {
	level, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	opts := &slog.HandlerOptions{Level: level}

	var writer io.Writer = os.Stderr
	var closer io.Closer

	if cfg.File != "" {
		lj := &lumberjack.Logger{
			Filename:   cfg.File,
			MaxBackups: cfg.Count,
			LocalTime:  true,
		}
		if maxSize, err := ParseSize(cfg.Size); err != nil {
			return nil, fmt.Errorf("parse log.size %q: %w", cfg.Size, err)
		} else if maxSize > 0 {
			lj.MaxSize = int(maxSize)
		}
		writer = lj
		closer = lj
	}

	return &Logger{
		Logger: slog.New(slog.NewTextHandler(writer, opts)),
		closer: closer,
	}, nil
}

// ParseLevel converts a string level name to slog.Level.
// Supported: trace, debug, info, warn/warning, error.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "trace", "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q", s)
	}
}

// ParseSize parses a size with a KB/MB/GB suffix (e.g. "5MB").
// A bare number is treated as bytes. The result is in bytes.
func ParseSize(s string) (int64, error) {
	value := strings.TrimSpace(s)
	if value == "" {
		return 0, fmt.Errorf("empty size")
	}

	multipliers := []struct {
		suffix string
		mult   int64
	}{
		{"GB", 1 << 30},
		{"MB", 1 << 20},
		{"KB", 1 << 10},
	}

	upper := strings.ToUpper(value)
	for _, m := range multipliers {
		if strings.HasSuffix(upper, m.suffix) {
			num := strings.TrimSpace(strings.TrimSuffix(upper, m.suffix))
			n, err := parseNonNegative(num)
			if err != nil {
				return 0, err
			}
			return n * m.mult, nil
		}
	}

	n, err := parseNonNegative(upper)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func parseNonNegative(s string) (int64, error) {
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("negative size %q", s)
	}
	return n, nil
}
