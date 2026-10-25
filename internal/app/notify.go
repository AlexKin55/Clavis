package app

import (
	"path/filepath"
	"strings"

	"github.com/clavis/clavis/internal/notify"
)

// keyFailureNotifier bridges fuse open failures into the GUI notice bus.
type keyFailureNotifier struct {
	bus *notify.Bus
}

// OpenFailed implements fuse.Notifier.
func (n keyFailureNotifier) OpenFailed(path string, err error) {
	if n.bus == nil {
		return
	}
	kind := classifyOpenFailure(err)
	text := "Не удалось открыть \"" + filepath.Base(path) + "\": " + err.Error()
	n.bus.Push(kind, text)
}

// classifyOpenFailure maps an open-time key error to a GUI notification
// kind: either the key servers were unreachable (offline) or no usable
// key material exists for the document.
func classifyOpenFailure(err error) notify.Kind {
	if err == nil {
		return notify.KindInfo
	}
	msg := strings.ToLower(err.Error())

	// Network / server availability problems: connection failures, DNS,
	// timeouts, TLS errors and the explicit e2e "no relay" configuration.
	var offline = []string{
		"request failed",
		"dial tcp",
		"connection refused",
		"no such host",
		"i/o timeout",
		"context deadline",
		"eof",
		"x509",
		"tls:",
		"servers failed",
		"server unreachable",
		"offline",
		"relay_addr",
	}
	for _, p := range offline {
		if strings.Contains(msg, p) {
			return notify.KindOffline
		}
	}

	// Key material problems: the owner has no key (unknown owner, key not
	// cached/registered) or a returned key cannot be used.
	var missing = []string{
		"not found",
		"no reader key",
		"unknown owner",
		"owner not found",
		"unwrap document key",
		"invalid payload",
		"no key",
	}
	for _, p := range missing {
		if strings.Contains(msg, p) {
			return notify.KindKeyMissing
		}
	}
	return notify.KindInfo
}
