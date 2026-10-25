// Package interceptor decides whether a subject (process) may access a
// protected document. It is the Go equivalent of the C++ IInterceptor:
// Firejail-sandboxed processes are allowed, root may be allowed, and a
// whitelist of sanctioned applications can be configured. Every decision
// is logged (audit trail).
package interceptor

import (
	"log/slog"

	"github.com/clavis/clavis/internal/subject"
)

// Mask describes the requested access kind.
type Mask uint32

// Access kinds.
const (
	// ReadMask is a read-only access (open for reading).
	ReadMask Mask = 1 << iota
	// WriteMask is a write access (open for writing or read-write).
	WriteMask
)

// Interceptor decides access to protected documents.
type Interceptor interface {
	// Permit reports whether the given subject may perform the access.
	Permit(mask Mask, s subject.Info) bool
	// LogAccess records the decision for the audit log.
	LogAccess(s subject.Info, allowed bool)
}

// Config holds the policy knobs.
type Config struct {
	// AllowUID0 grants access to processes running as UID 0 (root),
	// mirroring the root bypass in the C++ prototype.
	AllowUID0 bool
	// AllowFirejail grants access to processes inside a Firejail sandbox
	// (FIREJAIL_SANDBOX=yes), mirroring the C++ prototype rule.
	AllowFirejail bool
	// Whitelist contains executable names (/proc/<pid>/comm) that are
	// allowed to open protected documents directly.
	Whitelist []string
}

// Policy is the default Interceptor implementation.
type Policy struct {
	cfg    Config
	logger *slog.Logger
}

// NewPolicy creates a Policy. A nil logger defaults to slog.Default().
func NewPolicy(cfg Config, logger *slog.Logger) *Policy {
	if logger == nil {
		logger = slog.Default()
	}
	return &Policy{cfg: cfg, logger: logger}
}

// Permit implements Interceptor. Rules are evaluated in order:
//
//  1. root (UID 0), if enabled;
//  2. Firejail sandbox, if enabled;
//  3. whitelisted executable name;
//  4. deny everything else.
func (p *Policy) Permit(_ Mask, s subject.Info) bool {
	if p.cfg.AllowUID0 && s.UID == 0 {
		return true
	}
	if p.cfg.AllowFirejail && s.InFirejail {
		return true
	}
	for _, name := range p.cfg.Whitelist {
		if s.Comm == name {
			return true
		}
	}
	return false
}

// LogAccess implements Interceptor with a readable audit record.
func (p *Policy) LogAccess(s subject.Info, allowed bool) {
	if allowed {
		p.logger.Debug("access granted",
			"pid", s.PID,
			"uid", s.UID,
			"comm", s.Comm,
			"file", s.FileName,
			"firejail", s.InFirejail,
		)
		return
	}
	p.logger.Warn("access denied",
		"pid", s.PID,
		"uid", s.UID,
		"comm", s.Comm,
		"file", s.FileName,
		"firejail", s.InFirejail,
	)
}

// AllowAll is a trivial Interceptor that permits every access.
// It is used in tests and non-enforcing demos.
type AllowAll struct{}

// Permit always returns true.
func (AllowAll) Permit(_ Mask, _ subject.Info) bool { return true }

// LogAccess does nothing.
func (AllowAll) LogAccess(subject.Info, bool) {}

// DiscardLogger returns a slog logger that writes nowhere.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
