package interceptor

import (
	"testing"

	"github.com/clavis/clavis/internal/subject"
)

func baseSubject() subject.Info {
	return subject.Info{
		PID:  4242,
		UID:  1000,
		GID:  1000,
		Comm: "evil-app",
	}
}

// TestPolicyDenyByDefault verifies that unknown processes are denied.
func TestPolicyDenyByDefault(t *testing.T) {
	p := NewPolicy(Config{}, nil)
	if p.Permit(ReadMask, baseSubject()) {
		t.Error("unknown process must be denied")
	}
}

// TestPolicyAllowRoot verifies the root bypass.
func TestPolicyAllowRoot(t *testing.T) {
	p := NewPolicy(Config{AllowUID0: true}, nil)
	s := baseSubject()
	s.UID = 0
	if !p.Permit(WriteMask, s) {
		t.Error("root must be allowed when AllowUID0 is set")
	}
}

// TestPolicyRootIgnoredWhenDisabled verifies that root is denied when the
// bypass is disabled.
func TestPolicyRootIgnoredWhenDisabled(t *testing.T) {
	p := NewPolicy(Config{}, nil)
	s := baseSubject()
	s.UID = 0
	if p.Permit(ReadMask, s) {
		t.Error("root must not be allowed when AllowUID0 is disabled")
	}
}

// TestPolicyAllowFirejail verifies the sandbox rule.
func TestPolicyAllowFirejail(t *testing.T) {
	p := NewPolicy(Config{AllowFirejail: true}, nil)
	s := baseSubject()
	s.InFirejail = true
	if !p.Permit(WriteMask, s) {
		t.Error("firejail process must be allowed when AllowFirejail is set")
	}
}

// TestPolicyWhitelist verifies the sanctioned application list.
func TestPolicyWhitelist(t *testing.T) {
	p := NewPolicy(Config{Whitelist: []string{"libreoffice", "vim"}}, nil)
	s := baseSubject()
	s.Comm = "vim"
	if !p.Permit(WriteMask, s) {
		t.Error("whitelisted process must be allowed")
	}

	s.Comm = "malware"
	if p.Permit(WriteMask, s) {
		t.Error("non-whitelisted process must be denied")
	}
}

// TestAllowAll permits everything.
func TestAllowAll(t *testing.T) {
	if !(AllowAll{}).Permit(WriteMask, baseSubject()) {
		t.Error("AllowAll must permit every access")
	}
}
