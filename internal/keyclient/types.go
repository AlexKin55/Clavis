// Package keyclient contains the client side of the Key Server protocol:
// document key issuance over TLS (mTLS), per-document policies and a TTL
// cache. The server itself is planned for Phase 7.
package keyclient

import (
	"fmt"

	"github.com/clavis/clavis/internal/subject"
)

// Policies are the access policies granted by the Key Server for a
// document (from the presentation: ReadOnly, Read/Write, Print,
// Protect Off, GeoFencing).
type Policies struct {
	// ReadOnly allows read access only.
	ReadOnly bool `json:"read_only"`
	// ReadWrite allows read and write access.
	ReadWrite bool `json:"read_write"`
	// Print allows printing the document.
	Print bool `json:"print"`
	// ProtectOff allows saving the document in cleartext.
	ProtectOff bool `json:"protect_off"`
	// GeoFencing restricts access to a trusted area.
	GeoFencing bool `json:"geofencing"`
}

// CanWrite reports whether the write access described by the mask is
// permitted by the policies.
func (p Policies) CanWrite() bool {
	return p.ReadWrite && !p.ReadOnly
}

// Validate checks the policy invariants.
func (p Policies) Validate() error {
	if p.ReadOnly && p.ReadWrite {
		return fmt.Errorf("keyclient: read_only and read_write are mutually exclusive")
	}
	return nil
}

// IssueRequest is the body of the key issuance request. The UUID
// identifies the document, the Subject describes the requesting process.
type IssueRequest struct {
	// DocumentUUID is the UUID stored in the protected file header.
	DocumentUUID string `json:"document_uuid"`
	// Subject is the process requesting access.
	Subject Subject `json:"subject"`
}

// Subject mirrors subject.Info for JSON transport.
type Subject struct {
	PID        int    `json:"pid"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Comm       string `json:"comm"`
	FileName   string `json:"file_name"`
	InFirejail bool   `json:"in_firejail"`
}

// FromInfo converts subject.Info into the transport representation.
func FromInfo(s subject.Info) Subject {
	return Subject{
		PID:        s.PID,
		UID:        s.UID,
		GID:        s.GID,
		Comm:       s.Comm,
		FileName:   s.FileName,
		InFirejail: s.InFirejail,
	}
}

// ToInfo restores subject.Info from the transport representation.
func (s Subject) ToInfo() subject.Info {
	return subject.Info{
		PID:        s.PID,
		UID:        s.UID,
		GID:        s.GID,
		Comm:       s.Comm,
		FileName:   s.FileName,
		InFirejail: s.InFirejail,
	}
}

// IssueResponse is the Key Server answer: the key material (hex), its
// time to live in seconds and the granted policies.
type IssueResponse struct {
	// Key is the hex-encoded key material.
	Key string `json:"key"`
	// TTLSeconds is how long the key may be cached.
	TTLSeconds int64    `json:"ttl_seconds"`
	Policies   Policies `json:"policies"`
}
