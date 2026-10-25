// Package notify holds the agent's in-memory notification bus that feeds
// the desktop GUI. The filesystem pushes user-facing events (a document
// could not be opened because its key is missing or the key servers are
// unreachable), and the localhost UI API serves them to the GUI.
package notify

import (
	"encoding/json"
	"sync"
	"time"
)

// Kind categorizes a notification so the GUI can pick the title.
type Kind int

const (
	// KindInfo is a generic informational notification.
	KindInfo Kind = iota
	// KindKeyMissing means no key material could be found to open a
	// document (unknown owner, key neither cached nor registered).
	KindKeyMissing
	// KindOffline means the key servers could not be reached.
	KindOffline
)

// String returns the machine-readable kind name (used by the GUI).
func (k Kind) String() string {
	switch k {
	case KindKeyMissing:
		return "key_missing"
	case KindOffline:
		return "offline"
	default:
		return "info"
	}
}

// MarshalJSON encodes the kind as its name (e.g. "offline").
func (k Kind) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// UnmarshalJSON reverses MarshalJSON.
func (k *Kind) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "key_missing":
		*k = KindKeyMissing
	case "offline":
		*k = KindOffline
	default:
		*k = KindInfo
	}
	return nil
}

// Notice is one immutable notification record.
type Notice struct {
	ID   int64  `json:"id"`
	Kind Kind   `json:"kind"`
	Text string `json:"text"`
	Time int64  `json:"time"` // unix seconds
}

// Bus retains the most recent notices in a bounded ring buffer. It is
// safe for concurrent use: FUSE worker goroutines push, the UI handler
// reads snapshots.
type Bus struct {
	mu    sync.Mutex
	seq   int64
	ring  []Notice
	start int
	count int
}

// NewBus creates a bus that retains up to capacity notices (default 50).
func NewBus(capacity int) *Bus {
	if capacity <= 0 {
		capacity = 50
	}
	return &Bus{ring: make([]Notice, capacity)}
}

// Push appends a notice and returns its (monotonic) id.
func (b *Bus) Push(kind Kind, text string) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.seq++
	n := Notice{ID: b.seq, Kind: kind, Text: text, Time: time.Now().Unix()}
	if b.count < len(b.ring) {
		b.ring[(b.start+b.count)%len(b.ring)] = n
		b.count++
	} else {
		b.ring[b.start] = n
		b.start = (b.start + 1) % len(b.ring)
	}
	return n.ID
}

// Recent returns a snapshot of the retained notices in chronological
// order (oldest first). The largest ID tells the GUI where to continue.
func (b *Bus) Recent() []Notice {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]Notice, 0, b.count)
	for i := 0; i < b.count; i++ {
		out = append(out, b.ring[(b.start+i)%len(b.ring)])
	}
	return out
}
