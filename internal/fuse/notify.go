package fuse

// Notifier receives user-facing events raised by the filesystem so the
// agent can surface them in the desktop GUI. Implementations must be safe
// for concurrent use: callbacks run on FUSE worker goroutines.
type Notifier interface {
	// OpenFailed reports a protected file that could not be opened because
	// of key material problems (no key for the owner, an unusable key, or
	// the key servers are unreachable).
	OpenFailed(path string, err error)
}
