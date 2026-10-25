// Package version carries build information for the agent,
// injected via ldflags at compile time.
package version

import (
	"fmt"
	"runtime"
)

// Values are overridden at build time:
//
//	go build -ldflags "-X github.com/clavis/clavis/internal/version.Version=1.0.0"
var (
	// Version is the semantic version of the application.
	Version = "dev"
	// Commit is the short git commit hash.
	Commit = "none"
	// Date is the build date (RFC3339).
	Date = "unknown"
)

// String returns a one-line build description.
func String() string {
	return fmt.Sprintf("clavis %s (commit %s, built %s, %s/%s)",
		Version, Commit, Date, runtime.GOOS, runtime.GOARCH)
}

// Short returns the version number only.
func Short() string {
	return Version
}
