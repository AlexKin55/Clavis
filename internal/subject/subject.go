// Package subject describes the process that accesses a protected document
// (the "subject") and collects its identity from /proc: PID, effective
// UID/GID, executable name and the Firejail sandbox marker.
package subject

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// firejailMarker is the environment variable set inside a Firejail sandbox.
const firejailMarker = "FIREJAIL_SANDBOX=yes"

// Info describes the process accessing a protected file.
type Info struct {
	// PID of the accessing process.
	PID int
	// UID/GID are the effective credentials of the process.
	UID uint32
	GID uint32
	// Comm is the executable name as seen in /proc/<pid>/comm
	// (truncated to 15 characters by the kernel).
	Comm string
	// FileName is the path of the protected file being accessed.
	FileName string
	// DocUUID is the UUID of the protected document (if known).
	DocUUID [16]byte
	// InFirejail reports whether the process runs inside a Firejail sandbox.
	InFirejail bool
}

// FromPID builds the subject description from live /proc data.
func FromPID(pid int) (Info, error) {
	info := Info{PID: pid}
	if err := readProc(pid, &info); err != nil {
		return info, err
	}
	return info, nil
}

// readProc reads the process identity from /proc.
func readProc(pid int, info *Info) error {
	if _, err := os.Stat(procPath(pid, ".")); err != nil {
		return fmt.Errorf("subject: process %d not found: %w", pid, err)
	}

	// Environment: detects Firejail and provides the executable path.
	if env, err := os.ReadFile(procPath(pid, "environ")); err == nil {
		info.InFirejail = IsFirejailEnv(env)
	}

	// Executable name.
	if comm, err := os.ReadFile(procPath(pid, "comm")); err == nil {
		info.Comm = strings.TrimSpace(string(comm))
	}

	// Effective UID/GID from /proc/<pid>/status.
	if status, err := os.ReadFile(procPath(pid, "status")); err == nil {
		uid, gid := parseStatusID(status)
		info.UID = uid
		info.GID = gid
	}
	return nil
}

func procPath(pid int, name string) string {
	if name == "." {
		return fmt.Sprintf("/proc/%d", pid)
	}
	return fmt.Sprintf("/proc/%d/%s", pid, name)
}

// IsFirejailEnv reports whether a NUL-separated /proc environ payload
// contains the Firejail sandbox marker (direct port of the C++ prototype).
func IsFirejailEnv(environ []byte) bool {
	for _, kv := range bytes.Split(environ, []byte{0}) {
		if string(kv) == firejailMarker {
			return true
		}
	}
	return false
}

// parseStatusID extracts the real/effective UID and GID from a
// /proc/<pid>/status payload: lines like "Uid:	1000	1000	1000	1000".
func parseStatusID(status []byte) (uid, gid uint32) {
	for _, line := range bytes.Split(status, []byte{'\n'}) {
		switch {
		case bytes.HasPrefix(line, []byte("Uid:")):
			uid = firstID(line)
		case bytes.HasPrefix(line, []byte("Gid:")):
			gid = firstID(line)
		}
	}
	return uid, gid
}

func firstID(line []byte) uint32 {
	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		return 0
	}
	id, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(id)
}
