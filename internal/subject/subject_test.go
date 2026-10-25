package subject

import (
	"os"
	"testing"
)

// TestIsFirejailEnv verifies the sandbox marker detection.
func TestIsFirejailEnv(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want bool
	}{
		{"marker present", "PATH=/bin\x00FIREJAIL_SANDBOX=yes\x00HOME=/home/u", true},
		{"marker first", "FIREJAIL_SANDBOX=yes", true},
		{"no marker", "PATH=/bin\x00HOME=/home/u", false},
		{"empty", "", false},
		{"similar key ignored", "FIREJAIL_SANDBOX=no\x00FIREJAIL_SANDBOX=\x00", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsFirejailEnv([]byte(tc.env)); got != tc.want {
				t.Errorf("IsFirejailEnv() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFromPIDSelf verifies that the current process is described correctly.
func TestFromPIDSelf(t *testing.T) {
	info, err := FromPID(os.Getpid())
	if err != nil {
		t.Fatalf("FromPID(self) error: %v", err)
	}
	if info.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", info.PID, os.Getpid())
	}
	if info.Comm == "" {
		t.Error("Comm must not be empty for a live process")
	}
	if info.UID != uint32(os.Getuid()) {
		t.Errorf("UID = %d, want %d", info.UID, os.Getuid())
	}
	if info.GID != uint32(os.Getgid()) {
		t.Errorf("GID = %d, want %d", info.GID, os.Getgid())
	}
}

// TestFromPIDNonexistent verifies the error for a dead process.
func TestFromPIDNonexistent(t *testing.T) {
	if _, err := FromPID(1 << 30); err == nil {
		t.Fatal("FromPID(bogus) error = nil, want an error")
	}
}

// TestParseStatusID verifies UID/GID parsing from the status payload.
func TestParseStatusID(t *testing.T) {
	payload := []byte("Name:\ttest\nUid:\t1234\t5678\t9012\t3456\nGid:\t100\t200\t300\t400\n")
	uid, gid := parseStatusID(payload)
	if uid != 1234 {
		t.Errorf("UID = %d, want 1234", uid)
	}
	if gid != 100 {
		t.Errorf("GID = %d, want 100", gid)
	}
}
