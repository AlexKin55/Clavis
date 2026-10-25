package sandbox

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestDefaultFirejailArgs verifies the lockdown flags.
func TestDefaultFirejailArgs(t *testing.T) {
	args := defaultFirejailArgs(Profile{})
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"--net=none",
		"--nosound",
		"--noroot",
		"--seccomp",
		"--caps.drop=all",
		"--private",
		"--novideo",
		"--noprinters",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q do not contain %q", joined, want)
		}
	}
}

// TestDefaultFirejailArgsAllowPrint verifies that the Print policy
// disables the printer block.
func TestDefaultFirejailArgsAllowPrint(t *testing.T) {
	args := defaultFirejailArgs(Profile{AllowPrint: true})
	if slices.Contains(args, "--noprinters") {
		t.Error("--noprinters must be absent when AllowPrint is set")
	}
}

// TestRunnerFallback verifies the direct mode when firejail is missing.
func TestRunnerFallback(t *testing.T) {
	r, err := NewRunner(Options{
		FirejailBinary: "/nonexistent/firejail",
		FallbackDirect: true,
	})
	if err != nil {
		t.Fatalf("NewRunner() with fallback error: %v", err)
	}
	if r.Available() {
		t.Fatal("Fallback runner must report not available")
	}

	cmd := r.Command("/bin/echo", []string{"hi"}, Profile{})
	if cmd.Path != "/bin/echo" {
		t.Errorf("fallback cmd.Path = %q, want /bin/echo", cmd.Path)
	}
}

// TestRunnerMissingErrors verifies the error when firejail is absent and
// fallback is disabled.
func TestRunnerMissingErrors(t *testing.T) {
	if _, err := NewRunner(Options{
		FirejailBinary: "/nonexistent/firejail",
	}); err == nil {
		t.Fatal("NewRunner() error = nil, want an error")
	}
}

// TestRunnerCommand builds a mocked runner whose binary is a fixed path
// and checks the assembled argv.
func TestRunnerCommand(t *testing.T) {
	mock := filepath.Join(t.TempDir(), "firejail")
	r := &Runner{firejail: mock}

	p := Profile{ExtraArgs: []string{"--blacklist=/usr/bin/scrot"}}
	cmd := r.Command("gedit", []string{"/home/alex/Clavis/report.txt"}, p)

	if cmd.Path != mock {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, mock)
	}
	args := cmd.Args
	if len(args) < 2 || args[0] != mock {
		t.Fatalf("unexpected argv: %v", args)
	}
	rest := args[1:]
	joined := strings.Join(rest, " ")

	for _, want := range []string{
		"--net=none",
		"--noprinters",
		"--blacklist=/usr/bin/scrot",
		"gedit",
		"/home/alex/Clavis/report.txt",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv %q does not contain %q", joined, want)
		}
	}
}

// TestDefaultProfiles verifies that the sanctioned registry is non-empty
// and includes common editors.
func TestDefaultProfiles(t *testing.T) {
	profiles := DefaultProfiles()
	for _, app := range []string{"gedit", "vim", "evince", "libreoffice", "cat"} {
		if _, ok := profiles[app]; !ok {
			t.Errorf("DefaultProfiles() missing %q", app)
		}
	}
}
