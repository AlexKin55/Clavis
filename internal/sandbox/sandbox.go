// Package sandbox runs sanctioned applications inside a Firejail sandbox:
// network, printers, sound and screen capture are blocked; a private home
// prevents saving files outside the protected directory ("what enters the
// sandbox stays in the sandbox").
package sandbox

import (
	"fmt"
	"os"
	"os/exec"
)

// Profile tunes the sandbox for one application.
type Profile struct {
	// AllowPrint enables printers inside the sandbox (policy "Print").
	// Enabling requires the sandbox to run with print support.
	AllowPrint bool
	// ExtraArgs are appended to the firejail command line.
	ExtraArgs []string
}

// DefaultProfiles is the registry of sanctioned applications: executable
// name (see subject.Info.Comm) to sandbox profile. Tune AllowPrint per
// application as required by the Print policy.
func DefaultProfiles() map[string]Profile {
	return map[string]Profile{
		"gedit":       {},
		"vim":         {},
		"nano":        {},
		"kate":        {},
		"xed":         {},
		"evince":      {},
		"okular":      {},
		"libreoffice": {},
		"onlyoffice":  {},
		"cat":         {},
		"less":        {},
		"more":        {},
	}
}

// Options configures the Runner.
type Options struct {
	// FirejailBinary overrides the firejail executable path.
	// Empty means search in PATH.
	FirejailBinary string
	// FallbackDirect, when true and firejail is not installed, runs the
	// application directly with a warning (development mode).
	FallbackDirect bool
}

// Runner builds firejail command lines.
type Runner struct {
	firejail string
	fallback bool
}

// NewRunner locates the firejail binary and returns a Runner.
func NewRunner(opts Options) (*Runner, error) {
	var path string
	if opts.FirejailBinary == "" {
		p, err := exec.LookPath("firejail")
		if err != nil {
			if opts.FallbackDirect {
				return &Runner{fallback: true}, nil
			}
			return nil, fmt.Errorf("sandbox: firejail not found (install firejail or use FallbackDirect): %w", err)
		}
		path = p
	} else if _, err := os.Stat(opts.FirejailBinary); err != nil {
		if opts.FallbackDirect {
			return &Runner{fallback: true}, nil
		}
		return nil, fmt.Errorf("sandbox: firejail binary %q: %w", opts.FirejailBinary, err)
	} else {
		path = opts.FirejailBinary
	}
	return &Runner{firejail: path}, nil
}

// Available reports whether the sandbox runner actually uses firejail
// (as opposed to the direct fallback).
func (r *Runner) Available() bool {
	return r.firejail != ""
}

// Command builds the *exec.Cmd that runs the application in the sandbox.
// The caller decides how to start it (cmd.Run / cmd.Start / cmd.Output).
func (r *Runner) Command(binary string, args []string, p Profile) *exec.Cmd {
	if r.firejail == "" {
		// Direct fallback: no sandboxing; stays deterministic for tests.
		return exec.Command(binary, args...)
	}
	full := defaultFirejailArgs(p)
	full = append(full, binary)
	full = append(full, args...)
	return exec.Command(r.firejail, full...)
}

// defaultFirejailArgs returns the lockdown flags applied to every sandboxed
// application:
//
//	--net=none    block the network (spy plugins are useless)
//	--nosound     no audio capture
//	--noroot      drop root inside the sandbox
//	--seccomp     apply a restrictive system call filter
//	--caps.drop=all   drop all capabilities
//	--private     private HOME: nothing can be saved outside
//	--novideo     disable video devices (camera, capture)
//	--noprinters  block printers unless the Print policy allows them
func defaultFirejailArgs(p Profile) []string {
	args := []string{
		"--quiet",
		"--net=none",
		"--nosound",
		"--noroot",
		"--seccomp",
		"--caps.drop=all",
		"--private",
		"--novideo",
	}
	if !p.AllowPrint {
		args = append(args, "--noprinters")
	}
	args = append(args, p.ExtraArgs...)
	return args
}
