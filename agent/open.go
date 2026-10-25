package main

import (
	"fmt"
	"os"

	"github.com/clavis/clavis/internal/sandbox"
)

// runOpen launches an application inside the Firejail sandbox
// ("double security perimeter" from the product design):
//
//	clavis open <application> [args...]
//
// The sandbox blocks the network, printers, sound and screen capture and
// gives the application a private home directory, so nothing can be
// saved outside the protected folder.
func runOpen(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: clavis open <application> [args...]")
		return 2
	}

	runner, err := sandbox.NewRunner(sandbox.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox:", err)
		return 1
	}
	if !runner.Available() {
		fmt.Fprintln(os.Stderr, "warning: firejail not found, running the application directly")
	}

	// A profile from the sanctioned registry, or the default lockdown.
	profile := sandbox.DefaultProfiles()[args[0]]

	cmd := runner.Command(args[0], args[1:], profile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox:", err)
		return 1
	}
	return 0
}
