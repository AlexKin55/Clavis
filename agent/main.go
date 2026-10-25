// Command agent is the entry point of the Clavis agent.
//
// Usage:
//
//	clavis -config settings.yaml
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/clavis/clavis/internal/app"
	"github.com/clavis/clavis/internal/version"
)

func main() {
	os.Exit(run())
}

func run() int {
	// Subcommand: launch an application inside the Firejail sandbox.
	if len(os.Args) >= 2 && os.Args[1] == "open" {
		return runOpen(os.Args[2:])
	}

	fs := flag.NewFlagSet("clavis", flag.ContinueOnError)
	configPath := fs.String("config", "settings.yaml", "path to settings YAML file")
	showVersion := fs.Bool("version", false, "print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\nOptions:\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Println(version.String())
		return 0
	}

	// A context canceled by SIGINT/SIGTERM guarantees a graceful shutdown
	// (a clean FUSE unmount will be added in phase 2).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, *configPath); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}
