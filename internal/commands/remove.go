//go:build linux

package commands

import (
	"fmt"
	"io"

	"l2syncd/internal/config"
	"l2syncd/internal/preflight"
)

const (
	removeExitOK      = 0
	removeExitError   = 1
	removeExitInvalid = 2
)

func remove(cfg config.Config, args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: l2sync remove <name>")
		return removeExitError
	}
	if _, exists := cfg.Shares[args[0]]; !exists {
		fmt.Fprintf(stderr, "l2sync: share %q not found\n", args[0])
		return removeExitError
	}
	delete(cfg.Shares, args[0])
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(stderr, "l2sync: save config: %v\n", err)
		return removeExitError
	}
	return removeExitOK
}

// Remove unregisters a local share without touching its files.
func Remove(args []string, stderr io.Writer) int {
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return removeExitInvalid
	}
	return remove(cfg, args, stderr)
}
