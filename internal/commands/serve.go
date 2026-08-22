//go:build linux

package commands

import (
	"fmt"
	"io"
	"sort"

	"l2syncd/internal/config"
	"l2syncd/internal/transport"
)

const (
	serveExitOK    = 0
	serveExitError = 1
)

// Serve handles one read-only peer protocol request on stdin/stdout.
func Serve(stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, err := config.Load()
	if err != nil && err != config.ErrNotFound {
		fmt.Fprintf(stderr, "l2sync: load config: %v\n", err)
		return serveExitError
	}
	if err == config.ErrNotFound {
		cfg = config.New()
	}
	shares := make([]string, 0, len(cfg.Shares))
	for name := range cfg.Shares {
		shares = append(shares, name)
	}
	sort.Strings(shares)
	if err := transport.ServeShares(stdin, stdout, shares); err != nil {
		fmt.Fprintf(stderr, "l2sync: serve peer request: %v\n", err)
		return serveExitError
	}
	return serveExitOK
}
