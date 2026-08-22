//go:build linux

package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/preflight"
	"l2syncd/internal/transport"
)

const (
	joinExitOK          = 0
	joinExitError       = 1
	joinExitInvalid     = 2
	joinExitUnreachable = 3
)

// Join finds exactly one peer offering a folder and registers its local path.
func Join(args []string, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: l2sync join <name> <path>")
		return joinExitError
	}
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return joinExitInvalid
	}
	name := strings.ToLower(args[0])
	if err := validateShareName(name); err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return joinExitError
	}
	if _, exists := cfg.Shared[name]; exists {
		fmt.Fprintf(stderr, "l2sync: folder %q already exists as shared\n", name)
		return joinExitError
	}
	if _, exists := cfg.Remote[name]; exists {
		fmt.Fprintf(stderr, "l2sync: folder %q already exists\n", name)
		return joinExitError
	}
	matched := make([]string, 0, 1)
	for peerName, peer := range cfg.Peers {
		address, resolveErr := config.ResolvePeerAddress(peer)
		if resolveErr != nil {
			fmt.Fprintf(stderr, "l2sync: resolve peer %q: %v\n", peerName, resolveErr)
			return joinExitError
		}
		offered, listErr := transport.ListShares(context.Background(), address)
		if listErr != nil {
			fmt.Fprintf(stderr, "l2sync: peer %q unreachable: %v\n", peerName, listErr)
			return joinExitUnreachable
		}
		if contains(offered, name) {
			matched = append(matched, peerName)
		}
	}
	if len(matched) == 0 {
		fmt.Fprintf(stderr, "l2sync: no peer offers folder %q\n", name)
		return joinExitError
	}
	if len(matched) != 1 {
		fmt.Fprintf(stderr, "l2sync: multiple peers offer folder %q\n", name)
		return joinExitError
	}
	path, err := filepath.Abs(args[1])
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve folder path: %v\n", err)
		return joinExitError
	}
	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: folder %q: %v\n", args[1], err)
		return joinExitError
	}
	if !info.IsDir() {
		fmt.Fprintf(stderr, "l2sync: folder %q is not a directory\n", args[1])
		return joinExitError
	}
	if err := guard.WriteMarker(path, guard.Marker{Name: name}); err != nil {
		fmt.Fprintf(stderr, "l2sync: write folder marker: %v\n", err)
		return joinExitError
	}
	cfg.Remote[name] = path
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(stderr, "l2sync: save config: %v\n", err)
		return joinExitError
	}
	return joinExitOK
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
