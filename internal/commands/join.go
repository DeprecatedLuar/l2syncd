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
	peerName, address, err := findProvider(context.Background(), cfg, name)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		if strings.Contains(err.Error(), "unreachable") {
			return joinExitUnreachable
		}
		return joinExitError
	}
	if _, err := transport.ListFiles(context.Background(), address, name); err != nil {
		fmt.Fprintf(stderr, "l2sync: verify folder %q on peer %q: %v\n", name, peerName, err)
		return joinExitUnreachable
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
