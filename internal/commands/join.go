//go:build linux

package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"l2syncd/internal/config"
	"l2syncd/internal/preflight"
	"l2syncd/internal/transport"
)

const (
	joinExitOK          = 0
	joinExitError       = 1
	joinExitInvalid     = 2
	joinExitUnreachable = 3
)

// Join consumes an offered peer share at a local directory.
func Join(args []string, stderr io.Writer) int {
	if len(args) != 3 {
		fmt.Fprintln(stderr, "usage: l2sync join <peer> <share> <path>")
		return joinExitError
	}
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return joinExitInvalid
	}
	peerName, shareName, localArgument := args[0], args[1], args[2]
	peer, found := cfg.Peers[peerName]
	if !found {
		fmt.Fprintf(stderr, "l2sync: peer %q not found\n", peerName)
		return joinExitError
	}
	if _, exists := cfg.Mounts[shareName]; exists {
		fmt.Fprintf(stderr, "l2sync: mount %q already exists\n", shareName)
		return joinExitError
	}
	address, err := config.ResolvePeerAddress(peer)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve peer %q: %v\n", peerName, err)
		return joinExitError
	}
	offered, err := transport.ListShares(context.Background(), address)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: peer %q unreachable: %v\n", peerName, err)
		return joinExitUnreachable
	}
	if !contains(offered, shareName) {
		fmt.Fprintf(stderr, "l2sync: peer %q does not offer share %q\n", peerName, shareName)
		return joinExitError
	}
	local, err := filepath.Abs(localArgument)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve mount path: %v\n", err)
		return joinExitError
	}
	info, err := os.Stat(local)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: mount path %q: %v\n", localArgument, err)
		return joinExitError
	}
	if !info.IsDir() {
		fmt.Fprintf(stderr, "l2sync: mount path %q is not a directory\n", localArgument)
		return joinExitError
	}
	marker := filepath.Join(local, shareMarkerDirectory)
	if err := os.Mkdir(marker, shareMarkerMode); err != nil && !os.IsExist(err) {
		fmt.Fprintf(stderr, "l2sync: create mount marker: %v\n", err)
		return joinExitError
	}
	cfg.Mounts[shareName] = config.Mount{Peer: peerName, Local: local}
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
