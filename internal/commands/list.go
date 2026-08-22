//go:build linux

package commands

import (
	"context"
	"fmt"
	"io"
	"sort"

	"l2syncd/internal/config"
	"l2syncd/internal/preflight"
	"l2syncd/internal/transport"
)

const (
	listExitOK          = 0
	listExitError       = 1
	listExitInvalid     = 2
	listExitUnreachable = 3
)

func list(cfg config.Config, args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: l2sync list [peer]")
		return listExitError
	}
	for _, name := range sortedKeys(cfg.Shared) {
		fmt.Fprintf(stdout, "shared %s %s\n", name, cfg.Shared[name])
	}
	for _, name := range sortedKeys(cfg.Remote) {
		fmt.Fprintf(stdout, "remote %s %s\n", name, cfg.Remote[name])
	}
	if len(args) == 0 {
		return listExitOK
	}

	peerName := args[0]
	peer, found := cfg.Peers[peerName]
	if !found {
		fmt.Fprintf(stderr, "l2sync: peer %q not found\n", peerName)
		return listExitError
	}
	address, err := config.ResolvePeerAddress(peer)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve peer %q: %v\n", peerName, err)
		return listExitError
	}
	shares, err := transport.ListShares(context.Background(), address)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: peer %q unreachable: %v\n", peerName, err)
		return listExitUnreachable
	}
	for _, name := range shares {
		fmt.Fprintf(stdout, "remote-share %s peer=%s\n", name, peerName)
	}
	return listExitOK
}

// List prints locally registered folders.
func List(stdout, stderr io.Writer) int {
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return listExitInvalid
	}
	return list(cfg, nil, stdout, stderr)
}

// ListPeer prints local registrations and the folders offered by one peer.
func ListPeer(args []string, stdout, stderr io.Writer) int {
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return listExitInvalid
	}
	return list(cfg, args, stdout, stderr)
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
