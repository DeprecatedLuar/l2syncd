//go:build linux

package commands

import (
	"context"
	"fmt"
	"io"
	"sort"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
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
	return listWithLister(cfg, args, stdout, stderr, func(ctx context.Context, peer string) ([]string, error) {
		endpoint, err := peerEndpoint(ctx, cfg, peer)
		if err != nil {
			return nil, err
		}
		return transport.ListShares(ctx, endpoint)
	})
}

type shareLister func(context.Context, string) ([]string, error)

func listWithLister(cfg config.Config, args []string, stdout, stderr io.Writer, listShares shareLister) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: l2sync list [peer]")
		return listExitError
	}
	if len(args) == 1 {
		if _, found := cfg.Peers[args[0]]; !found {
			fmt.Fprintf(stderr, "l2sync: peer %q not found\n", args[0])
			return listExitError
		}
	}

	peerShares := make(map[string][]string, len(cfg.Peers))
	peerFailed := make(map[string]bool, len(cfg.Peers))
	networkFailure := false
	peerNames := make([]string, 0)
	if len(args) == 1 {
		peerNames = append(peerNames, args[0])
	} else {
		peerNames = sortedKeys(cfg.Peers)
	}
	for _, peerName := range peerNames {
		shares, err := listShares(context.Background(), peerName)
		if err != nil {
			networkFailure = true
			peerFailed[peerName] = true
			if len(args) == 1 && args[0] == peerName {
				fmt.Fprintf(stderr, "l2sync: peer %q unreachable: %v\n", peerName, err)
			}
			continue
		}
		peerShares[peerName] = shares
	}

	for _, name := range sortedEntryNames(cfg) {
		verified := localEntryVerified(cfg, name)
		if verified && cfg.Remote[name] != "" {
			binding := cfg.Bindings[name]
			verified = len(binding) == 1 && !peerFailed[binding[0]] && contains(peerShares[binding[0]], name)
		}
		prefix := "-"
		if verified {
			prefix = "+"
		}
		fmt.Fprintf(stdout, "%s %s\n", prefix, name)
	}

	networkNames := make(map[string]struct{})
	for _, peerName := range peerNames {
		for _, name := range peerShares[peerName] {
			networkNames[name] = struct{}{}
		}
	}
	if len(args) == 0 {
		for _, name := range sortedKeys(networkNames) {
			if _, localShared := cfg.Shared[name]; localShared {
				continue
			}
			if _, localRemote := cfg.Remote[name]; localRemote {
				continue
			}
			fmt.Fprintf(stdout, "- %s\n", name)
		}
	} else {
		for _, peerName := range peerNames {
			for _, name := range peerShares[peerName] {
				if _, localShared := cfg.Shared[name]; localShared {
					continue
				}
				if _, localRemote := cfg.Remote[name]; localRemote {
					continue
				}
				fmt.Fprintf(stdout, "remote-share %s peer=%s\n", name, peerName)
			}
		}
	}
	if networkFailure {
		return listExitUnreachable
	}
	return listExitOK
}

// List prints local registrations and folders offered by configured peers.
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

func sortedEntryNames(cfg config.Config) []string {
	entries := make(map[string]struct{}, len(cfg.Shared)+len(cfg.Remote))
	for name := range cfg.Shared {
		entries[name] = struct{}{}
	}
	for name := range cfg.Remote {
		entries[name] = struct{}{}
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func localEntryVerified(cfg config.Config, name string) bool {
	path, shared := cfg.Shared[name]
	if !shared {
		path = cfg.Remote[name]
	}
	marker, err := guard.ReadMarker(path)
	return err == nil && marker.Name == name
}
