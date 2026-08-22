//go:build linux

package commands

import (
	"context"
	"fmt"
	"io"

	"l2syncd/internal/config"
	"l2syncd/internal/engine"
	"l2syncd/internal/guard"
	"l2syncd/internal/preflight"
	"l2syncd/internal/scan"
	"l2syncd/internal/state"
	"l2syncd/internal/transport"
)

const (
	nowExitOK          = 0
	nowExitError       = 1
	nowExitInvalid     = 2
	nowExitUnreachable = 3
)

// Now performs a read-only reconciliation plan. Applying plans is a later
// phase; --dry-run is therefore mandatory for this phase.
func Now(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "--dry-run" {
		fmt.Fprintln(stderr, "usage: l2sync now --dry-run")
		return nowExitError
	}
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return nowExitInvalid
	}
	for name, path := range cfg.Remote {
		if err := planRemote(context.Background(), cfg, name, path, stdout); err != nil {
			fmt.Fprintf(stderr, "l2sync: now %q: %v\n", name, err)
			if isTransportError(err) {
				return nowExitUnreachable
			}
			return nowExitError
		}
	}
	return nowExitOK
}

func planRemote(ctx context.Context, cfg config.Config, name, path string, stdout io.Writer) error {
	marker, err := guard.ReadMarker(path)
	if err != nil {
		return fmt.Errorf("read marker: %w", err)
	}
	provider, address, err := findProvider(ctx, cfg, name)
	if err != nil {
		return err
	}
	remoteFiles, err := transport.ListFiles(ctx, address, name)
	if err != nil {
		return fmt.Errorf("peer %q listing: %w", provider, err)
	}
	localBaseline, err := loadBaseline(name)
	if err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}
	local, err := scanShare(path, localBaseline, marker.Ignore)
	if err != nil {
		return err
	}
	remote := state.New()
	for _, file := range remoteFiles {
		remote.Files[file.Path] = state.File{Hash: file.Hash, Size: file.Size}
	}
	plan := engine.PlanStates("local", local.Snapshot, provider, remote, localBaseline)
	if plan.Halted {
		return fmt.Errorf("halted: %s", plan.Reason)
	}
	for _, action := range plan.Actions {
		if _, err := fmt.Fprintf(stdout, "%s %s %s", action.Kind, name, action.Path); err != nil {
			return fmt.Errorf("write plan: %w", err)
		}
		if action.Kind == engine.Conflict {
			if _, err := fmt.Fprintf(stdout, " winner=%s loser=%s", action.Winner, action.Loser); err != nil {
				return fmt.Errorf("write plan: %w", err)
			}
		}
		if _, err := fmt.Fprintln(stdout); err != nil {
			return fmt.Errorf("write plan: %w", err)
		}
	}
	return nil
}

func scanShare(path string, baseline state.Baseline, ignore []string) (scan.Result, error) {
	result, err := scan.DetectWithIgnore(path, baseline, ignore)
	if err != nil {
		return scan.Result{}, fmt.Errorf("scan share: %w", err)
	}
	return result, nil
}

func findProvider(ctx context.Context, cfg config.Config, name string) (string, string, error) {
	providers := make([]string, 0, 1)
	addresses := make(map[string]string)
	for peerName, peer := range cfg.Peers {
		address, err := config.ResolvePeerAddress(peer)
		if err != nil {
			return "", "", fmt.Errorf("resolve peer %q: %w", peerName, err)
		}
		shares, err := transport.ListShares(ctx, address)
		if err != nil {
			return "", "", fmt.Errorf("peer %q unreachable: %w", peerName, err)
		}
		if contains(shares, name) {
			providers = append(providers, peerName)
			addresses[peerName] = address
		}
	}
	if len(providers) == 0 {
		return "", "", fmt.Errorf("no peer offers folder %q", name)
	}
	if len(providers) != 1 {
		return "", "", fmt.Errorf("multiple peers offer folder %q", name)
	}
	return providers[0], addresses[providers[0]], nil
}

func isTransportError(err error) bool {
	return err != nil
}
