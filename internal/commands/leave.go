//go:build linux

package commands

import (
	"context"
	"fmt"
	"io"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/lock"
	"l2syncd/internal/preflight"
	"l2syncd/internal/transport"
)

var leaveUnbindShare = transport.UnbindShare

const (
	leaveExitOK      = 0
	leaveExitError   = 1
	leaveExitInvalid = 2
)

// leave is the consumer-side detach from a folder it joined (concept.md
// 8.1). Only the consumer may leave; the provider's unilateral withdrawal
// is Remove. It never touches files, and it prunes the folder's index: the
// index is meaningful only while the pairing exists.
func leave(cfg config.Config, args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: l2sync leave <name>")
		return leaveExitError
	}
	name := args[0]
	if _, isShared := cfg.Shared[name]; isShared {
		fmt.Fprintf(stderr, "l2sync: folder %q is a shared folder; use remove\n", name)
		return leaveExitError
	}
	remoteFolder, exists := cfg.Remote[name]
	if !exists {
		fmt.Fprintf(stderr, "l2sync: folder %q not found\n", name)
		return leaveExitError
	}
	if len(remoteFolder.Peers) != 1 {
		fmt.Fprintf(stderr, "l2sync: remote folder %q has no valid peer binding\n", name)
		return leaveExitError
	}
	peerName := remoteFolder.Peers[0]
	endpoint, err := peerEndpoint(context.Background(), cfg, peerName)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: prepare peer %q for leave: %v; local registration retained\n", peerName, err)
		return leaveExitError
	}
	expectedPeer := cfg.Peers[peerName]
	if err := leaveUnbindShare(context.Background(), endpoint, name); err != nil {
		fmt.Fprintf(stderr, "l2sync: unbind folder %q on peer %q: %v; local registration retained for retry\n", name, peerName, err)
		return leaveExitError
	}
	var folderID string
	if marker, markerErr := guard.ReadMarker(remoteFolder.Path); markerErr == nil {
		folderID = marker.ID
	}
	installed, commitErr := commitConfigLocked(func(current *config.Config) error {
		if current.Peers[peerName] != expectedPeer {
			return fmt.Errorf("peer %q connection identity changed during leave", peerName)
		}
		currentFolder := current.Remote[name]
		if currentFolder.Path != remoteFolder.Path {
			return fmt.Errorf("folder %q changed concurrently after remote unbind", name)
		}
		if len(currentFolder.Peers) != 1 || currentFolder.Peers[0] != peerName {
			return fmt.Errorf("folder %q binding changed concurrently after remote unbind", name)
		}
		delete(current.Remote, name)
		return nil
	})
	if commitErr != nil {
		if installed {
			fmt.Fprintf(stderr, "l2sync: folder registration was removed, but durability or lock release failed: %v\n", commitErr)
		} else {
			fmt.Fprintf(stderr, "l2sync: peer unbound, but remove local folder registration: %v; retry leave to finish\n", commitErr)
		}
		return leaveExitError
	}
	if folderID != "" {
		if err := pruneIndex(folderID); err != nil {
			fmt.Fprintf(stderr, "l2sync: folder %q left, but prune its index: %v\n", name, err)
			return leaveExitError
		}
	}
	return leaveExitOK
}

// Leave detaches from a remote folder without touching its files.
func Leave(args []string, stderr io.Writer) (exitCode int) {
	transactionLock, err := lock.AcquireJoinWait(context.Background(), lock.DefaultWait)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: acquire folder transaction lock: %v\n", err)
		return leaveExitError
	}
	defer func() {
		if releaseErr := lock.Release(transactionLock); releaseErr != nil {
			fmt.Fprintf(stderr, "l2sync: release folder transaction lock: %v\n", releaseErr)
			if exitCode == leaveExitOK {
				exitCode = leaveExitError
			}
		}
	}()
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return leaveExitInvalid
	}
	return leave(cfg, args, stderr)
}
