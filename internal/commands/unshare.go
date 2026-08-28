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
)

const (
	unshareExitOK      = 0
	unshareExitError   = 1
	unshareExitInvalid = 2
)

// unshare is the provider-side unilateral withdrawal of an offered folder
// (concept.md 8.1). It no longer refuses while consumers are bound: the
// provider does not need their cooperation or reachability, and consumers
// discover the withdrawal on their own next successful connection. It never
// touches files, and it prunes the folder's index.
func unshare(cfg config.Config, args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: l2sync folder unshare <name>")
		return unshareExitError
	}
	name := args[0]
	if _, isRemote := cfg.Remote[name]; isRemote {
		fmt.Fprintf(stderr, "l2sync: folder %q is a remote folder; use folder detach\n", name)
		return unshareExitError
	}
	sharedFolder, exists := cfg.Shared[name]
	if !exists {
		fmt.Fprintf(stderr, "l2sync: share %q not found\n", name)
		return unshareExitError
	}
	var folderID string
	if marker, markerErr := guard.ReadMarker(sharedFolder.Path); markerErr == nil {
		folderID = marker.ID
	}
	_, err := commitConfigLocked(func(current *config.Config) error {
		currentFolder, exists := current.Shared[name]
		if !exists {
			return fmt.Errorf("shared folder %q removed concurrently", name)
		}
		if currentFolder.Path != sharedFolder.Path {
			return fmt.Errorf("shared folder %q changed concurrently", name)
		}
		delete(current.Shared, name)
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: save config: %v\n", err)
		return unshareExitError
	}
	if folderID != "" {
		if err := pruneIndex(folderID); err != nil {
			fmt.Fprintf(stderr, "l2sync: folder %q removed, but prune its index: %v\n", name, err)
			return unshareExitError
		}
	}
	return unshareExitOK
}

// Unshare withdraws a local shared folder offer without touching its files.
func Unshare(args []string, stderr io.Writer) (exitCode int) {
	transactionLock, err := lock.AcquireJoinWait(context.Background(), lock.DefaultWait)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: acquire folder transaction lock: %v\n", err)
		return unshareExitError
	}
	defer func() {
		if releaseErr := lock.Release(transactionLock); releaseErr != nil {
			fmt.Fprintf(stderr, "l2sync: release folder transaction lock: %v\n", releaseErr)
			if exitCode == unshareExitOK {
				exitCode = unshareExitError
			}
		}
	}()
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return unshareExitInvalid
	}
	return unshare(cfg, args, stderr)
}
