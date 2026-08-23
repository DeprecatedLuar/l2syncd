//go:build linux

package commands

import (
	"context"
	"fmt"
	"io"

	"l2syncd/internal/config"
	"l2syncd/internal/lock"
	"l2syncd/internal/preflight"
	"l2syncd/internal/transport"
)

var removeUnbindShare = transport.UnbindShare

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
	name := args[0]
	if _, exists := cfg.Shared[name]; !exists {
		if remotePath, remote := cfg.Remote[name]; remote {
			binding := cfg.Bindings[name]
			if len(binding) != 1 {
				fmt.Fprintf(stderr, "l2sync: remote folder %q has no valid peer binding\n", name)
				return removeExitError
			}
			peerName := binding[0]
			endpoint, err := peerEndpoint(context.Background(), cfg, peerName)
			if err != nil {
				fmt.Fprintf(stderr, "l2sync: prepare peer %q for folder removal: %v; local registration retained\n", peerName, err)
				return removeExitError
			}
			expectedPeer := cfg.Peers[peerName]
			if err := removeUnbindShare(context.Background(), endpoint, name); err != nil {
				fmt.Fprintf(stderr, "l2sync: unbind folder %q on peer %q: %v; local registration retained for retry\n", name, peerName, err)
				return removeExitError
			}
			installed, commitErr := commitConfigLocked(func(current *config.Config) error {
				if current.Peers[peerName] != expectedPeer {
					return fmt.Errorf("peer %q connection identity changed during folder removal", peerName)
				}
				if current.Remote[name] != remotePath {
					return fmt.Errorf("folder %q changed concurrently after remote unbind", name)
				}
				currentBinding := current.Bindings[name]
				if len(currentBinding) != 1 || currentBinding[0] != peerName {
					return fmt.Errorf("folder %q binding changed concurrently after remote unbind", name)
				}
				delete(current.Remote, name)
				delete(current.Bindings, name)
				return nil
			})
			if commitErr != nil {
				if installed {
					fmt.Fprintf(stderr, "l2sync: folder registration was removed, but durability or lock release failed: %v\n", commitErr)
				} else {
					fmt.Fprintf(stderr, "l2sync: peer unbound, but remove local folder registration: %v; retry remove to finish\n", commitErr)
				}
				return removeExitError
			}
			return removeExitOK
		}
		fmt.Fprintf(stderr, "l2sync: share %q not found\n", name)
		return removeExitError
	}
	if len(cfg.Bindings[name]) != 0 {
		fmt.Fprintf(stderr, "l2sync: shared folder %q is still bound; remove it from the consuming peer first\n", name)
		return removeExitError
	}
	sharedPath := cfg.Shared[name]
	installed, err := commitConfigLocked(func(current *config.Config) error {
		if current.Shared[name] != sharedPath {
			return fmt.Errorf("shared folder %q changed concurrently", name)
		}
		if len(current.Bindings[name]) != 0 {
			return fmt.Errorf("shared folder %q became bound concurrently", name)
		}
		delete(current.Shared, name)
		delete(current.Bindings, name)
		return nil
	})
	if err != nil {
		if installed {
			fmt.Fprintf(stderr, "l2sync: shared folder registration was removed, but durability or lock release failed: %v\n", err)
		} else {
			fmt.Fprintf(stderr, "l2sync: save config: %v\n", err)
		}
		return removeExitError
	}
	return removeExitOK
}

// Remove unregisters a local share without touching its files.
func Remove(args []string, stderr io.Writer) (exitCode int) {
	transactionLock, err := lock.AcquireJoinWait(context.Background(), lock.DefaultWait)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: acquire folder transaction lock: %v\n", err)
		return removeExitError
	}
	defer func() {
		if releaseErr := lock.Release(transactionLock); releaseErr != nil {
			fmt.Fprintf(stderr, "l2sync: release folder transaction lock: %v\n", releaseErr)
			if exitCode == removeExitOK {
				exitCode = removeExitError
			}
		}
	}()
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return removeExitInvalid
	}
	return remove(cfg, args, stderr)
}
