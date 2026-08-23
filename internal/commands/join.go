//go:build linux

package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/lock"
	"l2syncd/internal/preflight"
	"l2syncd/internal/sharename"
	"l2syncd/internal/transport"
)

const (
	joinExitOK          = 0
	joinExitError       = 1
	joinExitInvalid     = 2
	joinExitUnreachable = 3
)

var (
	joinFindProvider = findProvider
	joinBindShare    = transport.BindShare
	joinUnbindShare  = transport.UnbindShare
	joinListFiles    = transport.ListFiles
)

// Join finds exactly one peer offering a folder and registers its local path.
func Join(args []string, stderr io.Writer) (exitCode int) {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: l2sync join <name> <path>")
		return joinExitError
	}
	transactionLock, err := lock.AcquireJoinWait(context.Background(), lock.DefaultWait)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: acquire join transaction lock: %v\n", err)
		return joinExitError
	}
	defer func() {
		if releaseErr := lock.Release(transactionLock); releaseErr != nil {
			fmt.Fprintf(stderr, "l2sync: release join transaction lock: %v\n", releaseErr)
			if exitCode == joinExitOK {
				exitCode = joinExitError
			}
		}
	}()
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return joinExitInvalid
	}
	name := strings.ToLower(args[0])
	if err := sharename.Validate(name); err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
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
	if _, exists := cfg.Shared[name]; exists {
		fmt.Fprintf(stderr, "l2sync: folder %q already exists as shared\n", name)
		return joinExitError
	}
	if existing, exists := cfg.Remote[name]; exists {
		if existing != path {
			fmt.Fprintf(stderr, "l2sync: folder %q already exists at %q\n", name, existing)
			return joinExitError
		}
		bound := cfg.Bindings[name]
		if len(bound) != 1 {
			fmt.Fprintf(stderr, "l2sync: folder %q has no recoverable peer binding\n", name)
			return joinExitError
		}
		endpoint, endpointErr := peerEndpoint(context.Background(), cfg, bound[0])
		if endpointErr != nil {
			fmt.Fprintf(stderr, "l2sync: resume folder %q binding: %v\n", name, endpointErr)
			return joinExitUnreachable
		}
		expectedPeer := cfg.Peers[bound[0]]
		created, bindErr := joinBindShare(context.Background(), endpoint, name)
		if bindErr != nil {
			fmt.Fprintf(stderr, "l2sync: resume folder %q binding to peer %q: %v\n", name, bound[0], bindErr)
			return joinExitUnreachable
		}
		validated := false
		validateErr := withConfigLocked(context.Background(), func(current *config.Config) error {
			if current.Peers[bound[0]] != expectedPeer || current.Remote[name] != path {
				return fmt.Errorf("folder %q or peer %q changed during resumed join", name, bound[0])
			}
			currentBinding := current.Bindings[name]
			if len(currentBinding) != 1 || currentBinding[0] != bound[0] {
				return fmt.Errorf("folder %q binding changed during resumed join", name)
			}
			validated = true
			return nil
		})
		if validateErr != nil {
			if created && !validated {
				validateErr = errors.Join(validateErr, joinUnbindShare(context.Background(), endpoint, name))
			}
			fmt.Fprintf(stderr, "l2sync: validate resumed folder %q binding: %v\n", name, validateErr)
			return joinExitError
		}
		return joinExitOK
	}
	if peers := cfg.Bindings[name]; len(peers) != 0 {
		fmt.Fprintf(stderr, "l2sync: folder %q is already bound to peer %q\n", name, peers[0])
		return joinExitError
	}
	peerName, endpoint, err := joinFindProvider(context.Background(), cfg, name)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		if strings.Contains(err.Error(), "unreachable") {
			return joinExitUnreachable
		}
		return joinExitError
	}
	expectedPeer := cfg.Peers[peerName]
	remoteBindingCreated, err := joinBindShare(context.Background(), endpoint, name)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: bind folder %q to peer %q: %v\n", name, peerName, err)
		return joinExitUnreachable
	}
	compensateRemote := func(cause error) error {
		if !remoteBindingCreated {
			return cause
		}
		return errors.Join(cause, joinUnbindShare(context.Background(), endpoint, name))
	}
	if _, err := joinListFiles(context.Background(), endpoint, name); err != nil {
		fmt.Fprintf(stderr, "l2sync: verify newly bound folder %q on peer %q: %v\n", name, peerName, compensateRemote(err))
		return joinExitUnreachable
	}
	installed, err := commitJoinedFolder(name, path, peerName, expectedPeer)
	if err != nil {
		if !installed {
			err = compensateRemote(err)
		}
		fmt.Fprintf(stderr, "l2sync: save local folder binding: %v\n", err)
		return joinExitError
	}
	return joinExitOK
}

func prepareJoinMarker(path, name string) (bool, error) {
	if _, err := os.Lstat(guard.MarkerPath(path)); err == nil {
		marker, readErr := guard.ReadMarker(path)
		if readErr != nil {
			return false, readErr
		}
		if marker.Name != name {
			return false, fmt.Errorf("existing marker names folder %q, want %q", marker.Name, name)
		}
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := guard.WriteMarker(path, guard.Marker{Name: name}); err != nil {
		return false, err
	}
	return true, nil
}

func commitJoinedFolder(name, path, peerName string, expectedPeer config.Peer) (installed bool, err error) {
	err = withConfigLocked(context.Background(), func(current *config.Config) error {
		peer, exists := current.Peers[peerName]
		if !exists || peer.Status != config.PeerActive {
			return fmt.Errorf("peer %q is not active for binding", peerName)
		}
		if peer != expectedPeer {
			return fmt.Errorf("peer %q connection identity changed during join", peerName)
		}
		if _, exists := current.Shared[name]; exists {
			return fmt.Errorf("folder %q already exists as shared", name)
		}
		if existing, exists := current.Remote[name]; exists && existing != path {
			return fmt.Errorf("folder %q is already registered at %q", name, existing)
		}
		bound := current.Bindings[name]
		boundToOtherPeer := len(bound) != 0 && (len(bound) != 1 || bound[0] != peerName)
		if boundToOtherPeer {
			return fmt.Errorf("folder %q is already bound to another peer", name)
		}
		_, remoteExists := current.Remote[name]
		missingMatchingBinding := remoteExists && (len(bound) != 1 || bound[0] != peerName)
		if missingMatchingBinding {
			return fmt.Errorf("existing remote folder %q has no matching peer binding", name)
		}
		markerCreated, err := prepareJoinMarker(path, name)
		if err != nil {
			return fmt.Errorf("write folder marker: %w", err)
		}
		if _, exists := current.Remote[name]; !exists {
			current.Remote[name] = path
			current.Bindings[name] = []string{peerName}
		}
		saveErr := saveConfig(*current)
		installed = saveErr == nil || config.WasInstalled(saveErr)
		if saveErr != nil && markerCreated && !installed {
			if removeErr := os.Remove(guard.MarkerPath(path)); removeErr != nil {
				return errors.Join(saveErr, fmt.Errorf("remove newly created marker: %w", removeErr))
			}
		}
		return saveErr
	})
	return installed, err
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
