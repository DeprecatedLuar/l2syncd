//go:build linux

package commands

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/lock"
	"l2syncd/internal/preflight"
	"l2syncd/internal/sharename"
	"l2syncd/internal/transport"
	"l2syncd/internal/trash"
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
		if existing.Path != path {
			fmt.Fprintf(stderr, "l2sync: folder %q already exists at %q\n", name, existing.Path)
			return joinExitError
		}
		if len(existing.Peers) != 1 {
			fmt.Fprintf(stderr, "l2sync: folder %q has no recoverable peer binding\n", name)
			return joinExitError
		}
		boundPeer := existing.Peers[0]
		endpoint, endpointErr := peerEndpoint(context.Background(), cfg, boundPeer)
		if endpointErr != nil {
			fmt.Fprintf(stderr, "l2sync: resume folder %q binding: %v\n", name, endpointErr)
			return joinExitUnreachable
		}
		expectedPeer := cfg.Peers[boundPeer]
		created, bindErr := joinBindShare(context.Background(), endpoint, name)
		if bindErr != nil {
			fmt.Fprintf(stderr, "l2sync: resume folder %q binding to peer %q: %v\n", name, boundPeer, bindErr)
			return joinExitUnreachable
		}
		validated := false
		validateErr := withConfigLocked(context.Background(), func(current *config.Config) error {
			currentFolder := current.Remote[name]
			if current.Peers[boundPeer] != expectedPeer || currentFolder.Path != path {
				return fmt.Errorf("folder %q or peer %q changed during resumed join", name, boundPeer)
			}
			if len(currentFolder.Peers) != 1 || currentFolder.Peers[0] != boundPeer {
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
	remoteFiles, providerID, err := joinListFiles(context.Background(), endpoint, name, "")
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: verify newly bound folder %q on peer %q: %v\n", name, peerName, compensateRemote(err))
		return joinExitUnreachable
	}
	if providerID == "" {
		fmt.Fprintf(stderr, "l2sync: peer %q returned no folder identity for %q: %v\n", peerName, name, compensateRemote(errors.New("empty folder identity")))
		return joinExitUnreachable
	}
	var localIgnore []string
	if existingMarker, markerErr := guard.ReadMarker(path); markerErr == nil {
		localIgnore = existingMarker.Ignore
	}
	extras, err := divergentLocalPaths(path, localIgnore, remoteFiles)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: compare folder %q against provider %q: %v\n", name, peerName, compensateRemote(err))
		return joinExitError
	}
	if len(extras) > 0 {
		choice, promptErr := joinResolveDivergence(stderr, name, extras)
		if promptErr != nil {
			fmt.Fprintf(stderr, "l2sync: %v\n", compensateRemote(promptErr))
			return joinExitError
		}
		if choice == divergenceDrop {
			if dropErr := dropLocalExtras(path, extras); dropErr != nil {
				fmt.Fprintf(stderr, "l2sync: drop diverged local paths for folder %q: %v\n", name, compensateRemote(dropErr))
				return joinExitError
			}
		}
	}
	installed, err := commitJoinedFolder(name, path, peerName, expectedPeer, providerID)
	if err != nil {
		if !installed {
			err = compensateRemote(err)
		}
		fmt.Fprintf(stderr, "l2sync: save local folder binding: %v\n", err)
		return joinExitError
	}
	return joinExitOK
}

// prepareJoinMarker installs or validates the local marker for a folder being
// registered at path under name. id is the folder's authoritative identity:
// for add, a freshly generated id to use only if no marker exists yet
// (add never overrides an existing marker's id, mirroring the existing
// name-reuse behavior); for join, the provider's id, which an existing local
// marker must already match -- a mismatch is a hard error naming both, never
// resolved by preference (concept.md 5.9).
func prepareJoinMarker(path, name, id string) (bool, error) {
	if _, err := os.Lstat(guard.MarkerPath(path)); err == nil {
		marker, readErr := guard.ReadMarker(path)
		if readErr != nil {
			return false, readErr
		}
		if marker.Name != name {
			return false, fmt.Errorf("existing marker names folder %q, want %q", marker.Name, name)
		}
		if id != "" && marker.ID != id {
			return false, fmt.Errorf("existing marker id %q does not match provider id %q", marker.ID, id)
		}
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if id == "" {
		var genErr error
		id, genErr = guard.NewMarkerID()
		if genErr != nil {
			return false, genErr
		}
	}
	if err := guard.WriteMarker(path, guard.Marker{ID: id, Name: name}); err != nil {
		return false, err
	}
	return true, nil
}

func commitJoinedFolder(name, path, peerName string, expectedPeer config.Peer, providerID string) (installed bool, err error) {
	err = withConfigLocked(context.Background(), func(current *config.Config) error {
		peer, exists := current.Peers[peerName]
		if !exists || peer.PublicKey == "" {
			return fmt.Errorf("peer %q has no configured public key for binding", peerName)
		}
		if peer != expectedPeer {
			return fmt.Errorf("peer %q connection identity changed during join", peerName)
		}
		if _, exists := current.Shared[name]; exists {
			return fmt.Errorf("folder %q already exists as shared", name)
		}
		existing, remoteExists := current.Remote[name]
		if remoteExists && existing.Path != path {
			return fmt.Errorf("folder %q is already registered at %q", name, existing.Path)
		}
		bound := existing.Peers
		boundToOtherPeer := len(bound) != 0 && (len(bound) != 1 || bound[0] != peerName)
		if boundToOtherPeer {
			return fmt.Errorf("folder %q is already bound to another peer", name)
		}
		missingMatchingBinding := remoteExists && (len(bound) != 1 || bound[0] != peerName)
		if missingMatchingBinding {
			return fmt.Errorf("existing remote folder %q has no matching peer binding", name)
		}
		markerCreated, err := prepareJoinMarker(path, name, providerID)
		if err != nil {
			return fmt.Errorf("write folder marker: %w", err)
		}
		if !remoteExists {
			current.Remote[name] = config.Folder{Path: path, Peers: []string{peerName}}
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

// divergenceChoice is the user's answer to a rejoin prompt: keep local
// paths the provider does not offer by pushing them (merge), or discard
// them (drop). concept.md 8.1 "Rejoin prompts; it does not guess".
type divergenceChoice int

const (
	divergenceDrop divergenceChoice = iota
	divergenceMerge
)

var joinResolveDivergence = promptDivergenceInteractive

// divergentLocalPaths walks root and returns, sorted, every regular file
// path the provider's listing does not carry live. Symlinks and other
// unsupported types are skipped, matching scan.Reconcile's own handling,
// since v1 has no fidelity contract for them either way.
func divergentLocalPaths(root string, patterns []string, providerFiles []transport.PeerFile) ([]string, error) {
	ignore, err := guard.NewIgnore(patterns)
	if err != nil {
		return nil, err
	}
	providerPaths := make(map[string]bool, len(providerFiles))
	for _, file := range providerFiles {
		if file.Deleted || file.Directory {
			continue
		}
		providerPaths[file.Path] = true
	}
	var extras []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("make path relative: %w", err)
		}
		relative = filepath.ToSlash(relative)
		if relative == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if guard.DefaultIgnorePath(relative) || ignore.Match(relative, entry.IsDir()) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		if !providerPaths[relative] {
			extras = append(extras, relative)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk folder %q: %w", root, err)
	}
	sort.Strings(extras)
	return extras, nil
}

// dropLocalExtras trashes every listed path (never a hard delete, per the
// project's safety contract) so a "drop" answer to the rejoin prompt cannot
// destroy data outright.
func dropLocalExtras(root string, extras []string) error {
	for _, relative := range extras {
		if _, err := trash.Move(root, relative); err != nil {
			return fmt.Errorf("trash %q: %w", relative, err)
		}
	}
	return nil
}

// promptDivergenceInteractive asks the user to resolve a rejoin divergence.
// It never prompts when stdin is not a terminal: concept.md 8.1 requires a
// non-interactive invocation with a divergence to be an error, never a
// silently chosen default.
func promptDivergenceInteractive(stderr io.Writer, name string, extras []string) (divergenceChoice, error) {
	info, statErr := os.Stdin.Stat()
	if statErr != nil || info.Mode()&os.ModeCharDevice == 0 {
		return 0, fmt.Errorf("folder %q diverged from provider %q's copy (%d local path(s) not offered); rerun interactively to resolve", name, name, len(extras))
	}
	fmt.Fprintf(stderr, "l2sync: folder %q holds %d local path(s) the provider does not offer:\n", name, len(extras))
	for _, path := range extras {
		fmt.Fprintf(stderr, "  %s\n", path)
	}
	fmt.Fprint(stderr, "Drop them locally, or merge them by pushing to the provider?\n"+
		"Merging means any of these the provider deliberately deleted while you were detached will return.\n"+
		"[d]rop/[m]erge: ")
	reader := bufio.NewReader(os.Stdin)
	for {
		line, readErr := reader.ReadString('\n')
		switch answer := strings.ToLower(strings.TrimSpace(line)); answer {
		case "d", "drop":
			return divergenceDrop, nil
		case "m", "merge":
			return divergenceMerge, nil
		}
		if readErr != nil {
			return 0, fmt.Errorf("no answer given for folder %q divergence", name)
		}
		fmt.Fprint(stderr, "please answer drop or merge: ")
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
