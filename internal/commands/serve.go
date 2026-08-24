//go:build linux

package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"l2syncd/internal/apply"
	"l2syncd/internal/config"
	"l2syncd/internal/connection"
	"l2syncd/internal/guard"
	"l2syncd/internal/lock"
	"l2syncd/internal/metadata"
	"l2syncd/internal/preflight"
	"l2syncd/internal/scan"
	"l2syncd/internal/sharepath"
	"l2syncd/internal/state"
	"l2syncd/internal/transport"
)

const (
	serveExitOK     = 0
	serveExitError  = 1
	serveExitLocked = 4
)

type resolvedFolder struct {
	root   string
	marker guard.Marker
}

type folderResolver func(string) (resolvedFolder, error)

// Serve handles one peer protocol request on stdin/stdout.
func Serve(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 4 || args[0] != "--peer" || args[2] != "--fingerprint" {
		fmt.Fprintln(stderr, "usage: l2sync serve --peer <name> --fingerprint <sha256>")
		return serveExitError
	}
	peerName := args[1]
	forcedFingerprint := args[3]
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: load validated config: %v\n", err)
		return serveExitError
	}
	peer, exists := cfg.Peers[peerName]
	if !exists {
		fmt.Fprintf(stderr, "l2sync: peer %q is not configured\n", peerName)
		return serveExitError
	}
	if peer.PublicKey == "" {
		fmt.Fprintf(stderr, "l2sync: peer %q has no configured public key\n", peerName)
		return serveExitError
	}
	configuredFingerprint, err := connection.Fingerprint(peer.PublicKey)
	if err != nil || forcedFingerprint != configuredFingerprint {
		fmt.Fprintf(stderr, "l2sync: forced-command fingerprint does not match peer %q\n", peerName)
		return serveExitError
	}
	if err := rejectDuplicatePeerKey(cfg, peerName, peer.PublicKey); err != nil {
		fmt.Fprintf(stderr, "l2sync: invalid peer configuration: %v\n", err)
		return serveExitError
	}
	paths, err := connection.DefaultPaths()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve installation key: %v\n", err)
		return serveExitError
	}
	localKey, err := connection.EnsureKey(paths)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: load installation key: %v\n", err)
		return serveExitError
	}
	configuredPeerKey, _ := connection.NormalizePublicKey(peer.PublicKey)
	if configuredPeerKey == localKey {
		fmt.Fprintf(stderr, "l2sync: peer %q uses this installation's public key\n", peerName)
		return serveExitError
	}
	resolve := newReloadingFolderResolver(peerName, forcedFingerprint)
	callbacks := serveCallbacks(resolve)
	callbacks.ListShares = newReloadingShareLister(peerName, forcedFingerprint)
	callbacks.RequestCycle = func(name string) (int, error) {
		return runInitiatorFolderCycle(context.Background(), name, peerName, forcedFingerprint)
	}
	callbacks.BindShare = func(name string) (bool, error) { return bindSharedFolder(peerName, forcedFingerprint, name) }
	callbacks.UnbindShare = func(name string) error {
		return updateConfigLocked(func(current *config.Config) error {
			configured, exists := current.Peers[peerName]
			if !exists || configured.PublicKey == "" {
				return fmt.Errorf("peer %q has no configured public key", peerName)
			}
			if err := requireAuthenticatedFingerprint(configured, forcedFingerprint); err != nil {
				return fmt.Errorf("peer %q authorization changed: %w", peerName, err)
			}
			folder, exists := current.Shared[name]
			if !exists || len(folder.Peers) == 0 {
				return nil
			}
			if len(folder.Peers) != 1 || folder.Peers[0] != peerName {
				return fmt.Errorf("folder %q is not bound to peer %q", name, peerName)
			}
			folder.Peers = nil
			current.Shared[name] = folder
			return nil
		})
	}
	handshake := transport.Handshake{ExpectedPeerKey: peer.PublicKey, LocalPublicKey: localKey}
	if err := transport.Serve(stdin, stdout, callbacks, &handshake); err != nil {
		fmt.Fprintf(stderr, "l2sync: serve peer request: %v\n", err)
		return serveFailureExit(err)
	}
	return serveExitOK
}

func bindSharedFolder(peerName, authenticatedFingerprint, name string) (created bool, err error) {
	err = updateConfigLocked(func(current *config.Config) error {
		configured, exists := current.Peers[peerName]
		if !exists || configured.PublicKey == "" {
			return fmt.Errorf("peer %q has no configured public key", peerName)
		}
		if err := requireAuthenticatedFingerprint(configured, authenticatedFingerprint); err != nil {
			return fmt.Errorf("peer %q authorization changed: %w", peerName, err)
		}
		folder, exists := current.Shared[name]
		if !exists {
			return fmt.Errorf("folder %q is not shared", name)
		}
		if len(folder.Peers) != 0 {
			if len(folder.Peers) != 1 {
				return fmt.Errorf("folder %q has malformed peer binding", name)
			}
			if folder.Peers[0] != peerName {
				return fmt.Errorf("folder %q is already bound to peer %q", name, folder.Peers[0])
			}
			return nil
		}
		folder.Peers = []string{peerName}
		current.Shared[name] = folder
		created = true
		return nil
	})
	return created, err
}

func serveFailureExit(err error) int {
	if errors.Is(err, lock.ErrTimeout) {
		return serveExitLocked
	}
	return serveExitError
}

func serveCallbacks(resolve folderResolver) transport.Callbacks {
	fileLister := func(name string) ([]transport.PeerFile, error) {
		folder, err := resolve(name)
		if err != nil {
			return nil, err
		}
		listed, scanErr := scan.ListFiles(folder.root, folder.marker.Ignore)
		if scanErr != nil {
			return nil, fmt.Errorf("list folder %q: %w", name, scanErr)
		}
		files := make([]transport.PeerFile, 0, len(listed))
		for _, file := range listed {
			files = append(files, transport.PeerFile{Path: file.Path, Size: file.Size, Hash: file.Hash, Metadata: file.Metadata, Directory: file.Directory})
		}
		return files, nil
	}
	fileReader := func(name, relative string) (io.ReadCloser, error) {
		folder, err := resolve(name)
		if err != nil {
			return nil, err
		}
		file, openErr := sharepath.OpenRegular(folder.root, relative)
		if openErr != nil {
			return nil, fmt.Errorf("open folder file %q: %w", relative, openErr)
		}
		return file, nil
	}
	fileWriter := func(name, relative, expectedHash string, manifest metadata.Manifest, contents io.Reader) error {
		return mutateAndCommit(name, resolve, func(folder resolvedFolder) error {
			return apply.WriteWithMetadata(folder.root, relative, contents, expectedHash, manifest)
		})
	}
	fileDeleter := func(name, relative string) error {
		return mutateAndCommit(name, resolve, func(folder resolvedFolder) error {
			return apply.Delete(folder.root, relative)
		})
	}
	conflictWriter := func(name, relative, loser, expectedHash string, manifest metadata.Manifest, contents io.Reader) error {
		return mutateAndCommit(name, resolve, func(folder resolvedFolder) error {
			return apply.WriteConflictWinnerWithSuffix(folder.root, relative, loser, contents, expectedHash, manifest)
		})
	}
	conflictCopyWriter := func(name, relative, suffix, expectedHash string, manifest metadata.Manifest, contents io.Reader) error {
		return mutateAndCommit(name, resolve, func(folder resolvedFolder) error {
			return apply.WriteConflictCopyWithSuffix(folder.root, relative, suffix, contents, expectedHash, manifest)
		})
	}
	conflictCopyExists := func(name, relative, suffix string) (bool, error) {
		folder, err := resolve(name)
		if err != nil {
			return false, err
		}
		return apply.ConflictCopyExists(folder.root, relative, suffix)
	}
	fileReuser := func(name, relative, expectedHash string, manifest metadata.Manifest) (bool, error) {
		var reused bool
		err := mutateServedFolder(name, resolve, func(folder resolvedFolder) error {
			baseline, loadErr := loadBaseline(name)
			if loadErr != nil {
				return loadErr
			}
			for source, file := range baseline.Files {
				if file.Hash != expectedHash {
					continue
				}
				if reuseErr := apply.Reuse(folder.root, relative, source, expectedHash, manifest); reuseErr != nil {
					if errors.Is(reuseErr, apply.ErrReuseMismatch) {
						continue
					}
					return reuseErr
				}
				if commitErr := commitFolderBaseline(name, folder.root, folder.marker.Ignore); commitErr != nil {
					return commitErr
				}
				reused = true
				return nil
			}
			return nil
		})
		return reused, err
	}
	directoryWriter := func(name, relative string, manifest metadata.Manifest) error {
		return mutateAndCommit(name, resolve, func(folder resolvedFolder) error {
			return apply.ApplyDirectory(folder.root, relative, manifest)
		})
	}
	directoryDeleter := func(name, relative string) error {
		return mutateAndCommit(name, resolve, func(folder resolvedFolder) error {
			return apply.DeleteDirectory(folder.root, relative)
		})
	}
	return transport.Callbacks{
		ListFiles:          fileLister,
		ReadFile:           fileReader,
		WriteFile:          fileWriter,
		DeleteFile:         fileDeleter,
		WriteConflict:      conflictWriter,
		WriteConflictCopy:  conflictCopyWriter,
		ConflictCopyExists: conflictCopyExists,
		ReuseFile:          fileReuser,
		ApplyDirectory:     directoryWriter,
		DeleteDirectory:    directoryDeleter,
	}
}

func newReloadingShareLister(peer, authenticatedFingerprint string) func() ([]string, error) {
	return func() ([]string, error) {
		cfg, err := preflight.LoadConfig()
		if err != nil {
			return nil, fmt.Errorf("reload validated config for share discovery: %w", err)
		}
		configured, exists := cfg.Peers[peer]
		if !exists || configured.PublicKey == "" {
			return nil, fmt.Errorf("peer %q has no configured public key", peer)
		}
		if err := requireAuthenticatedFingerprint(configured, authenticatedFingerprint); err != nil {
			return nil, fmt.Errorf("peer %q authorization changed: %w", peer, err)
		}
		return sortedKeys(cfg.Shared), nil
	}
}

func newFolderResolver(cfg config.Config, peer, authenticatedFingerprint string) folderResolver {
	return func(name string) (resolvedFolder, error) {
		return resolveFolder(cfg, peer, authenticatedFingerprint, name)
	}
}

func newReloadingFolderResolver(peer, authenticatedFingerprint string) folderResolver {
	return func(name string) (resolvedFolder, error) {
		cfg, err := preflight.LoadConfig()
		if err != nil {
			return resolvedFolder{}, fmt.Errorf("reload validated config for folder authorization: %w", err)
		}
		return resolveFolder(cfg, peer, authenticatedFingerprint, name)
	}
}

func resolveFolder(cfg config.Config, peer, authenticatedFingerprint, name string) (resolvedFolder, error) {
	configured, exists := cfg.Peers[peer]
	if !exists || configured.PublicKey == "" {
		return resolvedFolder{}, fmt.Errorf("peer %q has no configured public key", peer)
	}
	if err := requireAuthenticatedFingerprint(configured, authenticatedFingerprint); err != nil {
		return resolvedFolder{}, fmt.Errorf("peer %q authorization changed: %w", peer, err)
	}
	if bound, ok := cfg.BoundPeer(name); !ok || bound != peer {
		return resolvedFolder{}, fmt.Errorf("folder %q is not bound to peer %q", name, peer)
	}
	folder, exists := cfg.Lookup(name)
	if !exists {
		return resolvedFolder{}, fmt.Errorf("folder %q is not registered", name)
	}
	path := folder.Path
	marker, err := guard.ReadMarker(path)
	if err != nil {
		return resolvedFolder{}, fmt.Errorf("folder %q marker: %w", name, err)
	}
	if marker.Name != name {
		return resolvedFolder{}, fmt.Errorf("folder %q marker names %q", name, marker.Name)
	}
	return resolvedFolder{root: path, marker: marker}, nil
}

func requireAuthenticatedFingerprint(peer config.Peer, authenticatedFingerprint string) error {
	current, err := connection.Fingerprint(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("derive current public-key fingerprint: %w", err)
	}
	if authenticatedFingerprint == "" || current != authenticatedFingerprint {
		return errors.New("authenticated fingerprint no longer matches configured public key")
	}
	return nil
}

func mutateServedFolder(name string, resolve folderResolver, mutation func(resolvedFolder) error) (err error) {
	return mutateServedFolderWithin(name, resolve, lock.DefaultWait, mutation)
}

// mutateAndCommit runs op against the resolved folder and, on success,
// rescans and saves its baseline within the same held lock.
func mutateAndCommit(name string, resolve folderResolver, op func(resolvedFolder) error) error {
	return mutateServedFolder(name, resolve, func(folder resolvedFolder) error {
		if err := op(folder); err != nil {
			return err
		}
		return commitFolderBaseline(name, folder.root, folder.marker.Ignore)
	})
}

func mutateServedFolderWithin(name string, resolve folderResolver, wait time.Duration, mutation func(resolvedFolder) error) (err error) {
	lockFile, err := lock.AcquireWait(context.Background(), wait)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := lock.Release(lockFile); releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}()
	folder, err := resolve(name)
	if err != nil {
		return err
	}
	return mutation(folder)
}

func commitFolderBaseline(name, path string, ignore []string) error {
	baseline, err := loadBaseline(name)
	if err != nil {
		return fmt.Errorf("load folder baseline: %w", err)
	}
	result, err := scan.DetectWithIgnore(path, baseline, ignore)
	if err != nil {
		return fmt.Errorf("scan folder after mutation: %w", err)
	}
	if err := state.Save(name, result.Snapshot); err != nil {
		return fmt.Errorf("save folder baseline after mutation: %w", err)
	}
	return nil
}
