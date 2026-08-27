//go:build linux

package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"l2syncd/internal/apply"
	"l2syncd/internal/config"
	"l2syncd/internal/connection"
	"l2syncd/internal/guard"
	"l2syncd/internal/index"
	"l2syncd/internal/lock"
	"l2syncd/internal/logging"
	"l2syncd/internal/metadata"
	"l2syncd/internal/preflight"
	"l2syncd/internal/scan"
	"l2syncd/internal/sharepath"
	"l2syncd/internal/transport"
	"l2syncd/internal/vector"
)

const (
	serveExitOK     = 0
	serveExitError  = 1
	serveExitLocked = 4
)

// serveLogger and commitLogger write to this process's stderr and, via
// logging.NewLogger, to the shared per-machine log file. Serve runs as an
// SSH forced-command subprocess: its stderr is piped back over the SSH
// channel to the peer that invoked it and captured there in a bounded
// buffer (see internal/transport sshStderrLimit) that is discarded on a
// successful request and only excerpted into an error message on failure,
// so stderr alone is not durably visible. The shared log file is what
// makes these lines durably observable; Serve points these package
// variables at it (with this process's own stderr as the fallback/mirror
// destination) before handling a request. The zero-value defaults below
// exist only so package-level helpers have a safe logger if ever invoked
// outside Serve (see status.go's IndexCommit, which sets commitLogger
// itself before calling those helpers).
var (
	serveLogger  = slog.New(slog.NewTextHandler(os.Stderr, nil)).With("pid", os.Getpid(), "component", "serve")
	commitLogger = slog.New(slog.NewTextHandler(os.Stderr, nil)).With("pid", os.Getpid(), "component", "commit")
)

// Handler names used in serve-side mutation logging, kept next to the
// callbacks that use them.
const (
	handlerWriteFile         = "WriteFile"
	handlerDeleteFile        = "DeleteFile"
	handlerWriteConflict     = "WriteConflict"
	handlerWriteConflictCopy = "WriteConflictCopy"
	handlerApplyDirectory    = "ApplyDirectory"
	handlerDeleteDirectory   = "DeleteDirectory"
	handlerReuseFile         = "ReuseFile"
)

type resolvedFolder struct {
	root   string
	marker guard.Marker
}

type folderResolver func(string) (resolvedFolder, error)

// Serve handles one peer protocol request on stdin/stdout.
func Serve(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	serveLogger = logging.NewLogger(stderr, "serve")
	commitLogger = logging.NewLogger(stderr, "commit")
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
	fileLister := func(name, expectedID string) ([]transport.PeerFile, string, error) {
		localIdentity, err := localFingerprint()
		if err != nil {
			return nil, "", err
		}
		var listed []scan.ListedFile
		var folderID string
		err = mutateServedFolderWithin(name, resolve, lock.DefaultWait, func(current resolvedFolder) error {
			if expectedID != "" && current.marker.ID != expectedID {
				return fmt.Errorf("folder %q identity mismatch: requester expects id %q, provider has %q", name, expectedID, current.marker.ID)
			}
			folderID = current.marker.ID
			previous, loadErr := loadIndex(current.marker.ID)
			if loadErr != nil {
				return loadErr
			}
			result, scanErr := scan.Reconcile(current.root, previous, current.marker.Ignore, localIdentity)
			if scanErr != nil {
				return fmt.Errorf("list folder %q: %w", name, scanErr)
			}
			if saveErr := index.Save(result.Index); saveErr != nil {
				return fmt.Errorf("save index for folder %q: %w", name, saveErr)
			}
			listed = scan.ListEntries(result.Index)
			return nil
		})
		if err != nil {
			return nil, "", err
		}
		files := make([]transport.PeerFile, 0, len(listed))
		for _, file := range listed {
			files = append(files, transport.PeerFile{
				Path: file.Path, Size: file.Size, Hash: file.Hash, Metadata: file.Metadata,
				Directory: file.Directory, Deleted: file.Deleted, DeletedAt: file.DeletedAt, Version: file.Version,
			})
		}
		return files, folderID, nil
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
	fileWriter := func(name, relative, expectedHash string, manifest metadata.Manifest, vec vector.Vector, contents io.Reader) error {
		return mutateAndLog(name, relative, handlerWriteFile, resolve, func(folder resolvedFolder) error {
			if err := apply.WriteWithMetadata(folder.root, relative, contents, expectedHash, manifest); err != nil {
				return err
			}
			return commitLocalEntry(folder.marker.ID, relative, index.Entry{Version: vec, Hash: expectedHash, Metadata: manifest})
		})
	}
	fileDeleter := func(name, relative string, vec vector.Vector) error {
		return mutateAndLog(name, relative, handlerDeleteFile, resolve, func(folder resolvedFolder) error {
			if err := apply.Delete(folder.root, relative); err != nil {
				return err
			}
			return commitLocalEntry(folder.marker.ID, relative, index.Entry{Version: vec, Deleted: true, DeletedAt: time.Now().UTC()})
		})
	}
	conflictWriter := func(name, relative, loser, expectedHash string, manifest metadata.Manifest, vec vector.Vector, contents io.Reader) error {
		return mutateAndLog(name, relative, handlerWriteConflict, resolve, func(folder resolvedFolder) error {
			if err := apply.WriteConflictWinnerWithSuffix(folder.root, relative, loser, contents, expectedHash, manifest); err != nil {
				return err
			}
			return commitLocalEntry(folder.marker.ID, relative, index.Entry{Version: vec, Hash: expectedHash, Metadata: manifest})
		})
	}
	conflictCopyWriter := func(name, relative, suffix, expectedHash string, manifest metadata.Manifest, contents io.Reader) error {
		return mutateAndLog(name, relative, handlerWriteConflictCopy, resolve, func(folder resolvedFolder) error {
			// A conflict copy lands at a new path neither replica has
			// tracked before, so it carries no vector to commit: the next
			// local scan on either side picks it up as an ordinary
			// creation (implementation-plan.md Phase C).
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
	fileReuser := func(name, relative, expectedHash string, manifest metadata.Manifest, vec vector.Vector) (bool, error) {
		serveLogger.Debug("mutation start", "handler", handlerReuseFile, "folder", name, "path", relative)
		var reused bool
		err := mutateServedFolder(name, resolve, func(folder resolvedFolder) error {
			previous, loadErr := loadIndex(folder.marker.ID)
			if loadErr != nil {
				return loadErr
			}
			for source, entry := range previous.Entries {
				if entry.Deleted || entry.Hash != expectedHash {
					continue
				}
				if reuseErr := apply.Reuse(folder.root, relative, source, expectedHash, manifest); reuseErr != nil {
					if errors.Is(reuseErr, apply.ErrReuseMismatch) {
						continue
					}
					serveLogger.Error("reuse failed", "handler", handlerReuseFile, "folder", name, "path", relative, "source", source, "error", reuseErr)
					return reuseErr
				}
				if commitErr := commitLocalEntry(folder.marker.ID, relative, index.Entry{Version: vec, Hash: expectedHash, Metadata: manifest}); commitErr != nil {
					serveLogger.Error("mutation applied WITHOUT index commit", "handler", handlerReuseFile, "folder", name, "path", relative, "source", source, "error", commitErr)
					return commitErr
				}
				serveLogger.Info("reuse applied and committed", "handler", handlerReuseFile, "folder", name, "path", relative, "source", source)
				reused = true
				return nil
			}
			serveLogger.Debug("reuse skipped: no matching index hash, no mutation, no commit", "handler", handlerReuseFile, "folder", name, "path", relative)
			return nil
		})
		if err != nil {
			serveLogger.Error("mutation complete", "handler", handlerReuseFile, "folder", name, "path", relative, "reused", reused, "error", err)
		} else {
			serveLogger.Debug("mutation complete", "handler", handlerReuseFile, "folder", name, "path", relative, "reused", reused)
		}
		return reused, err
	}
	directoryWriter := func(name, relative string, manifest metadata.Manifest) error {
		return mutateAndLog(name, relative, handlerApplyDirectory, resolve, func(folder resolvedFolder) error {
			if err := apply.ApplyDirectory(folder.root, relative, manifest); err != nil {
				return err
			}
			return commitDirectory(folder.marker.ID, relative, manifest)
		})
	}
	directoryDeleter := func(name, relative string) error {
		return mutateAndLog(name, relative, handlerDeleteDirectory, resolve, func(folder resolvedFolder) error {
			if err := apply.DeleteDirectory(folder.root, relative); err != nil {
				return err
			}
			// DeleteDirectory silently retains a non-empty directory
			// (apply.DeleteDirectory), so only drop the index entry when
			// the directory is actually gone.
			exists, statErr := directoryExists(folder.root, relative)
			if statErr != nil {
				return statErr
			}
			if exists {
				return nil
			}
			return removeDirectoryEntry(folder.marker.ID, relative)
		})
	}
	mergeVector := func(name, relative string, vec vector.Vector) error {
		return mutateAndLog(name, relative, "MergeVector", resolve, func(folder resolvedFolder) error {
			previous, loadErr := loadIndex(folder.marker.ID)
			if loadErr != nil {
				return loadErr
			}
			entry, exists := previous.Entries[relative]
			if !exists {
				return fmt.Errorf("cannot merge vector for untracked path %q", relative)
			}
			entry.Version = vec
			return commitLocalEntry(folder.marker.ID, relative, entry)
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
		MergeVector:        mergeVector,
	}
}

func directoryExists(root, relative string) (bool, error) {
	directory, err := sharepath.OpenDirectory(root, relative)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	return true, directory.Close()
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

// mutateAndLog runs op against the resolved folder under the per-folder
// mutation lock, logging start/failure/completion uniformly. op is
// responsible for both applying the mutation and persisting its result --
// via commitLocalEntry, commitDirectory, or removeDirectoryEntry, the
// index-commit functions every mutating path uses (implementation-plan.md
// Phase C).
func mutateAndLog(name, relative, handler string, resolve folderResolver, op func(resolvedFolder) error) error {
	serveLogger.Debug("mutation start", "handler", handler, "folder", name, "path", relative)
	err := mutateServedFolder(name, resolve, func(folder resolvedFolder) error {
		if err := op(folder); err != nil {
			serveLogger.Error("mutation failed", "handler", handler, "folder", name, "path", relative, "error", err)
			return err
		}
		return nil
	})
	if err == nil {
		serveLogger.Debug("mutation complete", "handler", handler, "folder", name, "path", relative)
	}
	return err
}

func mutateServedFolderWithin(name string, resolve folderResolver, wait time.Duration, mutation func(resolvedFolder) error) (err error) {
	lockFile, err := lock.AcquireWait(context.Background(), wait, name)
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
