//go:build linux

package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"l2syncd/internal/apply"
	"l2syncd/internal/config"
	"l2syncd/internal/engine"
	"l2syncd/internal/guard"
	"l2syncd/internal/index"
	"l2syncd/internal/lock"
	"l2syncd/internal/logging"
	"l2syncd/internal/preflight"
	"l2syncd/internal/scan"
	"l2syncd/internal/sharepath"
	"l2syncd/internal/transport"
	"l2syncd/internal/vector"
)

const (
	nowExitOK          = 0
	nowExitError       = 1
	nowExitInvalid     = 2
	nowExitUnreachable = 3
	nowExitLocked      = 4
)

// nowLogger reports initiator-side cycle activity: role resolution, the
// plan computed for each folder, and whether that folder's index commit
// actually succeeded. Used regardless of whether the cycle was triggered by
// `l2sync now` or by the daemon's cycle loop in run.go; both entrypoints
// point it (and commitLogger) at the shared per-machine log file via
// logging.NewLogger before invoking RunCycle. This default only covers
// callers that reach RunCycle without going through either entrypoint.
var nowLogger = slog.New(slog.NewTextHandler(os.Stderr, nil)).With("pid", os.Getpid(), "component", "now")

func Now(args []string, stdout, stderr io.Writer) int {
	nowLogger = logging.NewLogger(stderr, "now")
	commitLogger = logging.NewLogger(stderr, "commit")
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: l2sync now")
		return nowExitError
	}
	if _, err := RunCycle(context.Background()); err != nil {
		fmt.Fprintf(stderr, "l2sync: now: %v\n", err)
		if errors.Is(err, errInvalidConfig) {
			return nowExitInvalid
		}
		if errors.Is(err, lock.ErrTimeout) {
			return nowExitLocked
		}
		if isTransportError(err) {
			return nowExitUnreachable
		}
		return nowExitError
	}
	return nowExitOK
}

// FolderOutcome reports the observable per-folder result of one
// reconciliation cycle, so a folder whose mutation landed without an index
// commit is visible individually rather than only folded into the cycle's
// aggregate counts. Committed reflects whether the folder's cycle returned
// without error: for the local initiator this is a direct proxy for every
// action's commit succeeding (see planFolder); for a non-initiator
// requesting the peer run its own cycle, it reflects the request completing
// without a transport error and does not itself observe the peer's commit
// (see serve.go's own commit logging for that side).
type FolderOutcome struct {
	Name             string
	InitiatedLocally bool
	Actions          int
	Committed        bool
}

// CycleSummary reports the useful work completed by one reconciliation cycle.
type CycleSummary struct {
	Folders  int
	Actions  int
	Outcomes []FolderOutcome
}

var (
	requestPeerCycle   = transport.RequestCycle
	runBoundFolderPlan = planBoundFolder
)

// RunCycle dispatches each bound folder to its deterministic fingerprint
// initiator, running every folder's cycle concurrently so one folder's
// network-bound work never delays another's. A non-initiator holds no
// mutation lock while requesting work.
func RunCycle(ctx context.Context) (summary CycleSummary, err error) {
	cfg, err := preflight.LoadConfig()
	if err != nil {
		return summary, errors.Join(errInvalidConfig, err)
	}
	localIdentity, err := localFingerprint()
	if err != nil {
		return summary, err
	}
	names := cycleFolderNames(cfg)
	outcomes := make([]*FolderOutcome, len(names))
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			outcomes[i], errs[i] = runFolderCycle(ctx, localIdentity, name)
		}(i, name)
	}
	wg.Wait()
	for i, name := range names {
		if outcomes[i] != nil {
			summary.Outcomes = append(summary.Outcomes, *outcomes[i])
			if errs[i] == nil {
				summary.Folders++
				summary.Actions += outcomes[i].Actions
			}
		}
		if errs[i] != nil && err == nil {
			err = fmt.Errorf("%s: %w", name, errs[i])
		}
	}
	return summary, err
}

// runFolderCycle resolves and runs one folder's cycle in isolation so
// RunCycle can dispatch every folder concurrently. A nil outcome means the
// folder is no longer configured (loadActiveCycleFolder found it absent);
// that is not an error.
func runFolderCycle(ctx context.Context, localIdentity, name string) (*FolderOutcome, error) {
	cfg, peerName, endpoint, present, loadErr := loadActiveCycleFolder(ctx, name)
	if loadErr != nil {
		return nil, loadErr
	}
	if !present {
		return nil, nil
	}
	if _, ok := cfg.BoundPeer(name); !ok {
		return nil, fmt.Errorf("folder %q requires exactly one peer binding", name)
	}
	remoteIdentity, err := peerFingerprint(cfg.Peers[peerName])
	if err != nil {
		return nil, fmt.Errorf("derive peer %q identity: %w", peerName, err)
	}
	initiates, err := localInitiatesCycle(localIdentity, remoteIdentity)
	if err != nil {
		return nil, fmt.Errorf("folder %q: %w", name, err)
	}
	nowLogger.Info("cycle role resolved", "folder", name, "peer", peerName,
		"local_fingerprint", localIdentity, "remote_fingerprint", remoteIdentity,
		"initiates_locally", initiates)
	if initiates {
		actions, err := runInitiatorFolderCycle(ctx, name, peerName, remoteIdentity)
		return folderOutcome(name, initiates, actions, err)
	}
	actions, err := requestPeerCycle(ctx, endpoint, name)
	return folderOutcome(name, initiates, actions, err)
}

func folderOutcome(name string, initiates bool, actions int, err error) (*FolderOutcome, error) {
	outcome := FolderOutcome{Name: name, InitiatedLocally: initiates, Actions: actions, Committed: err == nil}
	if err != nil {
		nowLogger.Error("folder cycle failed", "folder", name, "initiated_locally", initiates, "actions", actions, "error", err)
		return &outcome, err
	}
	nowLogger.Info("folder cycle completed", "folder", name, "initiated_locally", initiates, "actions", actions)
	return &outcome, nil
}

// cycleFolderActivationAttempts bounds the reload retry in
// loadActiveCycleFolder: one initial read plus one reload to pick up a peer
// activation that completes concurrently with this cycle.
const cycleFolderActivationAttempts = 2

func loadActiveCycleFolder(ctx context.Context, name string) (config.Config, string, transport.Endpoint, bool, error) {
	for attempt := 0; attempt < cycleFolderActivationAttempts; attempt++ {
		cfg, err := preflight.LoadConfig()
		if err != nil {
			return config.Config{}, "", transport.Endpoint{}, false, errors.Join(errInvalidConfig, err)
		}
		if !contains(cycleFolderNames(cfg), name) {
			return cfg, "", transport.Endpoint{}, false, nil
		}
		peerName, ok := cfg.BoundPeer(name)
		if !ok {
			return config.Config{}, "", transport.Endpoint{}, false, fmt.Errorf("folder %q requires exactly one peer binding", name)
		}
		peer := cfg.Peers[peerName]
		endpoint, err := peerEndpoint(ctx, cfg, peerName)
		if err != nil {
			return config.Config{}, "", transport.Endpoint{}, false, err
		}
		if peer.PublicKey == "" {
			continue
		}
		return cfg, peerName, endpoint, true, nil
	}
	return config.Config{}, "", transport.Endpoint{}, false, fmt.Errorf("folder %q peer identity changed while activating", name)
}

func cycleFolderNames(cfg config.Config) []string {
	names := make(map[string]struct{})
	for name, folder := range cfg.Shared {
		if len(folder.Peers) == 1 {
			names[name] = struct{}{}
		}
	}
	for name := range cfg.Remote {
		names[name] = struct{}{}
	}
	return sortedKeys(names)
}

func localInitiatesCycle(localIdentity, remoteIdentity string) (bool, error) {
	if localIdentity == "" || remoteIdentity == "" {
		return false, errors.New("cycle fingerprints are required")
	}
	if localIdentity == remoteIdentity {
		return false, errors.New("cycle fingerprints are equal")
	}
	return localIdentity < remoteIdentity, nil
}

// runInitiatorFolderCycle plans and applies one folder's cycle. It holds no
// lock across this span: outbound transport calls to the peer must never
// wait behind this installation's own local mutation lock (see
// withFolderLock), which serve.go's forced-command handlers also acquire
// for unrelated, concurrent, per-folder work.
func runInitiatorFolderCycle(ctx context.Context, name, expectedPeer, authenticatedFingerprint string) (actions int, err error) {
	cfg, err := loadConfigForTransaction()
	if err != nil {
		return 0, err
	}
	if bound, ok := cfg.BoundPeer(name); !ok || bound != expectedPeer {
		return 0, fmt.Errorf("folder %q is not bound to authenticated peer %q", name, expectedPeer)
	}
	configured, exists := cfg.Peers[expectedPeer]
	if !exists || configured.PublicKey == "" {
		return 0, fmt.Errorf("peer %q has no configured public key", expectedPeer)
	}
	if err := requireAuthenticatedFingerprint(configured, authenticatedFingerprint); err != nil {
		return 0, fmt.Errorf("peer %q authorization changed: %w", expectedPeer, err)
	}
	localIdentity, err := localFingerprint()
	if err != nil {
		return 0, err
	}
	remoteIdentity, err := peerFingerprint(configured)
	if err != nil {
		return 0, err
	}
	initiates, err := localInitiatesCycle(localIdentity, remoteIdentity)
	if err != nil {
		return 0, err
	}
	if !initiates {
		return 0, fmt.Errorf("this installation is not the cycle initiator for folder %q", name)
	}
	return runBoundFolderPlan(ctx, cfg, name, expectedPeer)
}

// withFolderLock serializes a local filesystem mutation and its index
// commit against serve.go's forced-command handlers for the same folder. It
// must wrap only the local write and commit themselves, never a transport
// round trip: a peer waiting on this installation's response must never be
// blocked behind a lock this installation is holding while it, in turn,
// waits on that same peer.
func withFolderLock(ctx context.Context, folder string, fn func() error) (err error) {
	lockFile, err := lock.AcquireWait(ctx, lock.DefaultWait, folder)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := lock.Release(lockFile); releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}()
	return fn()
}

func planBoundFolder(ctx context.Context, cfg config.Config, name, expectedPeer string) (int, error) {
	if folder, exists := cfg.Shared[name]; exists {
		peer, endpoint, err := findPeerForShared(ctx, cfg, name)
		if err != nil {
			return 0, err
		}
		return planFolder(ctx, cfg, name, folder.Path, peer, endpoint)
	}
	folder, exists := cfg.Remote[name]
	if !exists {
		return 0, fmt.Errorf("folder %q is not registered", name)
	}
	provider, endpoint, err := findProvider(ctx, cfg, name)
	if err != nil {
		return 0, err
	}
	return planFolder(ctx, cfg, name, folder.Path, provider, endpoint)
}

// planFolder reconciles one folder against its bound peer. Unlike the
// agreed-snapshot model, there is no separate "commit the whole tree at the
// end" step: every applied action commits its own resulting vector as it
// lands, through the single commitLocalEntry/commitDirectory/
// removeDirectoryEntry functions also used by serve.go (implementation-plan.md
// Phase C).
func planFolder(ctx context.Context, cfg config.Config, name, path, peer string, endpoint transport.Endpoint) (int, error) {
	marker, err := guard.ReadMarker(path)
	if err != nil {
		return 0, fmt.Errorf("read marker: %w", err)
	}
	localIdentity, err := localFingerprint()
	if err != nil {
		return 0, fmt.Errorf("derive local identity: %w", err)
	}
	remoteIdentity, err := peerFingerprint(cfg.Peers[peer])
	if err != nil {
		return 0, fmt.Errorf("derive peer %q identity: %w", peer, err)
	}

	previous, err := loadIndex(marker.ID)
	if err != nil {
		return 0, fmt.Errorf("load index: %w", err)
	}
	local, err := scanShare(path, previous, marker.Ignore, localIdentity)
	if err != nil {
		return 0, err
	}
	// Locally confirmed changes are a local fact, durable regardless of
	// whether the peer is reachable: commit them before any network call.
	if err := index.Save(local); err != nil {
		return 0, fmt.Errorf("save index: %w", err)
	}

	remoteFiles, _, err := transport.ListFiles(ctx, endpoint, name, marker.ID)
	if err != nil {
		return 0, fmt.Errorf("peer %q listing: %w", peer, err)
	}
	remote := remoteIndexFromListing(remoteIdentity, remoteFiles)

	plan := engine.PlanStates(localIdentity, local, remoteIdentity, remote, previous.Directories)
	if plan.Halted {
		nowLogger.Error("plan halted", "folder", name, "peer", peer, "reason", plan.Reason)
		return 0, fmt.Errorf("halted: %s", plan.Reason)
	}
	nowLogger.Info("folder plan computed", "folder", name, "peer", peer,
		"actions", len(plan.Actions), "directory_actions", len(plan.DirectoryActions))

	reused, err := prepareContentReuse(ctx, plan.Actions, name, marker.ID, path, remoteIdentity, endpoint, local)
	if err != nil {
		return 0, err
	}
	for _, action := range plan.Actions {
		if reused[action.Path] {
			continue
		}
		if err := applyAction(ctx, action, name, marker.ID, path, remoteIdentity, endpoint, local, remote); err != nil {
			nowLogger.Error("initiator mutation applied WITHOUT index commit", "folder", name, "peer", peer, "path", action.Path, "kind", action.Kind, "error", err)
			return 0, err
		}
	}
	directoryActions := append([]engine.Action(nil), plan.DirectoryActions...)
	sortByDepthDescending(directoryActions, func(action engine.Action) string { return action.Path })
	for _, action := range directoryActions {
		if action.Kind != engine.Delete {
			continue
		}
		if err := applyDirectoryDelete(ctx, action, name, marker.ID, path, remoteIdentity, endpoint); err != nil {
			return 0, err
		}
	}
	if err := restoreDirectoryMetadata(ctx, plan.Actions, directoryActions, name, marker.ID, path, remoteIdentity, endpoint, local, remote); err != nil {
		return 0, err
	}
	nowLogger.Info("initiator cycle outcome", "folder", name, "peer", peer, "outcome", "success",
		"actions", len(plan.Actions), "directory_actions", len(plan.DirectoryActions))
	return len(plan.Actions) + len(plan.DirectoryActions), nil
}

// sortByDepthDescending orders items so deeper paths (more path separators)
// come first, so directory deletes and metadata restores process children
// before their parents.
func sortByDepthDescending[T any](items []T, path func(T) string) {
	sort.SliceStable(items, func(left, right int) bool {
		return strings.Count(path(items[left]), "/") > strings.Count(path(items[right]), "/")
	})
}

func restoreDirectoryMetadata(ctx context.Context, fileActions, directoryActions []engine.Action, share, folderID, root, provider string, endpoint transport.Endpoint, local, remote index.Index) error {
	directoryActionByPath := make(map[string]engine.Action, len(directoryActions))
	paths := make(map[string]struct{})
	for _, action := range directoryActions {
		directoryActionByPath[action.Path] = action
		if action.Kind != engine.Delete {
			paths[action.Path] = struct{}{}
		}
	}
	for _, action := range fileActions {
		parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(action.Path)))
		for parent != "." {
			paths[parent] = struct{}{}
			parent = filepath.ToSlash(filepath.Dir(filepath.FromSlash(parent)))
		}
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sortByDepthDescending(ordered, func(path string) string { return path })
	for _, path := range ordered {
		action, changed := directoryActionByPath[path]
		if changed && action.Kind == engine.Delete {
			continue
		}
		manifest, exists := local.Directories[path]
		if changed && action.Source == provider {
			manifest, exists = remote.Directories[path]
		} else if !exists {
			manifest, exists = remote.Directories[path]
		}
		if !exists {
			continue
		}
		if err := withFolderLock(ctx, share, func() error {
			if err := apply.ApplyDirectory(root, path, manifest); err != nil {
				return err
			}
			return commitDirectory(folderID, path, manifest)
		}); err != nil {
			return err
		}
		if err := transport.ApplyDirectory(ctx, endpoint, share, path, manifest); err != nil {
			return err
		}
	}
	return nil
}

func prepareContentReuse(ctx context.Context, actions []engine.Action, share, folderID, root, provider string, endpoint transport.Endpoint, local index.Index) (map[string]bool, error) {
	reused := make(map[string]bool)
	for _, action := range actions {
		remoteSource := action.Source == provider
		switch {
		case action.Kind == engine.Push || action.Kind == engine.Resurrect && !remoteSource:
			entry := local.Entries[action.Path]
			ok, err := transport.ReuseFile(ctx, endpoint, share, action.Path, entry.Hash, entry.Metadata, action.Vector)
			if err != nil {
				return nil, fmt.Errorf("reuse %q on peer: %w", action.Path, err)
			}
			reused[action.Path] = ok
		case (action.Kind == engine.Pull || action.Kind == engine.Resurrect) && remoteSource:
			ok, err := reuseLocal(ctx, share, folderID, root, action.Path, action.Vector, local)
			if err != nil {
				return nil, err
			}
			reused[action.Path] = ok
		}
	}
	return reused, nil
}

func applyDirectoryDelete(ctx context.Context, action engine.Action, share, folderID, root, provider string, endpoint transport.Endpoint) error {
	remoteSource := action.Source == provider
	if remoteSource {
		return withFolderLock(ctx, share, func() error {
			if err := apply.DeleteDirectory(root, action.Path); err != nil {
				return err
			}
			return removeDirectoryEntry(folderID, action.Path)
		})
	}
	return transport.DeleteDirectory(ctx, endpoint, share, action.Path)
}

func findPeerForShared(ctx context.Context, cfg config.Config, name string) (string, transport.Endpoint, error) {
	peer, ok := cfg.BoundPeer(name)
	if !ok {
		return "", transport.Endpoint{}, fmt.Errorf("shared folder %q requires exactly one peer binding", name)
	}
	endpoint, err := peerEndpoint(ctx, cfg, peer)
	if err != nil {
		return "", transport.Endpoint{}, err
	}
	if _, _, err := transport.ListFiles(ctx, endpoint, name, ""); err != nil {
		return "", transport.Endpoint{}, fmt.Errorf("peer %q does not serve folder %q: %w", peer, name, err)
	}
	return peer, endpoint, nil
}

// applyAction executes one file-entry decision. Every branch that changes
// this installation's own index commits the resulting action.Vector through
// commitLocalEntry; a branch that only changes the peer's copy relies on the
// corresponding transport call to carry that same vector across
// (implementation-plan.md Phase C).
func applyAction(ctx context.Context, action engine.Action, share, folderID, root, provider string, endpoint transport.Endpoint, local, remote index.Index) error {
	remoteEntry := remote.Entries[action.Path]
	localEntry := local.Entries[action.Path]
	remoteSource := action.Source == provider || action.Winner == provider
	switch action.Kind {
	case engine.Pull:
		if !remoteSource {
			return fmt.Errorf("pull source for %q is not the provider", action.Path)
		}
		return pullFile(ctx, endpoint, share, folderID, root, action.Path, remoteEntry, action.Vector)
	case engine.Resurrect:
		if remoteSource {
			return pullFile(ctx, endpoint, share, folderID, root, action.Path, remoteEntry, action.Vector)
		}
		return pushFile(ctx, endpoint, share, root, action.Path, localEntry, action.Vector)
	case engine.Delete:
		if remoteSource {
			return applyLocalDelete(ctx, share, folderID, root, action.Path, action.Vector)
		}
		return transport.DeleteFile(ctx, endpoint, share, action.Path, action.Vector)
	case engine.Merge:
		merged := localEntry
		merged.Version = action.Vector
		if err := withFolderLock(ctx, share, func() error {
			return commitLocalEntry(folderID, action.Path, merged)
		}); err != nil {
			return fmt.Errorf("commit merged vector for %q: %w", action.Path, err)
		}
		return transport.MergeVector(ctx, endpoint, share, action.Path, action.Vector)
	case engine.Conflict:
		return applyConflict(ctx, action, share, folderID, root, provider, endpoint, localEntry, remoteEntry)
	case engine.Push:
		return pushFile(ctx, endpoint, share, root, action.Path, localEntry, action.Vector)
	default:
		return fmt.Errorf("unknown action %q", action.Kind)
	}
}

func applyConflict(ctx context.Context, action engine.Action, share, folderID, root, provider string, endpoint transport.Endpoint, localEntry, remoteEntry index.Entry) error {
	remoteSource := action.Winner == provider
	suffix := deterministicConflictSuffix(localEntry, remoteEntry, action.Loser)
	localCollision, err := apply.ConflictCopyExists(root, action.Path, suffix)
	if err != nil {
		return fmt.Errorf("check local conflict destination for %q: %w", action.Path, err)
	}
	remoteCollision, err := transport.ConflictCopyExists(ctx, endpoint, share, action.Path, suffix)
	if err != nil {
		return fmt.Errorf("check peer conflict destination for %q: %w", action.Path, err)
	}
	if localCollision || remoteCollision {
		return fmt.Errorf("conflict destination for %q already exists on one or both replicas", action.Path)
	}
	if remoteSource {
		losing, err := readShareFile(root, action.Path)
		if err != nil {
			return fmt.Errorf("read local conflict loser %q: %w", action.Path, err)
		}
		if err := transport.WriteConflictCopy(ctx, endpoint, share, action.Path, losing, localEntry.Hash, suffix, localEntry.Metadata); err != nil {
			return fmt.Errorf("preserve conflict loser %q on peer: %w", action.Path, err)
		}
		data, err := transport.ReadFile(ctx, endpoint, share, action.Path, remoteEntry.Hash)
		if err != nil {
			return fmt.Errorf("read conflict winner %q from peer: %w", action.Path, err)
		}
		return withFolderLock(ctx, share, func() error {
			if err := apply.WriteConflictWinnerWithSuffix(root, action.Path, suffix, bytes.NewReader(data), remoteEntry.Hash, remoteEntry.Metadata); err != nil {
				return err
			}
			return commitLocalEntry(folderID, action.Path, index.Entry{Version: action.Vector, Hash: remoteEntry.Hash, Metadata: remoteEntry.Metadata})
		})
	}
	data, err := readShareFile(root, action.Path)
	if err != nil {
		return fmt.Errorf("read local conflict winner %q: %w", action.Path, err)
	}
	losing, err := transport.ReadFile(ctx, endpoint, share, action.Path, remoteEntry.Hash)
	if err != nil {
		return fmt.Errorf("read conflict loser %q from peer: %w", action.Path, err)
	}
	if err := withFolderLock(ctx, share, func() error {
		if err := apply.WriteConflictCopyWithSuffix(root, action.Path, suffix, bytes.NewReader(losing), remoteEntry.Hash, remoteEntry.Metadata); err != nil {
			return err
		}
		// The local canonical file already holds the winning bytes; only
		// its vector advances to the merged value.
		return commitLocalEntry(folderID, action.Path, index.Entry{Version: action.Vector, Hash: localEntry.Hash, Metadata: localEntry.Metadata})
	}); err != nil {
		return fmt.Errorf("preserve conflict loser %q locally: %w", action.Path, err)
	}
	if err := transport.WriteConflictFile(ctx, endpoint, share, action.Path, data, localEntry.Hash, suffix, localEntry.Metadata, action.Vector); err != nil {
		return fmt.Errorf("write conflict winner %q to peer: %w", action.Path, err)
	}
	return nil
}

func deterministicConflictSuffix(left, right index.Entry, loser string) string {
	stamp := left.Metadata.Mtime
	if right.Metadata.Mtime.After(stamp) {
		stamp = right.Metadata.Mtime
	}
	return stamp.UTC().Format("20060102-150405") + "-" + loser[:12]
}

func pullFile(ctx context.Context, endpoint transport.Endpoint, share, folderID, root, relative string, entry index.Entry, vec vector.Vector) error {
	data, err := transport.ReadFile(ctx, endpoint, share, relative, entry.Hash)
	if err != nil {
		return fmt.Errorf("read %q from peer: %w", relative, err)
	}
	return withFolderLock(ctx, share, func() error {
		if err := apply.WriteWithMetadata(root, relative, bytes.NewReader(data), entry.Hash, entry.Metadata); err != nil {
			return err
		}
		return commitLocalEntry(folderID, relative, index.Entry{Version: vec, Hash: entry.Hash, Metadata: entry.Metadata})
	})
}

func pushFile(ctx context.Context, endpoint transport.Endpoint, share, root, relative string, entry index.Entry, vec vector.Vector) error {
	data, err := readShareFile(root, relative)
	if err != nil {
		return fmt.Errorf("read local file %q: %w", relative, err)
	}
	if err := transport.WriteFile(ctx, endpoint, share, relative, data, entry.Hash, entry.Metadata, vec); err != nil {
		return fmt.Errorf("write %q to peer: %w", relative, err)
	}
	return nil
}

func applyLocalDelete(ctx context.Context, share, folderID, root, relative string, vec vector.Vector) error {
	return withFolderLock(ctx, share, func() error {
		if err := apply.Delete(root, relative); err != nil {
			return err
		}
		return commitLocalEntry(folderID, relative, index.Entry{Version: vec, Deleted: true, DeletedAt: time.Now().UTC()})
	})
}

func readShareFile(root, relative string) ([]byte, error) {
	file, err := sharepath.OpenRegular(root, relative)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

// reuseLocal asks whether some other locally tracked file already holds the
// bytes a pull needs, copying it in place of a wire transfer. It searches
// local's own index, which is this installation's authoritative record of
// what content it currently holds.
func reuseLocal(ctx context.Context, share, folderID, root, relative string, vec vector.Vector, local index.Index) (bool, error) {
	offered := local.Entries[relative]
	for source, entry := range local.Entries {
		if entry.Deleted || entry.Hash != offered.Hash {
			continue
		}
		err := withFolderLock(ctx, share, func() error {
			if err := apply.Reuse(root, relative, source, offered.Hash, offered.Metadata); err != nil {
				return err
			}
			return commitLocalEntry(folderID, relative, index.Entry{Version: vec, Hash: offered.Hash, Metadata: offered.Metadata})
		})
		if err != nil {
			if errors.Is(err, apply.ErrReuseMismatch) {
				continue
			}
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func scanShare(path string, previous index.Index, ignore []string, localIdentity string) (index.Index, error) {
	result, err := scan.Reconcile(path, previous, ignore, localIdentity)
	if err != nil {
		return index.Index{}, fmt.Errorf("scan share: %w", err)
	}
	return result.Index, nil
}

func remoteIndexFromListing(remoteID string, files []transport.PeerFile) index.Index {
	idx := index.New(remoteID)
	for _, file := range files {
		switch {
		case file.Directory:
			idx.Directories[file.Path] = file.Metadata
		case file.Deleted:
			idx.Entries[file.Path] = index.Entry{Version: file.Version, Deleted: true, DeletedAt: file.DeletedAt}
		default:
			idx.Entries[file.Path] = index.Entry{Version: file.Version, Hash: file.Hash, Size: file.Size, Metadata: file.Metadata}
		}
	}
	return idx
}

func findProvider(ctx context.Context, cfg config.Config, name string) (string, transport.Endpoint, error) {
	providers := make([]string, 0, 1)
	endpoints := make(map[string]transport.Endpoint)
	peerNames := sortedKeys(cfg.Peers)
	if bound, ok := cfg.BoundPeer(name); ok {
		peerNames = []string{bound}
	}
	for _, peerName := range peerNames {
		endpoint, err := peerEndpoint(ctx, cfg, peerName)
		if err != nil {
			return "", transport.Endpoint{}, err
		}
		shares, err := transport.ListShares(ctx, endpoint)
		if err != nil {
			return "", transport.Endpoint{}, fmt.Errorf("peer %q unreachable: %w", peerName, err)
		}
		if contains(shares, name) {
			providers = append(providers, peerName)
			endpoints[peerName] = endpoint
		}
	}
	if len(providers) == 0 {
		return "", transport.Endpoint{}, fmt.Errorf("no peer offers folder %q", name)
	}
	if len(providers) != 1 {
		return "", transport.Endpoint{}, fmt.Errorf("multiple peers offer folder %q", name)
	}
	return providers[0], endpoints[providers[0]], nil
}

func isTransportError(err error) bool {
	return transport.IsError(err)
}
