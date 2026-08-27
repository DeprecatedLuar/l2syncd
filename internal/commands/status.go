//go:build linux

package commands

import (
	"context"
	"errors"
	"fmt"
	"io"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/index"
	"l2syncd/internal/logging"
	"l2syncd/internal/metadata"
	"l2syncd/internal/preflight"
	"l2syncd/internal/scan"
)

const (
	statusExitOK      = 0
	statusExitError   = 1
	statusExitInvalid = 2
)

func Status(stdout, stderr io.Writer) int {
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return statusExitInvalid
	}
	for _, name := range sortedKeys(cfg.Shared) {
		if err := printStatus(stdout, name, cfg.Shared[name].Path); err != nil {
			fmt.Fprintf(stderr, "l2sync: status %q: %v\n", name, err)
			return statusExitError
		}
	}
	conditions, err := index.LoadWatchConditions()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: status watch conditions: %v\n", err)
		return statusExitError
	}
	for _, name := range sortedKeys(conditions) {
		condition := conditions[name]
		limit := "unknown"
		if condition.Limit > 0 {
			limit = fmt.Sprint(condition.Limit)
		}
		if _, err := fmt.Fprintf(stdout, "scan-only %s %s; limit %s (%s)\n", name, condition.Reason, limit, condition.Sysctl); err != nil {
			fmt.Fprintf(stderr, "l2sync: write status: %v\n", err)
			return statusExitError
		}
	}
	return statusExitOK
}

// IndexCommit is the hidden `l2sync index commit` subcommand, renamed from
// `baseline commit` (concept.md 8). It remains undocumented and unlisted.
func IndexCommit(args []string, stderr io.Writer) int {
	commitLogger = logging.NewLogger(stderr, "commit")
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: l2sync index commit <share>")
		return statusExitError
	}
	err := withConfigLocked(context.Background(), func(cfg *config.Config) error {
		folder, found := cfg.Shared[args[0]]
		if !found {
			return fmt.Errorf("share %q not found", args[0])
		}
		marker, err := guard.ReadMarker(folder.Path)
		if err != nil {
			return fmt.Errorf("read marker: %w", err)
		}
		localIdentity, err := localFingerprint()
		if err != nil {
			return err
		}
		previous, err := loadIndex(marker.ID)
		if err != nil {
			return fmt.Errorf("load index: %w", err)
		}
		result, err := scan.Reconcile(folder.Path, previous, marker.Ignore, localIdentity)
		if err != nil {
			return fmt.Errorf("scan folder: %w", err)
		}
		if err := index.Save(result.Index); err != nil {
			commitLogger.Error("index commit failed", "folder", args[0], "stage", "save", "error", err)
			return fmt.Errorf("save index: %w", err)
		}
		commitLogger.Info("index committed", "folder", args[0], "entries", len(result.Index.Entries))
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: commit index: %v\n", err)
		if errors.Is(err, errInvalidConfig) {
			return statusExitInvalid
		}
		return statusExitError
	}
	return statusExitOK
}

func printStatus(stdout io.Writer, name, path string) error {
	marker, err := guard.ReadMarker(path)
	if err != nil {
		return err
	}
	previous, err := loadIndex(marker.ID)
	if err != nil {
		return err
	}
	localIdentity, err := localFingerprint()
	if err != nil {
		return err
	}
	result, err := scan.Reconcile(path, previous, marker.Ignore, localIdentity)
	if err != nil {
		return err
	}
	for _, change := range result.Changes {
		if _, err := fmt.Fprintf(stdout, "%s %s %s\n", change.Kind, name, change.Path); err != nil {
			return fmt.Errorf("write status: %w", err)
		}
	}
	for _, skipped := range result.Skipped {
		if _, err := fmt.Fprintf(stdout, "skipped %s %s\n", name, skipped); err != nil {
			return fmt.Errorf("write status: %w", err)
		}
	}
	return nil
}

// loadIndex loads folder id's index, treating a missing file as an empty
// index rather than an error: most callers only care about current state
// and already handle "no index yet" as the natural starting point.
func loadIndex(id string) (index.Index, error) {
	idx, err := index.Load(id)
	if errors.Is(err, index.ErrNotFound) {
		return idx, nil
	}
	return idx, err
}

// commitLocalEntry is the single index-commit function every mutating path
// uses to persist the result of a local write, a peer-driven write, a
// content reuse, or a vector-only merge (implementation-plan.md Phase C).
func commitLocalEntry(folderID, path string, entry index.Entry) error {
	idx, err := loadIndex(folderID)
	if err != nil {
		return fmt.Errorf("load index: %w", err)
	}
	idx.Entries[path] = entry
	return index.Save(idx)
}

// commitDirectory persists a directory's manifest into folder id's index.
func commitDirectory(folderID, path string, manifest metadata.Manifest) error {
	idx, err := loadIndex(folderID)
	if err != nil {
		return fmt.Errorf("load index: %w", err)
	}
	idx.Directories[path] = manifest
	return index.Save(idx)
}

// removeDirectoryEntry drops a trashed directory's manifest from folder id's
// index. Directories carry no tombstone (concept.md 7): removal is simply
// dropping the entry, not recording an absence.
func removeDirectoryEntry(folderID, path string) error {
	idx, err := loadIndex(folderID)
	if err != nil {
		return fmt.Errorf("load index: %w", err)
	}
	delete(idx.Directories, path)
	return index.Save(idx)
}
