//go:build linux

package commands

import (
	"context"
	"errors"
	"fmt"
	"io"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/preflight"
	"l2syncd/internal/scan"
	"l2syncd/internal/state"
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
	conditions, err := state.LoadWatchConditions()
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

func BaselineCommit(args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: l2sync baseline commit <share>")
		return statusExitError
	}
	err := withConfigLocked(context.Background(), func(cfg *config.Config) error {
		folder, found := cfg.Shared[args[0]]
		if !found {
			return fmt.Errorf("share %q not found", args[0])
		}
		baseline, err := loadBaseline(args[0])
		if err != nil {
			return fmt.Errorf("load baseline: %w", err)
		}
		if baseline.HasUnknownMetadata() {
			return errors.New("baseline version 1 must be migrated by a successful sync cycle before manual baseline commit")
		}
		marker, err := guard.ReadMarker(folder.Path)
		if err != nil {
			return fmt.Errorf("read marker: %w", err)
		}
		return commitFolderBaseline(args[0], folder.Path, marker.Ignore)
	})
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: commit baseline: %v\n", err)
		if errors.Is(err, errInvalidConfig) {
			return statusExitInvalid
		}
		return statusExitError
	}
	return statusExitOK
}

func printStatus(stdout io.Writer, name, path string) error {
	baseline, err := loadBaseline(name)
	if err != nil {
		return err
	}
	marker, err := guard.ReadMarker(path)
	if err != nil {
		return err
	}
	result, err := scan.DetectWithIgnore(path, baseline, marker.Ignore)
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

func loadBaseline(share string) (state.Baseline, error) {
	baseline, err := state.Load(share)
	if errors.Is(err, state.ErrNotFound) {
		return baseline, nil
	}
	return baseline, err
}
