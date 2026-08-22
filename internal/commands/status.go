//go:build linux

package commands

import (
	"errors"
	"fmt"
	"io"

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
		if err := printStatus(stdout, name, cfg.Shared[name]); err != nil {
			fmt.Fprintf(stderr, "l2sync: status %q: %v\n", name, err)
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
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return statusExitInvalid
	}
	path, found := cfg.Shared[args[0]]
	if !found {
		fmt.Fprintf(stderr, "l2sync: share %q not found\n", args[0])
		return statusExitError
	}
	baseline, err := loadBaseline(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: load baseline: %v\n", err)
		return statusExitError
	}
	marker, err := guard.ReadMarker(path)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: read marker: %v\n", err)
		return statusExitError
	}
	result, err := scan.DetectWithIgnore(path, baseline, marker.Ignore)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: scan share %q: %v\n", args[0], err)
		return statusExitError
	}
	if err := state.Save(args[0], result.Snapshot); err != nil {
		fmt.Fprintf(stderr, "l2sync: save baseline: %v\n", err)
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
