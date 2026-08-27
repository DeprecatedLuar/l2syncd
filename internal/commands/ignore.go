//go:build linux

package commands

import (
	"context"
	"fmt"
	"io"
	"sort"

	"l2syncd/internal/guard"
	"l2syncd/internal/preflight"
)

const (
	ignoreExitOK      = 0
	ignoreExitError   = 1
	ignoreExitInvalid = 2
)

// Ignore manages a folder's local ignore patterns (concept.md 5.8). Patterns
// live in the folder's .l2sync marker and are never sent to a peer. It never
// creates or repairs a missing marker: only add and join may do that.
func Ignore(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: l2sync ignore <name> [add|rm <pattern>...]")
		return ignoreExitError
	}
	name := args[0]
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return ignoreExitInvalid
	}
	folder, exists := cfg.Lookup(name)
	if !exists {
		fmt.Fprintf(stderr, "l2sync: folder %q not found\n", name)
		return ignoreExitError
	}

	rest := args[1:]
	if len(rest) == 0 {
		return ignoreList(folder.Path, stdout, stderr)
	}
	switch rest[0] {
	case "add":
		return ignoreEdit(name, folder.Path, rest[1:], addPatterns, stderr)
	case "rm", "remove":
		return ignoreEdit(name, folder.Path, rest[1:], removePatterns, stderr)
	default:
		fmt.Fprintf(stderr, "l2sync: unknown ignore command %q\n", rest[0])
		return ignoreExitError
	}
}

func ignoreList(path string, stdout, stderr io.Writer) int {
	marker, err := guard.ReadMarker(path)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return ignoreExitError
	}
	patterns := append([]string(nil), marker.Ignore...)
	sort.Strings(patterns)
	for _, pattern := range patterns {
		fmt.Fprintln(stdout, pattern)
	}
	return ignoreExitOK
}

// ignoreEdit reads the marker, applies transform under the folder's
// mutation lock, and writes the result back. The lock keeps this from
// racing a running cycle's own marker-adjacent scan.
func ignoreEdit(name, path string, args []string, transform func(existing, args []string) ([]string, error), stderr io.Writer) int {
	err := withFolderLock(context.Background(), name, func() error {
		marker, err := guard.ReadMarker(path)
		if err != nil {
			return err
		}
		updated, err := transform(marker.Ignore, args)
		if err != nil {
			return err
		}
		if _, err := guard.NewIgnore(updated); err != nil {
			return fmt.Errorf("invalid ignore pattern: %w", err)
		}
		marker.Ignore = updated
		return guard.WriteMarker(path, marker)
	})
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return ignoreExitError
	}
	return ignoreExitOK
}

func addPatterns(existing, args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no pattern supplied")
	}
	updated := append([]string(nil), existing...)
	for _, pattern := range args {
		if pattern == "" {
			return nil, fmt.Errorf("empty pattern")
		}
		if !containsPattern(updated, pattern) {
			updated = append(updated, pattern)
		}
	}
	return updated, nil
}

func removePatterns(existing, args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no pattern supplied")
	}
	remove := make(map[string]bool, len(args))
	for _, pattern := range args {
		remove[pattern] = true
	}
	updated := make([]string, 0, len(existing))
	for _, pattern := range existing {
		if !remove[pattern] {
			updated = append(updated, pattern)
		}
	}
	return updated, nil
}

func containsPattern(patterns []string, target string) bool {
	for _, pattern := range patterns {
		if pattern == target {
			return true
		}
	}
	return false
}
