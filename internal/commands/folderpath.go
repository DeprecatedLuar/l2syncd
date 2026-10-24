//go:build linux

package commands

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const createdFolderMode = 0o755

// resolveFolderPath stats path, which the caller already resolved to an
// absolute form; rawPath is the original argument, used only for error text.
// A missing path is created outright when createMissing is set (the -p
// flag); otherwise, on an interactive terminal, the user is prompted to
// create it, mirroring the rejoin-divergence prompt's non-interactive
// refusal (concept.md 8.1: never silently choose a default without a
// terminal to ask on). The returned cleanup removes, deepest first, only the
// directories this call created, and fails if any is not empty.
func resolveFolderPath(path, rawPath string, createMissing bool, stderr io.Writer) (os.FileInfo, func() error, error) {
	noCleanup := func() error { return nil }
	info, err := os.Stat(path)
	if err == nil {
		return info, noCleanup, nil
	}
	if !os.IsNotExist(err) {
		return nil, noCleanup, err
	}
	create := createMissing
	if !create {
		var promptErr error
		create, promptErr = promptCreateFolder(stderr, rawPath)
		if promptErr != nil {
			return nil, noCleanup, promptErr
		}
	}
	if !create {
		return nil, noCleanup, err
	}
	created, err := missingDirectories(path)
	if err != nil {
		return nil, noCleanup, err
	}
	if mkdirErr := os.MkdirAll(path, createdFolderMode); mkdirErr != nil {
		return nil, noCleanup, fmt.Errorf("create folder %q: %w", rawPath, mkdirErr)
	}
	cleanup := func() error {
		for _, directory := range created {
			if err := os.Remove(directory); err != nil {
				return fmt.Errorf("remove created folder %q: %w", directory, err)
			}
		}
		return nil
	}
	info, err = os.Stat(path)
	return info, cleanup, err
}

// missingDirectories lists path and each missing ancestor, deepest first.
func missingDirectories(path string) ([]string, error) {
	var missing []string
	for current := path; ; current = filepath.Dir(current) {
		_, err := os.Stat(current)
		if err == nil {
			return missing, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		missing = append(missing, current)
		if filepath.Dir(current) == current {
			return missing, nil
		}
	}
}

// promptCreateFolder asks whether to create a missing folder path. It never
// prompts when stdin is not a terminal, returning false so the caller falls
// back to its usual missing-path error.
func promptCreateFolder(stderr io.Writer, rawPath string) (bool, error) {
	info, statErr := os.Stdin.Stat()
	if statErr != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false, nil
	}
	fmt.Fprintf(stderr, "l2sync: folder %q does not exist. Create it? [y/N]: ", rawPath)
	reader := bufio.NewReader(os.Stdin)
	line, readErr := reader.ReadString('\n')
	if readErr != nil && line == "" {
		return false, nil
	}
	switch answer := strings.ToLower(strings.TrimSpace(line)); answer {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
