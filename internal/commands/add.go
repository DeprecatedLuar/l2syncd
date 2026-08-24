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
	"l2syncd/internal/sharename"
)

const (
	addExitOK      = 0
	addExitError   = 1
	addExitInvalid = 2
)

func add(args []string, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: l2sync add <name> <path>")
		return addExitError
	}
	name := strings.ToLower(args[0])
	if err := sharename.Validate(name); err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return addExitError
	}
	path, err := filepath.Abs(args[1])
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve folder path: %v\n", err)
		return addExitError
	}
	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: folder %q: %v\n", args[1], err)
		return addExitError
	}
	if !info.IsDir() {
		fmt.Fprintf(stderr, "l2sync: folder %q is not a directory\n", args[1])
		return addExitError
	}
	if err := guard.Filesystem(path); err != nil {
		fmt.Fprintf(stderr, "l2sync: folder filesystem: %v\n", err)
		return addExitError
	}
	if err := withConfigLocked(context.Background(), func(current *config.Config) error {
		if _, exists := current.Shared[name]; exists {
			return fmt.Errorf("folder %q already exists", name)
		}
		if _, exists := current.Remote[name]; exists {
			return fmt.Errorf("folder %q already exists as remote", name)
		}
		markerCreated, err := prepareJoinMarker(path, name)
		if err != nil {
			return fmt.Errorf("write folder marker: %w", err)
		}
		current.Shared[name] = config.Folder{Path: path}
		saveErr := saveConfig(*current)
		installed := saveErr == nil || config.WasInstalled(saveErr)
		if saveErr != nil {
			if markerCreated && !installed {
				if removeErr := os.Remove(guard.MarkerPath(path)); removeErr != nil {
					return errors.Join(saveErr, fmt.Errorf("remove newly created marker: %w", removeErr))
				}
			}
			return saveErr
		}
		return nil
	}); err != nil {
		fmt.Fprintf(stderr, "l2sync: save config: %v\n", err)
		if errors.Is(err, errInvalidConfig) {
			return addExitInvalid
		}
		return addExitError
	}
	return addExitOK
}

// Add registers a local shared directory.
func Add(args []string, stderr io.Writer) int {
	return add(args, stderr)
}
