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
	shareExitOK      = 0
	shareExitError   = 1
	shareExitInvalid = 2
)

func share(args []string, stderr io.Writer) int {
	name, rawPath, createMissing, err := parseSharePath(args)
	if err != nil {
		fmt.Fprintln(stderr, "usage: l2sync folder share <name> <path> [-p]")
		return shareExitError
	}
	name = strings.ToLower(name)
	if err := sharename.Validate(name); err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return shareExitError
	}
	path, err := filepath.Abs(rawPath)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve folder path: %v\n", err)
		return shareExitError
	}
	info, err := resolveFolderPath(path, rawPath, createMissing, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: folder %q: %v\n", rawPath, err)
		return shareExitError
	}
	if !info.IsDir() {
		fmt.Fprintf(stderr, "l2sync: folder %q is not a directory\n", rawPath)
		return shareExitError
	}
	if err := guard.Filesystem(path); err != nil {
		fmt.Fprintf(stderr, "l2sync: folder filesystem: %v\n", err)
		return shareExitError
	}
	if err := withConfigLocked(context.Background(), func(current *config.Config) error {
		if _, exists := current.Shared[name]; exists {
			return fmt.Errorf("folder %q already exists", name)
		}
		if _, exists := current.Remote[name]; exists {
			return fmt.Errorf("folder %q already exists as remote", name)
		}
		markerCreated, err := prepareAttachMarker(path, name, "")
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
			return shareExitInvalid
		}
		return shareExitError
	}
	return shareExitOK
}

// parseSharePath parses the <name> <path> [-p] arguments shared by share and
// attach: -p may appear anywhere among the arguments.
func parseSharePath(args []string) (name, path string, createMissing bool, err error) {
	var positional []string
	for _, arg := range args {
		if arg == "-p" {
			createMissing = true
			continue
		}
		positional = append(positional, arg)
	}
	if len(positional) != 2 {
		return "", "", false, fmt.Errorf("expected <name> <path>")
	}
	return positional[0], positional[1], createMissing, nil
}

// Share registers a local shared directory.
func Share(args []string, stderr io.Writer) int {
	return share(args, stderr)
}
