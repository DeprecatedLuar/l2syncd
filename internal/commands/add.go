//go:build linux

package commands

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/preflight"
)

const (
	addExitOK      = 0
	addExitError   = 1
	addExitInvalid = 2
)

func add(cfg config.Config, args []string, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: l2sync add <name> <path>")
		return addExitError
	}
	name := strings.ToLower(args[0])
	if err := validateShareName(name); err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return addExitError
	}
	if _, exists := cfg.Shared[name]; exists {
		fmt.Fprintf(stderr, "l2sync: folder %q already exists\n", name)
		return addExitError
	}
	if _, exists := cfg.Remote[name]; exists {
		fmt.Fprintf(stderr, "l2sync: folder %q already exists as remote\n", name)
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
	if err := guard.WriteMarker(path, guard.Marker{Name: name}); err != nil {
		fmt.Fprintf(stderr, "l2sync: write folder marker: %v\n", err)
		return addExitError
	}
	cfg.Shared[name] = path
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(stderr, "l2sync: save config: %v\n", err)
		return addExitError
	}
	return addExitOK
}

func validateShareName(name string) error {
	if name == "" {
		return errors.New("folder name must not be empty")
	}
	for _, character := range name {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			if character > unicode.MaxASCII {
				return errors.New("folder name must contain only ASCII letters, numbers, hyphens, or underscores")
			}
			continue
		}
		if character != '-' && character != '_' {
			return errors.New("folder name must contain only ASCII letters, numbers, hyphens, or underscores")
		}
	}
	return nil
}

// Add registers a local shared directory.
func Add(args []string, stderr io.Writer) int {
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return addExitInvalid
	}
	return add(cfg, args, stderr)
}
