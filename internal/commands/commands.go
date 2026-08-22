package commands

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"l2syncd/internal/config"
	"l2syncd/internal/preflight"
)

const (
	exitOK      = 0
	exitError   = 1
	exitInvalid = 2
)

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printUsage(stdout)
		return exitOK
	}

	cfg, err := config.Load()
	if err != nil && !errors.Is(err, config.ErrNotFound) {
		fmt.Fprintf(stderr, "l2sync: invalid config: %v\n", err)
		return exitInvalid
	}
	if errors.Is(err, config.ErrNotFound) {
		cfg = config.New()
	}
	if err := preflight.Check(cfg); err != nil {
		fmt.Fprintf(stderr, "l2sync: preflight failed: %v\n", err)
		return exitInvalid
	}

	switch args[0] {
	case "add":
		return add(cfg, args[1:], stderr)
	case "rm":
		return remove(cfg, args[1:], stderr)
	case "list":
		return list(cfg, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "l2sync: command %q is not implemented yet\n", args[0])
		printUsage(stderr)
		return exitError
	}
}

func add(cfg config.Config, args []string, stderr io.Writer) int {
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(stderr, "usage: l2sync add <directory> [name]")
		return exitError
	}
	path, err := filepath.Abs(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve share path: %v\n", err)
		return exitError
	}
	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: share %q: %v\n", args[0], err)
		return exitError
	}
	if !info.IsDir() {
		fmt.Fprintf(stderr, "l2sync: share %q is not a directory\n", args[0])
		return exitError
	}

	name := filepath.Base(path)
	if len(args) == 2 {
		name = args[1]
	}
	if name == "" || name == "." || name == string(filepath.Separator) {
		fmt.Fprintln(stderr, "l2sync: share name must not be empty")
		return exitError
	}
	if _, exists := cfg.Shares[name]; exists {
		fmt.Fprintf(stderr, "l2sync: share %q already exists\n", name)
		return exitError
	}
	marker := filepath.Join(path, ".l2sync")
	if err := os.Mkdir(marker, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		fmt.Fprintf(stderr, "l2sync: create share marker: %v\n", err)
		return exitError
	}
	cfg.Shares[name] = config.Share{Local: path}
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(stderr, "l2sync: save config: %v\n", err)
		return exitError
	}
	return exitOK
}

func remove(cfg config.Config, args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: l2sync rm <name>")
		return exitError
	}
	if _, exists := cfg.Shares[args[0]]; !exists {
		fmt.Fprintf(stderr, "l2sync: share %q not found\n", args[0])
		return exitError
	}
	delete(cfg.Shares, args[0])
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(stderr, "l2sync: save config: %v\n", err)
		return exitError
	}
	return exitOK
}

func list(cfg config.Config, stdout, stderr io.Writer) int {
	shareNames := sortedKeys(cfg.Shares)
	for _, name := range shareNames {
		share := cfg.Shares[name]
		fmt.Fprintf(stdout, "share %s %s\n", name, share.Local)
	}
	mountNames := sortedKeys(cfg.Mounts)
	for _, name := range mountNames {
		mount := cfg.Mounts[name]
		fmt.Fprintf(stdout, "mount %s peer=%s local=%s\n", name, mount.Peer, mount.Local)
	}
	return exitOK
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: l2sync <command> [arguments]")
	fmt.Fprintln(w, "commands: add, rm, list, status, join, run")
}
