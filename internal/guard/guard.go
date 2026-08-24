//go:build linux

// Package guard contains the checks that must hold before a share is scanned
// or modified.
package guard

import (
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	fuseMagic       = 0x65735546
	defaultRatio    = 0.20
	defaultAbsFloor = 10
)

// Filesystem rejects FUSE-backed shares after resolving the root path.
func Filesystem(root string) error {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve share root: %w", err)
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(resolved, &stat); err != nil {
		return fmt.Errorf("stat filesystem: %w", err)
	}
	if uint64(stat.Type) == fuseMagic {
		return fmt.Errorf("FUSE filesystems are not supported")
	}
	return nil
}

// Symlinks returns symlink paths below root without following them.
func Symlinks(root string) ([]string, error) {
	paths := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return fmt.Errorf("make symlink path relative: %w", err)
			}
			paths = append(paths, filepath.ToSlash(relative))
			if entry.IsDir() {
				return filepath.SkipDir
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk symlinks: %w", err)
	}
	return paths, nil
}

// DeleteThreshold reports whether local deletions exceed the safety limit.
func DeleteThreshold(deletes, total int) bool {
	limit := math.Max(float64(defaultAbsFloor), math.Ceil(defaultRatio*float64(total)))
	return float64(deletes) > limit
}

// DefaultIgnore reports whether a path component is always ignored.
func DefaultIgnore(name string) bool {
	switch name {
	case ".git", ".svn", ".hg", "node_modules", ".DS_Store", "Thumbs.db", ".l2sync-trash", ".l2sync":
		return true
	default:
		return strings.HasSuffix(name, ".swp") || strings.HasPrefix(name, ".#") || strings.Contains(name, ".l2sync-conflict-")
	}
}

// DefaultIgnorePath reports whether any component of a slash-separated path is
// always ignored. The scan layer and the watch layer share this predicate so a
// path the scanner skips can never mark the tree dirty.
func DefaultIgnorePath(path string) bool {
	for part := range strings.SplitSeq(path, "/") {
		if DefaultIgnore(part) {
			return true
		}
	}
	return false
}
