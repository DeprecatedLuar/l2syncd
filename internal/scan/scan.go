//go:build linux

// Package scan compares a share tree with its saved baseline.
package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"l2syncd/internal/guard"
	"l2syncd/internal/state"
)

type ChangeKind string

const (
	Added    ChangeKind = "added"
	Modified ChangeKind = "modified"
	Deleted  ChangeKind = "deleted"
)

type Change struct {
	Path string
	Kind ChangeKind
}

type Result struct {
	Changes  []Change
	Snapshot state.Baseline
	Skipped  []string
}

// ListedFile is the minimal metadata needed for a peer tree listing.
type ListedFile struct {
	Path string
	Size int64
}

// ListFiles returns regular, non-ignored files without hashing their content.
func ListFiles(root string, patterns []string) ([]ListedFile, error) {
	if _, err := guard.ReadMarker(root); err != nil {
		return nil, err
	}
	if err := guard.Filesystem(root); err != nil {
		return nil, err
	}
	ignore, err := guard.NewIgnore(patterns)
	if err != nil {
		return nil, err
	}
	files := make([]ListedFile, 0)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("make path relative: %w", err)
		}
		relative = filepath.ToSlash(relative)
		if relative == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if ignoredByDefault(relative) || ignore.Match(relative, entry.IsDir()) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat %q: %w", path, err)
		}
		files = append(files, ListedFile{Path: relative, Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list share %q: %w", root, err)
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	return files, nil
}

// Detect scans with the default local ignore policy.
func Detect(root string, baseline state.Baseline) ([]Change, state.Baseline, error) {
	result, err := DetectWithIgnore(root, baseline, nil)
	if err != nil {
		return nil, state.Baseline{}, err
	}
	return result.Changes, result.Snapshot, nil
}

// DetectWithIgnore scans a share while applying its local ignore patterns.
func DetectWithIgnore(root string, baseline state.Baseline, patterns []string) (Result, error) {
	if _, err := guard.ReadMarker(root); err != nil {
		return Result{}, err
	}
	if err := guard.Filesystem(root); err != nil {
		return Result{}, err
	}
	ignore, err := guard.NewIgnore(patterns)
	if err != nil {
		return Result{}, err
	}
	snapshot := state.New()
	changes := make([]Change, 0)
	skipped := make([]string, 0)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("make path relative: %w", err)
		}
		relative = filepath.ToSlash(relative)
		if relative == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			skipped = append(skipped, relative)
			return nil
		}
		if ignoredByDefault(relative) || ignore.Match(relative, entry.IsDir()) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		file, err := fileState(path)
		if err != nil {
			return err
		}
		previous, found := baseline.Files[relative]
		if found && sameMetadata(file, previous) {
			file.Hash = previous.Hash
		} else {
			file.Hash, err = hash(path)
			if err != nil {
				return err
			}
			if !found || file.Hash != previous.Hash || !sameMetadata(file, previous) {
				kind := Modified
				if !found {
					kind = Added
				}
				changes = append(changes, Change{Path: relative, Kind: kind})
			}
		}
		snapshot.Files[relative] = file
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("walk share %q: %w", root, err)
	}
	for path := range baseline.Files {
		if ignoredByDefault(path) || ignore.Match(path, false) {
			continue
		}
		if _, found := snapshot.Files[path]; !found {
			changes = append(changes, Change{Path: path, Kind: Deleted})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	sort.Strings(skipped)
	return Result{Changes: changes, Snapshot: snapshot, Skipped: skipped}, nil
}

func ignoredByDefault(relative string) bool {
	for _, part := range strings.Split(relative, "/") {
		if guard.DefaultIgnore(part) {
			return true
		}
	}
	return false
}

func fileState(path string) (state.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return state.File{}, fmt.Errorf("stat %q: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return state.File{}, fmt.Errorf("read inode for %q", path)
	}
	return state.File{Ino: stat.Ino, Mtime: info.ModTime().UTC(), Size: info.Size()}, nil
}

func sameMetadata(current, previous state.File) bool {
	return current.Ino == previous.Ino && current.Size == previous.Size && current.Mtime.Equal(previous.Mtime)
}

func hash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("hash %q: %w", path, err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
