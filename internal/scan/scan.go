//go:build linux

// Package scan compares a share tree with its saved baseline.
package scan

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"l2syncd/internal/guard"
	"l2syncd/internal/metadata"
	"l2syncd/internal/sharepath"
	"l2syncd/internal/state"
)

var afterScanOpen = func(string) {}

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

// ListedFile is one regular file or directory in a peer tree listing.
type ListedFile struct {
	Path      string
	Size      int64
	Hash      string
	Metadata  metadata.Manifest
	Directory bool
}

// ListFiles returns non-ignored regular files and directories with complete
// portable metadata; regular file bytes are hashed with SHA-256.
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
		if entry.IsDir() {
			opened, err := sharepath.OpenDirectory(root, relative)
			if err != nil {
				return err
			}
			manifest, _, err := metadata.CaptureFile(opened, false)
			if err != nil {
				return closeOpened(opened, err)
			}
			if err := opened.Close(); err != nil {
				return err
			}
			files = append(files, ListedFile{Path: relative, Metadata: manifest, Directory: true})
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		opened, err := sharepath.OpenRegular(root, relative)
		if err != nil {
			return err
		}
		afterScanOpen(relative)
		manifest, info, err := metadata.CaptureFile(opened, true)
		if err != nil {
			return closeOpened(opened, err)
		}
		fileHash, err := hashOpened(opened, info)
		if err != nil {
			return closeOpened(opened, err)
		}
		if err := sharepath.RevalidateRegular(root, relative, info); err != nil {
			return closeOpened(opened, err)
		}
		if err := opened.Close(); err != nil {
			return err
		}
		files = append(files, ListedFile{Path: relative, Size: info.Size(), Hash: fileHash, Metadata: manifest})
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
			opened, err := sharepath.OpenDirectory(root, relative)
			if err != nil {
				return err
			}
			manifest, _, err := metadata.CaptureFile(opened, false)
			if err != nil {
				return closeOpened(opened, err)
			}
			if err := opened.Close(); err != nil {
				return err
			}
			snapshot.Directories[relative] = manifest
			return nil
		}
		if !entry.Type().IsRegular() {
			skipped = append(skipped, relative)
			return nil
		}
		opened, err := sharepath.OpenRegular(root, relative)
		if err != nil {
			return err
		}
		afterScanOpen(relative)
		file, info, err := openedFileState(opened)
		if err != nil {
			return closeOpened(opened, err)
		}
		previous, found := baseline.Files[relative]
		if found && sameMetadata(file, previous) {
			file.Hash = previous.Hash
		} else {
			file.Hash, err = hashOpened(opened, info)
			if err != nil {
				return closeOpened(opened, err)
			}
			if !found || file.Hash != previous.Hash || previous.MetadataKnown && !metadata.Equal(file.Metadata, previous.Metadata) {
				kind := Modified
				if !found {
					kind = Added
				}
				changes = append(changes, Change{Path: relative, Kind: kind})
			}
		}
		if err := sharepath.RevalidateRegular(root, relative, info); err != nil {
			return closeOpened(opened, err)
		}
		if err := opened.Close(); err != nil {
			return err
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

func openedFileState(file *os.File) (state.File, os.FileInfo, error) {
	manifest, info, err := metadata.CaptureFile(file, true)
	if err != nil {
		return state.File{}, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return state.File{}, nil, fmt.Errorf("read inode for %q", file.Name())
	}
	return state.File{Ino: stat.Ino, Ctime: time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec).UTC(), Size: info.Size(), Metadata: manifest, MetadataKnown: true}, info, nil
}

func sameMetadata(current, previous state.File) bool {
	return current.Ino == previous.Ino && current.Size == previous.Size && current.Ctime.Equal(previous.Ctime)
}

func hashOpened(file *os.File, before os.FileInfo) (string, error) {
	digest, err := sharepath.Hash(file)
	if err != nil {
		return "", err
	}
	after, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("revalidate hashed file %q: %w", file.Name(), err)
	}
	if !sharepath.SameState(before, after) {
		return "", fmt.Errorf("file %q changed while hashing", file.Name())
	}
	return digest, nil
}

func closeOpened(file *os.File, err error) error {
	return errors.Join(err, file.Close())
}
