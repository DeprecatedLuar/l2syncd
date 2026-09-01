//go:build linux

// Package scan walks a share tree, confirms local changes against its saved
// index, and produces the listing offered to a peer.
package scan

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"l2syncd/internal/guard"
	"l2syncd/internal/index"
	"l2syncd/internal/metadata"
	"l2syncd/internal/sharepath"
	"l2syncd/internal/vector"
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

// Result is the outcome of reconciling a share's live tree against its
// previously saved index.
type Result struct {
	Changes []Change
	Index   index.Index
	Skipped []string
}

// ListedFile is one entry offered to a peer: a live regular file, a
// directory, or a tombstone. A tombstone (Deleted true) carries no content
// fields, matching how a deletion has no content in the index itself
// (concept.md 4.2).
type ListedFile struct {
	Path      string
	Size      int64
	Hash      string
	Metadata  metadata.Manifest
	Directory bool
	Deleted   bool
	DeletedAt time.Time
	Version   vector.Vector
}

// ListEntries projects an already-reconciled index into the flat listing
// format the peer wire protocol carries. It is pure: no filesystem access,
// no I/O.
func ListEntries(idx index.Index) []ListedFile {
	files := make([]ListedFile, 0, len(idx.Entries)+len(idx.Directories))
	for path, entry := range idx.Entries {
		if entry.Deleted {
			files = append(files, ListedFile{Path: path, Deleted: true, DeletedAt: entry.DeletedAt, Version: entry.Version})
			continue
		}
		files = append(files, ListedFile{Path: path, Size: entry.Size, Hash: entry.Hash, Metadata: entry.Metadata, Version: entry.Version})
	}
	for path, manifest := range idx.Directories {
		files = append(files, ListedFile{Path: path, Metadata: manifest, Directory: true})
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	return files
}

// Reconcile walks root and confirms local changes against previous,
// incrementing fingerprint's counter only for paths a confirmed local
// change touched (added, modified, or deleted) and never touching an
// unchanged entry's vector (implementation-plan.md Phase C). A file
// deletion becomes a tombstone, never a removed entry (concept.md 4.2).
func Reconcile(root string, previous index.Index, patterns []string, fingerprint string) (Result, error) {
	if fingerprint == "" {
		return Result{}, errors.New("local installation fingerprint is required")
	}
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
	gitignore := guard.NewGitIgnore(root)
	next := index.New(previous.ID)
	changes := make([]Change, 0)
	skipped := make([]string, 0)
	seen := make(map[string]bool)
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
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		gitIgnored, err := gitignore.Match(relative, entry.IsDir())
		if err != nil {
			return fmt.Errorf("match gitignore for %q: %w", relative, err)
		}
		if guard.DefaultIgnorePath(relative) || ignore.Match(relative, entry.IsDir()) || gitIgnored {
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
			next.Directories[relative] = manifest
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
		manifest, info, err := metadata.CaptureFile(opened, true)
		if err != nil {
			return closeOpened(opened, err)
		}
		ino, ctime, err := inoAndCtime(info)
		if err != nil {
			return closeOpened(opened, err)
		}
		previousEntry, found := previous.Entries[relative]
		reuseHash := found && !previousEntry.Deleted && previousEntry.Ino == ino && previousEntry.Ctime.Equal(ctime) && previousEntry.Size == info.Size()
		hash := previousEntry.Hash
		if !reuseHash {
			hash, err = hashOpened(opened, info)
			if err != nil {
				return closeOpened(opened, err)
			}
		}
		if err := sharepath.RevalidateRegular(root, relative, info); err != nil {
			return closeOpened(opened, err)
		}
		if err := opened.Close(); err != nil {
			return err
		}
		changed := !found || previousEntry.Deleted || hash != previousEntry.Hash || !metadata.Equal(manifest, previousEntry.Metadata)
		version := previousEntry.Version
		if changed {
			version = vector.Increment(previousEntry.Version, fingerprint)
			kind := Modified
			if !found || previousEntry.Deleted {
				kind = Added
			}
			changes = append(changes, Change{Path: relative, Kind: kind})
		}
		next.Entries[relative] = index.Entry{Version: version, Hash: hash, Size: info.Size(), Ino: ino, Ctime: ctime, Metadata: manifest}
		seen[relative] = true
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("walk share %q: %w", root, err)
	}
	for path, previousEntry := range previous.Entries {
		if seen[path] {
			continue
		}
		gitIgnored, err := gitignore.Match(path, false)
		if err != nil {
			return Result{}, fmt.Errorf("match gitignore for %q: %w", path, err)
		}
		if guard.DefaultIgnorePath(path) || ignore.Match(path, false) || gitIgnored {
			// A path that is now ignored (by any layer) is carried forward
			// unchanged rather than dropped or tombstoned. Dropping it would
			// leave it at an all-zero version vector; if a peer still holds
			// the entry with a non-zero vector, the peer's copy would read
			// as causally ahead and get pulled straight back
			// (concept.md 5.8).
			next.Entries[path] = previousEntry
			continue
		}
		if previousEntry.Deleted {
			next.Entries[path] = previousEntry
			continue
		}
		next.Entries[path] = index.Entry{Version: vector.Increment(previousEntry.Version, fingerprint), Deleted: true, DeletedAt: time.Now().UTC()}
		changes = append(changes, Change{Path: path, Kind: Deleted})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	sort.Strings(skipped)
	return Result{Changes: changes, Index: next, Skipped: skipped}, nil
}

func inoAndCtime(info os.FileInfo) (uint64, time.Time, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, time.Time{}, fmt.Errorf("read inode for %q", info.Name())
	}
	return stat.Ino, time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec).UTC(), nil
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
