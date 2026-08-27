//go:build linux

// Package index persists per-folder causality state: version vectors and
// deletion tombstones. It replaces internal/state, whose Baseline recorded
// an agreed snapshot rather than causality (concept.md 4.2, 7). The type
// name change is deliberate: this is not a smaller baseline, it is a
// different thing.
package index

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/metadata"
	"l2syncd/internal/vector"
)

const (
	version       = 3
	indexSubdir   = "index"
	fileExtension = ".json"
	directoryMode = 0o700
	fileMode      = 0o600
	temporaryName = ".index-*.json"
)

// ErrNotFound is returned by Load alongside a fresh, empty Index when no
// index file exists yet for the given folder id.
var ErrNotFound = errors.New("index does not exist")

// Entry is one path's causality record. A live entry carries content and
// metadata; a tombstone (Deleted true) carries neither, only the vector and
// the deletion time (concept.md 4.2, 7).
type Entry struct {
	Version   vector.Vector     `json:"version"`
	Deleted   bool              `json:"deleted"`
	DeletedAt time.Time         `json:"deleted_at"`
	Ino       uint64            `json:"ino,omitempty"`
	Ctime     time.Time         `json:"ctime"`
	Size      int64             `json:"size,omitempty"`
	Hash      string            `json:"hash,omitempty"`
	Metadata  metadata.Manifest `json:"metadata"`
}

// Index is one folder's complete causality record, keyed by folder id
// (5.9), never by name: the name is a local label and can change without
// orphaning the folder's history.
type Index struct {
	Version      int                          `json:"version"`
	ID           string                       `json:"id"`
	Entries      map[string]Entry             `json:"entries"`
	Directories  map[string]metadata.Manifest `json:"directories,omitempty"`
	Acknowledged map[string]vector.Vector     `json:"acknowledged,omitempty"`
}

// New returns an empty version-3 index for folder id. It does not validate
// id or touch disk; Save and Path do.
func New(id string) Index {
	return Index{
		Version:      version,
		ID:           id,
		Entries:      make(map[string]Entry),
		Directories:  make(map[string]metadata.Manifest),
		Acknowledged: make(map[string]vector.Vector),
	}
}

// Load reads folder id's index. A missing file returns a fresh empty index
// alongside ErrNotFound, matching the prior baseline's convention so
// callers that already handle "no state yet" keep working unchanged. There
// is no migration path (concept.md 7): a file present under an earlier
// version is a hard error naming the file, never silently converted.
func Load(id string) (Index, error) {
	path, err := Path(id)
	if err != nil {
		return Index{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return New(id), ErrNotFound
		}
		return Index{}, fmt.Errorf("open index: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(file)
	if err != nil {
		return Index{}, fmt.Errorf("read index: %w", err)
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(contents, &header); err != nil {
		return Index{}, fmt.Errorf("decode index: %w", err)
	}
	if header.Version != version {
		return Index{}, fmt.Errorf("index %s has unsupported version %d (this installation understands version %d); delete this file and re-pair the folder, there is no migration from an earlier version", path, header.Version, version)
	}
	var idx Index
	if err := json.Unmarshal(contents, &idx); err != nil {
		return Index{}, fmt.Errorf("decode index: %w", err)
	}
	if idx.Entries == nil {
		idx.Entries = make(map[string]Entry)
	}
	if idx.Directories == nil {
		idx.Directories = make(map[string]metadata.Manifest)
	}
	if idx.Acknowledged == nil {
		idx.Acknowledged = make(map[string]vector.Vector)
	}
	return idx, nil
}

// Save atomically writes idx to its folder-id-keyed path.
func Save(idx Index) error {
	if idx.Version != version {
		return fmt.Errorf("cannot save index with unsupported version %d (expected %d)", idx.Version, version)
	}
	if err := guard.ValidateMarkerID(idx.ID); err != nil {
		return fmt.Errorf("cannot save index: %w", err)
	}
	path, err := Path(idx.ID)
	if err != nil {
		return err
	}
	return atomicWriteJSON(path, idx)
}

// Path resolves the on-disk location of folder id's index:
// <state dir>/index/<id>.json (concept.md 7).
func Path(id string) (string, error) {
	if err := guard.ValidateMarkerID(id); err != nil {
		return "", fmt.Errorf("invalid folder id %q: %w", id, err)
	}
	directory, err := config.StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, indexSubdir, id+fileExtension), nil
}

// GlobalVector returns the component-wise maximum of every entry's version
// vector in idx: the smallest vector that dominates everything idx
// currently records, live or tombstoned. After a cycle in which every path
// has converged between two replicas, this is exactly the vector the other
// replica is now known to have reached too, which is what a caller records
// as that member's acknowledgment (concept.md 4.2 "Tombstone lifetime").
func GlobalVector(idx Index) vector.Vector {
	var result vector.Vector
	for _, entry := range idx.Entries {
		result = vector.Merge(result, entry.Version)
	}
	return result
}

// Acknowledge records that member's confirmed knowledge for this folder has
// reached at least vec, then prunes every tombstone that members (the
// folder's complete known membership) now collectively dominate. vec is
// cloned so the caller's own copy is never aliased into the index.
func Acknowledge(idx Index, member string, vec vector.Vector, members []string) Index {
	if idx.Acknowledged == nil {
		idx.Acknowledged = make(map[string]vector.Vector)
	}
	idx.Acknowledged[member] = vector.Clone(vec)
	return Prune(idx, members)
}

// Prune removes every tombstone whose vector every member in members has
// acknowledged (concept.md 4.2 "Tombstone lifetime"). Pruning is lazy and
// always optional: an absent member, or one whose acknowledged vector does
// not dominate a given tombstone, leaves that tombstone untouched. Nothing
// here consults elapsed time; a tombstone with no members to check against
// is retained, never guessed away.
func Prune(idx Index, members []string) Index {
	if len(members) == 0 {
		return idx
	}
	for path, entry := range idx.Entries {
		if !entry.Deleted {
			continue
		}
		if allAcknowledge(idx.Acknowledged, members, entry.Version) {
			delete(idx.Entries, path)
		}
	}
	return idx
}

// allAcknowledge reports whether every member's acknowledged vector
// dominates target: target's knowledge is fully contained within each
// member's, i.e. never causally ahead of it.
func allAcknowledge(acknowledged map[string]vector.Vector, members []string, target vector.Vector) bool {
	for _, member := range members {
		bound, ok := acknowledged[member]
		if !ok {
			return false
		}
		switch vector.Compare(target, bound) {
		case vector.Equal, vector.Lesser:
		default:
			return false
		}
	}
	return true
}

// atomicWriteJSON writes value as JSON to path via a same-directory temp
// file, fsyncing the file and its parent directory before the rename
// becomes visible.
func atomicWriteJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), directoryMode); err != nil {
		return fmt.Errorf("create index directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), temporaryName)
	if err != nil {
		return fmt.Errorf("create temporary index file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(fileMode); err != nil {
		temporary.Close()
		return fmt.Errorf("set index file permissions: %w", err)
	}
	if err := json.NewEncoder(temporary).Encode(value); err != nil {
		temporary.Close()
		return fmt.Errorf("encode index file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync index file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary index file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace index file: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open index directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync index directory: %w", err)
	}
	return nil
}
