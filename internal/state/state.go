//go:build linux

// Package state persists the last agreed file baseline for a share.
package state

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
	"l2syncd/internal/metadata"
)

const (
	version       = 2
	fileExtension = ".json"
	directoryMode = 0o700
	fileMode      = 0o600
	temporaryName = ".baseline-*.json"
)

var ErrNotFound = errors.New("baseline does not exist")

type Baseline struct {
	Version     int                          `json:"version"`
	Files       map[string]File              `json:"files"`
	Directories map[string]metadata.Manifest `json:"directories,omitempty"`
}

type File struct {
	Ino           uint64            `json:"ino"`
	Ctime         time.Time         `json:"ctime"`
	Size          int64             `json:"size"`
	Hash          string            `json:"hash"`
	Metadata      metadata.Manifest `json:"metadata"`
	MetadataKnown bool              `json:"metadata_known"`
	LegacyMtime   time.Time         `json:"-"`
}

type legacyBaseline struct {
	Version int                   `json:"version"`
	Files   map[string]legacyFile `json:"files"`
}

type legacyFile struct {
	Ino   uint64    `json:"ino"`
	Mtime time.Time `json:"mtime"`
	Size  int64     `json:"size"`
	Hash  string    `json:"hash"`
}

func New() Baseline {
	return Baseline{Version: version, Files: make(map[string]File), Directories: make(map[string]metadata.Manifest)}
}

func Load(share string) (Baseline, error) {
	path, err := Path(share)
	if err != nil {
		return Baseline{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return New(), ErrNotFound
		}
		return Baseline{}, fmt.Errorf("open baseline: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(file)
	if err != nil {
		return Baseline{}, fmt.Errorf("read baseline: %w", err)
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(contents, &header); err != nil {
		return Baseline{}, fmt.Errorf("decode baseline: %w", err)
	}
	if header.Version == 1 {
		return loadLegacy(contents)
	}
	var baseline Baseline
	if err := json.Unmarshal(contents, &baseline); err != nil {
		return Baseline{}, fmt.Errorf("decode baseline: %w", err)
	}
	if baseline.Version != version {
		return Baseline{}, fmt.Errorf("unsupported baseline version %d", baseline.Version)
	}
	if baseline.Files == nil {
		baseline.Files = make(map[string]File)
	}
	if baseline.Directories == nil {
		baseline.Directories = make(map[string]metadata.Manifest)
	}
	return baseline, nil
}

func Save(share string, baseline Baseline) error {
	if baseline.Version != version {
		return fmt.Errorf("unsupported baseline version %d", baseline.Version)
	}
	for path, file := range baseline.Files {
		if !file.MetadataKnown {
			return fmt.Errorf("cannot save baseline with unknown metadata for %q", path)
		}
	}
	path, err := Path(share)
	if err != nil {
		return err
	}
	return atomicWriteJSON(path, temporaryName, baseline)
}

// atomicWriteJSON writes value as JSON to path via a same-directory temp
// file, fsyncing the file and its parent directory before the rename
// becomes visible.
func atomicWriteJSON(path, tempPattern string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), directoryMode); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), tempPattern)
	if err != nil {
		return fmt.Errorf("create temporary state file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(fileMode); err != nil {
		temporary.Close()
		return fmt.Errorf("set state file permissions: %w", err)
	}
	if err := json.NewEncoder(temporary).Encode(value); err != nil {
		temporary.Close()
		return fmt.Errorf("encode state file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync state file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary state file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

// HasUnknownMetadata reports whether baseline contains a legacy file whose
// agreed portable metadata is not represented in the version-1 schema.
func (baseline Baseline) HasUnknownMetadata() bool {
	for _, file := range baseline.Files {
		if !file.MetadataKnown {
			return true
		}
	}
	return false
}

func loadLegacy(contents []byte) (Baseline, error) {
	var legacy legacyBaseline
	if err := json.Unmarshal(contents, &legacy); err != nil {
		return Baseline{}, fmt.Errorf("decode version-1 baseline: %w", err)
	}
	baseline := New()
	for path, file := range legacy.Files {
		baseline.Files[path] = File{
			Ino:         file.Ino,
			Size:        file.Size,
			Hash:        file.Hash,
			LegacyMtime: file.Mtime,
		}
	}
	return baseline, nil
}

func Path(share string) (string, error) {
	if share == "" || share == "." || filepath.Base(share) != share {
		return "", fmt.Errorf("invalid share name %q", share)
	}
	directory, err := config.StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, share+fileExtension), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}
