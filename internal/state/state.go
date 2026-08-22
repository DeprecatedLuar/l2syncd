//go:build linux

// Package state persists the last agreed file baseline for a share.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"l2syncd/internal/config"
)

const (
	version       = 1
	fileExtension = ".json"
	directoryMode = 0o700
	fileMode      = 0o600
	temporaryName = ".baseline-*.json"
)

var ErrNotFound = errors.New("baseline does not exist")

type Baseline struct {
	Version int             `json:"version"`
	Files   map[string]File `json:"files"`
}

type File struct {
	Ino   uint64    `json:"ino"`
	Mtime time.Time `json:"mtime"`
	Size  int64     `json:"size"`
	Hash  string    `json:"hash"`
}

func New() Baseline {
	return Baseline{Version: version, Files: make(map[string]File)}
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
	var baseline Baseline
	if err := json.NewDecoder(file).Decode(&baseline); err != nil {
		return Baseline{}, fmt.Errorf("decode baseline: %w", err)
	}
	if baseline.Version != version {
		return Baseline{}, fmt.Errorf("unsupported baseline version %d", baseline.Version)
	}
	if baseline.Files == nil {
		baseline.Files = make(map[string]File)
	}
	return baseline, nil
}

func Save(share string, baseline Baseline) error {
	if baseline.Version != version {
		return fmt.Errorf("unsupported baseline version %d", baseline.Version)
	}
	path, err := Path(share)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), directoryMode); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), temporaryName)
	if err != nil {
		return fmt.Errorf("create temporary baseline: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(fileMode); err != nil {
		temporary.Close()
		return fmt.Errorf("set baseline permissions: %w", err)
	}
	if err := json.NewEncoder(temporary).Encode(baseline); err != nil {
		temporary.Close()
		return fmt.Errorf("encode baseline: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync baseline: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary baseline: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace baseline: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
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
