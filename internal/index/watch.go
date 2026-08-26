//go:build linux

package index

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"l2syncd/internal/config"
)

const (
	watchStatusFilename = "watch-status.json"
	watchTemporaryName  = ".watch-status-*.json"
)

// WatchCondition records why one folder is currently running scan-only.
type WatchCondition struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Limit  int    `json:"limit,omitempty"`
	Sysctl string `json:"sysctl"`
}

func LoadWatchConditions() (map[string]WatchCondition, error) {
	path, err := watchStatusPath()
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return make(map[string]WatchCondition), nil
		}
		return nil, fmt.Errorf("open watch status: %w", err)
	}
	defer file.Close()
	conditions := make(map[string]WatchCondition)
	if err := json.NewDecoder(file).Decode(&conditions); err != nil {
		return nil, fmt.Errorf("decode watch status: %w", err)
	}
	return conditions, nil
}

func SaveWatchConditions(conditions map[string]WatchCondition) error {
	path, err := watchStatusPath()
	if err != nil {
		return err
	}
	return atomicWriteJSON(path, conditions)
}

func watchStatusPath() (string, error) {
	// Locks and l2sync.log stay at the state-directory top level alongside
	// this file; only per-folder indexes move under index/ (concept.md 7).
	directory, err := config.StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, watchStatusFilename), nil
}
