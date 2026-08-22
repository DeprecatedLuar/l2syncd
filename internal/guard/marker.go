//go:build linux

package guard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	markerFilename = ".l2sync"
	markerMode     = 0o600
)

// Marker is the identity and local scan policy for one managed folder.
type Marker struct {
	Name   string   `toml:"name"`
	Ignore []string `toml:"ignore"`
}

func MarkerPath(folder string) string { return filepath.Join(folder, markerFilename) }

// ReadMarker validates an existing folder marker. It never creates or repairs it.
func ReadMarker(folder string) (Marker, error) {
	path := MarkerPath(folder)
	var marker Marker
	if _, err := toml.DecodeFile(path, &marker); err != nil {
		return Marker{}, fmt.Errorf("read marker %s: %w", path, err)
	}
	if strings.TrimSpace(marker.Name) == "" {
		return Marker{}, errors.New("marker name is empty")
	}
	return marker, nil
}

// WriteMarker registers a folder identity. Registration is the only operation
// permitted to create this file.
func WriteMarker(folder string, marker Marker) error {
	if strings.TrimSpace(marker.Name) == "" {
		return errors.New("marker name is empty")
	}
	temporary, err := os.CreateTemp(folder, ".l2sync-marker-*")
	if err != nil {
		return fmt.Errorf("create marker temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(markerMode); err != nil {
		temporary.Close()
		return fmt.Errorf("set marker permissions: %w", err)
	}
	if err := toml.NewEncoder(temporary).Encode(marker); err != nil {
		temporary.Close()
		return fmt.Errorf("encode marker: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync marker: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close marker: %w", err)
	}
	if err := os.Rename(temporaryName, MarkerPath(folder)); err != nil {
		return fmt.Errorf("install marker: %w", err)
	}
	return nil
}
