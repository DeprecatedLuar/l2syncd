//go:build linux

package guard

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	markerFilename = ".l2sync"
	markerMode     = 0o600
)

// Marker is the identity and local scan policy for one managed folder.
type Marker struct {
	ID     string   `toml:"id"`
	Name   string   `toml:"name"`
	Ignore []string `toml:"ignore"`
}

func MarkerPath(folder string) string { return filepath.Join(folder, markerFilename) }

var markerIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// NewMarkerID generates a fresh, immutable folder identity. Only `add` and
// `join` are permitted to call this: it is the sole source of new ids, and
// minting one anywhere else would let two unrelated folders that happen to
// share a name each generate their own id and disagree permanently.
func NewMarkerID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate marker id: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

// ValidateMarkerID reports whether id is a well-formed folder identity
// (concept.md 5.9). Exported so other packages that key state by folder id
// (internal/index) can validate it without duplicating the pattern.
func ValidateMarkerID(id string) error {
	if !markerIDPattern.MatchString(id) {
		return fmt.Errorf("marker id %q is not a valid identity", id)
	}
	return nil
}

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
	if strings.TrimSpace(marker.ID) == "" {
		return Marker{}, fmt.Errorf("marker %s has no id; re-register this folder with add or join", path)
	}
	if err := ValidateMarkerID(marker.ID); err != nil {
		return Marker{}, fmt.Errorf("marker %s: %w", path, err)
	}
	return marker, nil
}

// WriteMarker registers a folder identity. Registration is the only operation
// permitted to create this file.
func WriteMarker(folder string, marker Marker) error {
	if strings.TrimSpace(marker.Name) == "" {
		return errors.New("marker name is empty")
	}
	if strings.TrimSpace(marker.ID) == "" {
		return errors.New("marker id is empty")
	}
	if err := ValidateMarkerID(marker.ID); err != nil {
		return err
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
