//go:build linux

package commands

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"l2syncd/internal/apply"
	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/scan"
	"l2syncd/internal/state"
	"l2syncd/internal/transport"
)

const (
	serveExitOK    = 0
	serveExitError = 1
)

// Serve handles one read-only peer protocol request on stdin/stdout.
func Serve(stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, err := config.Load()
	if err != nil && err != config.ErrNotFound {
		fmt.Fprintf(stderr, "l2sync: load config: %v\n", err)
		return serveExitError
	}
	if err == config.ErrNotFound {
		cfg = config.New()
	}
	shares := make([]string, 0, len(cfg.Shared))
	markers := make(map[string]guard.Marker, len(cfg.Shared))
	for name, path := range cfg.Shared {
		marker, markerErr := guard.ReadMarker(path)
		if markerErr != nil || marker.Name != name {
			if markerErr != nil {
				err = fmt.Errorf("shared folder %q marker: %w", name, markerErr)
			} else {
				err = fmt.Errorf("shared folder %q marker names %q", name, marker.Name)
			}
			fmt.Fprintf(stderr, "l2sync: %v\n", err)
			return serveExitError
		}
		shares = append(shares, name)
		markers[name] = marker
	}
	sort.Strings(shares)
	fileLister := func(name string) ([]transport.PeerFile, error) {
		path, exists := folderPath(cfg, name)
		if !exists {
			return nil, fmt.Errorf("folder %q is not registered", name)
		}
		marker, markerErr := guard.ReadMarker(path)
		if markerErr != nil {
			return nil, fmt.Errorf("shared folder %q marker: %w", name, markerErr)
		}
		if marker.Name != name {
			return nil, fmt.Errorf("shared folder %q marker names %q", name, marker.Name)
		}
		listed, scanErr := scan.ListFiles(path, marker.Ignore)
		if scanErr != nil {
			return nil, fmt.Errorf("list folder %q: %w", name, scanErr)
		}
		files := make([]transport.PeerFile, 0, len(listed))
		for _, file := range listed {
			files = append(files, transport.PeerFile{Path: file.Path, Size: file.Size, Hash: file.Hash})
		}
		return files, nil
	}
	fileReader := func(name, relative string) (io.ReadCloser, error) {
		path, exists := folderPath(cfg, name)
		if !exists {
			return nil, fmt.Errorf("folder %q is not registered", name)
		}
		marker, markerErr := guard.ReadMarker(path)
		if markerErr != nil || marker.Name != name {
			return nil, fmt.Errorf("shared folder %q marker is invalid", name)
		}
		if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
			return nil, fmt.Errorf("invalid peer file path %q", relative)
		}
		file, openErr := os.Open(filepath.Join(path, filepath.FromSlash(relative)))
		if openErr != nil {
			return nil, fmt.Errorf("open folder file %q: %w", relative, openErr)
		}
		return file, nil
	}
	fileWriter := func(name, relative string, contents io.Reader) error {
		path, exists := folderPath(cfg, name)
		if !exists {
			return fmt.Errorf("folder %q is not registered", name)
		}
		marker, markerErr := guard.ReadMarker(path)
		if markerErr != nil || marker.Name != name {
			return fmt.Errorf("shared folder %q marker is invalid", name)
		}
		if err := apply.Write(path, relative, contents, ""); err != nil {
			return err
		}
		return commitFolderBaseline(name, path, marker.Ignore)
	}
	fileDeleter := func(name, relative string) error {
		path, exists := folderPath(cfg, name)
		if !exists {
			return fmt.Errorf("folder %q is not registered", name)
		}
		marker, markerErr := guard.ReadMarker(path)
		if markerErr != nil || marker.Name != name {
			return fmt.Errorf("shared folder %q marker is invalid", name)
		}
		if err := apply.Delete(path, relative); err != nil {
			return err
		}
		return commitFolderBaseline(name, path, marker.Ignore)
	}
	conflictWriter := func(name, relative, loser string, contents io.Reader) error {
		path, exists := folderPath(cfg, name)
		if !exists {
			return fmt.Errorf("folder %q is not registered", name)
		}
		marker, markerErr := guard.ReadMarker(path)
		if markerErr != nil || marker.Name != name {
			return fmt.Errorf("shared folder %q marker is invalid", name)
		}
		if err := apply.PreserveConflict(path, relative, loser); err != nil {
			return err
		}
		if err := apply.Write(path, relative, contents, ""); err != nil {
			return err
		}
		return commitFolderBaseline(name, path, marker.Ignore)
	}
	if err := transport.ServePeerWithConflict(stdin, stdout, shares, fileLister, fileReader, fileWriter, fileDeleter, conflictWriter); err != nil {
		fmt.Fprintf(stderr, "l2sync: serve peer request: %v\n", err)
		return serveExitError
	}
	return serveExitOK
}

func folderPath(cfg config.Config, name string) (string, bool) {
	if path, exists := cfg.Shared[name]; exists {
		return path, true
	}
	path, exists := cfg.Remote[name]
	return path, exists
}

func commitFolderBaseline(name, path string, ignore []string) error {
	baseline, err := state.Load(name)
	if err != nil && err != state.ErrNotFound {
		return fmt.Errorf("load folder baseline: %w", err)
	}
	if err == state.ErrNotFound {
		baseline = state.New()
	}
	result, err := scan.DetectWithIgnore(path, baseline, ignore)
	if err != nil {
		return fmt.Errorf("scan folder after mutation: %w", err)
	}
	if err := state.Save(name, result.Snapshot); err != nil {
		return fmt.Errorf("save folder baseline after mutation: %w", err)
	}
	return nil
}
