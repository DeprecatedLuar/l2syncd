//go:build linux

package commands

import (
	"fmt"
	"io"
	"sort"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/scan"
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
		path, exists := cfg.Shared[name]
		if !exists {
			return nil, fmt.Errorf("shared folder %q is not offered", name)
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
			return nil, fmt.Errorf("list shared folder %q: %w", name, scanErr)
		}
		files := make([]transport.PeerFile, 0, len(listed))
		for _, file := range listed {
			files = append(files, transport.PeerFile{Path: file.Path, Size: file.Size})
		}
		return files, nil
	}
	if err := transport.ServePeer(stdin, stdout, shares, fileLister); err != nil {
		fmt.Fprintf(stderr, "l2sync: serve peer request: %v\n", err)
		return serveExitError
	}
	return serveExitOK
}
