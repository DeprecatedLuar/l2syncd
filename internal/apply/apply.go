//go:build linux

// Package apply performs recoverable, atomic filesystem changes.
package apply

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"l2syncd/internal/trash"
)

const (
	temporaryPattern = ".l2sync-apply-*"
	defaultFileMode  = 0o600
)

// Write atomically replaces relative with bytes from source. Existing files
// are moved to trash before replacement.
func Write(root, relative string, source io.Reader, expectedHash string) error {
	destination, err := safePath(root, relative)
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(destination); statErr == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("destination %q is not a regular file", relative)
		}
		if _, err := trash.Move(root, relative); err != nil {
			return err
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect destination %q: %w", relative, statErr)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return fmt.Errorf("create parent directory for %q: %w", relative, err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), temporaryPattern)
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(defaultFileMode); err != nil {
		temporary.Close()
		return fmt.Errorf("set temporary permissions: %w", err)
	}
	digest := sha256.New()
	if _, err := io.Copy(io.MultiWriter(temporary, digest), source); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if expectedHash != "" && fmt.Sprintf("%x", digest.Sum(nil)) != expectedHash {
		temporary.Close()
		return fmt.Errorf("received content hash does not match %q", relative)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return fmt.Errorf("replace %q: %w", relative, err)
	}
	keep = true
	return syncDirectory(filepath.Dir(destination))
}

// Delete moves relative to recoverable trash. Missing files are an error so a
// caller cannot silently commit a state it did not apply.
func Delete(root, relative string) error {
	if _, err := trash.Move(root, relative); err != nil {
		return err
	}
	return nil
}

// PreserveConflict renames the existing local version using the documented
// conflict suffix. It is intended to run immediately before writing the
// winning peer version.
func PreserveConflict(root, relative, peer string) error {
	destination, err := safePath(root, relative)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(destination); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect conflict %q: %w", relative, err)
	}
	extension := filepath.Ext(destination)
	base := strings.TrimSuffix(destination, extension)
	stamp := time.Now().UTC().Format("20060102-150405")
	conflict := base + ".l2sync-conflict-" + stamp + "-" + peer + extension
	conflict = uniquePath(conflict)
	if err := os.Rename(destination, conflict); err != nil {
		return fmt.Errorf("preserve conflict %q: %w", relative, err)
	}
	return nil
}

// WriteConflictCopy writes a peer's losing version beside the current file.
func WriteConflictCopy(root, relative, peer string, source io.Reader, expectedHash string) error {
	if relative == "" || peer == "" {
		return fmt.Errorf("conflict path requires a file and peer")
	}
	extension := filepath.Ext(relative)
	base := strings.TrimSuffix(relative, extension)
	conflict := base + ".l2sync-conflict-" + time.Now().UTC().Format("20060102-150405") + "-" + peer + extension
	return Write(root, conflict, source, expectedHash)
}

func safePath(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(filepath.ToSlash(relative), "../") {
		return "", fmt.Errorf("invalid relative path %q", relative)
	}
	return filepath.Join(root, filepath.FromSlash(relative)), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open destination directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync destination directory: %w", err)
	}
	return nil
}

func uniquePath(path string) string {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return path
	}
	for index := 1; ; index++ {
		candidate := fmt.Sprintf("%s.%d", path, index)
		if _, err := os.Lstat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
}
