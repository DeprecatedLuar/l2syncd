//go:build linux

// Package apply performs recoverable, atomic filesystem changes.
package apply

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"l2syncd/internal/metadata"
	"l2syncd/internal/peername"
	"l2syncd/internal/sharepath"
	"l2syncd/internal/trash"
)

var (
	ErrReuseMismatch      = errors.New("content reuse source no longer matches baseline")
	errHashMismatch       = errors.New("content hash mismatch")
	beforeConflictCommit  = func() {}
	afterReuseOpen        = func() {}
	beforeInstalledVerify = func() {}
)

const (
	temporaryPattern = ".l2sync-apply-*"
	defaultFileMode  = 0o600
)

// Write atomically replaces relative with bytes from source. Existing files
// are moved to trash before replacement.
func Write(root, relative string, source io.Reader, expectedHash string) error {
	return write(root, relative, source, expectedHash, nil, "")
}

// WriteWithMetadata atomically replaces relative and verifies its bytes and
// full portable metadata declaration before returning.
func WriteWithMetadata(root, relative string, source io.Reader, expectedHash string, manifest metadata.Manifest) error {
	return write(root, relative, source, expectedHash, &manifest, "")
}

// WriteConflictWinnerWithMetadata validates the winning version before moving
// the existing canonical file to its conflict name.
func WriteConflictWinnerWithMetadata(root, relative, loser string, source io.Reader, expectedHash string, manifest metadata.Manifest) error {
	if loser == "" {
		return errors.New("conflict loser is required")
	}
	return write(root, relative, source, expectedHash, &manifest, loser)
}

// WriteConflictWinnerWithSuffix uses a precomputed suffix so both replicas
// preserve the losing version under exactly the same name.
func WriteConflictWinnerWithSuffix(root, relative, suffix string, source io.Reader, expectedHash string, manifest metadata.Manifest) error {
	if err := peername.Validate(suffix); err != nil {
		return err
	}
	return writeWithConflictSuffix(root, relative, source, expectedHash, &manifest, suffix)
}

func write(root, relative string, source io.Reader, expectedHash string, manifest *metadata.Manifest, conflictLoser string) error {
	if conflictLoser != "" {
		if err := peername.Validate(conflictLoser); err != nil {
			return err
		}
	}
	suffix := ""
	if conflictLoser != "" {
		suffix = time.Now().UTC().Format("20060102-150405") + "-" + conflictLoser
	}
	return writeWithConflictSuffix(root, relative, source, expectedHash, manifest, suffix)
}

func writeWithConflictSuffix(root, relative string, source io.Reader, expectedHash string, manifest *metadata.Manifest, conflictSuffix string) error {
	parent, err := sharepath.OpenParent(root, relative, true)
	if err != nil {
		return err
	}
	defer parent.Close()
	destination := parent.Path()
	if info, statErr := os.Lstat(destination); statErr == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("destination %q is not a regular file", relative)
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect destination %q: %w", relative, statErr)
	}
	temporary, err := os.CreateTemp(parent.Directory(), temporaryPattern)
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer temporary.Close()
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
	if expectedHash != "" && !strings.EqualFold(fmt.Sprintf("%x", digest.Sum(nil)), expectedHash) {
		temporary.Close()
		return fmt.Errorf("%w for %q", errHashMismatch, relative)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if manifest != nil {
		if err := metadata.ApplyFile(temporary, *manifest); err != nil {
			temporary.Close()
			return err
		}
		if err := metadata.VerifyFile(temporary, *manifest, true); err != nil {
			temporary.Close()
			return err
		}
		if err := temporary.Sync(); err != nil {
			temporary.Close()
			return fmt.Errorf("sync temporary metadata: %w", err)
		}
	}
	if _, statErr := os.Lstat(destination); statErr == nil {
		if conflictSuffix != "" {
			if err := PreserveConflictWithSuffix(root, relative, conflictSuffix); err != nil {
				return err
			}
		} else {
			if _, err := trash.Move(root, relative); err != nil {
				return err
			}
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect destination %q: %w", relative, statErr)
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		temporary.Close()
		return fmt.Errorf("replace %q: %w", relative, err)
	}
	keep = true
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close installed file %q: %w", relative, err)
	}
	if err := syncDirectory(parent.Directory()); err != nil {
		return err
	}
	if expectedHash != "" || manifest != nil {
		return verifyInstalled(root, relative, expectedHash, manifest)
	}
	return nil
}

// Reuse copies a baseline-backed local file after reverifying its content.
// ErrReuseMismatch tells the caller to fetch the bytes normally.
func Reuse(root, relative, sourceRelative, expectedHash string, manifest metadata.Manifest) error {
	file, err := sharepath.OpenRegular(root, sourceRelative)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrReuseMismatch, err)
	}
	defer file.Close()
	afterReuseOpen()
	actual, err := sharepath.Hash(file)
	if err != nil || !strings.EqualFold(actual, expectedHash) {
		return fmt.Errorf("%w: source hash changed", ErrReuseMismatch)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind reuse source %q: %w", sourceRelative, err)
	}
	if err := WriteWithMetadata(root, relative, file, expectedHash, manifest); err != nil {
		if errors.Is(err, errHashMismatch) {
			return fmt.Errorf("%w: source changed while copying", ErrReuseMismatch)
		}
		return err
	}
	return nil
}

// ApplyDirectory creates a directory when needed, then applies and verifies
// its metadata. Callers invoke this after child mutations.
func ApplyDirectory(root, relative string, manifest metadata.Manifest) error {
	parent, err := sharepath.OpenParent(root, relative, true)
	if err != nil {
		return err
	}
	defer parent.Close()
	destination := parent.Path()
	probe, err := os.MkdirTemp(parent.Directory(), temporaryPattern)
	if err != nil {
		return fmt.Errorf("create directory metadata probe: %w", err)
	}
	probeFile, err := os.Open(probe)
	if err != nil {
		return fmt.Errorf("open directory metadata probe: %w", err)
	}
	if err := metadata.ApplyFile(probeFile, manifest); err != nil {
		probeFile.Close()
		if removeErr := os.Remove(probe); removeErr != nil {
			return fmt.Errorf("directory metadata capability check: %v; remove probe: %w", err, removeErr)
		}
		return fmt.Errorf("directory metadata capability check: %w", err)
	}
	if err := metadata.VerifyFile(probeFile, manifest, false); err != nil {
		probeFile.Close()
		if removeErr := os.Remove(probe); removeErr != nil {
			return fmt.Errorf("directory metadata capability check: %v; remove probe: %w", err, removeErr)
		}
		return fmt.Errorf("directory metadata capability check: %w", err)
	}
	if err := probeFile.Close(); err != nil {
		return fmt.Errorf("close directory metadata probe: %w", err)
	}
	if err := os.Remove(probe); err != nil {
		return fmt.Errorf("remove directory metadata probe: %w", err)
	}
	if info, statErr := os.Lstat(destination); statErr == nil {
		if !info.IsDir() {
			return fmt.Errorf("directory destination %q is not a directory", relative)
		}
	} else if os.IsNotExist(statErr) {
		if err := os.Mkdir(destination, 0o700); err != nil {
			return fmt.Errorf("create directory %q: %w", relative, err)
		}
	} else {
		return fmt.Errorf("inspect directory %q: %w", relative, statErr)
	}
	opened, err := sharepath.OpenDirectory(root, relative)
	if err != nil {
		return err
	}
	defer opened.Close()
	if err := metadata.ApplyFile(opened, manifest); err != nil {
		return err
	}
	return metadata.VerifyFile(opened, manifest, false)
}

// DeleteDirectory moves an empty directory to trash. Non-empty directories
// are retained so ignored or otherwise out-of-set children are never removed.
func DeleteDirectory(root, relative string) error {
	directory, err := sharepath.OpenDirectory(root, relative)
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(1)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			directory.Close()
			return fmt.Errorf("read directory %q before deletion: %w", relative, err)
		}
	}
	if closeErr := directory.Close(); closeErr != nil {
		return fmt.Errorf("close directory %q before deletion: %w", relative, closeErr)
	}
	if len(entries) != 0 {
		return nil
	}
	_, err = trash.Move(root, relative)
	return err
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
	if err := peername.Validate(peer); err != nil {
		return err
	}
	return PreserveConflictWithSuffix(root, relative, time.Now().UTC().Format("20060102-150405")+"-"+peer)
}

// PreserveConflictWithSuffix renames the canonical file with an exact,
// precomputed timestamp-and-fingerprint suffix.
func PreserveConflictWithSuffix(root, relative, suffix string) error {
	if err := peername.Validate(suffix); err != nil {
		return err
	}
	parent, err := sharepath.OpenParent(root, relative, false)
	if err != nil {
		return err
	}
	defer parent.Close()
	destination := parent.Path()
	info, err := os.Lstat(destination)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect conflict %q: %w", relative, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("conflict source %q is not a regular file", relative)
	}
	extension := filepath.Ext(destination)
	base := strings.TrimSuffix(destination, extension)
	conflict := base + ".l2sync-conflict-" + suffix + extension
	if _, err := os.Lstat(conflict); err == nil {
		return fmt.Errorf("conflict destination %q already exists", filepath.Base(conflict))
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect conflict destination: %w", err)
	}
	beforeConflictCommit()
	if err := unix.Renameat2(parent.FD(), parent.Leaf, parent.FD(), filepath.Base(conflict), unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("conflict destination %q already exists", filepath.Base(conflict))
		}
		return fmt.Errorf("preserve conflict %q: %w", relative, err)
	}
	return syncDirectory(parent.Directory())
}

// WriteConflictCopy writes a peer's losing version beside the current file.
func WriteConflictCopy(root, relative, peer string, source io.Reader, expectedHash string) error {
	return writeConflictCopy(root, relative, peer, source, expectedHash, nil)
}

// WriteConflictCopyWithMetadata writes a losing peer version with its full
// metadata declaration intact.
func WriteConflictCopyWithMetadata(root, relative, peer string, source io.Reader, expectedHash string, manifest metadata.Manifest) error {
	return writeConflictCopy(root, relative, peer, source, expectedHash, &manifest)
}

// WriteConflictCopyWithSuffix writes the loser under an exact suffix shared by
// both replicas.
func WriteConflictCopyWithSuffix(root, relative, suffix string, source io.Reader, expectedHash string, manifest metadata.Manifest) error {
	return writeConflictCopyExact(root, relative, suffix, source, expectedHash, &manifest)
}

func writeConflictCopy(root, relative, peer string, source io.Reader, expectedHash string, manifest *metadata.Manifest) error {
	if err := peername.Validate(peer); err != nil {
		return err
	}
	return writeConflictCopyExact(root, relative, time.Now().UTC().Format("20060102-150405")+"-"+peer, source, expectedHash, manifest)
}

func writeConflictCopyExact(root, relative, suffix string, source io.Reader, expectedHash string, manifest *metadata.Manifest) error {
	if err := peername.Validate(suffix); err != nil {
		return err
	}
	extension := filepath.Ext(relative)
	base := strings.TrimSuffix(relative, extension)
	conflict := base + ".l2sync-conflict-" + suffix + extension
	parent, err := sharepath.OpenParent(root, conflict, true)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(parent.Path()); err == nil {
		parent.Close()
		return fmt.Errorf("conflict destination %q already exists", conflict)
	} else if !os.IsNotExist(err) {
		parent.Close()
		return fmt.Errorf("inspect conflict destination: %w", err)
	}
	if err := parent.Close(); err != nil {
		return fmt.Errorf("close conflict parent: %w", err)
	}
	return writeExact(root, conflict, source, expectedHash, manifest)
}

func writeExact(root, relative string, source io.Reader, expectedHash string, manifest *metadata.Manifest) error {
	parent, err := sharepath.OpenParent(root, relative, true)
	if err != nil {
		return err
	}
	defer parent.Close()
	temporary, err := os.CreateTemp(parent.Directory(), temporaryPattern)
	if err != nil {
		return fmt.Errorf("create exact-write temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer temporary.Close()
	defer os.Remove(temporaryPath)
	digest := sha256.New()
	if _, err := io.Copy(io.MultiWriter(temporary, digest), source); err != nil {
		temporary.Close()
		return fmt.Errorf("write exact conflict copy: %w", err)
	}
	if expectedHash != "" && !strings.EqualFold(fmt.Sprintf("%x", digest.Sum(nil)), expectedHash) {
		temporary.Close()
		return errHashMismatch
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if manifest != nil {
		if err := metadata.ApplyFile(temporary, *manifest); err != nil {
			temporary.Close()
			return err
		}
		if err := metadata.VerifyFile(temporary, *manifest, true); err != nil {
			temporary.Close()
			return err
		}
		if err := temporary.Sync(); err != nil {
			temporary.Close()
			return err
		}
	}
	beforeConflictCommit()
	if err := unix.Renameat2(parent.FD(), filepath.Base(temporaryPath), parent.FD(), parent.Leaf, unix.RENAME_NOREPLACE); err != nil {
		temporary.Close()
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("conflict destination %q already exists", relative)
		}
		return fmt.Errorf("install exact conflict copy: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close installed conflict copy: %w", err)
	}
	if err := syncDirectory(parent.Directory()); err != nil {
		return err
	}
	if expectedHash != "" || manifest != nil {
		return verifyInstalled(root, relative, expectedHash, manifest)
	}
	return nil
}

// ConflictCopyExists reports whether the exact deterministic conflict artifact
// already exists. Existing artifacts are never renamed or overwritten.
func ConflictCopyExists(root, relative, suffix string) (bool, error) {
	if err := peername.Validate(suffix); err != nil {
		return false, err
	}
	extension := filepath.Ext(relative)
	base := strings.TrimSuffix(relative, extension)
	conflict := base + ".l2sync-conflict-" + suffix + extension
	parent, err := sharepath.OpenParent(root, conflict, false)
	if err != nil {
		return false, err
	}
	defer parent.Close()
	_, err = os.Lstat(parent.Path())
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("inspect conflict destination: %w", err)
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

func verifyInstalled(root, relative, expected string, manifest *metadata.Manifest) error {
	beforeInstalledVerify()
	file, err := sharepath.OpenRegular(root, relative)
	if err != nil {
		return fmt.Errorf("open %q for verification: %w", relative, err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return err
	}
	actual, err := sharepath.Hash(file)
	if err != nil {
		return err
	}
	if expected != "" && !strings.EqualFold(actual, expected) {
		return fmt.Errorf("content verification failed for %q", relative)
	}
	if manifest != nil {
		if err := metadata.VerifyFile(file, *manifest, true); err != nil {
			return err
		}
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	if !sharepath.SameState(before, after) {
		return fmt.Errorf("installed file %q changed during verification", relative)
	}
	return sharepath.RevalidateRegular(root, relative, after)
}
