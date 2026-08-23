//go:build linux

// Package sharepath resolves mutation targets beneath a share without
// following symlink ancestors.
package sharepath

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	directoryMode = 0o700
	procFDPrefix  = "/proc/self/fd/"
)

// Parent holds an open descriptor for a target's parent directory. Path is a
// procfs path through that descriptor, so later ancestor replacement cannot
// redirect an operation outside the resolved directory.
type Parent struct {
	file *os.File
	Leaf string
}

// OpenParent resolves relative's parent below root. Existing symlink
// ancestors are rejected. When create is true, missing parent directories are
// created one segment at a time without following symlinks.
func OpenParent(root, relative string, create bool) (*Parent, error) {
	if err := Validate(relative); err != nil {
		return nil, err
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open share root: %w", err)
	}
	current := os.NewFile(uintptr(rootFD), root)
	segments := strings.Split(relative, "/")
	for _, segment := range segments[:len(segments)-1] {
		nextFD, openErr := unix.Openat(int(current.Fd()), segment, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(int(current.Fd()), segment, directoryMode); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				current.Close()
				return nil, fmt.Errorf("create share directory %q: %w", segment, mkdirErr)
			}
			nextFD, openErr = unix.Openat(int(current.Fd()), segment, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			current.Close()
			return nil, fmt.Errorf("resolve share path %q: %w", relative, openErr)
		}
		current.Close()
		current = os.NewFile(uintptr(nextFD), segment)
	}
	return &Parent{file: current, Leaf: segments[len(segments)-1]}, nil
}

// Path returns the target path through the held parent descriptor.
func (parent *Parent) Path() string {
	return procFDPrefix + fmt.Sprint(parent.file.Fd()) + "/" + parent.Leaf
}

// Directory returns the held parent directory through procfs.
func (parent *Parent) Directory() string {
	return procFDPrefix + fmt.Sprint(parent.file.Fd())
}

// FD returns the held parent directory descriptor for Linux *at syscalls.
func (parent *Parent) FD() int { return int(parent.file.Fd()) }

func (parent *Parent) Close() error { return parent.file.Close() }

// OpenRegular opens an existing regular file below root without following a
// symlink in either an ancestor or the leaf. The returned descriptor remains
// anchored to the resolved inode even if the directory tree changes later.
func OpenRegular(root, relative string) (*os.File, error) {
	return openLeaf(root, relative, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, unix.S_IFREG, "file")
}

// OpenDirectory opens an existing directory below root without following
// symlink ancestors or the leaf.
func OpenDirectory(root, relative string) (*os.File, error) {
	return openLeaf(root, relative, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, unix.S_IFDIR, "directory")
}

func openLeaf(root, relative string, flags int, wanted uint32, kind string) (*os.File, error) {
	parent, err := OpenParent(root, relative, false)
	if err != nil {
		return nil, err
	}
	fd, openErr := unix.Openat(parent.FD(), parent.Leaf, flags, 0)
	closeErr := parent.Close()
	if openErr != nil {
		return nil, fmt.Errorf("open share %s %q: %w", kind, relative, openErr)
	}
	file := os.NewFile(uintptr(fd), relative)
	if closeErr != nil {
		file.Close()
		return nil, fmt.Errorf("close share parent for %q: %w", relative, closeErr)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect share %s %q: %w", kind, relative, err)
	}
	if stat.Mode&unix.S_IFMT != wanted {
		file.Close()
		return nil, fmt.Errorf("share path %q is not a %s", relative, kind)
	}
	if flags&unix.O_NONBLOCK != 0 {
		if err := unix.SetNonblock(fd, false); err != nil {
			file.Close()
			return nil, fmt.Errorf("configure share %s %q: %w", kind, relative, err)
		}
	}
	return file, nil
}

// Hash rewinds and hashes the exact inode represented by file.
func Hash(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind %q: %w", file.Name(), err)
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("hash %q: %w", file.Name(), err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// RevalidateRegular requires the configured path to still name the same inode
// and state as an earlier anchored open. It reads no bytes from the new open.
func RevalidateRegular(root, relative string, expected os.FileInfo) error {
	current, err := OpenRegular(root, relative)
	if err != nil {
		return fmt.Errorf("revalidate share file %q: %w", relative, err)
	}
	defer current.Close()
	actual, err := current.Stat()
	if err != nil {
		return fmt.Errorf("stat revalidated share file %q: %w", relative, err)
	}
	if !SameState(expected, actual) {
		return fmt.Errorf("share file %q changed during operation", relative)
	}
	return nil
}

// SameState compares the inode and mutable state used to bind one operation.
func SameState(left, right os.FileInfo) bool {
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Dev == rightStat.Dev && leftStat.Ino == rightStat.Ino && leftStat.Ctim == rightStat.Ctim && left.Size() == right.Size() && left.Mode() == right.Mode() && left.ModTime().Equal(right.ModTime())
}

// Validate accepts one canonical, non-empty slash-separated relative path.
func Validate(relative string) error {
	if relative == "" || strings.HasPrefix(relative, "/") || path.Clean(relative) != relative || relative == "." || strings.HasPrefix(relative, "../") {
		return fmt.Errorf("invalid relative path %q", relative)
	}
	return nil
}
