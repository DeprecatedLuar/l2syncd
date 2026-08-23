//go:build linux

// Package metadata captures, validates, applies, and verifies the portable
// filesystem metadata supported by l2sync.
package metadata

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"l2syncd/internal/sharepath"

	"golang.org/x/sys/unix"
)

const (
	permissionMask  = 0o777
	unsupportedBits = syscall.S_ISUID | syscall.S_ISGID | syscall.S_ISVTX
	aclAccessName   = "system.posix_acl_access"
	aclDefaultName  = "system.posix_acl_default"
)

// Manifest is the complete portable metadata declaration for one entry.
type Manifest struct {
	Mode       uint32            `json:"mode"`
	Mtime      time.Time         `json:"mtime"`
	Xattrs     map[string][]byte `json:"xattrs,omitempty"`
	ACLAccess  []byte            `json:"acl_access,omitempty"`
	ACLDefault []byte            `json:"acl_default,omitempty"`
}

// Capture opens path and reads all supported metadata, rejecting
// regular-file properties that cannot be reproduced faithfully by an
// unprivileged peer.
func Capture(path string, regular bool) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open metadata target %q: %w", path, err)
	}
	defer file.Close()
	manifest, _, err := CaptureFile(file, regular)
	return manifest, err
}

// CaptureFile captures metadata from one already-open inode and rejects a
// concurrent identity or metadata change during capture.
func CaptureFile(file *os.File, regular bool) (Manifest, os.FileInfo, error) {
	before, err := file.Stat()
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("stat opened metadata target %q: %w", file.Name(), err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		return Manifest{}, nil, fmt.Errorf("read Linux metadata for %q", file.Name())
	}
	if regular {
		if err := validateRegular(file.Name(), stat, uint32(os.Geteuid()), uint32(os.Getegid())); err != nil {
			return Manifest{}, nil, err
		}
	}
	manifest := Manifest{Mode: uint32(before.Mode().Perm() & permissionMask), Mtime: before.ModTime().UTC(), Xattrs: make(map[string][]byte)}
	names, err := listXattrsFile(file)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("list extended attributes on %q: %w", file.Name(), err)
	}
	for _, name := range names {
		if !supportedXattr(name) {
			continue
		}
		value, err := getXattrFile(file, name)
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("read extended attribute %q on %q: %w", name, file.Name(), err)
		}
		switch name {
		case aclAccessName:
			manifest.ACLAccess = value
		case aclDefaultName:
			manifest.ACLDefault = value
		default:
			manifest.Xattrs[name] = value
		}
	}
	if len(manifest.Xattrs) == 0 {
		manifest.Xattrs = nil
	}
	after, err := file.Stat()
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("revalidate opened metadata target %q: %w", file.Name(), err)
	}
	if !sharepath.SameState(before, after) {
		return Manifest{}, nil, fmt.Errorf("metadata target %q changed during capture", file.Name())
	}
	return manifest, before, nil
}

func validateRegular(path string, stat *syscall.Stat_t, uid, gid uint32) error {
	if stat.Uid != uid {
		return fmt.Errorf("unsupported owner on %q: uid %d differs from sync uid %d", path, stat.Uid, uid)
	}
	if stat.Gid != gid {
		return fmt.Errorf("unsupported group on %q: gid %d differs from sync gid %d", path, stat.Gid, gid)
	}
	if stat.Nlink > 1 {
		return fmt.Errorf("unsupported hard link on %q: link count %d", path, stat.Nlink)
	}
	if stat.Mode&unsupportedBits != 0 {
		return fmt.Errorf("unsupported special permission bits on %q: %#o", path, stat.Mode&unsupportedBits)
	}
	return nil
}

// ApplyFile applies portable metadata to one already-open inode.
func ApplyFile(file *os.File, manifest Manifest) error {
	current, err := listXattrsFile(file)
	if err != nil {
		return fmt.Errorf("list existing extended attributes on %q: %w", file.Name(), err)
	}
	wanted, err := wantedXattrs(manifest)
	if err != nil {
		return err
	}
	fd := int(file.Fd())
	for _, name := range current {
		if !supportedXattr(name) {
			continue
		}
		if _, exists := wanted[name]; !exists {
			if err := unix.Fremovexattr(fd, name); err != nil && !errors.Is(err, unix.ENODATA) {
				return fmt.Errorf("remove extended attribute %q on %q: %w", name, file.Name(), err)
			}
		}
	}
	for name, value := range wanted {
		if err := unix.Fsetxattr(fd, name, value, 0); err != nil {
			return fmt.Errorf("set extended attribute %q on %q: %w", name, file.Name(), err)
		}
	}
	if err := file.Chmod(os.FileMode(manifest.Mode & permissionMask)); err != nil {
		return fmt.Errorf("set mode on %q: %w", file.Name(), err)
	}
	times := []unix.Timespec{unix.NsecToTimespec(manifest.Mtime.UnixNano()), unix.NsecToTimespec(manifest.Mtime.UnixNano())}
	if err := unix.UtimesNanoAt(fd, "", times, unix.AT_EMPTY_PATH); err != nil {
		return fmt.Errorf("restore mtime on %q: %w", file.Name(), err)
	}
	return nil
}

func wantedXattrs(manifest Manifest) (map[string][]byte, error) {
	wanted := make(map[string][]byte, len(manifest.Xattrs)+2)
	for name, value := range manifest.Xattrs {
		if !strings.HasPrefix(name, "user.") {
			return nil, fmt.Errorf("metadata manifest contains unsupported xattr %q", name)
		}
		wanted[name] = value
	}
	if manifest.ACLAccess != nil {
		wanted[aclAccessName] = manifest.ACLAccess
	}
	if manifest.ACLDefault != nil {
		wanted[aclDefaultName] = manifest.ACLDefault
	}
	return wanted, nil
}

func supportedXattr(name string) bool {
	return strings.HasPrefix(name, "user.") || name == aclAccessName || name == aclDefaultName
}

// Verify reads metadata back and requires an exact match.
func Verify(path string, expected Manifest) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat metadata target %q: %w", path, err)
	}
	actual, err := Capture(path, info.Mode().IsRegular())
	if err != nil {
		return err
	}
	if !Equal(actual, expected) {
		return fmt.Errorf("metadata verification failed for %q", path)
	}
	return nil
}

// VerifyFile reads metadata back from the same opened inode.
func VerifyFile(file *os.File, expected Manifest, regular bool) error {
	actual, _, err := CaptureFile(file, regular)
	if err != nil {
		return err
	}
	if !Equal(actual, expected) {
		return fmt.Errorf("metadata verification failed for %q", file.Name())
	}
	return nil
}

// Equal compares all declared portable attributes.
func Equal(left, right Manifest) bool {
	if left.Mode != right.Mode || !left.Mtime.Equal(right.Mtime) || !bytes.Equal(left.ACLAccess, right.ACLAccess) || !bytes.Equal(left.ACLDefault, right.ACLDefault) || len(left.Xattrs) != len(right.Xattrs) {
		return false
	}
	for name, value := range left.Xattrs {
		rightValue, exists := right.Xattrs[name]
		if !exists || !bytes.Equal(value, rightValue) {
			return false
		}
	}
	return true
}

func listXattrsFile(file *os.File) ([]string, error) {
	fd := int(file.Fd())
	size, err := unix.Flistxattr(fd, nil)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}
	buffer := make([]byte, size)
	size, err = unix.Flistxattr(fd, buffer)
	if err != nil {
		return nil, err
	}
	names := strings.Split(strings.TrimSuffix(string(buffer[:size]), "\x00"), "\x00")
	sort.Strings(names)
	return names, nil
}

func getXattrFile(file *os.File, name string) ([]byte, error) {
	fd := int(file.Fd())
	size, err := unix.Fgetxattr(fd, name, nil)
	if err != nil {
		return nil, err
	}
	value := make([]byte, size)
	if size == 0 {
		return value, nil
	}
	size, err = unix.Fgetxattr(fd, name, value)
	if err != nil {
		return nil, err
	}
	return value[:size], nil
}
