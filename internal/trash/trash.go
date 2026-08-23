//go:build linux

// Package trash moves files out of a share without unlinking them.
package trash

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"l2syncd/internal/sharepath"
)

const (
	trashFilesMode = 0o700
	trashInfoMode  = 0o700
	trashFileMode  = 0o600
	trashDate      = "20060102-150405"
)

// Move moves an existing path to recoverable trash. The returned path is the
// trash destination. The share root is used as the final fallback.
func Move(shareRoot, relative string) (string, error) {
	parent, err := sharepath.OpenParent(shareRoot, relative, false)
	if err != nil {
		return "", err
	}
	defer parent.Close()
	source := parent.Path()
	if _, err := os.Lstat(source); err != nil {
		return "", fmt.Errorf("trash %q: %w", relative, err)
	}
	originalSource := filepath.Join(shareRoot, filepath.FromSlash(relative))
	if destination, ok := xdgDestination(source, originalSource, relative); ok {
		if moved, err := moveTo(source, destination); err == nil {
			return moved, nil
		}
	}
	if destination, ok := mountDestination(source, relative); ok {
		if moved, err := moveTo(source, destination); err == nil {
			return moved, nil
		}
	}
	date := time.Now().UTC().Format(trashDate)
	fallbackRelative := filepath.ToSlash(filepath.Join(".l2sync-trash", date, filepath.FromSlash(relative)))
	fallbackParent, err := sharepath.OpenParent(shareRoot, fallbackRelative, true)
	if err != nil {
		return "", fmt.Errorf("resolve fallback trash for %q: %w", relative, err)
	}
	defer fallbackParent.Close()
	destination := fallbackParent.Path()
	moved, err := moveTo(source, destination)
	if err != nil {
		return "", fmt.Errorf("move %q to fallback trash: %w", relative, err)
	}
	return filepath.Join(shareRoot, filepath.Dir(filepath.FromSlash(fallbackRelative)), filepath.Base(moved)), nil
}

func xdgDestination(source, originalSource, relative string) (string, bool) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	trashRoot := filepath.Join(dataHome, "Trash")
	if !sameDevice(source, trashRoot) {
		return "", false
	}
	name := filepath.Base(relative)
	destination := uniquePath(filepath.Join(trashRoot, "files", name))
	info := filepath.Join(trashRoot, "info", filepath.Base(destination)+".trashinfo")
	if err := os.MkdirAll(filepath.Dir(destination), trashFilesMode); err != nil {
		return "", false
	}
	if err := os.MkdirAll(filepath.Dir(info), trashInfoMode); err != nil {
		return "", false
	}
	contents := "[Trash Info]\nPath=" + url.PathEscape(filepath.ToSlash(originalSource)) + "\nDeletionDate=" + time.Now().UTC().Format("2006-01-02T15:04:05") + "\n"
	if err := os.WriteFile(info, []byte(contents), trashFileMode); err != nil {
		return "", false
	}
	return destination, true
}

func mountDestination(source, relative string) (string, bool) {
	info, err := os.Stat(source)
	if err != nil {
		return "", false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	for _, root := range []string{"/"} {
		rootInfo, statErr := os.Stat(root)
		rootStat, statOK := rootInfo.Sys().(*syscall.Stat_t)
		if statErr == nil && statOK && rootStat.Dev == stat.Dev {
			return filepath.Join(root, ".Trash-"+strconv.Itoa(os.Getuid()), filepath.FromSlash(relative)), true
		}
	}
	return "", false
}

func moveTo(source, destination string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(destination), trashFilesMode); err != nil {
		return "", err
	}
	destination = uniquePath(destination)
	if err := os.Rename(source, destination); err != nil {
		return "", err
	}
	return destination, nil
}

func uniquePath(path string) string {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return path
	}
	for index := 1; ; index++ {
		candidate := path + "." + strconv.Itoa(index)
		if _, err := os.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}
}

func sameDevice(source, destination string) bool {
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return false
	}
	destinationInfo, err := os.Stat(destination)
	if err != nil {
		destinationInfo, err = os.Stat(filepath.Dir(destination))
	}
	if err != nil {
		return false
	}
	sourceStat, sourceOK := sourceInfo.Sys().(*syscall.Stat_t)
	destinationStat, destinationOK := destinationInfo.Sys().(*syscall.Stat_t)
	return sourceOK && destinationOK && sourceStat.Dev == destinationStat.Dev
}
