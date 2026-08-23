//go:build linux

// Package lock owns the process-wide l2sync daemon lock.
package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"l2syncd/internal/config"
)

var ErrContended = errors.New("another l2sync daemon is running")

const (
	lockFilename  = "daemon.lock"
	directoryMode = 0o700
	fileMode      = 0o600
)

// Acquire takes the non-blocking process lock and keeps its file open until
// the returned handle is closed.
func Acquire() (*os.File, error) {
	directory, err := config.StateDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	file, err := os.OpenFile(filepath.Join(directory, lockFilename), os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return nil, fmt.Errorf("open daemon lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrContended
		}
		return nil, fmt.Errorf("acquire daemon lock: %w", err)
	}
	return file, nil
}

func Release(file *os.File) error {
	if file == nil {
		return nil
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		file.Close()
		return fmt.Errorf("release daemon lock: %w", err)
	}
	return file.Close()
}
