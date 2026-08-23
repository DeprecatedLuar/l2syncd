//go:build linux

// Package lock owns l2sync daemon-instance and mutation locks.
package lock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"l2syncd/internal/config"
)

var (
	ErrContended = errors.New("another l2sync mutation is running")
	ErrTimeout   = errors.New("timed out waiting for the l2sync mutation lock")
)

const (
	mutationLockFilename = "mutation.lock"
	daemonLockFilename   = "daemon.lock"
	joinLockFilename     = "join.lock"
	directoryMode        = 0o700
	fileMode             = 0o600
	retryInterval        = 50 * time.Millisecond
	DefaultWait          = 5 * time.Second
)

// Acquire takes the non-blocking mutation lock and keeps its file open until
// the returned handle is released.
func Acquire() (*os.File, error) {
	return acquire(mutationLockFilename)
}

// AcquireDaemon takes the non-blocking daemon-instance lock. It is separate
// from mutation serialization so an active daemon does not block SSH-served
// writes for its entire lifetime.
func AcquireDaemon() (*os.File, error) {
	file, err := acquire(daemonLockFilename)
	if errors.Is(err, ErrContended) {
		return nil, errors.New("another l2sync daemon is running")
	}
	return file, err
}

// AcquireWait waits up to timeout for the mutation lock. Kernel flock
// ownership is tied to the open file description: a dead owner is recovered
// automatically, while a live owner can never be displaced by elapsed time.
func AcquireWait(ctx context.Context, timeout time.Duration) (*os.File, error) {
	return acquireWait(ctx, timeout, mutationLockFilename)
}

// AcquireJoinWait serializes the outbound join transaction without blocking
// inbound peer callbacks that use the general mutation lock.
func AcquireJoinWait(ctx context.Context, timeout time.Duration) (*os.File, error) {
	return acquireWait(ctx, timeout, joinLockFilename)
}

func acquireWait(ctx context.Context, timeout time.Duration, filename string) (*os.File, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("mutation lock wait must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()
	for {
		file, err := acquire(filename)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, ErrContended) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, ErrTimeout
			}
			return nil, fmt.Errorf("wait for mutation lock: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func acquire(filename string) (*os.File, error) {
	directory, err := config.StateDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	file, err := os.OpenFile(filepath.Join(directory, filename), os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filename, err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrContended
		}
		return nil, fmt.Errorf("acquire %s: %w", filename, err)
	}
	return file, nil
}

func Release(file *os.File) error {
	if file == nil {
		return nil
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		file.Close()
		return fmt.Errorf("release lock: %w", err)
	}
	return file.Close()
}
