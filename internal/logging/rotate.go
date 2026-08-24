//go:build linux

package logging

import (
	"fmt"
	"os"
	"sync"
)

const (
	// rotatedSuffix names the single retained previous log, replaced on
	// each rotation. Keeping exactly one rotated file is a size-cap
	// safeguard against unbounded growth, not an archival scheme.
	rotatedSuffix = ".1"
	// logFileMode matches the file permissions state already uses for
	// its own files.
	logFileMode = 0o600
)

// rotatingWriter appends to a single log file, rotating it out to a
// "<name>.1" sibling (replacing any previous one) once the next write
// would push it past maxSize.
//
// Concurrency: the file is opened O_APPEND, so each Write call this
// process makes is placed atomically at the file's current end by the
// kernel, and callers are expected to emit one log record per Write call
// — together this keeps records from different processes (the daemon and
// any number of `l2sync serve` subprocesses) from interleaving mid-line.
// The mutex here only serializes the size-check-then-write-or-rotate
// sequence against other goroutines *in this process*; it gives no cross-
// process coordination, so two processes rotating at (almost) the same
// instant can race — one process's rotation can be immediately followed
// by another's, or a write can land in the old file right as another
// process renames it out. l2sync accepts that as the simple, good-enough
// behavior for a size cap: the failure mode is losing a little context
// around a rotation boundary, not corrupting or interleaving records.
type rotatingWriter struct {
	mu      sync.Mutex
	path    string
	maxSize int64
	file    *os.File
}

func newRotatingWriter(path string, maxSize int64) (*rotatingWriter, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, logFileMode)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	return &rotatingWriter{path: path, maxSize: maxSize, file: file}, nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if info, err := w.file.Stat(); err == nil && info.Size()+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	return w.file.Write(p)
}

func (w *rotatingWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close log file before rotation: %w", err)
	}
	rotatedPath := w.path + rotatedSuffix
	if err := os.Rename(w.path, rotatedPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rotate log file: %w", err)
	}
	file, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, logFileMode)
	if err != nil {
		return fmt.Errorf("reopen log file after rotation: %w", err)
	}
	w.file = file
	return nil
}
