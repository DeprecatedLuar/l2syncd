//go:build linux

// Package logging provides the single per-machine log file that l2sync's
// daemon (`l2sync run`) and its SSH forced-command subprocess (`l2sync
// serve`) both append to. Without it the mutating side of a sync (serve,
// spawned fresh by sshd on every connection) only ever wrote to a stderr
// pipe that the initiator captures and discards on success — so daemon
// cycles and serve-side mutations never showed up in one place. Every
// command entrypoint that logs calls NewLogger so both processes end up
// appending to the same file.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"l2syncd/internal/config"
)

const (
	// logFileName is the shared log file, resolved under the same state
	// directory internal/state uses for baselines (config.StateDir).
	logFileName = "l2sync.log"
	// logDirMode matches the directory permissions state and config
	// already use for this directory.
	logDirMode = 0o700
	// maxLogSize is the size a log file may reach before the next write
	// rotates it out to logFileName+rotatedSuffix. l2sync is a
	// long-running daemon, so unbounded growth is not acceptable; a
	// single-file rotation is enough to cap it without pulling in a
	// dependency or a multi-file scheme.
	maxLogSize = 10 * 1024 * 1024 // 10 MiB
)

// NewLogger returns a slog.Logger tagged with component and the calling
// process's pid (multiple processes share the log file, so the reader
// needs to tell them apart) that writes to primary — the process's own
// stderr — and, best-effort, appends to the shared per-machine log file.
//
// If the log file cannot be opened or created (permissions, read-only
// filesystem), that is never fatal and never silent: NewLogger reports the
// failure once on primary and falls back to logging to primary only.
func NewLogger(primary io.Writer, component string) *slog.Logger {
	writer := primary
	if file, err := openLogFile(); err != nil {
		fmt.Fprintf(primary, "l2sync: log file unavailable, logging to stderr only: %v\n", err)
	} else {
		writer = io.MultiWriter(primary, file)
	}
	return slog.New(slog.NewTextHandler(writer, nil)).With("pid", os.Getpid(), "component", component)
}

// openLogFile opens (creating if needed) the shared log file, wrapped in a
// writer that rotates it out once it exceeds maxLogSize.
func openLogFile() (io.Writer, error) {
	dir, err := config.StateDir()
	if err != nil {
		return nil, fmt.Errorf("resolve state directory: %w", err)
	}
	if err := os.MkdirAll(dir, logDirMode); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	return newRotatingWriter(filepath.Join(dir, logFileName), maxLogSize)
}
