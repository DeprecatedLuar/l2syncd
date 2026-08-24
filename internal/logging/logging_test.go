//go:build linux

package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNewLoggerWritesToPrimaryAndFile(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	var primary bytes.Buffer
	logger := NewLogger(&primary, "test")
	logger.Info("hello", "key", "value")

	if !strings.Contains(primary.String(), "hello") {
		t.Fatalf("primary output = %q, want log record", primary.String())
	}
	pidAttr := "pid=" + strconv.Itoa(os.Getpid())
	if !strings.Contains(primary.String(), pidAttr) {
		t.Fatalf("primary output = %q, want %q", primary.String(), pidAttr)
	}

	contents, err := os.ReadFile(filepath.Join(stateHome, "l2sync", logFileName))
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(contents), "hello") {
		t.Fatalf("log file = %q, want log record", string(contents))
	}
	if !strings.Contains(string(contents), pidAttr) {
		t.Fatalf("log file = %q, want %q", string(contents), pidAttr)
	}
}

// TestNewLoggerFallsBackWhenLogFileUnopenable exercises requirement 7: an
// unopenable log file must not be fatal and must not vanish silently. It
// blocks the log directory path with a plain file (rather than relying on
// permission bits, which root ignores), so config.StateDir()'s resolved
// path exists but cannot be mkdir'd into.
func TestNewLoggerFallsBackWhenLogFileUnopenable(t *testing.T) {
	stateHome := t.TempDir()
	blocked := filepath.Join(stateHome, "l2sync")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("create blocking file: %v", err)
	}
	t.Setenv("XDG_STATE_HOME", stateHome)

	var primary bytes.Buffer
	logger := NewLogger(&primary, "test")
	logger.Info("hello")

	output := primary.String()
	if !strings.Contains(output, "log file unavailable") {
		t.Fatalf("primary output = %q, want fallback warning", output)
	}
	if !strings.Contains(output, "hello") {
		t.Fatalf("primary output = %q, want log record despite fallback", output)
	}
}
