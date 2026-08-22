//go:build linux

package preflight

import (
	"os"
	"path/filepath"
	"testing"

	"l2syncd/internal/config"
)

func TestCheckDoesNotCreateStateDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	if err := Check(config.New()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	stateDir, err := config.StateDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("state directory exists after Check(): %v", err)
	}
}

func TestCheckRejectsEmptyPeerAddress(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	cfg := config.New()
	cfg.Peers["phone"] = ""
	if err := Check(cfg); err == nil {
		t.Fatal("Check() error = nil, want empty peer address error")
	}
}
