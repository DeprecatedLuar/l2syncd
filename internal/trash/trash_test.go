//go:build linux

package trash

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMoveFallsBackInsideShareWhenXDGTrashIsUnavailable(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "missing-data"))
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination, err := Move(root, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.ToSlash(destination), ".l2sync-trash/") {
		t.Fatalf("destination = %q, want fallback trash", destination)
	}
	if _, err := os.Stat(destination); err != nil {
		t.Fatal(err)
	}
}

func TestMoveRejectsSymlinkAncestor(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "share")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "file")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := Move(root, "escape/file"); err == nil {
		t.Fatal("Move through symlink ancestor succeeded")
	}
	if _, err := os.Stat(outsideFile); err != nil {
		t.Fatalf("outside file moved: %v", err)
	}
}
