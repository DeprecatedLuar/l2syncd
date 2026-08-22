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
