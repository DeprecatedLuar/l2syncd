//go:build linux

package apply

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteIsAtomicAndReplacesRecoverably(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	path := filepath.Join(root, "nested", "note.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(root, "nested/note.txt", bytes.NewBufferString("new"), ""); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "new" {
		t.Fatalf("contents = %q, want new", contents)
	}
	trashRoot := filepath.Join(root, ".l2sync-trash")
	if _, err := os.Stat(trashRoot); err != nil {
		t.Fatalf("trash root = %v", err)
	}
}

func TestPreserveConflictKeepsExtension(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "note.md")
	if err := os.WriteFile(path, []byte("local"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PreserveConflict(root, "note.md", "phone"); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(root, "note.l2sync-conflict-*-phone.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("conflict files = %v", matches)
	}
	if strings.HasSuffix(matches[0], ".txt") {
		t.Fatal("conflict extension changed")
	}
}

func TestWriteHashMismatchLeavesNoPartialDestination(t *testing.T) {
	root := t.TempDir()
	err := Write(root, "nested/file.txt", bytes.NewBufferString("wrong"), strings.Repeat("0", 64))
	if err == nil {
		t.Fatal("Write() error = nil for hash mismatch")
	}
	if _, statErr := os.Stat(filepath.Join(root, "nested", "file.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("destination stat error = %v, want not exists", statErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(root, "nested", ".l2sync-apply-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}
