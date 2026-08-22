//go:build linux

package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadAtomicJSON(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	want := New()
	want.Files["a.txt"] = File{Ino: 7, Size: 3, Hash: "abc"}
	if err := Save("notes", want); err != nil {
		t.Fatal(err)
	}
	got, err := Load("notes")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version || got.Files["a.txt"] != want.Files["a.txt"] {
		t.Fatalf("loaded baseline = %#v, want %#v", got, want)
	}
	path, err := Path("notes")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
