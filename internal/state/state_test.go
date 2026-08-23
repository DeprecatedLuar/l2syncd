//go:build linux

package state

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"l2syncd/internal/metadata"
)

func TestSaveLoadAtomicJSON(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	want := New()
	want.Files["a.txt"] = File{Ino: 7, Size: 3, Hash: "abc", Metadata: metadata.Manifest{Mode: 0o640, Mtime: time.Unix(10, 20), Xattrs: map[string][]byte{"user.test": []byte("value")}}, MetadataKnown: true}
	want.Directories["folder"] = metadata.Manifest{Mode: 0o750, Mtime: time.Unix(30, 40)}
	if err := Save("notes", want); err != nil {
		t.Fatal(err)
	}
	got, err := Load("notes")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version || !reflect.DeepEqual(got, want) {
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

func TestLoadMigratesVersionOneInMemoryWithoutRewritingHistory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	path, err := Path("notes")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := `{"version":1,"files":{"a.txt":{"ino":7,"mtime":"2025-01-01T00:00:00Z","size":3,"hash":"abc"},"deleted-on-one-peer":{"ino":8,"mtime":"2025-02-01T00:00:00Z","size":9,"hash":"def"}}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err := Load("notes")
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Version != version || len(baseline.Files) != 2 {
		t.Fatalf("migrated baseline = %#v, want both historical paths", baseline)
	}
	file := baseline.Files["a.txt"]
	if file.Ino != 7 || file.Size != 3 || file.Hash != "abc" || file.MetadataKnown || !file.LegacyMtime.Equal(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("migrated file = %#v, want retained v1 fields and unknown metadata", file)
	}
	if !baseline.HasUnknownMetadata() {
		t.Fatal("migrated baseline does not report unknown metadata")
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(contents) != legacy {
		t.Fatal("legacy baseline changed during Load")
	}
}

func TestSaveRejectsUnknownMetadata(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	known := New()
	known.Files["a"] = File{Hash: "known", MetadataKnown: true}
	if err := Save("notes", known); err != nil {
		t.Fatal(err)
	}
	path, err := Path("notes")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	unknown := New()
	unknown.Files["a"] = File{Hash: "legacy"}
	if err := Save("notes", unknown); err == nil {
		t.Fatal("Save accepted unknown metadata")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("rejected Save changed baseline")
	}
}
