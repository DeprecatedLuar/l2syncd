//go:build linux

package index

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"l2syncd/internal/metadata"
	"l2syncd/internal/vector"
)

const testID = "7f3a91c2-4e8b-4d15-9a06-2c5e1f8b3d47"

func withStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	return dir
}

func TestPathIsKeyedByIDUnderIndexSubdir(t *testing.T) {
	stateDir := withStateDir(t)
	path, err := Path(testID)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(stateDir, "l2sync", "index", testID+".json")
	if path != want {
		t.Fatalf("Path(%q) = %q, want %q", testID, path, want)
	}
}

func TestPathRejectsInvalidID(t *testing.T) {
	withStateDir(t)
	for _, id := range []string{"", "not-a-uuid", "../escape", "some-name"} {
		if _, err := Path(id); err == nil {
			t.Fatalf("Path(%q) = nil error, want error", id)
		}
	}
}

func TestLoadMissingReturnsEmptyIndexAndErrNotFound(t *testing.T) {
	withStateDir(t)
	idx, err := Load(testID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if idx.ID != testID || len(idx.Entries) != 0 {
		t.Fatalf("idx = %#v, want empty index for %q", idx, testID)
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	withStateDir(t)
	idx := New(testID)
	idx.Entries["notes/a.md"] = Entry{
		Version:  vector.Vector{"a1b2c3d4e5f60718": 7, "0f1e2d3c4b5a6978": 3},
		Hash:     "deadbeef",
		Size:     412,
		Ino:      236953,
		Metadata: metadataWithMode(0o640),
	}
	idx.Entries["notes/old.md"] = Entry{
		Version: vector.Vector{"a1b2c3d4e5f60718": 4},
		Deleted: true,
	}
	idx.Directories["notes"] = metadataWithMode(0o750)
	if err := Save(idx); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(testID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != testID || loaded.Version != version {
		t.Fatalf("loaded = %#v", loaded)
	}
	live, ok := loaded.Entries["notes/a.md"]
	if !ok || live.Hash != "deadbeef" || live.Size != 412 || live.Deleted {
		t.Fatalf("live entry = %#v", live)
	}
	if vector.Compare(live.Version, vector.Vector{"a1b2c3d4e5f60718": 7, "0f1e2d3c4b5a6978": 3}) != vector.Equal {
		t.Fatalf("live entry vector = %v, want round-tripped exactly", live.Version)
	}
	tombstone, ok := loaded.Entries["notes/old.md"]
	if !ok || !tombstone.Deleted || tombstone.Hash != "" {
		t.Fatalf("tombstone entry = %#v", tombstone)
	}
	if _, ok := loaded.Directories["notes"]; !ok {
		t.Fatalf("directories = %#v, want notes preserved", loaded.Directories)
	}
}

func TestSaveRejectsWrongVersion(t *testing.T) {
	withStateDir(t)
	idx := New(testID)
	idx.Version = 2
	if err := Save(idx); err == nil {
		t.Fatal("Save with wrong version = nil error, want error")
	}
}

func TestSaveRejectsInvalidID(t *testing.T) {
	withStateDir(t)
	idx := New("not-a-uuid")
	if err := Save(idx); err == nil {
		t.Fatal("Save with invalid id = nil error, want error")
	}
}

func TestLoadRejectsUnsupportedVersionNamingTheFile(t *testing.T) {
	withStateDir(t)
	path, err := Path(testID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"files":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Load(testID)
	if err == nil {
		t.Fatal("Load of version-2 file = nil error, want a hard error")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "re-pair") {
		t.Fatalf("error = %q, want it to name the file and say re-pair, no migration", err.Error())
	}
}

func TestLoadRejectsVersion1LegacyFile(t *testing.T) {
	withStateDir(t)
	path, err := Path(testID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"files":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(testID); err == nil {
		t.Fatal("Load of version-1 file = nil error, want a hard error")
	}
}

func metadataWithMode(mode uint32) metadata.Manifest {
	return metadata.Manifest{Mode: mode}
}
