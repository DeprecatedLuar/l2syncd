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

func TestGlobalVectorMergesEveryEntry(t *testing.T) {
	idx := New(testID)
	idx.Entries["a"] = Entry{Version: vector.Vector{"m1": 3, "m2": 1}}
	idx.Entries["b"] = Entry{Version: vector.Vector{"m1": 1, "m2": 5}, Deleted: true}
	got := GlobalVector(idx)
	want := vector.Vector{"m1": 3, "m2": 5}
	if vector.Compare(got, want) != vector.Equal {
		t.Fatalf("GlobalVector = %v, want %v", got, want)
	}
}

func TestGlobalVectorOfEmptyIndexIsNil(t *testing.T) {
	if got := GlobalVector(New(testID)); len(got) != 0 {
		t.Fatalf("GlobalVector(empty) = %v, want empty", got)
	}
}

// TestAcknowledgeTwoMembersPrunesWhenBothCatchUp covers the two-peer case:
// pruning happens at the end of the cycle in which both sides agree
// (concept.md 4.2 "Tombstone lifetime").
func TestAcknowledgeTwoMembersPrunesWhenBothCatchUp(t *testing.T) {
	idx := New(testID)
	idx.Entries["gone.txt"] = Entry{Version: vector.Vector{"a": 2}, Deleted: true}
	idx.Entries["live.txt"] = Entry{Version: vector.Vector{"a": 1}}

	idx = Acknowledge(idx, "peer-b", vector.Vector{"a": 1}, []string{"peer-b"})
	if _, exists := idx.Entries["gone.txt"]; !exists {
		t.Fatal("tombstone pruned before its acknowledged member caught up")
	}

	idx = Acknowledge(idx, "peer-b", vector.Vector{"a": 2}, []string{"peer-b"})
	if _, exists := idx.Entries["gone.txt"]; exists {
		t.Fatal("tombstone retained after its only member fully acknowledged it")
	}
	if _, exists := idx.Entries["live.txt"]; !exists {
		t.Fatal("Prune removed a live entry, not just tombstones")
	}
}

// TestPruneRetainsTombstoneWithAbsentMember covers a three-member folder
// where one member has never acknowledged: the tombstone must be retained
// regardless of what the other members have confirmed, and only pruned once
// every member (including the absent one) reconnects and acknowledges.
func TestPruneRetainsTombstoneWithAbsentMember(t *testing.T) {
	idx := New(testID)
	idx.Entries["gone.txt"] = Entry{Version: vector.Vector{"a": 5}, Deleted: true}
	idx.Acknowledged["peer-b"] = vector.Vector{"a": 5}
	// peer-c has never acknowledged anything for this folder.
	members := []string{"peer-b", "peer-c"}

	pruned := Prune(idx, members)
	if _, exists := pruned.Entries["gone.txt"]; !exists {
		t.Fatal("tombstone pruned despite an absent member: partial acknowledgment must never prune")
	}

	pruned.Acknowledged["peer-c"] = vector.Vector{"a": 5}
	pruned = Prune(pruned, members)
	if _, exists := pruned.Entries["gone.txt"]; exists {
		t.Fatal("tombstone retained after every known member acknowledged it")
	}
}

// TestPruneRejectsPartialAcknowledgmentVector covers forcing a prune with a
// member whose acknowledged vector does not yet dominate the tombstone: it
// must be rejected outright, not merely discouraged.
func TestPruneRejectsPartialAcknowledgmentVector(t *testing.T) {
	idx := New(testID)
	idx.Entries["gone.txt"] = Entry{Version: vector.Vector{"a": 2, "b": 1}, Deleted: true}
	// peer-b's acknowledged vector is concurrent with the tombstone's, not
	// dominating it.
	idx.Acknowledged["peer-b"] = vector.Vector{"a": 1, "b": 2}

	pruned := Prune(idx, []string{"peer-b"})
	if _, exists := pruned.Entries["gone.txt"]; !exists {
		t.Fatal("tombstone pruned against a non-dominating acknowledged vector")
	}
}

func TestPruneWithNoKnownMembersNeverGuesses(t *testing.T) {
	idx := New(testID)
	idx.Entries["gone.txt"] = Entry{Version: vector.Vector{"a": 1}, Deleted: true}
	pruned := Prune(idx, nil)
	if _, exists := pruned.Entries["gone.txt"]; !exists {
		t.Fatal("tombstone pruned with no known members to check against")
	}
}
