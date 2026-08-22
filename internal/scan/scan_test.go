//go:build linux

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"l2syncd/internal/state"
)

func TestDetectChangesAndSkipMarker(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".l2sync"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "same.txt"), []byte("same"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "new.txt"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline := state.New()
	_, snapshot, err := Detect(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Files) != 2 {
		t.Fatalf("snapshot files = %d, want 2", len(snapshot.Files))
	}
	if _, ok := snapshot.Files[".l2sync/ignored"]; ok {
		t.Fatal("marker contents entered snapshot")
	}
	changes, _, err := Detect(root, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("unchanged changes = %#v, want none", changes)
	}
	if err := os.WriteFile(filepath.Join(root, "same.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "new.txt")); err != nil {
		t.Fatal(err)
	}
	changes, _, err = Detect(root, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Fatalf("changes = %#v, want modified and deleted", changes)
	}
	if changes[0].Path != "new.txt" || changes[0].Kind != Deleted || changes[1].Path != "same.txt" || changes[1].Kind != Modified {
		t.Fatalf("changes = %#v, want deleted new.txt and modified same.txt", changes)
	}
}

func TestDetectSkipsIgnoredFilesAndSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".l2sync"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "package.json"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "kept.txt"), []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/outside", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	result, err := DetectWithIgnore(root, state.New(), []string{"custom.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if _, found := result.Snapshot.Files["node_modules/package.json"]; found {
		t.Fatal("ignored file entered snapshot")
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "link" {
		t.Fatalf("skipped = %#v, want [link]", result.Skipped)
	}
}
