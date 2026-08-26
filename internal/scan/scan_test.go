//go:build linux

package scan

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"l2syncd/internal/state"
)

func TestDetectChangesAndSkipMarker(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".l2sync"), []byte("id = \"00000000-0000-4000-8000-000000000000\"\nname = \"notes\"\n"), 0o600); err != nil {
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

func TestDetectFindsMetadataOnlyFileAndDirectoryEdits(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
	directory := filepath.Join(root, "folder")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "file")
	if err := os.WriteFile(file, []byte("same bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := DetectWithIgnore(root, state.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := os.Chmod(file, 0o640); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1_700_000_000, 321)
	if err := os.Chtimes(directory, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	second, err := DetectWithIgnore(root, first.Snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Changes) != 1 || second.Changes[0].Kind != Modified {
		t.Fatalf("changes = %#v, want one metadata-only modification", second.Changes)
	}
	if second.Snapshot.Files["folder/file"].Hash != first.Snapshot.Files["folder/file"].Hash {
		t.Fatal("metadata-only edit changed content hash")
	}
	if second.Snapshot.Directories["folder"].Mtime.Equal(first.Snapshot.Directories["folder"].Mtime) {
		t.Fatal("directory metadata edit was not captured")
	}
}

func TestLegacyUnknownMetadataDefersManifestDecisionAndProducesKnownSnapshot(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
	contents := []byte("same bytes")
	if err := os.WriteFile(filepath.Join(root, "same.txt"), contents, 0o640); err != nil {
		t.Fatal(err)
	}
	legacy := state.New()
	legacy.Files["same.txt"] = state.File{Size: int64(len(contents)), Hash: fmt.Sprintf("%x", sha256.Sum256(contents)), MetadataKnown: false}
	result, err := DetectWithIgnore(root, legacy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 0 {
		t.Fatalf("legacy unknown metadata changes = %#v, want deferred decision", result.Changes)
	}
	current := result.Snapshot.Files["same.txt"]
	if !current.MetadataKnown || current.Metadata.Mode != 0o640 || current.Hash != legacy.Files["same.txt"].Hash {
		t.Fatalf("current snapshot = %#v, want known captured metadata", current)
	}
}

func TestDetectReportsOutOfSetEntriesWithoutFailing(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
	if err := os.WriteFile(filepath.Join(root, "regular"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("regular", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(socket)
	wantSkipped := "fifo,link,socket"
	if err := unix.Bind(socket, &unix.SockaddrUnix{Name: filepath.Join(root, "socket")}); err != nil {
		if errors.Is(err, unix.EPERM) {
			wantSkipped = "fifo,link"
		} else {
			t.Fatal(err)
		}
	}
	result, err := DetectWithIgnore(root, state.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(result.Skipped, ","); got != wantSkipped {
		t.Fatalf("skipped = %q, want %q", got, wantSkipped)
	}
	if len(result.Snapshot.Files) != 1 {
		t.Fatalf("regular files = %d, want 1", len(result.Snapshot.Files))
	}
}

func TestScanFailsClosedWhenOpenedPathIsReplacedBySymlink(t *testing.T) {
	for _, ancestor := range []bool{false, true} {
		name := "leaf"
		if ancestor {
			name = "ancestor"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeTestMarker(t, root)
			directory := filepath.Join(root, "dir")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			filePath := filepath.Join(directory, "file")
			if err := os.WriteFile(filePath, []byte("inside"), 0o600); err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			outsideFile := filepath.Join(outside, "file")
			if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			original := afterScanOpen
			fired := false
			afterScanOpen = func(relative string) {
				if fired || relative != "dir/file" {
					return
				}
				fired = true
				if ancestor {
					if err := os.Rename(directory, filepath.Join(root, "held")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, directory); err != nil {
						t.Fatal(err)
					}
					return
				}
				if err := os.Rename(filePath, filepath.Join(directory, "held")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outsideFile, filePath); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { afterScanOpen = original })
			if _, err := DetectWithIgnore(root, state.New(), nil); err == nil {
				t.Fatal("scan accepted a path replaced after its anchored open")
			}
			contents, err := os.ReadFile(outsideFile)
			if err != nil || string(contents) != "outside" {
				t.Fatalf("outside contents = %q, %v", contents, err)
			}
		})
	}
}

func TestDetectRejectsHardLinkedRegularFile(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
	first := filepath.Join(root, "first")
	if err := os.WriteFile(first, []byte("linked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, filepath.Join(root, "second")); err != nil {
		t.Fatal(err)
	}
	if _, err := DetectWithIgnore(root, state.New(), nil); err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("DetectWithIgnore error = %v, want hard-link rejection", err)
	}
}

func writeTestMarker(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".l2sync"), []byte("id = \"00000000-0000-4000-8000-000000000000\"\nname = \"notes\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDetectSkipsIgnoredFilesAndSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".l2sync"), []byte("id = \"00000000-0000-4000-8000-000000000000\"\nname = \"notes\"\n"), 0o600); err != nil {
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
