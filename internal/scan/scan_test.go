//go:build linux

package scan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"l2syncd/internal/index"
	"l2syncd/internal/metadata"
	"l2syncd/internal/vector"
)

const testFingerprint = "aaaaaaaaaaaaaaaa"

func TestReconcileDetectsAddedModifiedAndDeleted(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
	if err := os.WriteFile(filepath.Join(root, "same.txt"), []byte("same"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "new.txt"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Reconcile(root, index.New("test-id"), nil, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Index.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(first.Index.Entries))
	}
	if len(first.Changes) != 2 || first.Changes[0].Kind != Added {
		t.Fatalf("changes = %#v, want two additions", first.Changes)
	}
	for _, entry := range first.Index.Entries {
		if vector.Compare(entry.Version, vector.Vector{testFingerprint: 1}) != vector.Equal {
			t.Fatalf("new entry version = %v, want {%s: 1}", entry.Version, testFingerprint)
		}
	}

	second, err := Reconcile(root, first.Index, nil, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Changes) != 0 {
		t.Fatalf("unchanged changes = %#v, want none", second.Changes)
	}
	if vector.Compare(second.Index.Entries["same.txt"].Version, first.Index.Entries["same.txt"].Version) != vector.Equal {
		t.Fatal("unchanged file's vector was touched")
	}

	if err := os.WriteFile(filepath.Join(root, "same.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "new.txt")); err != nil {
		t.Fatal(err)
	}
	third, err := Reconcile(root, first.Index, nil, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(third.Changes) != 2 || third.Changes[0].Path != "new.txt" || third.Changes[0].Kind != Deleted || third.Changes[1].Path != "same.txt" || third.Changes[1].Kind != Modified {
		t.Fatalf("changes = %#v, want deleted new.txt and modified same.txt", third.Changes)
	}
	tombstone := third.Index.Entries["new.txt"]
	if !tombstone.Deleted || tombstone.Hash != "" {
		t.Fatalf("deleted entry = %#v, want a tombstone with no content", tombstone)
	}
	if vector.Compare(tombstone.Version, first.Index.Entries["new.txt"].Version) != vector.Greater {
		t.Fatalf("tombstone version = %v, want strictly ahead of the pre-deletion version", tombstone.Version)
	}
	modified := third.Index.Entries["same.txt"]
	if vector.Compare(modified.Version, first.Index.Entries["same.txt"].Version) != vector.Greater {
		t.Fatalf("modified version = %v, want strictly ahead", modified.Version)
	}
}

func TestReconcileCarriesExistingTombstonesForward(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
	previous := index.New("test-id")
	previous.Entries["gone.txt"] = index.Entry{Version: vector.Vector{testFingerprint: 3}, Deleted: true, DeletedAt: time.Unix(1, 0)}
	result, err := Reconcile(root, previous, nil, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 0 {
		t.Fatalf("changes = %#v, want none: an existing tombstone is not a new deletion", result.Changes)
	}
	carried := result.Index.Entries["gone.txt"]
	if !carried.Deleted || vector.Compare(carried.Version, previous.Entries["gone.txt"].Version) != vector.Equal {
		t.Fatalf("carried tombstone = %#v, want untouched", carried)
	}
}

func TestReconcileTreatsLocalRecreationAfterDeletionAsANewChange(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
	previous := index.New("test-id")
	previous.Entries["back.txt"] = index.Entry{Version: vector.Vector{testFingerprint: 2}, Deleted: true, DeletedAt: time.Unix(1, 0)}
	if err := os.WriteFile(filepath.Join(root, "back.txt"), []byte("recreated"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Reconcile(root, previous, nil, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 1 || result.Changes[0].Kind != Added {
		t.Fatalf("changes = %#v, want one addition", result.Changes)
	}
	recreated := result.Index.Entries["back.txt"]
	if recreated.Deleted {
		t.Fatal("recreated file is still marked deleted")
	}
	if vector.Compare(recreated.Version, previous.Entries["back.txt"].Version) != vector.Greater {
		t.Fatalf("recreated version = %v, want strictly ahead of the tombstone", recreated.Version)
	}
}

func TestReconcileFindsMetadataOnlyFileAndDirectoryEdits(t *testing.T) {
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
	first, err := Reconcile(root, index.New("test-id"), nil, testFingerprint)
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
	second, err := Reconcile(root, first.Index, nil, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Changes) != 1 || second.Changes[0].Kind != Modified {
		t.Fatalf("changes = %#v, want one metadata-only modification", second.Changes)
	}
	if second.Index.Entries["folder/file"].Hash != first.Index.Entries["folder/file"].Hash {
		t.Fatal("metadata-only edit changed content hash")
	}
	if second.Index.Directories["folder"].Mtime.Equal(first.Index.Directories["folder"].Mtime) {
		t.Fatal("directory metadata edit was not captured")
	}
}

func TestReconcileReportsOutOfSetEntriesWithoutFailing(t *testing.T) {
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
	result, err := Reconcile(root, index.New("test-id"), nil, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(result.Skipped, ","); got != wantSkipped {
		t.Fatalf("skipped = %q, want %q", got, wantSkipped)
	}
	if len(result.Index.Entries) != 1 {
		t.Fatalf("regular files = %d, want 1", len(result.Index.Entries))
	}
}

func TestReconcileFailsClosedWhenOpenedPathIsReplacedBySymlink(t *testing.T) {
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
			if _, err := Reconcile(root, index.New("test-id"), nil, testFingerprint); err == nil {
				t.Fatal("scan accepted a path replaced after its anchored open")
			}
			contents, err := os.ReadFile(outsideFile)
			if err != nil || string(contents) != "outside" {
				t.Fatalf("outside contents = %q, %v", contents, err)
			}
		})
	}
}

func TestReconcileRejectsHardLinkedRegularFile(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
	first := filepath.Join(root, "first")
	if err := os.WriteFile(first, []byte("linked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, filepath.Join(root, "second")); err != nil {
		t.Fatal(err)
	}
	if _, err := Reconcile(root, index.New("test-id"), nil, testFingerprint); err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("Reconcile error = %v, want hard-link rejection", err)
	}
}

func TestReconcileRequiresFingerprint(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
	if _, err := Reconcile(root, index.New("test-id"), nil, ""); err == nil {
		t.Fatal("Reconcile with empty fingerprint = nil error, want error")
	}
}

func writeTestMarker(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".l2sync"), []byte("id = \"00000000-0000-4000-8000-000000000000\"\nname = \"notes\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileSkipsIgnoredFilesAndSymlinks(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
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
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("*.secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "leaked.secret"), []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := Reconcile(root, index.New("test-id"), []string{"custom.txt"}, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := result.Index.Entries["node_modules/package.json"]; found {
		t.Fatal("ignored file entered the index")
	}
	if _, found := result.Index.Entries["leaked.secret"]; found {
		t.Fatal("gitignored file entered the index")
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "link" {
		t.Fatalf("skipped = %#v, want [link]", result.Skipped)
	}
}

func TestReconcileCarriesNowIgnoredEntryForwardWithoutReportingADeletion(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Reconcile(root, index.New("test-id"), nil, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first.Index.Entries["keep.txt"]; !ok {
		t.Fatal("setup failed: keep.txt was not tracked")
	}
	second, err := Reconcile(root, first.Index, []string{"keep.txt"}, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Changes) != 0 {
		t.Fatalf("changes = %#v, want none: a newly ignored path is carried forward, not reported deleted", second.Changes)
	}
	carried, ok := second.Index.Entries["keep.txt"]
	if !ok {
		t.Fatal("now-ignored entry was dropped instead of carried forward")
	}
	// Carrying the exact prior version (not a fresh one) is what keeps this
	// entry causally Equal to whatever a peer still holds for it, so an
	// ignore-only local change can never trigger a pull-back of the file a
	// peer already has (concept.md 5.8).
	if vector.Compare(carried.Version, first.Index.Entries["keep.txt"].Version) != vector.Equal {
		t.Fatalf("carried version = %v, want unchanged from before it became ignored", carried.Version)
	}
}

func TestReconcileCarriesNowGitignoredEntryForward(t *testing.T) {
	root := t.TempDir()
	writeTestMarker(t, root)
	if err := os.WriteFile(filepath.Join(root, "secret.env"), []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Reconcile(root, index.New("test-id"), nil, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first.Index.Entries["secret.env"]; !ok {
		t.Fatal("setup failed: secret.env was not tracked")
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("secret.env\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	second, err := Reconcile(root, first.Index, nil, testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	// .gitignore itself is an ordinary tracked file: it is added, secret.env
	// is carried forward untouched, nothing is reported deleted.
	if len(second.Changes) != 1 || second.Changes[0].Path != ".gitignore" || second.Changes[0].Kind != Added {
		t.Fatalf("changes = %#v, want only .gitignore added", second.Changes)
	}
	carried, ok := second.Index.Entries["secret.env"]
	if !ok || vector.Compare(carried.Version, first.Index.Entries["secret.env"].Version) != vector.Equal {
		t.Fatalf("carried secret.env = %#v, want unchanged version", carried)
	}
}

func TestListEntriesProjectsLiveFilesDirectoriesAndTombstones(t *testing.T) {
	idx := index.New("test-id")
	idx.Entries["live.txt"] = index.Entry{Version: vector.Vector{testFingerprint: 1}, Hash: "abc", Size: 3}
	idx.Entries["gone.txt"] = index.Entry{Version: vector.Vector{testFingerprint: 2}, Deleted: true, DeletedAt: time.Unix(5, 0)}
	idx.Directories["folder"] = metadataWithMode(0o750)

	files := ListEntries(idx)
	if len(files) != 3 {
		t.Fatalf("files = %#v, want 3", files)
	}
	byPath := make(map[string]ListedFile, len(files))
	for _, file := range files {
		byPath[file.Path] = file
	}
	live, ok := byPath["live.txt"]
	if !ok || live.Deleted || live.Hash != "abc" || live.Size != 3 {
		t.Fatalf("live = %#v", live)
	}
	tombstone, ok := byPath["gone.txt"]
	if !ok || !tombstone.Deleted || tombstone.Hash != "" {
		t.Fatalf("tombstone = %#v, want no content", tombstone)
	}
	directory, ok := byPath["folder"]
	if !ok || !directory.Directory {
		t.Fatalf("directory = %#v", directory)
	}
}

func metadataWithMode(mode uint32) metadata.Manifest {
	return metadata.Manifest{Mode: mode}
}
