//go:build linux

package commands

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"l2syncd/internal/guard"
	"l2syncd/internal/index"
	"l2syncd/internal/transport"
	"l2syncd/internal/vector"
)

// TestApplyLocalDeleteSetsDeletedAt guards against a bug found in live
// paired testing: applyLocalDelete committed a tombstone with a zero-value
// DeletedAt when the initiator applied a peer-driven delete locally, while
// serve.go's fileDeleter correctly set it. concept.md 4.2 requires a
// tombstone to carry the deletion time recorded.
func TestApplyLocalDeleteSetsDeletedAt(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "notes")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	relative := "a.txt"
	if err := os.WriteFile(filepath.Join(root, relative), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))

	folderID, err := guard.NewMarkerID()
	if err != nil {
		t.Fatal(err)
	}
	vec := vector.Vector{"peer-fingerprint": 1}
	before := time.Now().UTC()

	if err := applyLocalDelete(context.Background(), "notes", folderID, root, relative, vec); err != nil {
		t.Fatal(err)
	}

	idx, err := index.Load(folderID)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := idx.Entries[relative]
	if !ok {
		t.Fatalf("index has no entry for %q", relative)
	}
	if !entry.Deleted {
		t.Fatalf("entry.Deleted = false, want true")
	}
	if entry.DeletedAt.IsZero() {
		t.Fatal("entry.DeletedAt is zero, want the recorded deletion time")
	}
	if entry.DeletedAt.Before(before) {
		t.Fatalf("entry.DeletedAt = %v, want >= %v", entry.DeletedAt, before)
	}
}

func TestUncommittedMarksOnlyCommitFailures(t *testing.T) {
	if uncommitted(nil) != nil {
		t.Fatal("uncommitted(nil) != nil")
	}
	wrapped := uncommitted(errors.New("disk full"))
	if !errors.Is(wrapped, errUncommitted) || !strings.Contains(wrapped.Error(), "disk full") {
		t.Fatalf("uncommitted = %v", wrapped)
	}
}

func TestSharedPeerErrorSeparatesTransportFromRefusal(t *testing.T) {
	err := sharedPeerError("phone", "notes", transport.NewAuthErrorForTest("connect to peer: timeout"))
	if strings.Contains(err.Error(), "does not serve") {
		t.Fatalf("transport failure reported as not served: %v", err)
	}
	served := sharedPeerError("phone", "notes", errors.New(`folder "notes" is not bound`))
	if !strings.Contains(served.Error(), "does not serve") {
		t.Fatalf("application refusal = %v, want does-not-serve", served)
	}
}
