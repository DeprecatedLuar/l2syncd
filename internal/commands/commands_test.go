//go:build linux

package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"l2syncd/internal/config"
	"l2syncd/internal/connection"
	"l2syncd/internal/guard"
	"l2syncd/internal/index"
	"l2syncd/internal/lock"
	"l2syncd/internal/metadata"
	"l2syncd/internal/preflight"
	"l2syncd/internal/transport"
)

const (
	successExitCode       = 0
	invalidConfigExitCode = 2
)

func newTestMarker(t *testing.T, name string, ignore ...string) guard.Marker {
	t.Helper()
	id, err := guard.NewMarkerID()
	if err != nil {
		t.Fatal(err)
	}
	return guard.Marker{ID: id, Name: name, Ignore: ignore}
}

func TestAddListAndRemoveShare(t *testing.T) {
	root := t.TempDir()
	sharePath := filepath.Join(root, "notes")
	if err := os.Mkdir(sharePath, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	var stdout, stderr bytes.Buffer
	if got := Share([]string{"NOTES", sharePath}, &stderr); got != successExitCode {
		t.Fatalf("add exit code = %d, stderr = %q", got, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("add output = stdout %q, stderr %q, want silent", stdout.String(), stderr.String())
	}
	if info, err := os.Stat(filepath.Join(sharePath, ".l2sync")); err != nil || info.IsDir() {
		t.Fatalf("share marker = %v, %v, want file", info, err)
	}

	stdout.Reset()
	stderr.Reset()
	if got := List(&stdout, &stderr); got != successExitCode {
		t.Fatalf("list exit code = %d, stderr = %q", got, stderr.String())
	}
	if want := "+ notes\n"; stdout.String() != want {
		t.Fatalf("list stdout = %q, want %q", stdout.String(), want)
	}

	stdout.Reset()
	stderr.Reset()
	if got := Unshare([]string{"notes"}, &stderr); got != successExitCode {
		t.Fatalf("rm exit code = %d, stderr = %q", got, stderr.String())
	}
	if _, err := os.Stat(sharePath); err != nil {
		t.Fatalf("share path removed: %v", err)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := cfg.Shared["notes"]; exists {
		t.Fatal("share remains in config after rm")
	}
}

func TestShareCreateMissingPath(t *testing.T) {
	root := t.TempDir()
	sharePath := filepath.Join(root, "notes")
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	var stderr bytes.Buffer
	if got := Share([]string{"notes", sharePath}, &stderr); got == successExitCode {
		t.Fatalf("share succeeded on missing path without -p, stderr = %q", stderr.String())
	}

	stderr.Reset()
	if got := Share([]string{"notes", sharePath, "-p"}, &stderr); got != successExitCode {
		t.Fatalf("share -p exit code = %d, stderr = %q", got, stderr.String())
	}
	if info, err := os.Stat(sharePath); err != nil || !info.IsDir() {
		t.Fatalf("share -p created path = %v, %v, want directory", info, err)
	}
}

func TestAddRollsBackOnlyMarkerCreatedByFailedCommit(t *testing.T) {
	for _, existingMarker := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%v", existingMarker), func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
			t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
			folder := filepath.Join(root, "notes")
			if err := os.Mkdir(folder, 0o700); err != nil {
				t.Fatal(err)
			}
			wantMarker := newTestMarker(t, "notes", []string{"private/**"}...)
			if existingMarker {
				if err := guard.WriteMarker(folder, wantMarker); err != nil {
					t.Fatal(err)
				}
			}
			originalSave := saveConfig
			saveConfig = func(config.Config) error { return errors.New("injected save failure") }
			t.Cleanup(func() { saveConfig = originalSave })
			var stderr bytes.Buffer
			if code := Share([]string{"notes", folder}, &stderr); code == shareExitOK {
				t.Fatal("Add succeeded after save failure")
			}
			marker, err := guard.ReadMarker(folder)
			if existingMarker {
				if err != nil || !reflect.DeepEqual(marker, wantMarker) {
					t.Fatalf("existing marker = %#v, %v", marker, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("new marker survived failed commit: %v", err)
			}
		})
	}
}

func TestRunCycleReloadsConfigInsteadOfUsingCallerSnapshot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	if err := config.Save(config.New()); err != nil {
		t.Fatal(err)
	}
	summary, err := RunCycle(context.Background())
	if err != nil || summary.Folders != 0 {
		t.Fatalf("RunCycle stale snapshot = %#v, %v", summary, err)
	}
}

func TestLeaveUnbindsProviderBeforeLocalRegistration(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := newTestMarker(t, "notes")
	if err := guard.WriteMarker(folder, marker); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "peer-key"))}
	cfg.Remote["notes"] = config.Folder{Path: folder, Peers: []string{"phone"}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := index.Save(index.New(marker.ID)); err != nil {
		t.Fatal(err)
	}
	original := detachUnbindShare
	t.Cleanup(func() { detachUnbindShare = original })
	unbound := false
	detachUnbindShare = func(_ context.Context, endpoint transport.Endpoint, share string) error {
		if endpoint.Name != "phone" || share != "notes" {
			return fmt.Errorf("unexpected unbind %q/%q", endpoint.Name, share)
		}
		unbound = true
		return nil
	}
	var stderr bytes.Buffer
	if code := Detach([]string{"notes"}, &stderr); code != detachExitOK {
		t.Fatalf("Leave = %d, stderr = %q", code, stderr.String())
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, remains := loaded.Remote["notes"]; !unbound || remains {
		t.Fatalf("unbound = %v, config = %#v", unbound, loaded)
	}
	indexPath, err := index.Path(marker.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(indexPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leave left an index file behind: %v", err)
	}
}

func TestLeaveOfflineRetainsRetryableLocalRegistration(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(folder, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "peer-key"))}
	cfg.Remote["notes"] = config.Folder{Path: folder, Peers: []string{"phone"}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	original := detachUnbindShare
	t.Cleanup(func() { detachUnbindShare = original })
	detachUnbindShare = func(context.Context, transport.Endpoint, string) error { return errors.New("offline") }
	var stderr bytes.Buffer
	if code := Detach([]string{"notes"}, &stderr); code == detachExitOK {
		t.Fatal("Leave succeeded while provider was offline")
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if remaining := loaded.Remote["notes"]; remaining.Path != folder || !reflect.DeepEqual(remaining.Peers, []string{"phone"}) {
		t.Fatalf("offline leave changed retryable config: %#v", loaded)
	}
}

func TestRemovePrunesIndexWhileBound(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := newTestMarker(t, "notes")
	if err := guard.WriteMarker(folder, marker); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "peer-key"))}
	cfg.Shared["notes"] = config.Folder{Path: folder, Peers: []string{"phone"}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := index.Save(index.New(marker.ID)); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := Unshare([]string{"notes"}, &stderr); code != unshareExitOK {
		t.Fatalf("Remove = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(folder); err != nil {
		t.Fatalf("share path removed: %v", err)
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := loaded.Shared["notes"]; exists {
		t.Fatal("share remains in config after remove")
	}
	indexPath, err := index.Path(marker.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(indexPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove left an index file behind: %v", err)
	}
}

func TestDeterministicConflictSuffixUsesLosingFingerprint(t *testing.T) {
	left := index.Entry{Metadata: metadata.Manifest{Mtime: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)}}
	right := index.Entry{Metadata: metadata.Manifest{Mtime: time.Date(2026, 8, 23, 13, 30, 45, 0, time.FixedZone("other", -3*60*60))}}
	loser := strings.Repeat("a", 64)
	if got, want := deterministicConflictSuffix(left, right, loser), "20260823-163045-aaaaaaaaaaaa"; got != want {
		t.Fatalf("suffix = %q, want %q", got, want)
	}
}

// TestRunCycleOverlapsIndependentFolders proves a folder syncing does not
// delay a cycle for a different folder: RunCycle must not process folders
// one at a time.
func TestRunCycleOverlapsIndependentFolders(t *testing.T) {
	root, cfg := cycleTestConfig(t, true)
	firstFolder := filepath.Join(root, "notes")
	secondFolder := filepath.Join(root, "photos")
	if err := os.Mkdir(secondFolder, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.Shared["notes"] = config.Folder{Path: firstFolder, Peers: []string{"phone"}}
	cfg.Shared["photos"] = config.Folder{Path: secondFolder, Peers: []string{"phone"}}
	if err := guard.WriteMarker(firstFolder, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(secondFolder, newTestMarker(t, "photos")); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	original := runBoundFolderPlan
	entered := make(chan string, 2)
	release := make(chan struct{})
	runBoundFolderPlan = func(_ context.Context, _ config.Config, name, _ string) (int, error) {
		entered <- name
		<-release
		return 0, nil
	}
	t.Cleanup(func() { runBoundFolderPlan = original })

	done := make(chan struct{})
	go func() {
		RunCycle(context.Background())
		close(done)
	}()

	seen := map[string]bool{}
	for range 2 {
		select {
		case name := <-entered:
			seen[name] = true
		case <-time.After(time.Second):
			t.Fatal("both folder cycles did not start concurrently")
		}
	}
	if !seen["notes"] || !seen["photos"] {
		t.Fatalf("folders entered = %#v", seen)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunCycle did not complete after folders released")
	}
}

func TestCycleSharedNamesSkipsUnboundOffers(t *testing.T) {
	cfg := config.New()
	cfg.Shared["bound"] = config.Folder{Path: "/bound", Peers: []string{"phone"}}
	cfg.Shared["offer-only"] = config.Folder{Path: "/offer"}
	if got := cycleFolderNames(cfg); !reflect.DeepEqual(got, []string{"bound"}) {
		t.Fatalf("cycle shared folders = %#v, want only bound offer", got)
	}
}

func TestCycleInitiatorOrderingIsSymmetricAndRejectsEqualIdentity(t *testing.T) {
	if initiates, err := localInitiatesCycle("01", "02"); err != nil || !initiates {
		t.Fatalf("lower fingerprint initiates = %v, %v", initiates, err)
	}
	if initiates, err := localInitiatesCycle("02", "01"); err != nil || initiates {
		t.Fatalf("higher fingerprint initiates = %v, %v", initiates, err)
	}
	if _, err := localInitiatesCycle("01", "01"); err == nil {
		t.Fatal("equal fingerprints selected an initiator")
	}
}

func TestNonInitiatorRequestsActualCycleResultWithoutMutationLock(t *testing.T) {
	root, cfg := cycleTestConfig(t, false)
	folder := filepath.Join(root, "notes")
	cfg.Shared["notes"] = config.Folder{Path: folder, Peers: []string{"phone"}}
	if err := guard.WriteMarker(folder, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	original := requestPeerCycle
	requestPeerCycle = func(_ context.Context, endpoint transport.Endpoint, name string) (int, error) {
		if endpoint.Name != "phone" || name != "notes" {
			t.Fatalf("cycle request = %q/%q", endpoint.Name, name)
		}
		lockFile, err := lock.Acquire("notes")
		if err != nil {
			return 0, fmt.Errorf("request made while mutation lock held: %w", err)
		}
		if err := lock.Release(lockFile); err != nil {
			return 0, err
		}
		return 7, nil
	}
	t.Cleanup(func() { requestPeerCycle = original })

	summary, err := RunCycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Folders != 1 || summary.Actions != 7 {
		t.Fatalf("summary = %#v", summary)
	}
	requestPeerCycle = func(context.Context, transport.Endpoint, string) (int, error) {
		return 0, lock.ErrTimeout
	}
	var stderr bytes.Buffer
	if got := Now(nil, io.Discard, &stderr); got != nowExitLocked {
		t.Fatalf("remote initiator lock timeout exit = %d, stderr = %q", got, stderr.String())
	}
}

// TestInitiatorDoesNotHoldMutationLockAcrossPlanning proves the initiator no
// longer holds any lock spanning planning: a folder cycle proceeds even
// while an outside actor (e.g. a concurrent serve.go mutation for the same
// folder) is mid-hold of that folder's mutation lock. Holding a lock across
// the whole cycle -- including outbound transport round trips -- was the
// documented cause of cross-process "timed out waiting for the l2sync
// mutation lock" failures; withFolderLock (now.go) only wraps the narrow
// local-write and commit calls, not planning itself.
func TestInitiatorDoesNotHoldMutationLockAcrossPlanning(t *testing.T) {
	root, cfg := cycleTestConfig(t, true)
	folder := filepath.Join(root, "notes")
	cfg.Shared["notes"] = config.Folder{Path: folder, Peers: []string{"phone"}}
	if err := guard.WriteMarker(folder, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	original := runBoundFolderPlan
	remoteFingerprint, err := peerFingerprint(cfg.Peers["phone"])
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	runBoundFolderPlan = func(_ context.Context, _ config.Config, name, peer string) (int, error) {
		if name != "notes" || peer != "phone" {
			return 0, fmt.Errorf("unexpected plan target %q/%q", peer, name)
		}
		close(entered)
		return 3, nil
	}
	t.Cleanup(func() { runBoundFolderPlan = original })

	held, err := lock.Acquire("notes")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release(held)

	done := make(chan error, 1)
	go func() {
		_, err := runInitiatorFolderCycle(context.Background(), "notes", "phone", remoteFingerprint)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("planning did not start while the folder's mutation lock was externally held")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if _, err := runInitiatorFolderCycle(context.Background(), "notes", "other", remoteFingerprint); err == nil {
		t.Fatal("wrong authenticated peer triggered a folder cycle")
	}
}

func TestInitiatorRejectsDelayedSessionAfterPeerKeyReplacement(t *testing.T) {
	root, cfg := cycleTestConfig(t, true)
	folder := filepath.Join(root, "notes")
	cfg.Shared["notes"] = config.Folder{Path: folder, Peers: []string{"phone"}}
	if err := guard.WriteMarker(folder, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	authenticatedFingerprint, err := peerFingerprint(cfg.Peers["phone"])
	if err != nil {
		t.Fatal(err)
	}
	replacement := cfg.Peers["phone"]
	replacement.PublicKey = generatedPublicKey(t, filepath.Join(root, "replacement-key"))
	cfg.Peers["phone"] = replacement
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := runInitiatorFolderCycle(context.Background(), "notes", "phone", authenticatedFingerprint); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("delayed request-cycle authorization = %v", err)
	}
}

func TestCommitJoinedFolderRejectsExistingRemoteWithoutExpectedBinding(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(folder, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "peer-key"))}
	cfg.Remote["notes"] = config.Folder{Path: folder}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := commitAttachedFolder("notes", folder, "phone", cfg.Peers["phone"], ""); err == nil || !strings.Contains(err.Error(), "bind") {
		t.Fatalf("existing malformed remote registration = %v", err)
	}
}

func cycleTestConfig(t *testing.T, localInitiator bool) (string, config.Config) {
	t.Helper()
	base := t.TempDir()
	firstRoot := filepath.Join(base, "first")
	secondRoot := filepath.Join(base, "second")
	firstKey := generatedPublicKey(t, firstRoot)
	secondKey := generatedPublicKey(t, secondRoot)
	firstID, err := connection.Fingerprint(firstKey)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := connection.Fingerprint(secondKey)
	if err != nil {
		t.Fatal(err)
	}
	if firstID == secondID {
		t.Fatal("distinct fixture keys produced the same fingerprint")
	}
	root, remoteKey := firstRoot, secondKey
	localIsLower := firstID < secondID
	if localIsLower != localInitiator {
		root, remoteKey = secondRoot, firstKey
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	if err := os.Mkdir(filepath.Join(root, "notes"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: remoteKey}
	return root, cfg
}

func TestFreshJoinBindsBeforeAuthorizedListing(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "remote-key"))}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	originalFind, originalBind, originalUnbind, originalList := attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles
	t.Cleanup(func() {
		attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles = originalFind, originalBind, originalUnbind, originalList
	})
	bound := false
	wantProviderID, err := guard.NewMarkerID()
	if err != nil {
		t.Fatal(err)
	}
	attachFindProvider = func(context.Context, config.Config, string) (string, transport.Endpoint, error) {
		return "phone", transport.Endpoint{Name: "phone"}, nil
	}
	attachBindShare = func(context.Context, transport.Endpoint, string) (bool, error) {
		bound = true
		return true, nil
	}
	attachUnbindShare = func(context.Context, transport.Endpoint, string) error {
		bound = false
		return nil
	}
	attachListFiles = func(context.Context, transport.Endpoint, string, string) ([]transport.PeerFile, string, error) {
		if !bound {
			return nil, "", errors.New("listing reached before binding authorization")
		}
		return nil, wantProviderID, nil
	}
	var stderr bytes.Buffer
	if code := Attach([]string{"notes", folder}, &stderr); code != attachExitOK {
		t.Fatalf("Join = %d, stderr = %q", code, stderr.String())
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if joined := loaded.Remote["notes"]; joined.Path != folder || !reflect.DeepEqual(joined.Peers, []string{"phone"}) {
		t.Fatalf("joined config = %#v", loaded)
	}
	marker, err := guard.ReadMarker(folder)
	if err != nil {
		t.Fatal(err)
	}
	if marker.ID != wantProviderID {
		t.Fatalf("joined marker id = %q, want provider id %q", marker.ID, wantProviderID)
	}
}

func TestAttachCreateMissingPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "notes")
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "remote-key"))}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	if code := Attach([]string{"notes", folder}, &stderr); code == attachExitOK {
		t.Fatalf("attach succeeded on missing path without -p, stderr = %q", stderr.String())
	}

	originalFind, originalBind, originalUnbind, originalList := attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles
	t.Cleanup(func() {
		attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles = originalFind, originalBind, originalUnbind, originalList
	})
	wantProviderID, err := guard.NewMarkerID()
	if err != nil {
		t.Fatal(err)
	}
	attachFindProvider = func(context.Context, config.Config, string) (string, transport.Endpoint, error) {
		return "phone", transport.Endpoint{Name: "phone"}, nil
	}
	attachBindShare = func(context.Context, transport.Endpoint, string) (bool, error) { return true, nil }
	attachUnbindShare = func(context.Context, transport.Endpoint, string) error { return nil }
	attachListFiles = func(context.Context, transport.Endpoint, string, string) ([]transport.PeerFile, string, error) {
		return nil, wantProviderID, nil
	}
	stderr.Reset()
	if code := Attach([]string{"notes", folder, "-p"}, &stderr); code != attachExitOK {
		t.Fatalf("attach -p exit code = %d, stderr = %q", code, stderr.String())
	}
	if info, err := os.Stat(folder); err != nil || !info.IsDir() {
		t.Fatalf("attach -p created path = %v, %v, want directory", info, err)
	}
}

func joinDivergenceTestSetup(t *testing.T) (folder, extraPath, providerID string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder = filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	extraPath = filepath.Join(folder, "local-only.txt")
	if err := os.WriteFile(extraPath, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "remote-key"))}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	id, err := guard.NewMarkerID()
	if err != nil {
		t.Fatal(err)
	}
	return folder, extraPath, id
}

func TestJoinDivergenceMergeKeepsLocalExtras(t *testing.T) {
	folder, extraPath, providerID := joinDivergenceTestSetup(t)
	originalFind, originalBind, originalUnbind, originalList, originalResolve :=
		attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles, attachResolveDivergence
	t.Cleanup(func() {
		attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles, attachResolveDivergence =
			originalFind, originalBind, originalUnbind, originalList, originalResolve
	})
	attachFindProvider = func(context.Context, config.Config, string) (string, transport.Endpoint, error) {
		return "phone", transport.Endpoint{Name: "phone"}, nil
	}
	attachBindShare = func(context.Context, transport.Endpoint, string) (bool, error) { return true, nil }
	attachUnbindShare = func(context.Context, transport.Endpoint, string) error { return nil }
	attachListFiles = func(context.Context, transport.Endpoint, string, string) ([]transport.PeerFile, string, error) {
		return nil, providerID, nil
	}
	prompted := false
	attachResolveDivergence = func(_ io.Writer, _ string, extras []string) (divergenceChoice, error) {
		prompted = true
		if len(extras) != 1 || extras[0] != "local-only.txt" {
			t.Fatalf("prompted extras = %v", extras)
		}
		return divergenceMerge, nil
	}
	var stderr bytes.Buffer
	if code := Attach([]string{"notes", folder}, &stderr); code != attachExitOK {
		t.Fatalf("Join = %d, stderr = %q", code, stderr.String())
	}
	if !prompted {
		t.Fatal("divergence was not prompted")
	}
	if _, err := os.Stat(extraPath); err != nil {
		t.Fatalf("merge should keep local extra: %v", err)
	}
}

func TestJoinDivergenceDropTrashesLocalExtras(t *testing.T) {
	folder, extraPath, providerID := joinDivergenceTestSetup(t)
	originalFind, originalBind, originalUnbind, originalList, originalResolve :=
		attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles, attachResolveDivergence
	t.Cleanup(func() {
		attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles, attachResolveDivergence =
			originalFind, originalBind, originalUnbind, originalList, originalResolve
	})
	attachFindProvider = func(context.Context, config.Config, string) (string, transport.Endpoint, error) {
		return "phone", transport.Endpoint{Name: "phone"}, nil
	}
	attachBindShare = func(context.Context, transport.Endpoint, string) (bool, error) { return true, nil }
	attachUnbindShare = func(context.Context, transport.Endpoint, string) error { return nil }
	attachListFiles = func(context.Context, transport.Endpoint, string, string) ([]transport.PeerFile, string, error) {
		return nil, providerID, nil
	}
	attachResolveDivergence = func(io.Writer, string, []string) (divergenceChoice, error) {
		return divergenceDrop, nil
	}
	var stderr bytes.Buffer
	if code := Attach([]string{"notes", folder}, &stderr); code != attachExitOK {
		t.Fatalf("Join = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(extraPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("drop should trash local extra: %v", err)
	}
}

func TestJoinDivergenceNonInteractiveErrorsAndCompensates(t *testing.T) {
	folder, extraPath, providerID := joinDivergenceTestSetup(t)
	originalFind, originalBind, originalUnbind, originalList := attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles
	t.Cleanup(func() {
		attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles = originalFind, originalBind, originalUnbind, originalList
	})
	attachFindProvider = func(context.Context, config.Config, string) (string, transport.Endpoint, error) {
		return "phone", transport.Endpoint{Name: "phone"}, nil
	}
	attachBindShare = func(context.Context, transport.Endpoint, string) (bool, error) { return true, nil }
	unbound := false
	attachUnbindShare = func(context.Context, transport.Endpoint, string) error { unbound = true; return nil }
	attachListFiles = func(context.Context, transport.Endpoint, string, string) ([]transport.PeerFile, string, error) {
		return nil, providerID, nil
	}
	var stderr bytes.Buffer
	if code := Attach([]string{"notes", folder}, &stderr); code == attachExitOK {
		t.Fatal("Join succeeded on a divergence with no interactive answer")
	}
	if !unbound {
		t.Fatal("non-interactive divergence did not compensate the remote binding")
	}
	if _, err := os.Stat(extraPath); err != nil {
		t.Fatalf("non-interactive divergence should leave local files untouched: %v", err)
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, remains := loaded.Remote["notes"]; remains {
		t.Fatal("non-interactive divergence left a remote registration behind")
	}
}

func TestFreshJoinListingFailureCompensatesOnlyNewRemoteBinding(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "remote-key"))}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	originalFind, originalBind, originalUnbind, originalList := attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles
	t.Cleanup(func() {
		attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles = originalFind, originalBind, originalUnbind, originalList
	})
	attachFindProvider = func(context.Context, config.Config, string) (string, transport.Endpoint, error) {
		return "phone", transport.Endpoint{Name: "phone"}, nil
	}
	attachBindShare = func(context.Context, transport.Endpoint, string) (bool, error) { return true, nil }
	unbound := false
	attachUnbindShare = func(context.Context, transport.Endpoint, string) error { unbound = true; return nil }
	attachListFiles = func(context.Context, transport.Endpoint, string, string) ([]transport.PeerFile, string, error) {
		return nil, "", errors.New("authorization verification failed")
	}
	var stderr bytes.Buffer
	if code := Attach([]string{"notes", folder}, &stderr); code == attachExitOK {
		t.Fatal("Join succeeded after listing failure")
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, remains := loaded.Remote["notes"]; !unbound || remains {
		t.Fatalf("unbound = %v, config = %#v", unbound, loaded)
	}
	if _, err := os.Lstat(guard.MarkerPath(folder)); !os.IsNotExist(err) {
		t.Fatalf("marker created before authorized listing: %v", err)
	}
}

func TestFreshJoinPeerIdentityChangeCompensates(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "remote-key"))}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	originalFind, originalBind, originalUnbind, originalList := attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles
	t.Cleanup(func() {
		attachFindProvider, attachBindShare, attachUnbindShare, attachListFiles = originalFind, originalBind, originalUnbind, originalList
	})
	attachFindProvider = func(context.Context, config.Config, string) (string, transport.Endpoint, error) {
		return "phone", transport.Endpoint{Name: "phone"}, nil
	}
	attachBindShare = func(context.Context, transport.Endpoint, string) (bool, error) { return true, nil }
	unbound := false
	attachUnbindShare = func(context.Context, transport.Endpoint, string) error { unbound = true; return nil }
	attachListFiles = func(context.Context, transport.Endpoint, string, string) ([]transport.PeerFile, string, error) {
		changed, err := config.Load()
		if err != nil {
			return nil, "", err
		}
		peer := changed.Peers["phone"]
		peer.Address = "replacement-address"
		changed.Peers["phone"] = peer
		return nil, "", config.Save(changed)
	}
	var stderr bytes.Buffer
	if code := Attach([]string{"notes", folder}, &stderr); code == attachExitOK {
		t.Fatal("Join accepted changed RPC endpoint identity")
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, remains := loaded.Remote["notes"]; !unbound || remains {
		t.Fatalf("unbound = %v, config = %#v", unbound, loaded)
	}
	if _, err := os.Lstat(guard.MarkerPath(folder)); !os.IsNotExist(err) {
		t.Fatalf("marker survived identity-change compensation: %v", err)
	}
}

func TestJoinMarkerAndLocalBindingRegistrationAreIdempotent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	wantMarker := newTestMarker(t, "notes", []string{"private/**"}...)
	if err := guard.WriteMarker(folder, wantMarker); err != nil {
		t.Fatal(err)
	}
	created, err := prepareAttachMarker(folder, "notes", wantMarker.ID)
	if err != nil || created {
		t.Fatalf("prepare existing marker = %v, %v", created, err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "peer-key"))}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := commitAttachedFolder("notes", folder, "phone", cfg.Peers["phone"], wantMarker.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := commitAttachedFolder("notes", folder, "phone", cfg.Peers["phone"], wantMarker.ID); err != nil {
		t.Fatalf("idempotent registration: %v", err)
	}
	marker, err := guard.ReadMarker(folder)
	if err != nil || !reflect.DeepEqual(marker, wantMarker) {
		t.Fatalf("marker after rollback = %#v, %v", marker, err)
	}
	cfg, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if joined := cfg.Remote["notes"]; joined.Path != folder || !reflect.DeepEqual(joined.Peers, []string{"phone"}) {
		t.Fatalf("config after idempotent registration = %#v", cfg)
	}
}

func TestInvalidConfigExitsInvalid(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	configPath, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("[shares\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := List(&stdout, &stderr); got != invalidConfigExitCode {
		t.Fatalf("list exit code = %d, stderr = %q", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid config") {
		t.Fatalf("stderr = %q, want invalid config message", stderr.String())
	}
}

func TestNowAndAddPreserveInvalidConfigExitClassification(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	configPath, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("misspelled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if got := Now(nil, io.Discard, &stderr); got != nowExitInvalid {
		t.Fatalf("now exit = %d, stderr = %q", got, stderr.String())
	}
	stderr.Reset()
	if got := Share([]string{"notes", folder}, &stderr); got != shareExitInvalid {
		t.Fatalf("add exit = %d, stderr = %q", got, stderr.String())
	}
	if _, err := os.Stat(guard.MarkerPath(folder)); !os.IsNotExist(err) {
		t.Fatalf("add mutated marker with invalid config: %v", err)
	}
}

func TestConfigEditOpensConfigFile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	marker := filepath.Join(root, "edited-path")
	editor := filepath.Join(root, "editor.sh")
	if err := os.WriteFile(editor, []byte("#!/bin/sh\ncat > \""+marker+"\" <<EOF\n$1\nEOF\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", editor)
	t.Setenv("EDITOR", "this-editor-must-not-run")

	var stderr bytes.Buffer
	if got := ConfigEdit(nil, &stderr); got != successExitCode {
		t.Fatalf("config edit exit code = %d, stderr = %q", got, stderr.String())
	}
	contents, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(strings.TrimSpace(string(contents))); !strings.HasPrefix(got, ".config-edit-") {
		t.Fatalf("editor received %q, want isolated edit snapshot", got)
	}
	configPath, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	configContents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configContents), "# l2sync configuration") {
		t.Fatalf("config = %q, want starter preset", configContents)
	}
}

func TestConfigEditRejectsArguments(t *testing.T) {
	var stderr bytes.Buffer
	if got := ConfigEdit([]string{"unexpected"}, &stderr); got != 1 {
		t.Fatalf("config edit exit code = %d, want 1", got)
	}
	if want := "usage: l2sync config\n"; stderr.String() != want {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
}

func TestConfigEditSnapshotRefusesConcurrentConfigMutation(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	path, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	original, err := snapshotConfigForEdit(path)
	if err != nil {
		t.Fatal(err)
	}
	concurrent := append(append([]byte(nil), original...), []byte("\n# concurrent mutation\n")...)
	if err := config.Replace(concurrent); err != nil {
		t.Fatal(err)
	}
	if err := installEditedConfig(path, original, append(original, []byte("\n# editor mutation\n")...)); err == nil || !strings.Contains(err.Error(), "changed while") {
		t.Fatalf("installEditedConfig error = %v", err)
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, concurrent) {
		t.Fatalf("current config = %q, %v", current, err)
	}
}

func TestConfigEditOpensInvalidConfigForRepair(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	remotePath := filepath.Join(root, "testsync")
	if err := os.Mkdir(remotePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(remotePath, newTestMarker(t, "testsync")); err != nil {
		t.Fatal(err)
	}

	// Reproduces the reported bug: a remote entry with no matching binding
	// fails preflight.Validate with `remote folder "testsync" must bind
	// exactly one peer`.
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone"}
	cfg.Remote["testsync"] = config.Folder{Path: remotePath}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	fixed := "[peers.phone]\naddress = \"phone\"\n\n[remote.testsync]\npath = \"" + remotePath + "\"\npeers = [\"phone\"]\n"
	editor := filepath.Join(root, "editor.sh")
	script := "#!/bin/sh\ncat > \"$1\" <<'EOF'\n" + fixed + "EOF\n"
	if err := os.WriteFile(editor, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", editor)

	var stderr bytes.Buffer
	if got := ConfigEdit(nil, &stderr); got != successExitCode {
		t.Fatalf("config edit exit code = %d, stderr = %q", got, stderr.String())
	}

	configPath, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := preflight.Validate(loaded); err != nil {
		t.Fatalf("installed config still invalid: %v", err)
	}
}

func TestConfigEditNonInteractiveInvalidEditPreservesEditedFile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	// Force the non-interactive path deterministically: a regular file is
	// never a character device, unlike a real terminal (or /dev/null).
	stdinFile, err := os.CreateTemp(root, "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer stdinFile.Close()
	oldStdin := os.Stdin
	os.Stdin = stdinFile
	defer func() { os.Stdin = oldStdin }()

	editor := filepath.Join(root, "editor.sh")
	script := "#!/bin/sh\ncat > \"$1\" <<'EOF'\nnot valid toml [[[\nEOF\n"
	if err := os.WriteFile(editor, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", editor)

	var stderr bytes.Buffer
	if got := ConfigEdit(nil, &stderr); got != configEditExitError {
		t.Fatalf("config edit exit code = %d, want %d, stderr = %q", got, configEditExitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "edited config is invalid") {
		t.Fatalf("stderr = %q, want validation error", stderr.String())
	}

	configPath, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(configPath), ".config-edit-*.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("preserved edit files = %v, want exactly one", matches)
	}
	if !strings.Contains(stderr.String(), matches[0]) {
		t.Fatalf("stderr = %q, want preserved path %q", stderr.String(), matches[0])
	}
	contents, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "not valid toml") {
		t.Fatalf("preserved contents = %q, want the user's edit", contents)
	}
}

func TestConfigEditValidEditInstallsAndCleansUpTempFile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	editor := filepath.Join(root, "editor.sh")
	script := "#!/bin/sh\ncat > \"$1\" <<'EOF'\n# edited\nEOF\n"
	if err := os.WriteFile(editor, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", editor)

	var stderr bytes.Buffer
	if got := ConfigEdit(nil, &stderr); got != successExitCode {
		t.Fatalf("config edit exit code = %d, stderr = %q", got, stderr.String())
	}

	configPath, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "# edited") {
		t.Fatalf("config = %q, want edited contents installed", contents)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(configPath), ".config-edit-*.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("leftover edit temp files = %v, want none", matches)
	}
}

func TestAddRejectsUnsafeName(t *testing.T) {
	root := t.TempDir()
	sharePath := filepath.Join(root, "project")
	if err := os.Mkdir(sharePath, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	var stderr bytes.Buffer
	if got := share([]string{"My Project", sharePath}, &stderr); got != 1 {
		t.Fatalf("add exit code = %d, stderr = %q", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "folder name must contain only") {
		t.Fatalf("stderr = %q, want unsafe-name error", stderr.String())
	}

	stderr.Reset()
	if got := share([]string{"My_Project", sharePath}, &stderr); got != successExitCode {
		t.Fatalf("add exit code = %d, stderr = %q", got, stderr.String())
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Shared["my_project"]; !ok {
		t.Fatalf("shared = %#v, want lowercase share name", loaded.Shared)
	}
}

func TestIndexCommitAndStatus(t *testing.T) {
	root := t.TempDir()
	sharePath := filepath.Join(root, "notes")
	if err := os.Mkdir(sharePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sharePath, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	var stdout, stderr bytes.Buffer
	if got := Share([]string{"notes", sharePath}, &stderr); got != successExitCode {
		t.Fatalf("add exit code = %d, stderr = %q", got, stderr.String())
	}
	stderr.Reset()
	if got := IndexCommit([]string{"notes"}, &stderr); got != successExitCode {
		t.Fatalf("index commit exit code = %d, stderr = %q", got, stderr.String())
	}
	if got := Status(&stdout, &stderr); got != successExitCode || stdout.Len() != 0 {
		t.Fatalf("clean status = code %d, stdout %q, stderr %q", got, stdout.String(), stderr.String())
	}
	if err := os.WriteFile(filepath.Join(sharePath, "a.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if got := Status(&stdout, &stderr); got != successExitCode || stdout.String() != "modified notes a.txt\n" {
		t.Fatalf("modified status = code %d, stdout %q, stderr %q", got, stdout.String(), stderr.String())
	}
}

func TestIndexCommitDoesNotRewriteUnsupportedVersion(t *testing.T) {
	root := t.TempDir()
	sharePath := filepath.Join(root, "notes")
	if err := os.Mkdir(sharePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sharePath, "a.txt"), []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	var stderr bytes.Buffer
	if got := Share([]string{"notes", sharePath}, &stderr); got != successExitCode {
		t.Fatalf("add exit code = %d, stderr = %q", got, stderr.String())
	}
	marker, err := guard.ReadMarker(sharePath)
	if err != nil {
		t.Fatal(err)
	}
	indexPath, err := index.Path(marker.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(indexPath), 0o700); err != nil {
		t.Fatal(err)
	}
	// There is no migration from any earlier index format: version 3 is the
	// only format this installation understands, so any other version --
	// including a well-formed one -- must be refused, not rewritten.
	unsupported := `{"version":2,"entries":{"deleted":{"ino":7,"ctime":"2025-01-01T00:00:00Z","size":3,"hash":"abc"}}}`
	if err := os.WriteFile(indexPath, []byte(unsupported), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if got := IndexCommit([]string{"notes"}, &stderr); got == successExitCode {
		t.Fatal("index commit accepted an unsupported index version")
	}
	contents, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != unsupported {
		t.Fatal("index commit rewrote the unsupported-version file")
	}
}

func TestListVerifiesRemoteProvider(t *testing.T) {
	root := t.TempDir()
	remotePath := filepath.Join(root, "notes")
	if err := os.Mkdir(remotePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(remotePath, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone"}
	cfg.Remote["notes"] = config.Folder{Path: remotePath, Peers: []string{"phone"}}

	var stdout, stderr bytes.Buffer
	got := listWithLister(cfg, nil, &stdout, &stderr, func(context.Context, string) ([]string, error) {
		return []string{"notes"}, nil
	})
	if got != successExitCode || stdout.String() != "+ notes\n" || stderr.Len() != 0 {
		t.Fatalf("list = code %d, stdout %q, stderr %q", got, stdout.String(), stderr.String())
	}
}

func TestListQueriesConfiguredPeersWithoutLocalRemoteEntries(t *testing.T) {
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone"}
	cfg.Shared["notes"] = config.Folder{Path: "/missing/notes"}
	var stdout, stderr bytes.Buffer
	got := listWithLister(cfg, nil, &stdout, &stderr, func(context.Context, string) ([]string, error) {
		return []string{"photos"}, nil
	})
	if got != listExitOK {
		t.Fatalf("list = code %d, stderr %q", got, stderr.String())
	}
	want := "- notes\n- photos\n"
	if stdout.String() != want {
		t.Fatalf("list stdout = %q, want %q", stdout.String(), want)
	}
}

func TestListKeepsLocalEntriesWhenPeerIsUnreachable(t *testing.T) {
	root := t.TempDir()
	sharedPath := filepath.Join(root, "notes")
	if err := os.Mkdir(sharedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(sharedPath, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone"}
	cfg.Shared["notes"] = config.Folder{Path: sharedPath}

	var stdout, stderr bytes.Buffer
	got := listWithLister(cfg, []string{"phone"}, &stdout, &stderr, func(context.Context, string) ([]string, error) {
		return nil, errors.New("connection refused")
	})
	if got != listExitUnreachable || stdout.String() != "+ notes\n" {
		t.Fatalf("list = code %d, stdout %q, stderr %q", got, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "peer \"phone\" unreachable") {
		t.Fatalf("stderr = %q, want unreachable message", stderr.String())
	}
}
