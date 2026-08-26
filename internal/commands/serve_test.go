//go:build linux

package commands

import (
	"bytes"
	"crypto/sha256"
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
	"l2syncd/internal/lock"
	"l2syncd/internal/metadata"
	"l2syncd/internal/state"
)

func TestServeResolverRevalidatesMarkerForEveryOperation(t *testing.T) {
	root := t.TempDir()
	if err := guard.WriteMarker(root, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	phone, fingerprint := testPeerIdentity(t, "phone")
	cfg.Peers["phone"] = phone
	cfg.Shared["notes"] = config.Folder{Path: root, Peers: []string{"phone"}}
	callbacks := serveCallbacks(newFolderResolver(cfg, "phone", fingerprint))
	if _, _, err := callbacks.ListFiles("notes", ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, ".l2sync")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := callbacks.ListFiles("notes", ""); err == nil || !strings.Contains(err.Error(), "marker") {
		t.Fatalf("second listing error = %v, want marker failure", err)
	}
}

func TestListFilesCallbackRejectsFolderIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	marker := newTestMarker(t, "notes")
	if err := guard.WriteMarker(root, marker); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	phone, fingerprint := testPeerIdentity(t, "phone")
	cfg.Peers["phone"] = phone
	cfg.Shared["notes"] = config.Folder{Path: root, Peers: []string{"phone"}}
	callbacks := serveCallbacks(newFolderResolver(cfg, "phone", fingerprint))

	requesterID, err := guard.NewMarkerID()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = callbacks.ListFiles("notes", requesterID)
	if err == nil {
		t.Fatal("ListFiles callback accepted a mismatched folder identity")
	}
	if !strings.Contains(err.Error(), requesterID) || !strings.Contains(err.Error(), marker.ID) {
		t.Fatalf("ListFiles callback error = %v, want both ids named", err)
	}

	_, id, err := callbacks.ListFiles("notes", marker.ID)
	if err != nil {
		t.Fatalf("ListFiles callback with matching id = %v", err)
	}
	if id != marker.ID {
		t.Fatalf("ListFiles callback id = %q, want %q", id, marker.ID)
	}
}

func TestServeAuthorizationUsesBindingForSharedAndRemote(t *testing.T) {
	for _, registration := range []string{"shared", "remote"} {
		t.Run(registration, func(t *testing.T) {
			root := t.TempDir()
			if err := guard.WriteMarker(root, newTestMarker(t, "notes")); err != nil {
				t.Fatal(err)
			}
			cfg := config.New()
			phone, phoneFingerprint := testPeerIdentity(t, "phone")
			other, otherFingerprint := testPeerIdentity(t, "other")
			cfg.Peers["phone"] = phone
			cfg.Peers["other"] = other
			if registration == "shared" {
				cfg.Shared["notes"] = config.Folder{Path: root, Peers: []string{"phone"}}
			} else {
				cfg.Remote["notes"] = config.Folder{Path: root, Peers: []string{"phone"}}
			}
			if folder, err := newFolderResolver(cfg, "phone", phoneFingerprint)("notes"); err != nil || folder.root != root {
				t.Fatalf("authorized folder = %#v, %v", folder, err)
			}
			if _, err := newFolderResolver(cfg, "other", otherFingerprint)("notes"); err == nil {
				t.Fatal("wrong peer resolved bound folder")
			}
			if registration == "shared" {
				cfg.Shared["notes"] = config.Folder{Path: root}
			} else {
				cfg.Remote["notes"] = config.Folder{Path: root}
			}
			if _, err := newFolderResolver(cfg, "phone", phoneFingerprint)("notes"); err == nil {
				t.Fatal("peer resolved unbound folder")
			}
		})
	}
}

func TestReloadingResolverRejectsDelayedSessionAfterIdentityOrKeyRemoval(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(folder, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	peer, authenticatedFingerprint := testPeerIdentity(t, "phone")
	cfg := config.New()
	cfg.Peers["phone"] = peer
	cfg.Shared["notes"] = config.Folder{Path: folder, Peers: []string{"phone"}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	resolve := newReloadingFolderResolver("phone", authenticatedFingerprint)
	if _, err := resolve("notes"); err != nil {
		t.Fatal(err)
	}

	replacement, _ := testPeerIdentity(t, "replacement")
	replacement.Address = "phone"
	cfg.Peers["phone"] = replacement
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve("notes"); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("delayed old-key session authorization = %v", err)
	}

	peer.PublicKey = ""
	cfg.Peers["phone"] = peer
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve("notes"); err == nil || !strings.Contains(err.Error(), "no configured public key") {
		t.Fatalf("delayed keyless session authorization = %v", err)
	}
}

func TestReloadingShareListerReflectsCurrentValidatedAuthorizationAndOffers(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	cfg := config.New()
	peer, authenticatedFingerprint := testPeerIdentity(t, "phone")
	cfg.Peers["phone"] = peer
	for _, name := range []string{"notes", "photos"} {
		folder := filepath.Join(root, name)
		if err := os.Mkdir(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := guard.WriteMarker(folder, newTestMarker(t, name)); err != nil {
			t.Fatal(err)
		}
		cfg.Shared[name] = config.Folder{Path: folder}
	}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	list := newReloadingShareLister("phone", authenticatedFingerprint)
	if shares, err := list(); err != nil || !reflect.DeepEqual(shares, []string{"notes", "photos"}) {
		t.Fatalf("initial shares = %#v, %v", shares, err)
	}
	delete(cfg.Shared, "notes")
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if shares, err := list(); err != nil || !reflect.DeepEqual(shares, []string{"photos"}) {
		t.Fatalf("shares after removal = %#v, %v", shares, err)
	}
	replacement, _ := testPeerIdentity(t, "replacement")
	replacement.Address = "phone"
	cfg.Peers["phone"] = replacement
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := list(); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("old-key discovery session = %v", err)
	}
	peer.PublicKey = ""
	cfg.Peers["phone"] = peer
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := list(); err == nil || !strings.Contains(err.Error(), "no configured public key") {
		t.Fatalf("keyless discovery session = %v", err)
	}
}

func TestBindShareRejectsMalformedExistingBinding(t *testing.T) {
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
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "phone-key"))}
	cfg.Peers["other"] = config.Peer{Address: "other", PublicKey: generatedPublicKey(t, filepath.Join(root, "other-key"))}
	cfg.Shared["notes"] = config.Folder{Path: folder, Peers: []string{"phone", "other"}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := connection.Fingerprint(cfg.Peers["phone"].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bindSharedFolder("phone", fingerprint, "notes"); err == nil {
		t.Fatal("BindShare collapsed malformed binding")
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Shared["notes"].Peers; len(got) != 2 {
		t.Fatalf("binding after rejected bind = %#v", got)
	}
}

// TestBindSharedFolderRefusesRemoteFolder guards the no-transitive-re-export
// rule: bindSharedFolder must only ever bind a folder registered in Shared,
// never one registered in Remote, now that both tables share one Folder
// struct and Shared-membership is the only thing enforcing this.
func TestBindSharedFolderRefusesRemoteFolder(t *testing.T) {
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
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: generatedPublicKey(t, filepath.Join(root, "phone-key"))}
	cfg.Remote["notes"] = config.Folder{Path: folder}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := connection.Fingerprint(cfg.Peers["phone"].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bindSharedFolder("phone", fingerprint, "notes"); err == nil {
		t.Fatal("bindSharedFolder bound a remote (joined) folder")
	}
}

func TestServeRefusesUnknownForcedCommandPeer(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	if err := config.Save(config.New()); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := Serve([]string{"--peer", "removed", "--fingerprint", strings.Repeat("0", 64)}, strings.NewReader(""), io.Discard, &stderr); code == serveExitOK {
		t.Fatal("Serve accepted a forced command for an absent peer")
	}
	if !strings.Contains(stderr.String(), "not configured") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestServeRefusesPeerWithoutPublicKey(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone"}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := Serve([]string{"--peer", "phone", "--fingerprint", strings.Repeat("0", 64)}, strings.NewReader(""), io.Discard, &stderr); code == serveExitOK {
		t.Fatal("Serve accepted a peer with no configured public key")
	}
	if !strings.Contains(stderr.String(), "no configured public key") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestServedMutationWaitsForLiveOwnerThenCommitsBaseline(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "notes")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(root, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	cfg := config.New()
	phone, fingerprint := testPeerIdentity(t, "phone")
	cfg.Peers["phone"] = phone
	cfg.Shared["notes"] = config.Folder{Path: root, Peers: []string{"phone"}}
	callbacks := serveCallbacks(newFolderResolver(cfg, "phone", fingerprint))
	owner, err := lock.Acquire("notes")
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("serialized")
	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	manifest := metadata.Manifest{Mode: 0o600, Mtime: time.Unix(100, 200)}
	done := make(chan error, 1)
	go func() {
		done <- callbacks.WriteFile("notes", "a.txt", hash, manifest, bytes.NewReader(data))
	}()
	select {
	case err := <-done:
		t.Fatalf("mutation completed while lock held: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := lock.Release(owner); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("mutation did not continue after lock release")
	}
	baseline, err := state.Load("notes")
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Files["a.txt"].Hash != hash {
		t.Fatalf("baseline = %#v, want committed file", baseline.Files)
	}
}

func testPeerIdentity(t *testing.T, name string) (config.Peer, string) {
	t.Helper()
	key := generatedPublicKey(t, filepath.Join(t.TempDir(), name))
	fingerprint, err := connection.Fingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	return config.Peer{Address: name, PublicKey: key}, fingerprint
}

func TestServedMutationReturnsLockTimeout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	owner, err := lock.Acquire("notes")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release(owner)
	resolve := func(string) (resolvedFolder, error) {
		return resolvedFolder{}, nil
	}
	err = mutateServedFolderWithin("notes", resolve, 20*time.Millisecond, func(resolvedFolder) error {
		return nil
	})
	if !errors.Is(err, lock.ErrTimeout) {
		t.Fatalf("mutation error = %v, want lock timeout", err)
	}
	if got := serveFailureExit(err); got != serveExitLocked {
		t.Fatalf("serve exit = %d, want distinct lock exit %d", got, serveExitLocked)
	}
}
