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
	if err := guard.WriteMarker(root, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	phone, fingerprint := testPeerIdentity(t, "phone")
	cfg.Peers["phone"] = phone
	cfg.Shared["notes"] = root
	cfg.Bindings["notes"] = []string{"phone"}
	callbacks := serveCallbacks(newFolderResolver(cfg, "phone", fingerprint))
	if _, err := callbacks.ListFiles("notes"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, ".l2sync")); err != nil {
		t.Fatal(err)
	}
	if _, err := callbacks.ListFiles("notes"); err == nil || !strings.Contains(err.Error(), "marker") {
		t.Fatalf("second listing error = %v, want marker failure", err)
	}
}

func TestServeAuthorizationUsesBindingForSharedAndRemote(t *testing.T) {
	for _, registration := range []string{"shared", "remote"} {
		t.Run(registration, func(t *testing.T) {
			root := t.TempDir()
			if err := guard.WriteMarker(root, guard.Marker{Name: "notes"}); err != nil {
				t.Fatal(err)
			}
			cfg := config.New()
			phone, phoneFingerprint := testPeerIdentity(t, "phone")
			other, otherFingerprint := testPeerIdentity(t, "other")
			cfg.Peers["phone"] = phone
			cfg.Peers["other"] = other
			if registration == "shared" {
				cfg.Shared["notes"] = root
			} else {
				cfg.Remote["notes"] = root
			}
			cfg.Bindings["notes"] = []string{"phone"}
			if folder, err := newFolderResolver(cfg, "phone", phoneFingerprint)("notes"); err != nil || folder.root != root {
				t.Fatalf("authorized folder = %#v, %v", folder, err)
			}
			if _, err := newFolderResolver(cfg, "other", otherFingerprint)("notes"); err == nil {
				t.Fatal("wrong peer resolved bound folder")
			}
			delete(cfg.Bindings, "notes")
			if _, err := newFolderResolver(cfg, "phone", phoneFingerprint)("notes"); err == nil {
				t.Fatal("peer resolved unbound folder")
			}
		})
	}
}

func TestReloadingResolverRejectsDelayedSessionAfterIdentityOrStatusChange(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(folder, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	peer, authenticatedFingerprint := testPeerIdentity(t, "phone")
	cfg := config.New()
	cfg.Peers["phone"] = peer
	cfg.Shared["notes"] = folder
	cfg.Bindings["notes"] = []string{"phone"}
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

	peer.Status = config.PeerPending
	cfg.Peers["phone"] = peer
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve("notes"); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("delayed pending session authorization = %v", err)
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
		if err := guard.WriteMarker(folder, guard.Marker{Name: name}); err != nil {
			t.Fatal(err)
		}
		cfg.Shared[name] = folder
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
	peer.Status = config.PeerPending
	cfg.Peers["phone"] = peer
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := list(); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("pending discovery session = %v", err)
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
	if err := guard.WriteMarker(folder, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", Status: config.PeerActive, PublicKey: generatedPublicKey(t, filepath.Join(root, "phone-key"))}
	cfg.Peers["other"] = config.Peer{Address: "other", Status: config.PeerActive, PublicKey: generatedPublicKey(t, filepath.Join(root, "other-key"))}
	cfg.Shared["notes"] = folder
	cfg.Bindings["notes"] = []string{"phone", "other"}
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
	if got := loaded.Bindings["notes"]; len(got) != 2 {
		t.Fatalf("binding after rejected bind = %#v", got)
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

func TestServeRefusesUnknownPeerStatusBeforeProtocol(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	key := generatedPublicKey(t, filepath.Join(root, "peer"))
	fingerprint, err := connection.Fingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", Status: "corrupt", PublicKey: key}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := Serve([]string{"--peer", "phone", "--fingerprint", fingerprint}, strings.NewReader(""), io.Discard, &stderr); code == serveExitOK {
		t.Fatal("Serve accepted unknown peer status")
	}
	if !strings.Contains(stderr.String(), "invalid status") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRepeatedActiveHelloDoesNotRewriteConfig(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	peer, _ := testPeerIdentity(t, "phone")
	cfg := config.New()
	cfg.Peers["phone"] = peer
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	originalSave := saveConfig
	writes := 0
	saveConfig = func(cfg config.Config) error {
		writes++
		return originalSave(cfg)
	}
	t.Cleanup(func() { saveConfig = originalSave })
	for range 2 {
		if err := activateServedPeer("phone", peer.PublicKey); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 0 {
		t.Fatalf("repeated active hello config writes = %d", writes)
	}
}

func TestPeerActivationProducesOneRelevantConfigTriggerThenQuiesces(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	peer, _ := testPeerIdentity(t, "phone")
	peer.Status = config.PeerPending
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(folder, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	before := config.New()
	before.Peers["phone"] = peer
	before.Shared["notes"] = folder
	before.Bindings["notes"] = []string{"phone"}
	if err := config.Save(before); err != nil {
		t.Fatal(err)
	}
	originalSave := saveConfig
	writes := 0
	saveConfig = func(cfg config.Config) error {
		writes++
		return originalSave(cfg)
	}
	t.Cleanup(func() { saveConfig = originalSave })
	if err := activateServedPeer("phone", peer.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := activateServedPeer("phone", peer.PublicKey); err != nil {
		t.Fatal(err)
	}
	after, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("pending-to-active hello config writes = %d, want one", writes)
	}
	if sameCycleConfiguration(before, after) {
		t.Fatal("activation did not produce one relevant daemon trigger")
	}
	if !sameCycleConfiguration(after, config.Clone(after)) {
		t.Fatal("repeated active hello did not quiesce semantically")
	}
}

func TestServedMutationWaitsForLiveOwnerThenCommitsBaseline(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "notes")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(root, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	cfg := config.New()
	phone, fingerprint := testPeerIdentity(t, "phone")
	cfg.Peers["phone"] = phone
	cfg.Shared["notes"] = root
	cfg.Bindings["notes"] = []string{"phone"}
	callbacks := serveCallbacks(newFolderResolver(cfg, "phone", fingerprint))
	owner, err := lock.Acquire()
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
	return config.Peer{Address: name, Status: config.PeerActive, PublicKey: key}, fingerprint
}

func TestServedMutationReturnsLockTimeout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	owner, err := lock.Acquire()
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
