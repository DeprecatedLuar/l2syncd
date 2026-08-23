//go:build linux

package commands

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"l2syncd/internal/config"
	connectionpkg "l2syncd/internal/connection"
	"l2syncd/internal/transport"
)

func generatedPublicKey(t *testing.T, root string) string {
	t.Helper()
	paths := connectionpkg.Paths{
		PrivateKey:     filepath.Join(root, ".ssh", "id_l2sync"),
		PublicKey:      filepath.Join(root, ".ssh", "id_l2sync.pub"),
		AuthorizedKeys: filepath.Join(root, ".ssh", "authorized_keys"),
	}
	key, err := connectionpkg.EnsureKey(paths)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestConnectionAddInboundStoresStructuredPendingPeerAndWarnsForBash(t *testing.T) {
	remoteKey := generatedPublicKey(t, filepath.Join(t.TempDir(), "remote"))
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	originalShell := loginShell
	loginShell = func() (string, error) { return "/bin/bash", nil }
	t.Cleanup(func() { loginShell = originalShell })

	var stdout, stderr bytes.Buffer
	if code := connectionAdd([]string{"phone", "phone-host", "--key", remoteKey + " sender-comment"}, strings.NewReader(""), &stdout, &stderr); code != connectionExitOK {
		t.Fatalf("connectionAdd = %d, stderr %q", code, stderr.String())
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	peer := cfg.Peers["phone"]
	if peer.Address != "phone-host" || peer.Status != config.PeerPending || peer.PublicKey != remoteKey {
		t.Fatalf("peer = %#v", peer)
	}
	configBytes, err := os.ReadFile(filepath.Join(root, "config", "l2sync", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(configBytes), "fingerprint") {
		t.Fatalf("stored derived fingerprint: %s", configBytes)
	}
	if !strings.Contains(stderr.String(), "login shell \"/bin/bash\"") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	authorized, err := os.ReadFile(filepath.Join(root, ".ssh", "authorized_keys"))
	if err != nil || !strings.Contains(string(authorized), "serve --peer phone") || !strings.Contains(string(authorized), ",restrict ") {
		t.Fatalf("authorized_keys = %q, %v", authorized, err)
	}
}

func TestConnectionAddRejectsUnsafeAddressBeforePersistingOrGranting(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	key := generatedPublicKey(t, filepath.Join(root, "remote"))
	var stdout, stderr bytes.Buffer
	if code := connectionAdd([]string{"phone", "-oProxyCommand=sh", "--key", key}, strings.NewReader(""), &stdout, &stderr); code == connectionExitOK {
		t.Fatal("connection add accepted option-like destination")
	}
	if _, err := config.Load(); !errors.Is(err, config.ErrNotFound) {
		t.Fatalf("config after rejected address = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".ssh", "authorized_keys")); !os.IsNotExist(err) {
		t.Fatalf("authorized_keys after rejected address: %v", err)
	}
}

func TestConnectionAddWithoutAccessRecordsPendingAndPrintsInvite(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	originalProbe := connectionProbe
	originalInstall := connectionInstall
	connectionProbe = func(context.Context, string) error { return errors.New("unreachable") }
	connectionInstall = func(context.Context, string, string, string, string) error {
		t.Fatal("remote state was written")
		return nil
	}
	t.Cleanup(func() { connectionProbe, connectionInstall = originalProbe, originalInstall })

	var stdout, stderr bytes.Buffer
	if code := connectionAdd([]string{"friend", "alex@example.test"}, strings.NewReader(""), &stdout, &stderr); code != connectionExitOK {
		t.Fatalf("connectionAdd = %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "l2sync connection add") || !strings.Contains(stdout.String(), "--key \"") {
		t.Fatalf("invite = %q", stdout.String())
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if peer := cfg.Peers["friend"]; peer.Status != config.PeerPending || peer.PublicKey != "" {
		t.Fatalf("pending peer = %#v", peer)
	}
}

func TestConnectionAddWithAccessActivatesPinnedPeer(t *testing.T) {
	remoteKey := generatedPublicKey(t, filepath.Join(t.TempDir(), "remote"))
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	originalProbe, originalInstall := connectionProbe, connectionInstall
	originalExchange, originalConfirm := connectionExchange, connectionConfirm
	connectionProbe = func(context.Context, string) error { return nil }
	connectionConfirm = func(io.Reader, io.Writer, string) (bool, error) { return true, nil }
	installed := false
	connectionInstall = func(_ context.Context, destination, name, address, key string) error {
		installed = destination == "login@example.test" && name != "" && address != "" && strings.HasPrefix(key, "ssh-ed25519 ")
		return nil
	}
	connectionExchange = func(_ context.Context, endpoint transport.Endpoint) error {
		return endpoint.AcceptPublicKey(remoteKey)
	}
	t.Cleanup(func() {
		connectionProbe, connectionInstall = originalProbe, originalInstall
		connectionExchange, connectionConfirm = originalExchange, originalConfirm
	})
	var stdout, stderr bytes.Buffer
	if code := connectionAdd([]string{"vps", "login@example.test"}, strings.NewReader("y\n"), &stdout, &stderr); code != connectionExitOK {
		t.Fatalf("connectionAdd = %d, stderr %q", code, stderr.String())
	}
	if !installed {
		t.Fatal("remote install did not receive safe structured arguments")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if peer := cfg.Peers["vps"]; peer.Status != config.PeerActive || peer.PublicKey != remoteKey {
		t.Fatalf("active peer = %#v", peer)
	}
}

func TestConnectionRemoveRefusesBoundPeer(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", Status: config.PeerPending}
	cfg.Bindings["notes"] = []string{"phone"}
	cfg.Shared["notes"] = "/unused"
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := connectionRemove([]string{"phone"}, &stderr); code == connectionExitOK || !strings.Contains(stderr.String(), "still bound") {
		t.Fatalf("connectionRemove = %d, stderr %q", code, stderr.String())
	}
}

func TestPeerEndpointCompletesPendingHandshakeBeforeNormalUse(t *testing.T) {
	remoteKey := generatedPublicKey(t, filepath.Join(t.TempDir(), "remote"))
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", Status: config.PeerPending}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	originalExchange := connectionExchange
	connectionExchange = func(_ context.Context, endpoint transport.Endpoint) error {
		return endpoint.AcceptPublicKey(remoteKey)
	}
	t.Cleanup(func() { connectionExchange = originalExchange })
	endpoint, err := peerEndpoint(context.Background(), cfg, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.PublicKey != remoteKey || endpoint.AcceptPublicKey != nil {
		t.Fatalf("endpoint = %#v", endpoint)
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if peer := loaded.Peers["phone"]; peer.Status != config.PeerActive || peer.PublicKey != remoteKey {
		t.Fatalf("completed peer = %#v", peer)
	}
}

func TestStorePeerCannotResurrectRevokedPeer(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	key := generatedPublicKey(t, filepath.Join(root, "remote"))
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", Status: config.PeerRevoked, PublicKey: key}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	err := storePeerLocked("phone", config.Peer{Address: "phone", Status: config.PeerActive, PublicKey: key})
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("storePeerLocked error = %v", err)
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Peers["phone"].Status != config.PeerRevoked {
		t.Fatalf("peer was resurrected: %#v", loaded.Peers["phone"])
	}
}

func TestConnectionRemoveCompletesRevocationAndGrantRemoval(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	key := generatedPublicKey(t, filepath.Join(root, "remote"))
	paths, err := connectionpkg.DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := connectionpkg.AddGrant(paths.AuthorizedKeys, "phone", key); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", Status: config.PeerActive, PublicKey: key}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := connectionRemove([]string{"phone"}, &stderr); code != connectionExitOK {
		t.Fatalf("connectionRemove = %d, stderr %q", code, stderr.String())
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := loaded.Peers["phone"]; exists {
		t.Fatalf("peer remains: %#v", loaded.Peers["phone"])
	}
	authorized, err := os.ReadFile(paths.AuthorizedKeys)
	if err != nil || strings.Contains(string(authorized), "l2sync:phone") {
		t.Fatalf("authorized_keys = %q, %v", authorized, err)
	}
}
