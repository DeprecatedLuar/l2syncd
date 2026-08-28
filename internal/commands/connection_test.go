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
	"strings"
	"testing"

	"l2syncd/internal/config"
	connectionpkg "l2syncd/internal/connection"
	"l2syncd/internal/guard"
	"l2syncd/internal/index"
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
	if peer.Address != "phone-host" || peer.PublicKey != remoteKey {
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
	connectionProbe = func(context.Context, string) error { return errors.New("Permission denied (publickey)") }
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
	if peer := cfg.Peers["friend"]; peer.PublicKey != "" {
		t.Fatalf("pending peer = %#v", peer)
	}
}

func TestConnectionAddUnreachableFailsWithoutWritingConfig(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	originalProbe := connectionProbe
	originalInstall := connectionInstall
	connectionProbe = func(context.Context, string) error {
		return fmt.Errorf("%w: ssh: Could not resolve hostname bogus: Name or service not known", errSSHUnreachable)
	}
	connectionInstall = func(context.Context, string, string, string, string) error {
		t.Fatal("remote state was written")
		return nil
	}
	t.Cleanup(func() { connectionProbe, connectionInstall = originalProbe, originalInstall })

	var stdout, stderr bytes.Buffer
	if code := connectionAdd([]string{"bogus"}, strings.NewReader(""), &stdout, &stderr); code != connectionExitError {
		t.Fatalf("connectionAdd = %d, stdout %q", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "unreachable") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if _, err := config.Load(); !errors.Is(err, config.ErrNotFound) {
		t.Fatalf("config after unreachable probe = %v", err)
	}
}

func TestConnectionAddWithAccessActivatesPinnedPeer(t *testing.T) {
	remoteKey := generatedPublicKey(t, filepath.Join(t.TempDir(), "remote"))
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	originalProbe, originalInstall := connectionProbe, connectionInstall
	originalExchange := connectionExchange
	connectionProbe = func(context.Context, string) error { return nil }
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
		connectionExchange = originalExchange
	})
	var stdout, stderr bytes.Buffer
	if code := connectionAdd([]string{"vps", "login@example.test"}, strings.NewReader(""), &stdout, &stderr); code != connectionExitOK {
		t.Fatalf("connectionAdd = %d, stderr %q", code, stderr.String())
	}
	if !installed {
		t.Fatal("remote install did not receive safe structured arguments")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if peer := cfg.Peers["vps"]; peer.PublicKey != remoteKey {
		t.Fatalf("active peer = %#v", peer)
	}
}

// forceNonInteractiveStdin points os.Stdin at a regular file for the
// duration of the test: a regular file is never a character device, unlike
// a real terminal (or /dev/null), so this deterministically forces the
// non-interactive path regardless of how the test binary itself was invoked.
func forceNonInteractiveStdin(t *testing.T, root string) {
	t.Helper()
	stdinFile, err := os.CreateTemp(root, "stdin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdinFile.Close() })
	oldStdin := os.Stdin
	os.Stdin = stdinFile
	t.Cleanup(func() { os.Stdin = oldStdin })
}

// TestConnectionRemoveRefusesBoundPeerWithoutForce covers the non-interactive
// path: connection rm never silently guesses a decision when folders are
// bound to the peer, and tells the caller to use --force.
func TestConnectionRemoveRefusesBoundPeerWithoutForce(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	forceNonInteractiveStdin(t, root)
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone"}
	cfg.Shared["notes"] = config.Folder{Path: "/unused", Peers: []string{"phone"}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code := connectionRemove([]string{"phone"}, &stderr)
	if code == connectionExitOK || !strings.Contains(stderr.String(), "notes") || !strings.Contains(stderr.String(), "--force") {
		t.Fatalf("connectionRemove = %d, stderr %q", code, stderr.String())
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := loaded.Peers["phone"]; !exists {
		t.Fatal("peer was removed despite refusal")
	}
	if folder := loaded.Shared["notes"]; len(folder.Peers) != 1 || folder.Peers[0] != "phone" {
		t.Fatalf("shared folder binding changed despite refusal: %#v", folder)
	}
}

// TestConnectionRemoveForceUnbindsSharedFolder covers --force revoking a peer
// bound to a shared folder: the peer and its grant are gone, but the shared
// folder registration survives with its peers cleared (an unbound folder is
// refused to everyone, so this alone cuts access).
func TestConnectionRemoveForceUnbindsSharedFolder(t *testing.T) {
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
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(folder, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: key}
	cfg.Shared["notes"] = config.Folder{Path: folder, Peers: []string{"phone"}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := connectionRemove([]string{"phone", "--force"}, &stderr); code != connectionExitOK {
		t.Fatalf("connectionRemove = %d, stderr %q", code, stderr.String())
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := loaded.Peers["phone"]; exists {
		t.Fatalf("peer remains: %#v", loaded.Peers["phone"])
	}
	sharedFolder, exists := loaded.Shared["notes"]
	if !exists {
		t.Fatal("shared folder registration was dropped, not unbound")
	}
	if len(sharedFolder.Peers) != 0 {
		t.Fatalf("shared folder still bound: %#v", sharedFolder)
	}
	authorized, err := os.ReadFile(paths.AuthorizedKeys)
	if err != nil || strings.Contains(string(authorized), "l2sync:phone") {
		t.Fatalf("authorized_keys = %q, %v", authorized, err)
	}
}

// TestConnectionRemoveForceDropsRemoteFolderAndPrunesIndex covers --force
// revoking a peer bound to a remote folder: since that registration only
// existed as the peer's offer, it is dropped (mirroring leave) and its index
// is pruned.
func TestConnectionRemoveForceDropsRemoteFolderAndPrunesIndex(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	folder := filepath.Join(root, "docs")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := newTestMarker(t, "docs")
	if err := guard.WriteMarker(folder, marker); err != nil {
		t.Fatal(err)
	}
	key := generatedPublicKey(t, filepath.Join(root, "remote"))
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: key}
	cfg.Remote["docs"] = config.Folder{Path: folder, Peers: []string{"phone"}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := index.Save(index.New(marker.ID)); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := connectionRemove([]string{"phone", "--force"}, &stderr); code != connectionExitOK {
		t.Fatalf("connectionRemove = %d, stderr %q", code, stderr.String())
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := loaded.Peers["phone"]; exists {
		t.Fatalf("peer remains: %#v", loaded.Peers["phone"])
	}
	if _, exists := loaded.Remote["docs"]; exists {
		t.Fatal("remote folder registration remains")
	}
	if _, err := os.Stat(folder); err != nil {
		t.Fatalf("remote folder files were touched: %v", err)
	}
	indexPath, err := index.Path(marker.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(indexPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("connection rm left an index file behind: %v", err)
	}
}

// TestConnectionRemoveConfigCommitFailureLeavesGrantRemovedForRetry covers
// the crash-between-grant-removal-and-config-update window: the grant must
// already be gone (access cut is not undone), and re-running must finish the
// job.
func TestConnectionRemoveConfigCommitFailureLeavesGrantRemovedForRetry(t *testing.T) {
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
	folder := filepath.Join(root, "notes")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(folder, newTestMarker(t, "notes")); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: key}
	cfg.Shared["notes"] = config.Folder{Path: folder, Peers: []string{"phone"}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	originalSave := saveConfig
	saveConfig = func(config.Config) error { return errors.New("injected save failure") }
	var stderr bytes.Buffer
	if code := connectionRemove([]string{"phone", "--force"}, &stderr); code == connectionExitOK {
		t.Fatalf("connectionRemove succeeded despite injected save failure: %q", stderr.String())
	}
	saveConfig = originalSave

	authorized, err := os.ReadFile(paths.AuthorizedKeys)
	if err != nil || strings.Contains(string(authorized), "l2sync:phone") {
		t.Fatalf("grant survived failed commit: authorized_keys = %q, %v", authorized, err)
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := loaded.Peers["phone"]; !exists {
		t.Fatal("peer entry missing before retry")
	}

	stderr.Reset()
	if code := connectionRemove([]string{"phone", "--force"}, &stderr); code != connectionExitOK {
		t.Fatalf("retry connectionRemove = %d, stderr %q", code, stderr.String())
	}
	loaded, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := loaded.Peers["phone"]; exists {
		t.Fatalf("peer remains after retry: %#v", loaded.Peers["phone"])
	}
	if folder := loaded.Shared["notes"]; len(folder.Peers) != 0 {
		t.Fatalf("shared folder still bound after retry: %#v", folder)
	}
}

func TestPeerEndpointCompletesPendingHandshakeBeforeNormalUse(t *testing.T) {
	remoteKey := generatedPublicKey(t, filepath.Join(t.TempDir(), "remote"))
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone"}
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
	if peer := loaded.Peers["phone"]; peer.PublicKey != remoteKey {
		t.Fatalf("completed peer = %#v", peer)
	}
}

func TestStorePeerRefusesUnpinningPeer(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	key := generatedPublicKey(t, filepath.Join(root, "remote"))
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: key}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	err := storePeerLocked("phone", config.Peer{Address: "phone"})
	if err == nil || !strings.Contains(err.Error(), "pinned public key") {
		t.Fatalf("storePeerLocked error = %v", err)
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Peers["phone"].PublicKey != key {
		t.Fatalf("peer was unpinned: %#v", loaded.Peers["phone"])
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
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: key}
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

// TestConnectionRemoveIsIdempotentAfterInterruptedGrantRemoval covers the
// replacement for the deleted revoked-tombstone: an interrupted "connection
// rm" leaves a peer entry whose grant is already gone, and re-running "rm"
// must still succeed and remove the entry.
func TestConnectionRemoveIsIdempotentAfterInterruptedGrantRemoval(t *testing.T) {
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
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: key}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between the grant being removed and the config entry
	// being deleted.
	if err := connectionpkg.RemoveGrant(paths.AuthorizedKeys, "phone", key); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := connectionRemove([]string{"phone"}, &stderr); code != connectionExitOK {
		t.Fatalf("connectionRemove after interrupted grant removal = %d, stderr %q", code, stderr.String())
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := loaded.Peers["phone"]; exists {
		t.Fatalf("peer remains after idempotent removal: %#v", loaded.Peers["phone"])
	}
}

// TestConnectionAddSucceedsAfterInterruptedRemove covers the case the
// deleted revoked-peer resurrection guard used to block: re-adding a peer
// whose removal was interrupted must now succeed.
func TestConnectionAddSucceedsAfterInterruptedRemove(t *testing.T) {
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
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: key}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := connectionRemove([]string{"phone"}, &stderr); code != connectionExitOK {
		t.Fatalf("connectionRemove = %d, stderr %q", code, stderr.String())
	}
	var stdout bytes.Buffer
	if code := connectionAdd([]string{"phone", "phone-host", "--key", key}, strings.NewReader(""), &stdout, &stderr); code != connectionExitOK {
		t.Fatalf("connectionAdd after removal = %d, stderr %q", code, stderr.String())
	}
}

func TestConnectionListGroupsPendingThenHealthyThenUnhealthy(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	cfg := config.New()
	cfg.Peers["qingyou"] = config.Peer{Address: "mayday@100.75.16.121:22", PublicKey: "ssh-ed25519 AAAA1"}
	cfg.Peers["paraloid"] = config.Peer{Address: "luar@100.73.155.103:22", PublicKey: "ssh-ed25519 AAAA2"}
	cfg.Peers["aezt"] = config.Peer{Address: "user@10.244.121.182:22"}
	cfg.Peers["ae"] = config.Peer{Address: "user@100.97.51.22:22", PublicKey: "ssh-ed25519 AAAA3"}
	cfg.Peers["nuremberg"] = config.Peer{Address: "user@100.64.0.9:22", PublicKey: "ssh-ed25519 AAAA4"}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	originalShares := connectionListShares
	connectionListShares = func(_ context.Context, endpoint transport.Endpoint) ([]string, error) {
		switch endpoint.Name {
		case "ae":
			return nil, errors.New("unreachable")
		case "nuremberg":
			return nil, transport.NewAuthErrorForTest("permission denied")
		}
		return nil, nil
	}
	t.Cleanup(func() { connectionListShares = originalShares })

	var stdout bytes.Buffer
	if code := connectionList(nil, &stdout, io.Discard); code != connectionExitOK {
		t.Fatalf("connectionList = %d", code)
	}
	want := "~ aezt       user@10.244.121.182:22\n" +
		"+ paraloid   luar@100.73.155.103:22\n" +
		"+ qingyou    mayday@100.75.16.121:22\n" +
		"x nuremberg  user@100.64.0.9:22\n" +
		"- ae         user@100.97.51.22:22\n"
	if got := stdout.String(); got != want {
		t.Fatalf("connectionList output =\n%q\nwant\n%q", got, want)
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("connectionList emitted ANSI codes for a non-terminal writer: %q", stdout.String())
	}
}

func TestConnectionBareDispatchListsSameAsLs(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone"}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	var bare, ls bytes.Buffer
	if code := Connection(nil, &bare, io.Discard); code != connectionExitOK {
		t.Fatalf("Connection(nil) = %d", code)
	}
	if code := Connection([]string{"ls"}, &ls, io.Discard); code != connectionExitOK {
		t.Fatalf("Connection(ls) = %d", code)
	}
	if bare.String() != ls.String() {
		t.Fatalf("bare dispatch = %q, ls = %q", bare.String(), ls.String())
	}
}
