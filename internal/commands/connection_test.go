//go:build linux

package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"l2syncd/internal/config"
	connectionpkg "l2syncd/internal/connection"
	"l2syncd/internal/guard"
	"l2syncd/internal/index"
	"l2syncd/internal/transport"
)

// fixtureKeyDir is where generatedPublicKey stages a keypair for use as
// fixture material (typically a peer's public key). It is deliberately not
// ".ssh": these files are test scaffolding, not the on-disk locations
// production code resolves via connection.DefaultPaths(). A test that needs
// the generated key discoverable as this machine's own installation
// identity must additionally install it at DefaultPaths() itself (see
// installLocalFixtureKey in commands_test.go).
const fixtureKeyDir = ".fixture-key"

func generatedPublicKey(t *testing.T, root string) string {
	t.Helper()
	paths := connectionpkg.Paths{
		PrivateKey:     filepath.Join(root, fixtureKeyDir, "id_l2sync"),
		PublicKey:      filepath.Join(root, fixtureKeyDir, "id_l2sync.pub"),
		AuthorizedKeys: filepath.Join(root, fixtureKeyDir, "authorized_keys"),
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
	connectionInstall = func(context.Context, string, string, string) (bool, error) {
		t.Fatal("remote state was written")
		return false, nil
	}
	t.Cleanup(func() { connectionProbe, connectionInstall = originalProbe, originalInstall })

	var stdout, stderr bytes.Buffer
	if code := connectionAdd([]string{"friend", "alex@example.test"}, strings.NewReader(""), &stdout, &stderr); code != connectionExitOK {
		t.Fatalf("connectionAdd = %d, stderr %q", code, stderr.String())
	}
	invite := stdout.String()
	if !strings.Contains(invite, "l2sync connection add") || !strings.Contains(invite, "--key \"") || !strings.HasSuffix(invite, "Then run this command again to finish.\n") {
		t.Fatalf("invite = %q", invite)
	}
	if strings.Contains(invite, "warning: this machine's hostname") {
		t.Fatalf("invite carries an address warning: %q", invite)
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
	connectionInstall = func(context.Context, string, string, string) (bool, error) {
		t.Fatal("remote state was written")
		return false, nil
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
	installed := false
	restore := []func(){
		swap(&connectionProbe, func(context.Context, string) error { return nil }),
		swap(&connectionInstall, func(_ context.Context, destination, name, key string) (bool, error) {
			installed = destination == "login@example.test" && name != "" && strings.HasPrefix(key, "ssh-ed25519 ")
			return true, nil
		}),
		swap(&connectionExchange, func(_ context.Context, endpoint transport.Endpoint) error {
			return endpoint.AcceptPublicKey(remoteKey)
		}),
		swap(&localSSHD, func() (connectionpkg.SSHD, error) {
			return connectionpkg.SSHD{Port: 22, HostKeys: []string{testReturnHostKey}}, nil
		}),
		swap(&connectionVerifyReturn, func(context.Context, transport.Endpoint, transport.ReturnRoute) error { return nil }),
	}
	t.Cleanup(func() {
		for _, undo := range restore {
			undo()
		}
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
	stubReturnRouteSuccess(t)
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

func TestParseConnectionAddForms(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want connectionAddRequest
	}{
		{[]string{"vps"}, connectionAddRequest{name: "vps"}},
		{[]string{"vps", "luar@host"}, connectionAddRequest{name: "vps", destination: "luar@host"}},
		{[]string{"vps", "luar@host", "--address", "me@mine"}, connectionAddRequest{name: "vps", destination: "luar@host", returnAddress: "me@mine"}},
	} {
		got, err := parseConnectionAdd(tc.args, strings.NewReader(""))
		if err != nil || got != tc.want {
			t.Fatalf("parse %v = %+v, %v; want %+v", tc.args, got, err, tc.want)
		}
	}
}

func TestParseConnectionAddKeyOnlyHasNoDestination(t *testing.T) {
	_, cfg := cycleTestConfig(t, true)
	key := cfg.Peers["phone"].PublicKey
	got, err := parseConnectionAdd([]string{"paraloid", "--key", key}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if got.destination != "" || got.key == "" {
		t.Fatalf("key-only parse = %+v", got)
	}
	if _, err := parseConnectionAdd([]string{"paraloid", "--key", key, "--address", "x@y"}, strings.NewReader("")); err == nil {
		t.Fatal("--address accepted together with --key")
	}
}

func TestActivatePeerRevertsOnReturnFailure(t *testing.T) {
	_, cfg := cycleTestConfig(t, true)
	remoteKey := cfg.Peers["phone"].PublicKey
	cfg.Peers["phone"] = config.Peer{Address: "phone"}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	paths, err := connectionpkg.DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	restore := []func(){
		swap(&connectionExchange, func(ctx context.Context, endpoint transport.Endpoint) error {
			if err := endpoint.AcceptPublicKey(remoteKey); err != nil {
				return err
			}
			return connectionpkg.AddGrant(endpoint.AuthorizedKeys, endpoint.Name, remoteKey)
		}),
		swap(&localSSHD, func() (connectionpkg.SSHD, error) {
			return connectionpkg.SSHD{Port: 22, HostKeys: []string{testReturnHostKey}}, nil
		}),
		swap(&connectionVerifyReturn, func(context.Context, transport.Endpoint, transport.ReturnRoute) error {
			return errors.New("dial back timeout")
		}),
	}
	t.Cleanup(func() {
		for _, undo := range restore {
			undo()
		}
	})
	if _, err := activatePeer(context.Background(), cfg, "phone", ""); err == nil || !strings.Contains(err.Error(), "--address") {
		t.Fatalf("activatePeer error = %v, want failure suggesting --address", err)
	}
	after, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Peers["phone"].PublicKey != "" {
		t.Fatal("peer left active after failed return verification")
	}
	contents, err := os.ReadFile(paths.AuthorizedKeys)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "l2sync:phone") {
		t.Fatal("reciprocal grant left behind")
	}
}

func TestDialPeerFailedActivationRemovesRemoteAndLocalState(t *testing.T) {
	_, cfg := cycleTestConfig(t, true)
	remoteKey := cfg.Peers["phone"].PublicKey
	delete(cfg.Peers, "phone")
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	removedRemote := false
	restore := []func(){
		swap(&connectionProbe, func(context.Context, string) error { return nil }),
		swap(&connectionInstall, func(context.Context, string, string, string) (bool, error) { return true, nil }),
		swap(&connectionRemoteRemove, func(context.Context, string, string) error { removedRemote = true; return nil }),
		swap(&connectionExchange, func(ctx context.Context, endpoint transport.Endpoint) error {
			return endpoint.AcceptPublicKey(remoteKey)
		}),
		swap(&localSSHD, func() (connectionpkg.SSHD, error) {
			return connectionpkg.SSHD{Port: 22, HostKeys: []string{testReturnHostKey}}, nil
		}),
		swap(&connectionVerifyReturn, func(context.Context, transport.Endpoint, transport.ReturnRoute) error {
			return errors.New("dial back timeout")
		}),
	}
	t.Cleanup(func() {
		for _, undo := range restore {
			undo()
		}
	})
	var stdout, stderr bytes.Buffer
	if code := connectionAdd([]string{"phone", "luar@phone"}, strings.NewReader(""), &stdout, &stderr); code == connectionExitOK {
		t.Fatal("connection add succeeded despite failed dial-back")
	}
	if !removedRemote {
		t.Fatal("remote grant created by this run was not removed")
	}
	after, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := after.Peers["phone"]; exists {
		t.Fatalf("local peer entry left behind: %+v", after.Peers["phone"])
	}
}

func swap[T any](target *T, value T) func() {
	previous := *target
	*target = value
	return func() { *target = previous }
}

// stubReturnRouteSuccess makes the dial-back step of activation succeed.
func stubReturnRouteSuccess(t *testing.T) {
	t.Helper()
	restoreSSHD := swap(&localSSHD, func() (connectionpkg.SSHD, error) {
		return connectionpkg.SSHD{Port: 22, HostKeys: []string{testReturnHostKey}}, nil
	})
	restoreVerify := swap(&connectionVerifyReturn, func(context.Context, transport.Endpoint, transport.ReturnRoute) error { return nil })
	t.Cleanup(func() { restoreSSHD(); restoreVerify() })
}

func TestConnectionRemoveUnpinsHostKeysUnlessShared(t *testing.T) {
	for _, tc := range []struct {
		name       string
		otherHost  string
		wantPinned bool
	}{
		{"unshared", "elsewhere", false},
		{"shared", "pinned.test", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
			t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
			paths, err := connectionpkg.DefaultPaths()
			if err != nil {
				t.Fatal(err)
			}
			if err := connectionpkg.PinHostKeys(paths.KnownHosts, "pinned.test", 22, []string{testReturnHostKey}); err != nil {
				t.Fatal(err)
			}
			cfg := config.New()
			cfg.Peers["gone"] = config.Peer{Address: "luar@pinned.test"}
			cfg.Peers["stays"] = config.Peer{Address: "other@" + tc.otherHost}
			if err := config.Save(cfg); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			if code := connectionRemove([]string{"gone"}, &stderr); code != connectionExitOK {
				t.Fatalf("connectionRemove = %d, stderr %q", code, stderr.String())
			}
			keys, err := connectionpkg.HostKeysFor(paths.KnownHosts, "pinned.test", 22)
			if err != nil {
				t.Fatal(err)
			}
			if pinned := len(keys) > 0; pinned != tc.wantPinned {
				t.Fatalf("pinned keys after rm = %v, want pinned=%v", keys, tc.wantPinned)
			}
		})
	}
}

func TestAcceptPeerKeyRevertsStoredPeerWhenGrantFails(t *testing.T) {
	for _, existed := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%v", existed), func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
			t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
			key := generatedPublicKey(t, filepath.Join(root, "remote"))
			staleKey := generatedPublicKey(t, filepath.Join(root, "stale"))
			paths, err := connectionpkg.DefaultPaths()
			if err != nil {
				t.Fatal(err)
			}
			if err := connectionpkg.AddGrant(paths.AuthorizedKeys, "phone", staleKey); err != nil {
				t.Fatal(err)
			}
			cfg := config.New()
			previous := config.Peer{Address: "phone-host", Port: 2222}
			if existed {
				cfg.Peers["phone"] = previous
			}
			if err := config.Save(cfg); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := connectionAdd([]string{"phone", "--key", key}, strings.NewReader(""), &stdout, &stderr); code == connectionExitOK {
				t.Fatal("connection add succeeded despite grant refusal")
			}
			if !strings.Contains(stderr.String(), "install restricted grant") {
				t.Fatalf("stderr = %q", stderr.String())
			}
			after, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			got, exists := after.Peers["phone"]
			if existed && got != previous || !existed && exists {
				t.Fatalf("peer after failed grant = %+v, exists=%v", got, exists)
			}
		})
	}
}

func TestParseConnectionAddRejectsDegenerateReturnAddress(t *testing.T) {
	for _, address := range []string{"", "@host", "user@", "bad*host", "user@!x", "user@ho st", "user@a@b", "-oProxyCommand=x", "user@|x"} {
		if got, err := parseConnectionAdd([]string{"vps", "luar@host", "--address", address}, strings.NewReader("")); err == nil {
			t.Errorf("--address %q accepted: %+v", address, got)
		}
	}
	if _, err := parseConnectionAdd([]string{"vps", "luar@host", "--address", "alex@Host.LAN"}, strings.NewReader("")); err != nil {
		t.Fatalf("valid --address refused: %v", err)
	}
}

func TestLocalReturnRouteRejectsDegenerateOverrides(t *testing.T) {
	restore := swap(&localSSHD, func() (connectionpkg.SSHD, error) {
		return connectionpkg.SSHD{Port: 22, HostKeys: []string{testReturnHostKey}}, nil
	})
	t.Cleanup(restore)
	for _, address := range []string{"@host", "user@", "bad*host", "user@!x"} {
		if route, err := localReturnRoute(address); err == nil {
			t.Errorf("localReturnRoute(%q) = %+v, want error", address, route)
		}
	}
	route, err := localReturnRoute("alex@Host.LAN")
	if err != nil {
		t.Fatal(err)
	}
	if route.User != "alex" || route.Host != "host.lan" {
		t.Fatalf("route = %+v, want alex@host.lan", route)
	}
}

func TestConnectionAddRerunActivatesAcceptedInviteWithStoredDestination(t *testing.T) {
	remoteKey := generatedPublicKey(t, filepath.Join(t.TempDir(), "remote"))
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	inviteAccepted := false
	var dialedAddress string
	var sentRoute transport.ReturnRoute
	restore := []func(){
		swap(&connectionProbe, func(context.Context, string) error { return errors.New("Permission denied (publickey)") }),
		swap(&connectionInstall, func(context.Context, string, string, string) (bool, error) {
			t.Fatal("login install attempted")
			return false, nil
		}),
		swap(&connectionExchange, func(_ context.Context, endpoint transport.Endpoint) error {
			if !inviteAccepted {
				return transport.NewAuthErrorForTest("invite not run yet")
			}
			dialedAddress = endpoint.Address
			return endpoint.AcceptPublicKey(remoteKey)
		}),
		swap(&localSSHD, func() (connectionpkg.SSHD, error) {
			return connectionpkg.SSHD{Port: 22, HostKeys: []string{testReturnHostKey}}, nil
		}),
		swap(&connectionVerifyReturn, func(_ context.Context, _ transport.Endpoint, route transport.ReturnRoute) error {
			sentRoute = route
			return nil
		}),
	}
	t.Cleanup(func() {
		for _, undo := range restore {
			undo()
		}
	})
	var stdout, stderr bytes.Buffer
	if code := connectionAdd([]string{"friend", "alex@example.test"}, strings.NewReader(""), &stdout, &stderr); code != connectionExitOK {
		t.Fatalf("invite run = %d, stderr %q", code, stderr.String())
	}
	inviteAccepted = true
	stdout.Reset()
	stderr.Reset()
	if code := connectionAdd([]string{"friend", "--address", "me@mine.example"}, strings.NewReader(""), &stdout, &stderr); code != connectionExitOK {
		t.Fatalf("rerun = %d, stderr %q", code, stderr.String())
	}
	if dialedAddress != "alex@example.test" {
		t.Fatalf("dialed %q, want stored destination", dialedAddress)
	}
	if sentRoute.User != "me" || sentRoute.Host != "mine.example" {
		t.Fatalf("return route = %+v, want me@mine.example", sentRoute)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if peer := cfg.Peers["friend"]; peer.PublicKey != remoteKey || peer.Address != "alex@example.test" {
		t.Fatalf("peer after rerun = %+v", peer)
	}
}

func TestConnectionAddRefusesDifferentExplicitDestination(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	cfg := config.New()
	cfg.Peers["friend"] = config.Peer{Address: "alex@example.test"}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := connectionAdd([]string{"friend", "other@example.test"}, strings.NewReader(""), &stdout, &stderr); code == connectionExitOK {
		t.Fatal("different destination accepted")
	}
	if !strings.Contains(stderr.String(), "different connection data") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// activePeerFixture stores an active peer and records every verify-return
// call made against it.
func activePeerFixture(t *testing.T, peer config.Peer, verifyErr error) (*[]transport.ReturnRoute, *[]transport.Endpoint) {
	t.Helper()
	_, cfg := cycleTestConfig(t, true)
	peer.PublicKey = cfg.Peers["phone"].PublicKey
	cfg.Peers["phone"] = peer
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	var routes []transport.ReturnRoute
	var endpoints []transport.Endpoint
	restore := []func(){
		swap(&connectionProbe, func(context.Context, string) error {
			t.Fatal("login probe attempted for an active peer")
			return nil
		}),
		swap(&connectionExchange, func(context.Context, transport.Endpoint) error {
			t.Fatal("hello exchange attempted for an active peer")
			return nil
		}),
		swap(&localSSHD, func() (connectionpkg.SSHD, error) {
			return connectionpkg.SSHD{Port: 2222, HostKeys: []string{testReturnHostKey}}, nil
		}),
		swap(&connectionVerifyReturn, func(_ context.Context, endpoint transport.Endpoint, route transport.ReturnRoute) error {
			routes = append(routes, route)
			endpoints = append(endpoints, endpoint)
			return verifyErr
		}),
	}
	t.Cleanup(func() {
		for _, undo := range restore {
			undo()
		}
	})
	return &routes, &endpoints
}

func TestConnectionAddActivePeerReverifiesReturnRoute(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name               string
		args               []string
		wantUser, wantHost string
	}{
		{"no destination", []string{"phone"}, current.Username, ""},
		{"same destination", []string{"phone", "luar@phone.example"}, current.Username, ""},
		{"address override", []string{"phone", "--address", "user@Host.example"}, "user", "host.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes, endpoints := activePeerFixture(t, config.Peer{Address: "luar@phone.example", Port: 2200}, nil)
			before, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := connectionAdd(tc.args, strings.NewReader(""), &stdout, &stderr); code != connectionExitOK {
				t.Fatalf("connectionAdd = %d, stderr %q", code, stderr.String())
			}
			if len(*routes) != 1 {
				t.Fatalf("verify-return calls = %d, want 1", len(*routes))
			}
			route, endpoint := (*routes)[0], (*endpoints)[0]
			if route.User != tc.wantUser || route.Host != tc.wantHost || route.Port != 2222 || len(route.HostKeys) != 1 {
				t.Fatalf("route = %+v", route)
			}
			if endpoint.Address != "luar@phone.example" || endpoint.Port != 2200 || endpoint.PublicKey != before.Peers["phone"].PublicKey {
				t.Fatalf("endpoint = %+v", endpoint)
			}
			after, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			if after.Peers["phone"] != before.Peers["phone"] {
				t.Fatalf("peer changed: %+v -> %+v", before.Peers["phone"], after.Peers["phone"])
			}
		})
	}
}

func TestConnectionAddActivePeerReportsReturnFailureWithHint(t *testing.T) {
	routes, _ := activePeerFixture(t, config.Peer{Address: "luar@phone.example"}, errors.New("dial back timeout"))
	before, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := connectionAdd([]string{"phone"}, strings.NewReader(""), &stdout, &stderr); code == connectionExitOK {
		t.Fatal("connection add succeeded despite failed dial-back")
	}
	if len(*routes) != 1 {
		t.Fatalf("verify-return calls = %d, want 1", len(*routes))
	}
	if !strings.Contains(stderr.String(), "dial back timeout") || !strings.Contains(stderr.String(), "l2sync connection add phone --address <user@host>") {
		t.Fatalf("stderr = %q, want cause and --address hint", stderr.String())
	}
	after, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Peers["phone"] != before.Peers["phone"] {
		t.Fatalf("peer changed: %+v -> %+v", before.Peers["phone"], after.Peers["phone"])
	}
}

func TestConnectionAddKeyOnlyActivePeerDoesNotDial(t *testing.T) {
	routes, _ := activePeerFixture(t, config.Peer{}, nil)
	before, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	connectionAdd([]string{"phone"}, strings.NewReader(""), &stdout, &stderr)
	if len(*routes) != 0 {
		t.Fatalf("key-only peer dialed back %d times", len(*routes))
	}
	after, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Peers["phone"] != before.Peers["phone"] {
		t.Fatalf("peer changed: %+v -> %+v", before.Peers["phone"], after.Peers["phone"])
	}
}
