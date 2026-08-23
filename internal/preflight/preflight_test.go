//go:build linux

package preflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"l2syncd/internal/config"
	"l2syncd/internal/connection"
	"l2syncd/internal/guard"
)

func TestCheckDoesNotCreateStateDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	if err := Check(config.New()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	stateDir, err := config.StateDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("state directory exists after Check(): %v", err)
	}
}

func TestCheckRejectsEmptyPeerAddress(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Status: config.PeerPending}
	if err := Check(cfg); err == nil {
		t.Fatal("Check() error = nil, want empty peer address error")
	}
}

func TestValidateRejectsMultiplePeerBinding(t *testing.T) {
	cfg := config.New()
	cfg.Peers["one"] = config.Peer{Address: "one", Status: config.PeerPending}
	cfg.Peers["two"] = config.Peer{Address: "two", Status: config.PeerPending}
	cfg.Shared["notes"] = t.TempDir()
	if err := guard.WriteMarker(cfg.Shared["notes"], guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	cfg.Bindings["notes"] = []string{"one", "two"}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "exactly one peer") {
		t.Fatalf("Validate error = %v", err)
	}
}

func TestValidateRejectsBindingToRevokedPeer(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	paths, err := connection.DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	key, err := connection.EnsureKey(paths)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", Status: config.PeerRevoked, PublicKey: key}
	cfg.Shared["notes"] = t.TempDir()
	if err := guard.WriteMarker(cfg.Shared["notes"], guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	cfg.Bindings["notes"] = []string{"phone"}
	if validateErr := Validate(cfg); validateErr == nil || !strings.Contains(validateErr.Error(), "revoked") {
		t.Fatalf("Validate error = %v", validateErr)
	}
}

func TestValidateRejectsNonCanonicalConfiguredFolderNames(t *testing.T) {
	tests := []struct {
		name string
		set  func(*config.Config)
	}{
		{name: "shared", set: func(cfg *config.Config) { cfg.Shared["Work Notes"] = "/unused" }},
		{name: "remote", set: func(cfg *config.Config) { cfg.Remote["../notes"] = "/unused" }},
		{name: "binding", set: func(cfg *config.Config) { cfg.Bindings["Notes"] = []string{"phone"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.New()
			test.set(&cfg)
			if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "folder name") {
				t.Fatalf("Validate error = %v", err)
			}
		})
	}
}

func TestValidateRequiresExactlyOneUsableBindingForRemoteFolder(t *testing.T) {
	root := t.TempDir()
	if err := guard.WriteMarker(root, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		status string
		bind   []string
	}{
		{name: "missing", status: config.PeerActive},
		{name: "revoked", status: config.PeerRevoked, bind: []string{"phone"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.New()
			cfg.Peers["phone"] = config.Peer{Address: "phone", Status: test.status, PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINa41as+a6N57asFGGQUcElHbuSpntT7uZFWQMgphLxE"}
			cfg.Remote["notes"] = root
			cfg.Bindings["notes"] = test.bind
			if err := Validate(cfg); err == nil {
				t.Fatal("Validate accepted unusable remote binding")
			}
		})
	}
}
