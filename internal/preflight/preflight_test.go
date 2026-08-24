//go:build linux

package preflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"l2syncd/internal/config"
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
	cfg.Peers["phone"] = config.Peer{}
	if err := Check(cfg); err == nil {
		t.Fatal("Check() error = nil, want empty peer address error")
	}
}

func TestValidateRejectsMultiplePeerBinding(t *testing.T) {
	cfg := config.New()
	cfg.Peers["one"] = config.Peer{Address: "one"}
	cfg.Peers["two"] = config.Peer{Address: "two"}
	root := t.TempDir()
	if err := guard.WriteMarker(root, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	cfg.Shared["notes"] = config.Folder{Path: root, Peers: []string{"one", "two"}}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "exactly one peer") {
		t.Fatalf("Validate error = %v", err)
	}
}

func TestValidateRejectsMultiplePeerBindingOnRemoteFolder(t *testing.T) {
	cfg := config.New()
	cfg.Peers["one"] = config.Peer{Address: "one"}
	cfg.Peers["two"] = config.Peer{Address: "two"}
	root := t.TempDir()
	if err := guard.WriteMarker(root, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	cfg.Remote["notes"] = config.Folder{Path: root, Peers: []string{"one", "two"}}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "exactly one peer") {
		t.Fatalf("Validate error = %v", err)
	}
}

func TestValidateAcceptsUnboundSharedFolder(t *testing.T) {
	cfg := config.New()
	root := t.TempDir()
	if err := guard.WriteMarker(root, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	cfg.Shared["notes"] = config.Folder{Path: root}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error = %v, want unbound shared folder accepted", err)
	}
}

func TestValidateRejectsUnboundRemoteFolder(t *testing.T) {
	cfg := config.New()
	root := t.TempDir()
	if err := guard.WriteMarker(root, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	cfg.Remote["notes"] = config.Folder{Path: root}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "exactly one peer") {
		t.Fatalf("Validate error = %v", err)
	}
}

func TestValidateRejectsNonCanonicalConfiguredFolderNames(t *testing.T) {
	tests := []struct {
		name string
		set  func(*config.Config)
	}{
		{name: "shared", set: func(cfg *config.Config) { cfg.Shared["Work Notes"] = config.Folder{Path: "/unused"} }},
		{name: "remote", set: func(cfg *config.Config) { cfg.Remote["../notes"] = config.Folder{Path: "/unused"} }},
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
		name string
		bind []string
	}{
		{name: "missing"},
		{name: "unknown peer", bind: []string{"ghost"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.New()
			cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINa41as+a6N57asFGGQUcElHbuSpntT7uZFWQMgphLxE"}
			cfg.Remote["notes"] = config.Folder{Path: root, Peers: test.bind}
			if err := Validate(cfg); err == nil {
				t.Fatal("Validate accepted unusable remote binding")
			}
		})
	}
}
