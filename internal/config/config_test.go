//go:build linux

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))

	want := New()
	want.Peers["phone"] = Peer{Addr: "phone"}
	want.Shares["notes"] = Share{Local: "/tmp/notes", Ignore: []string{"node_modules", "*.swp"}}
	want.Mounts["notes"] = Mount{Peer: "phone", Local: "/tmp/phone-notes"}
	if err := Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got.Peers["phone"], want.Peers["phone"]) || !reflect.DeepEqual(got.Shares["notes"], want.Shares["notes"]) || !reflect.DeepEqual(got.Mounts["notes"], want.Mounts["notes"]) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestLoadMalformed(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	path, err := Path()
	if err != nil {
		t.Fatalf("Path() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[shares\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want malformed TOML error")
	}
}

func TestResolvePeerAddress(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	sshDir := filepath.Join(root, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte("Host phone\n  HostName 192.0.2.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ResolvePeerAddress(Peer{Addr: "phone"})
	if err != nil {
		t.Fatalf("ResolvePeerAddress() error = %v", err)
	}
	if got != "192.0.2.10" {
		t.Fatalf("ResolvePeerAddress() = %q, want %q", got, "192.0.2.10")
	}
}

func TestResolvePeerAddressFallsBackToRawAddress(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)

	got, err := ResolvePeerAddress(Peer{Addr: "phone"})
	if err != nil {
		t.Fatalf("ResolvePeerAddress() error = %v", err)
	}
	if got != "phone" {
		t.Fatalf("ResolvePeerAddress() = %q, want %q", got, "phone")
	}
}
