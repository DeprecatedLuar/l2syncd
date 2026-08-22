package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))

	want := New()
	want.Peers["phone"] = Peer{Addr: "phone"}
	want.Shares["notes"] = Share{Local: "/tmp/notes"}
	want.Mounts["notes"] = Mount{Peer: "phone", Local: "/tmp/phone-notes"}
	if err := Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Peers["phone"] != want.Peers["phone"] || got.Shares["notes"] != want.Shares["notes"] || got.Mounts["notes"] != want.Mounts["notes"] {
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
