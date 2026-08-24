//go:build linux

package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))

	want := New()
	want.Peers["phone"] = Peer{Address: "phone"}
	want.Shared["notes"] = Folder{Path: "/tmp/notes", Peers: []string{"phone"}}
	want.Remote["photos"] = Folder{Path: "/tmp/photos"}
	if err := Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
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

	got, err := ResolvePeerAddress("phone")
	if err != nil {
		t.Fatalf("ResolvePeerAddress() error = %v", err)
	}
	if got != "phone" {
		t.Fatalf("ResolvePeerAddress() = %q, want %q", got, "phone")
	}
}

func TestResolvePeerAddressFallsBackToRawAddress(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)

	got, err := ResolvePeerAddress("phone")
	if err != nil {
		t.Fatalf("ResolvePeerAddress() error = %v", err)
	}
	if got != "phone" {
		t.Fatalf("ResolvePeerAddress() = %q, want %q", got, "phone")
	}
}

func TestLoadRejectsMalformedStructuredPeers(t *testing.T) {
	for name, document := range map[string]string{
		"wrong address type":    "[peers.phone]\naddress = 7\n",
		"wrong public key type": "[peers.phone]\naddress = \"phone\"\npublic_key = 7\n",
		"unknown field":         "[peers.phone]\naddress = \"phone\"\nfingerprint = \"derived\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", root)
			path, err := Path()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(); err == nil {
				t.Fatalf("Load accepted %s", document)
			}
		})
	}
}

func TestLoadRejectsUnknownFolderField(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	document := "[shared.notes]\npath = \"/tmp/notes\"\nrole = \"origin\"\n"
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatalf("Load accepted %s", document)
	}
}

func TestSaveLoadRoundTripPreservesUnboundSharedFolder(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))

	want := New()
	want.Shared["notes"] = Folder{Path: "/tmp/notes"}
	if err := Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if folder := got.Shared["notes"]; folder.Path != "/tmp/notes" || len(folder.Peers) != 0 {
		t.Fatalf("unbound shared folder = %#v", folder)
	}
}

func TestEqualDetectsBindingChange(t *testing.T) {
	left := New()
	left.Shared["notes"] = Folder{Path: "/tmp/notes", Peers: []string{"phone"}}
	right := New()
	right.Shared["notes"] = Folder{Path: "/tmp/notes"}
	if Equal(left, right) {
		t.Fatal("Equal() = true for configs differing only in folder binding")
	}
}

func TestLoadRejectsUnknownGlobalKeys(t *testing.T) {
	for name, document := range map[string]string{
		"top level":       "[shraed]\nnotes = \"/tmp/notes\"\n",
		"unknown section": "mystery = true\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", root)
			path, err := Path()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "unknown configuration keys") {
				t.Fatalf("Load error = %v", err)
			}
		})
	}
}

func TestWasInstalledRecognizesPostRenameFailure(t *testing.T) {
	underlying := errors.New("directory sync failed")
	err := &installedError{err: underlying}
	if !WasInstalled(err) || !errors.Is(err, underlying) {
		t.Fatalf("installed error classification = %v, unwrap = %v", WasInstalled(err), errors.Is(err, underlying))
	}
	if WasInstalled(underlying) {
		t.Fatal("pre-rename failure classified as installed")
	}
}

func TestResolvePeerAddressPreservesExplicitDestination(t *testing.T) {
	for _, value := range []string{"user@example.test", "example.test:2222"} {
		got, err := ResolvePeerAddress(value)
		if err != nil || got != value {
			t.Fatalf("ResolvePeerAddress(%q) = %q, %v", value, got, err)
		}
	}
}
