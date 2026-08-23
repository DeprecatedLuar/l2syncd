//go:build linux

package connection

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testPaths(root string) Paths {
	return Paths{
		PrivateKey:     filepath.Join(root, ".ssh", "id_l2sync"),
		PublicKey:      filepath.Join(root, ".ssh", "id_l2sync.pub"),
		AuthorizedKeys: filepath.Join(root, ".ssh", "authorized_keys"),
	}
}

func TestEnsureKeyAndFingerprint(t *testing.T) {
	paths := testPaths(t.TempDir())
	key, err := EnsureKey(paths)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EnsureKey(paths)
	if err != nil || again != key {
		t.Fatalf("second EnsureKey = %q, %v", again, err)
	}
	withComment := key + " arbitrary comment"
	first, err := Fingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Fingerprint(withComment)
	if err != nil || first != second || len(first) != 64 {
		t.Fatalf("fingerprints = %q, %q, %v", first, second, err)
	}
	short, err := ShortFingerprint(key)
	if err != nil || short != first[:12] {
		t.Fatalf("short fingerprint = %q, %v", short, err)
	}
	if _, err := exec.LookPath("ssh-keygen"); err == nil {
		output, commandErr := exec.Command("ssh-keygen", "-y", "-f", paths.PrivateKey).Output()
		if commandErr != nil {
			t.Fatalf("ssh-keygen rejected generated private key: %v", commandErr)
		}
		derived, normalizeErr := NormalizePublicKey(string(output))
		if normalizeErr != nil || derived != key {
			t.Fatalf("ssh-keygen public key = %q, %v", derived, normalizeErr)
		}
	}
}

func TestEnsureKeyRejectsMismatchedPublicKey(t *testing.T) {
	first := testPaths(filepath.Join(t.TempDir(), "first"))
	second := testPaths(filepath.Join(t.TempDir(), "second"))
	if _, err := EnsureKey(first); err != nil {
		t.Fatal(err)
	}
	other, err := EnsureKey(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first.PublicKey, []byte(other+"\n"), publicKeyMode); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureKey(first); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("EnsureKey mismatch error = %v", err)
	}
}

func TestEnsureKeyRejectsGroupWritablePublicKey(t *testing.T) {
	paths := testPaths(t.TempDir())
	if _, err := EnsureKey(paths); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.PublicKey, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureKey(paths); err == nil || !strings.Contains(err.Error(), "writable by group") {
		t.Fatalf("EnsureKey error = %v", err)
	}
}

func TestGrantLifecycleIsExactAndIdempotent(t *testing.T) {
	paths := testPaths(t.TempDir())
	key, err := EnsureKey(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddGrant(paths.AuthorizedKeys, "phone", key); err != nil {
		t.Fatal(err)
	}
	if err := AddGrant(paths.AuthorizedKeys, "phone", key+" ignored-comment"); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(paths.AuthorizedKeys)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(contents), "l2sync:phone") != 1 || !strings.Contains(string(contents), "command=\"l2sync serve --peer phone --fingerprint ") {
		t.Fatalf("authorized_keys = %q", contents)
	}
	if err := RemoveGrant(paths.AuthorizedKeys, "phone", key); err != nil {
		t.Fatal(err)
	}
	contents, err = os.ReadFile(paths.AuthorizedKeys)
	if err != nil || len(contents) != 0 {
		t.Fatalf("authorized_keys after remove = %q, %v", contents, err)
	}
}

func TestGrantRejectsExistingUnrestrictedKey(t *testing.T) {
	paths := testPaths(t.TempDir())
	key, err := EnsureKey(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.AuthorizedKeys, []byte(key+" login-key\n"), authorizedMode); err != nil {
		t.Fatal(err)
	}
	if err := AddGrant(paths.AuthorizedKeys, "phone", key); err == nil || !strings.Contains(err.Error(), "unmanaged") {
		t.Fatalf("AddGrant error = %v", err)
	}
}

func TestGrantParserIgnoresKeyWordsInsideQuotedOptions(t *testing.T) {
	paths := testPaths(t.TempDir())
	key, err := EnsureKey(paths)
	if err != nil {
		t.Fatal(err)
	}
	line := `command="printf ssh-ed25519 harmless",environment="NOTE=ssh-ed25519" ` + key + " unrestricted\n"
	if err := os.WriteFile(paths.AuthorizedKeys, []byte(line), authorizedMode); err != nil {
		t.Fatal(err)
	}
	if err := AddGrant(paths.AuthorizedKeys, "phone", key); err == nil || !strings.Contains(err.Error(), "unmanaged") {
		t.Fatalf("AddGrant error = %v", err)
	}
}

func TestGrantRejectsUnsafeAuthorizedKeysPaths(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, paths Paths)
	}{
		{name: "authorized keys symlink", setup: func(t *testing.T, paths Paths) {
			t.Helper()
			target := filepath.Join(filepath.Dir(paths.AuthorizedKeys), "target")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, paths.AuthorizedKeys); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "authorized keys writable by group", setup: func(t *testing.T, paths Paths) {
			t.Helper()
			if err := os.WriteFile(paths.AuthorizedKeys, nil, 0o620); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "lock symlink", setup: func(t *testing.T, paths Paths) {
			t.Helper()
			target := filepath.Join(filepath.Dir(paths.AuthorizedKeys), "lock-target")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(filepath.Dir(paths.AuthorizedKeys), ".l2sync-authorized_keys.lock")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths := testPaths(t.TempDir())
			key, err := EnsureKey(paths)
			if err != nil {
				t.Fatal(err)
			}
			test.setup(t, paths)
			if err := AddGrant(paths.AuthorizedKeys, "phone", key); err == nil {
				t.Fatal("AddGrant accepted unsafe SSH path")
			}
		})
	}
}
