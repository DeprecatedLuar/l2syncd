//go:build linux

package commands

import (
	"os"
	"path/filepath"
	"testing"

	"l2syncd/internal/transport"
)

func TestDivergentLocalPathsSkipsGitignoredFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("*.secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "leaked.secret"), []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "extra.txt"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}

	extras, err := divergentLocalPaths(root, nil, []transport.PeerFile{})
	if err != nil {
		t.Fatal(err)
	}
	if len(extras) != 2 || extras[0] != ".gitignore" || extras[1] != "extra.txt" {
		t.Fatalf("extras = %#v, want [.gitignore extra.txt]: leaked.secret must be excluded", extras)
	}
}
