//go:build linux

package sharepath

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRegularRejectsSymlinkLeafAndAncestor(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "leaf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "ancestor")); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"leaf", "ancestor/secret"} {
		t.Run(relative, func(t *testing.T) {
			if file, err := OpenRegular(root, relative); err == nil {
				file.Close()
				t.Fatal("OpenRegular followed a symlink outside the share")
			}
		})
	}
}

func TestOpenRegularReadsRegularFile(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dir", "file"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := OpenRegular(root, "dir/file")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	contents, err := io.ReadAll(file)
	if err != nil || string(contents) != "inside" {
		t.Fatalf("read = %q, %v", contents, err)
	}
}
