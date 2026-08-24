//go:build linux

package logging

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingWriterRotatesAtSizeCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l2sync.log")
	rotatedPath := path + rotatedSuffix

	writer, err := newRotatingWriter(path, 10)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}

	first := []byte("0123456789") // exactly fills the cap: no rotation yet
	if _, err := writer.Write(first); err != nil {
		t.Fatalf("write first record: %v", err)
	}
	if _, err := os.Stat(rotatedPath); !os.IsNotExist(err) {
		t.Fatalf("rotated file exists after first write, err = %v", err)
	}

	second := []byte("ABCDEFGHIJ") // pushes past the cap: must rotate first
	if _, err := writer.Write(second); err != nil {
		t.Fatalf("write second record: %v", err)
	}

	rotatedContents, err := os.ReadFile(rotatedPath)
	if err != nil {
		t.Fatalf("read rotated file: %v", err)
	}
	if string(rotatedContents) != string(first) {
		t.Fatalf("rotated file = %q, want %q", rotatedContents, first)
	}

	currentContents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current file: %v", err)
	}
	if string(currentContents) != string(second) {
		t.Fatalf("current file = %q, want %q (rotation must not carry over old content)", currentContents, second)
	}

	// A previous rotated file must be replaced, not accumulated.
	third := []byte("KLMNOPQRST")
	if _, err := writer.Write(third); err != nil {
		t.Fatalf("write third record: %v", err)
	}
	rotatedContents, err = os.ReadFile(rotatedPath)
	if err != nil {
		t.Fatalf("read rotated file after second rotation: %v", err)
	}
	if string(rotatedContents) != string(second) {
		t.Fatalf("rotated file after second rotation = %q, want %q", rotatedContents, second)
	}
	currentContents, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current file after second rotation: %v", err)
	}
	if string(currentContents) != string(third) {
		t.Fatalf("current file after second rotation = %q, want %q", currentContents, third)
	}
}
