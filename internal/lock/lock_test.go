//go:build linux

package lock

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestAcquireRejectsContention(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	first, err := Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer Release(first)
	second, err := Acquire()
	if !errors.Is(err, ErrContended) {
		t.Fatalf("second acquire error = %v, want contention", err)
	}
	if second != nil {
		t.Fatal("second acquire returned a lock handle")
	}
}

func TestReleaseAllowsReacquire(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	first, err := Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if err := Release(first); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if err := Release(second); err != nil {
		t.Fatal(err)
	}
}
