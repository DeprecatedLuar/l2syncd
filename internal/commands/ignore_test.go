//go:build linux

package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"l2syncd/internal/guard"
)

func setupIgnoreShare(t *testing.T) (name, sharePath string) {
	t.Helper()
	root := t.TempDir()
	sharePath = filepath.Join(root, "notes")
	if err := os.Mkdir(sharePath, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	var stderr bytes.Buffer
	if got := Add([]string{"notes", sharePath}, &stderr); got != successExitCode {
		t.Fatalf("add exit code = %d, stderr = %q", got, stderr.String())
	}
	return "notes", sharePath
}

func TestIgnoreAddListAndRemove(t *testing.T) {
	name, sharePath := setupIgnoreShare(t)

	var stdout, stderr bytes.Buffer
	if got := Ignore([]string{name, "add", "*.swp", "build/"}, &stdout, &stderr); got != ignoreExitOK {
		t.Fatalf("ignore add exit code = %d, stderr = %q", got, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if got := Ignore([]string{name}, &stdout, &stderr); got != ignoreExitOK {
		t.Fatalf("ignore list exit code = %d, stderr = %q", got, stderr.String())
	}
	if want := "*.swp\nbuild/\n"; stdout.String() != want {
		t.Fatalf("ignore list stdout = %q, want %q", stdout.String(), want)
	}

	marker, err := guard.ReadMarker(sharePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(marker.Ignore) != 2 {
		t.Fatalf("marker ignore = %v, want 2 patterns", marker.Ignore)
	}

	stdout.Reset()
	stderr.Reset()
	if got := Ignore([]string{name, "rm", "*.swp"}, &stdout, &stderr); got != ignoreExitOK {
		t.Fatalf("ignore rm exit code = %d, stderr = %q", got, stderr.String())
	}

	marker, err = guard.ReadMarker(sharePath)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"build/"}; len(marker.Ignore) != 1 || marker.Ignore[0] != want[0] {
		t.Fatalf("marker ignore after rm = %v, want %v", marker.Ignore, want)
	}
}

func TestIgnoreAddIsIdempotent(t *testing.T) {
	name, sharePath := setupIgnoreShare(t)

	var stdout, stderr bytes.Buffer
	if got := Ignore([]string{name, "add", "*.swp"}, &stdout, &stderr); got != ignoreExitOK {
		t.Fatalf("ignore add exit code = %d, stderr = %q", got, stderr.String())
	}
	if got := Ignore([]string{name, "add", "*.swp"}, &stdout, &stderr); got != ignoreExitOK {
		t.Fatalf("ignore add exit code = %d, stderr = %q", got, stderr.String())
	}

	marker, err := guard.ReadMarker(sharePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(marker.Ignore) != 1 {
		t.Fatalf("marker ignore = %v, want a single deduplicated pattern", marker.Ignore)
	}
}

func TestIgnoreRejectsInvalidPattern(t *testing.T) {
	name, sharePath := setupIgnoreShare(t)

	var stdout, stderr bytes.Buffer
	if got := Ignore([]string{name, "add", "!negated"}, &stdout, &stderr); got != ignoreExitError {
		t.Fatalf("ignore add exit code = %d, want error", got)
	}

	marker, err := guard.ReadMarker(sharePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(marker.Ignore) != 0 {
		t.Fatalf("marker ignore = %v, want unchanged", marker.Ignore)
	}
}

func TestIgnoreUnknownFolderErrors(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	var stdout, stderr bytes.Buffer
	if got := Ignore([]string{"nonexistent"}, &stdout, &stderr); got != ignoreExitError {
		t.Fatalf("ignore exit code = %d, want error", got)
	}
}
