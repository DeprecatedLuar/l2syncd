//go:build linux

package commands

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
)

const (
	successExitCode       = 0
	invalidConfigExitCode = 2
)

func TestAddListAndRemoveShare(t *testing.T) {
	root := t.TempDir()
	sharePath := filepath.Join(root, "notes")
	if err := os.Mkdir(sharePath, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	var stdout, stderr bytes.Buffer
	if got := Add([]string{"NOTES", sharePath}, &stderr); got != successExitCode {
		t.Fatalf("add exit code = %d, stderr = %q", got, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("add output = stdout %q, stderr %q, want silent", stdout.String(), stderr.String())
	}
	if info, err := os.Stat(filepath.Join(sharePath, ".l2sync")); err != nil || info.IsDir() {
		t.Fatalf("share marker = %v, %v, want file", info, err)
	}

	stdout.Reset()
	stderr.Reset()
	if got := List(&stdout, &stderr); got != successExitCode {
		t.Fatalf("list exit code = %d, stderr = %q", got, stderr.String())
	}
	if want := "+ notes\n"; stdout.String() != want {
		t.Fatalf("list stdout = %q, want %q", stdout.String(), want)
	}

	stdout.Reset()
	stderr.Reset()
	if got := Remove([]string{"notes"}, &stderr); got != successExitCode {
		t.Fatalf("rm exit code = %d, stderr = %q", got, stderr.String())
	}
	if _, err := os.Stat(sharePath); err != nil {
		t.Fatalf("share path removed: %v", err)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := cfg.Shared["notes"]; exists {
		t.Fatal("share remains in config after rm")
	}
}

func TestInvalidConfigExitsInvalid(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	configPath, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("[shares\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := List(&stdout, &stderr); got != invalidConfigExitCode {
		t.Fatalf("list exit code = %d, stderr = %q", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid config") {
		t.Fatalf("stderr = %q, want invalid config message", stderr.String())
	}
}

func TestConfigEditOpensConfigFile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	marker := filepath.Join(root, "edited-path")
	editor := filepath.Join(root, "editor.sh")
	if err := os.WriteFile(editor, []byte("#!/bin/sh\ncat > \""+marker+"\" <<EOF\n$1\nEOF\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", editor)
	t.Setenv("EDITOR", "this-editor-must-not-run")

	var stderr bytes.Buffer
	if got := ConfigEdit(nil, &stderr); got != successExitCode {
		t.Fatalf("config edit exit code = %d, stderr = %q", got, stderr.String())
	}
	configPath, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(contents)) != configPath {
		t.Fatalf("editor received %q, want %q", strings.TrimSpace(string(contents)), configPath)
	}
	configContents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configContents), "# l2sync configuration") {
		t.Fatalf("config = %q, want starter preset", configContents)
	}
}

func TestConfigEditRejectsArguments(t *testing.T) {
	var stderr bytes.Buffer
	if got := ConfigEdit([]string{"unexpected"}, &stderr); got != 1 {
		t.Fatalf("config edit exit code = %d, want 1", got)
	}
	if want := "usage: l2sync config\n"; stderr.String() != want {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
}

func TestAddRejectsUnsafeName(t *testing.T) {
	root := t.TempDir()
	sharePath := filepath.Join(root, "project")
	if err := os.Mkdir(sharePath, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	cfg := config.New()
	var stderr bytes.Buffer
	if got := add(cfg, []string{"My Project", sharePath}, &stderr); got != 1 {
		t.Fatalf("add exit code = %d, stderr = %q", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "folder name must contain only") {
		t.Fatalf("stderr = %q, want unsafe-name error", stderr.String())
	}

	stderr.Reset()
	if got := add(cfg, []string{"My_Project", sharePath}, &stderr); got != successExitCode {
		t.Fatalf("add exit code = %d, stderr = %q", got, stderr.String())
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Shared["my_project"]; !ok {
		t.Fatalf("shared = %#v, want lowercase share name", loaded.Shared)
	}
}

func TestBaselineCommitAndStatus(t *testing.T) {
	root := t.TempDir()
	sharePath := filepath.Join(root, "notes")
	if err := os.Mkdir(sharePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sharePath, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	var stdout, stderr bytes.Buffer
	if got := Add([]string{"notes", sharePath}, &stderr); got != successExitCode {
		t.Fatalf("add exit code = %d, stderr = %q", got, stderr.String())
	}
	stderr.Reset()
	if got := BaselineCommit([]string{"notes"}, &stderr); got != successExitCode {
		t.Fatalf("baseline exit code = %d, stderr = %q", got, stderr.String())
	}
	if got := Status(&stdout, &stderr); got != successExitCode || stdout.Len() != 0 {
		t.Fatalf("clean status = code %d, stdout %q, stderr %q", got, stdout.String(), stderr.String())
	}
	if err := os.WriteFile(filepath.Join(sharePath, "a.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if got := Status(&stdout, &stderr); got != successExitCode || stdout.String() != "modified notes a.txt\n" {
		t.Fatalf("modified status = code %d, stdout %q, stderr %q", got, stdout.String(), stderr.String())
	}
}

func TestListVerifiesRemoteProvider(t *testing.T) {
	root := t.TempDir()
	remotePath := filepath.Join(root, "notes")
	if err := os.Mkdir(remotePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(remotePath, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = "phone"
	cfg.Remote["notes"] = remotePath

	var stdout, stderr bytes.Buffer
	got := listWithLister(cfg, nil, &stdout, &stderr, func(context.Context, string) ([]string, error) {
		return []string{"notes"}, nil
	})
	if got != successExitCode || stdout.String() != "+ notes\n" || stderr.Len() != 0 {
		t.Fatalf("list = code %d, stdout %q, stderr %q", got, stdout.String(), stderr.String())
	}
}

func TestListQueriesConfiguredPeersWithoutLocalRemoteEntries(t *testing.T) {
	cfg := config.New()
	cfg.Peers["phone"] = "phone"
	cfg.Shared["notes"] = "/missing/notes"
	var stdout, stderr bytes.Buffer
	got := listWithLister(cfg, nil, &stdout, &stderr, func(context.Context, string) ([]string, error) {
		return []string{"photos"}, nil
	})
	if got != listExitOK {
		t.Fatalf("list = code %d, stderr %q", got, stderr.String())
	}
	want := "- notes\n- photos\n"
	if stdout.String() != want {
		t.Fatalf("list stdout = %q, want %q", stdout.String(), want)
	}
}

func TestListKeepsLocalEntriesWhenPeerIsUnreachable(t *testing.T) {
	root := t.TempDir()
	sharedPath := filepath.Join(root, "notes")
	if err := os.Mkdir(sharedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.WriteMarker(sharedPath, guard.Marker{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Peers["phone"] = "phone"
	cfg.Shared["notes"] = sharedPath

	var stdout, stderr bytes.Buffer
	got := listWithLister(cfg, []string{"phone"}, &stdout, &stderr, func(context.Context, string) ([]string, error) {
		return nil, errors.New("connection refused")
	})
	if got != listExitUnreachable || stdout.String() != "+ notes\n" {
		t.Fatalf("list = code %d, stdout %q, stderr %q", got, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "peer \"phone\" unreachable") {
		t.Fatalf("stderr = %q, want unreachable message", stderr.String())
	}
}
