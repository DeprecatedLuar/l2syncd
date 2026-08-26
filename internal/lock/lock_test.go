//go:build linux

package lock

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const (
	lockHelperEnvironment = "L2SYNC_LOCK_HELPER"
	lockReadyEnvironment  = "L2SYNC_LOCK_READY"
	lockTestWait          = 250 * time.Millisecond
)

func TestAcquireRejectsContention(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	first, err := Acquire("notes")
	if err != nil {
		t.Fatal(err)
	}
	defer Release(first)
	second, err := Acquire("notes")
	if !errors.Is(err, ErrContended) {
		t.Fatalf("second acquire error = %v, want contention", err)
	}
	if second != nil {
		t.Fatal("second acquire returned a lock handle")
	}
}

func TestDifferentFoldersDoNotContend(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	notes, err := Acquire("notes")
	if err != nil {
		t.Fatal(err)
	}
	defer Release(notes)
	photos, err := Acquire("photos")
	if err != nil {
		t.Fatalf("unrelated folder contended: %v", err)
	}
	if err := Release(photos); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireRejectsInvalidFolderName(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	if _, err := Acquire("Bad Name!"); err == nil {
		t.Fatal("invalid folder name was accepted")
	}
	entries, err := os.ReadDir(filepath.Join(root, "state"))
	if err == nil {
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) == ".lock" {
				t.Fatalf("invalid folder name created lock file %q", entry.Name())
			}
		}
	}
}

func TestReleaseAllowsReacquire(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))

	first, err := Acquire("notes")
	if err != nil {
		t.Fatal(err)
	}
	if err := Release(first); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire("notes")
	if err != nil {
		t.Fatal(err)
	}
	if err := Release(second); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireWaitTimesOutWithoutStealingLiveOwner(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	owner, err := Acquire("notes")
	if err != nil {
		t.Fatal(err)
	}
	defer Release(owner)

	if _, err := AcquireWait(context.Background(), 20*time.Millisecond, "notes"); !errors.Is(err, ErrTimeout) {
		t.Fatalf("AcquireWait error = %v, want timeout", err)
	}
}

func TestDaemonLockDoesNotBlockMutationLock(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	daemon, err := AcquireDaemon()
	if err != nil {
		t.Fatal(err)
	}
	defer Release(daemon)
	mutation, err := Acquire("notes")
	if err != nil {
		t.Fatalf("mutation lock while daemon lock held: %v", err)
	}
	if err := Release(mutation); err != nil {
		t.Fatal(err)
	}
}

func TestConfigLockIsIndependentOfMutationLock(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	mutation, err := Acquire("notes")
	if err != nil {
		t.Fatal(err)
	}
	defer Release(mutation)
	config, err := AcquireConfigWait(context.Background(), 20*time.Millisecond)
	if err != nil {
		t.Fatalf("config lock while unrelated mutation lock held: %v", err)
	}
	if err := Release(config); err != nil {
		t.Fatal(err)
	}
}

func TestDeadOwnerLockIsRecovered(t *testing.T) {
	if os.Getenv(lockHelperEnvironment) == "1" {
		file, err := Acquire("notes")
		if err != nil {
			os.Exit(2)
		}
		defer Release(file)
		if err := os.WriteFile(os.Getenv(lockReadyEnvironment), []byte("ready"), 0o600); err != nil {
			os.Exit(3)
		}
		time.Sleep(time.Hour)
		return
	}

	root := t.TempDir()
	stateHome := filepath.Join(root, "state")
	ready := filepath.Join(root, "ready")
	command := exec.Command(os.Args[0], "-test.run=TestDeadOwnerLockIsRecovered")
	command.Env = append(os.Environ(),
		"HOME="+root,
		"XDG_STATE_HOME="+stateHome,
		lockHelperEnvironment+"=1",
		lockReadyEnvironment+"="+ready,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(lockTestWait)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			command.Process.Kill()
			command.Wait()
			t.Fatal("helper did not acquire lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed helper exited successfully")
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_STATE_HOME", stateHome)
	file, err := AcquireWait(context.Background(), lockTestWait, "notes")
	if err != nil {
		t.Fatalf("acquire after owner death: %v", err)
	}
	if err := Release(file); err != nil {
		t.Fatal(err)
	}
}
