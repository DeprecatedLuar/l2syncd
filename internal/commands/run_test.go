//go:build linux

package commands

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"l2syncd/internal/config"
	"l2syncd/internal/state"
)

func TestExecuteCycleLogsSummary(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil)).With("component", "daemon")
	retry := stoppedTimer(t)

	delay := executeCycle(
		context.Background(),
		logger,
		retry,
		runBackoffMax,
		cycleTriggerFilesystem,
		func(context.Context) (CycleSummary, error) {
			return CycleSummary{Folders: 2, Actions: 3}, nil
		},
	)

	if delay != runBackoffStart {
		t.Fatalf("next delay = %v, want %v", delay, runBackoffStart)
	}
	assertLogContains(t, output.String(),
		`level=INFO msg="sync cycle started"`,
		`trigger=filesystem`,
		`level=INFO msg="sync cycle completed"`,
		`folders=2`,
		`actions=3`,
	)
}

func TestExecuteCycleLogsFailureAndRetry(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil)).With("component", "daemon")
	retry := stoppedTimer(t)

	delay := executeCycle(
		context.Background(),
		logger,
		retry,
		runBackoffStart,
		cycleTriggerRetry,
		func(context.Context) (CycleSummary, error) {
			return CycleSummary{Folders: 1, Actions: 2}, errors.New("peer unreachable")
		},
	)

	if delay != 2*runBackoffStart {
		t.Fatalf("next delay = %v, want %v", delay, 2*runBackoffStart)
	}
	assertLogContains(t, output.String(),
		`level=ERROR msg="sync cycle failed"`,
		`trigger=retry`,
		`folders_completed=1`,
		`actions_completed=2`,
		`retry_in=1s`,
		`error="peer unreachable"`,
	)
}

func stoppedTimer(t *testing.T) *time.Timer {
	t.Helper()
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	t.Cleanup(func() {
		timer.Stop()
	})
	return timer
}

func assertLogContains(t *testing.T, output string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(output, fragment) {
			t.Fatalf("log output %q does not contain %q", output, fragment)
		}
	}
}

func TestWatchFailureIsRetriedAndClearedWithoutRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "notes")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	roots := []watchRoot{{name: "notes", path: root}}
	conditions := map[string]state.WatchCondition{
		"notes": newWatchCondition(root, errors.New("watch limit reached")),
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	if changed := retryWatchConditions(watcher, roots, conditions, logger); !changed {
		t.Fatal("retry did not report cleared condition")
	}
	if len(conditions) != 0 {
		t.Fatalf("watch conditions = %#v, want cleared", conditions)
	}
}

func TestStatusReportsPersistedScanOnlyCondition(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	condition := state.WatchCondition{
		Path:   filepath.Join(root, "notes"),
		Reason: "watch directory: no space left on device",
		Limit:  8192,
		Sysctl: inotifyLimitName,
	}
	if err := state.SaveWatchConditions(map[string]state.WatchCondition{"notes": condition}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if got := Status(&stdout, &stderr); got != statusExitOK {
		t.Fatalf("status exit = %d, stderr = %q", got, stderr.String())
	}
	assertLogContains(t, stdout.String(), "scan-only notes", "limit 8192", inotifyLimitName)
}

func TestWatchRootComparisonDistinguishesBindingFromRegistrationChanges(t *testing.T) {
	current := []watchRoot{{name: "notes", path: "/notes"}}
	if !sameWatchRoots(current, []watchRoot{{name: "notes", path: "/notes"}}) {
		t.Fatal("unchanged roots require restart for binding-only config change")
	}
	if sameWatchRoots(current, []watchRoot{{name: "notes", path: "/moved"}}) {
		t.Fatal("path change did not require watcher restart")
	}
	if sameWatchRoots(current, append(current, watchRoot{name: "photos", path: "/photos"})) {
		t.Fatal("registration addition did not require watcher restart")
	}
}

func TestCycleConfigurationIgnoresUnchangedRewritesAndUnboundPeers(t *testing.T) {
	current := config.New()
	current.Peers["phone"] = config.Peer{Address: "phone", Status: config.PeerActive, PublicKey: "key"}
	current.Shared["notes"] = "/notes"
	current.Bindings["notes"] = []string{"phone"}
	if !sameCycleConfiguration(current, config.Clone(current)) {
		t.Fatal("semantic no-op config rewrite scheduled a cycle")
	}
	unboundChange := config.Clone(current)
	unboundChange.Peers["other"] = config.Peer{Address: "other", Status: config.PeerPending}
	if !sameCycleConfiguration(current, unboundChange) {
		t.Fatal("unbound address-book change scheduled a cycle")
	}
	boundChange := config.Clone(current)
	peer := boundChange.Peers["phone"]
	peer.Status = config.PeerPending
	boundChange.Peers["phone"] = peer
	if sameCycleConfiguration(current, boundChange) {
		t.Fatal("bound peer status change did not schedule a cycle")
	}
}
