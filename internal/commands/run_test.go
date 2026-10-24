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
	"l2syncd/internal/index"
)

func TestExecuteCycleResetsPeerOnSuccess(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	backoff := newPeerBackoff()
	backoff.Fail("phone", time.Now())
	executeCycle(context.Background(), logger, stoppedTimer(t), backoff, cycleTriggerFilesystem,
		func(context.Context, func(string) bool) (CycleSummary, error) {
			return CycleSummary{Folders: 1, Actions: 3, Outcomes: []FolderOutcome{{Name: "notes", Peer: "phone", Committed: true, Actions: 3}}}, nil
		})
	if _, waiting := backoff.Next(time.Now()); waiting {
		t.Fatal("successful peer still backing off")
	}
	assertLogContains(t, output.String(), `msg="sync cycle completed"`, `actions=3`)
}

func TestExecuteCycleBacksOffOnlyFailedPeer(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	backoff := newPeerBackoff()
	executeCycle(context.Background(), logger, stoppedTimer(t), backoff, cycleTriggerRetry,
		func(context.Context, func(string) bool) (CycleSummary, error) {
			return CycleSummary{Folders: 1, Outcomes: []FolderOutcome{
				{Name: "notes", Peer: "phone", Committed: true},
				{Name: "pics", Peer: "raspberries"},
			}}, errors.New("pics: peer unreachable")
		})
	if backoff.Ready("raspberries", time.Now()) {
		t.Fatal("failed peer not backing off")
	}
	if !backoff.Ready("phone", time.Now()) {
		t.Fatal("healthy peer backing off")
	}
	assertLogContains(t, output.String(), `msg="sync cycle failed"`, `error="pics: peer unreachable"`)
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
	conditions := map[string]index.WatchCondition{
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
	condition := index.WatchCondition{
		Path:   filepath.Join(root, "notes"),
		Reason: "watch directory: no space left on device",
		Limit:  8192,
		Sysctl: inotifyLimitName,
	}
	if err := index.SaveWatchConditions(map[string]index.WatchCondition{"notes": condition}); err != nil {
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

func TestEventMarksDirty(t *testing.T) {
	configPath := filepath.Join(string(filepath.Separator), "home", "user", ".config", "l2sync", "config.toml")
	configDir := filepath.Dir(configPath)
	shareRoot := filepath.Join(string(filepath.Separator), "home", "user", "notes")

	cases := []struct {
		name  string
		event fsnotify.Event
		want  bool
	}{
		{
			name:  "trash write",
			event: fsnotify.Event{Name: filepath.Join(shareRoot, ".l2sync-trash", "2026-08-24", "notes.txt"), Op: fsnotify.Write},
			want:  false,
		},
		{
			name:  "conflict artifact create",
			event: fsnotify.Event{Name: filepath.Join(shareRoot, "notes.txt.l2sync-conflict-20260824"), Op: fsnotify.Create},
			want:  false,
		},
		{
			name:  "l2sync marker write",
			event: fsnotify.Event{Name: filepath.Join(shareRoot, ".l2sync"), Op: fsnotify.Write},
			want:  false,
		},
		{
			name:  "config temp file create",
			event: fsnotify.Event{Name: filepath.Join(configDir, ".config-abc.toml"), Op: fsnotify.Create},
			want:  false,
		},
		{
			name:  "config temp file rename",
			event: fsnotify.Event{Name: filepath.Join(configDir, ".config-abc.toml"), Op: fsnotify.Rename},
			want:  false,
		},
		{
			name:  "ordinary share write",
			event: fsnotify.Event{Name: filepath.Join(shareRoot, "report.txt"), Op: fsnotify.Write},
			want:  true,
		},
		{
			name:  "real config write",
			event: fsnotify.Event{Name: configPath, Op: fsnotify.Write},
			want:  true,
		},
		{
			name:  "chmod only",
			event: fsnotify.Event{Name: filepath.Join(shareRoot, "report.txt"), Op: fsnotify.Chmod},
			want:  false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := eventMarksDirty(testCase.event, configPath); got != testCase.want {
				t.Fatalf("eventMarksDirty(%+v) = %v, want %v", testCase.event, got, testCase.want)
			}
		})
	}
}

func TestAddTreeExcludesTrashDirectory(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	trash := filepath.Join(root, ".l2sync-trash", "2026-08-24")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(trash, 0o700); err != nil {
		t.Fatal(err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()

	if err := addTree(watcher, root); err != nil {
		t.Fatal(err)
	}

	watched := make(map[string]bool)
	for _, path := range watcher.WatchList() {
		watched[path] = true
	}
	if !watched[root] {
		t.Fatalf("watch list %v missing root %q", watcher.WatchList(), root)
	}
	if !watched[sub] {
		t.Fatalf("watch list %v missing sub %q", watcher.WatchList(), sub)
	}
	if watched[filepath.Join(root, ".l2sync-trash")] {
		t.Fatalf("watch list %v includes .l2sync-trash", watcher.WatchList())
	}
	if watched[trash] {
		t.Fatalf("watch list %v includes trash date directory", watcher.WatchList())
	}
}

func TestBoundCyclePeersDeduplicatesAcrossFolders(t *testing.T) {
	cfg := config.New()
	cfg.Peers["phone"] = config.Peer{Address: "phone", PublicKey: "key"}
	cfg.Shared["notes"] = config.Folder{Path: "/notes", Peers: []string{"phone"}}
	cfg.Remote["photos"] = config.Folder{Path: "/photos", Peers: []string{"phone"}}

	got := boundCyclePeers(cfg)
	if len(got) != 1 || got[0] != "phone" {
		t.Fatalf("boundCyclePeers = %v, want [phone]", got)
	}
}

func TestApplyReachabilityReportsOnlyTransitions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	reachable := map[string]bool{"phone": false, "vps": true}
	got := applyReachability(reachable, map[string]bool{"phone": true, "vps": true}, logger)
	if len(got) != 1 || got[0] != "phone" {
		t.Fatalf("reconnected = %v, want [phone]", got)
	}
	if again := applyReachability(reachable, map[string]bool{"phone": true}, logger); len(again) != 0 {
		t.Fatalf("already-reachable peer reported again: %v", again)
	}
}

func TestProbePeersRunsConcurrently(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	probe := func(context.Context, config.Config, string) bool {
		started <- struct{}{}
		<-release
		return true
	}
	done := make(chan map[string]bool)
	go func() { done <- probePeers(context.Background(), config.New(), []string{"a", "b"}, probe) }()
	for range 2 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("probes did not start concurrently")
		}
	}
	close(release)
	if results := <-done; !results["a"] || !results["b"] {
		t.Fatalf("results = %v", results)
	}
}

func TestLockFolderCycleSerializesSameFolder(t *testing.T) {
	unlockFirst := lockFolderCycle("notes")
	started := make(chan struct{})
	acquired := make(chan struct{})
	go func() {
		close(started)
		unlockSecond := lockFolderCycle("notes")
		close(acquired)
		unlockSecond()
	}()
	<-started
	select {
	case <-acquired:
		t.Fatal("second cycle lock acquired while first cycle still holds it")
	case <-time.After(50 * time.Millisecond):
	}
	unlockFirst()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("second cycle lock never acquired after first released")
	}
}

func TestLockFolderCycleAllowsDifferentFolders(t *testing.T) {
	unlockA := lockFolderCycle("folder-a")
	defer unlockA()
	done := make(chan struct{})
	go func() {
		unlockB := lockFolderCycle("folder-b")
		unlockB()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lock for a different folder blocked unexpectedly")
	}
}

func TestCycleConfigurationIgnoresUnchangedRewritesAndUnboundPeers(t *testing.T) {
	current := config.New()
	current.Peers["phone"] = config.Peer{Address: "phone", PublicKey: "key"}
	current.Shared["notes"] = config.Folder{Path: "/notes", Peers: []string{"phone"}}
	if !sameCycleConfiguration(current, config.Clone(current)) {
		t.Fatal("semantic no-op config rewrite scheduled a cycle")
	}
	unboundChange := config.Clone(current)
	unboundChange.Peers["other"] = config.Peer{Address: "other"}
	if !sameCycleConfiguration(current, unboundChange) {
		t.Fatal("unbound address-book change scheduled a cycle")
	}
	boundChange := config.Clone(current)
	peer := boundChange.Peers["phone"]
	peer.PublicKey = ""
	boundChange.Peers["phone"] = peer
	if sameCycleConfiguration(current, boundChange) {
		t.Fatal("bound peer key change did not schedule a cycle")
	}
}

func TestConfiguredWatchRootsResolveSymlinkedRoot(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(target, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	cfg.Shared["notes"] = config.Folder{Path: link}
	roots, err := configuredWatchRoots(cfg)
	if err != nil {
		t.Fatal(err)
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	if err := addTree(watcher, roots[0].path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "sub", "new"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-watcher.Events:
		if !strings.HasSuffix(event.Name, filepath.Join("sub", "new")) {
			t.Fatalf("event = %v, want sub/new", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event for a file created in a subdirectory of a symlinked root")
	}
}
