//go:build linux

package commands

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/lock"
	"l2syncd/internal/logging"
	"l2syncd/internal/preflight"
	"l2syncd/internal/state"
)

const (
	runExitOK        = 0
	runExitError     = 1
	runDebounce      = 500 * time.Millisecond
	runFullScan      = 15 * time.Minute
	runBackoffStart  = time.Second
	runBackoffMax    = time.Minute
	runWatchRetry    = time.Minute
	runConfigDirMode = 0o700
	inotifyLimitPath = "/proc/sys/fs/inotify/max_user_watches"
	inotifyLimitName = "fs.inotify.max_user_watches"

	cycleTriggerFilesystem = "filesystem"
	cycleTriggerPeriodic   = "periodic"
	cycleTriggerRetry      = "retry"
	cycleTriggerStartup    = "startup"
)

type cycleRunner func(context.Context) (CycleSummary, error)

type watchRoot struct {
	name string
	path string
}

// Run starts the foreground daemon. Filesystem events only mark the tree
// dirty; reconciliation is performed by the same cycle used by `now`.
func Run(args []string, stderr io.Writer) (exitCode int) {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: l2sync run")
		return runExitError
	}
	logger := logging.NewLogger(stderr, "daemon")
	// RunCycle (invoked below via executeCycle) and the baseline commit it
	// performs log through the shared now/commit loggers regardless of
	// whether they were reached from `l2sync now` or the daemon's cycle
	// loop; point them at this process's stderr and the shared log file
	// so daemon cycles land in the same file as serve-side mutations.
	nowLogger = logging.NewLogger(stderr, "now")
	commitLogger = logging.NewLogger(stderr, "commit")
	lockFile, err := lock.AcquireDaemon()
	if err != nil {
		logger.Error("acquire daemon lock", "error", err)
		return runExitError
	}
	defer func() {
		if err := lock.Release(lockFile); err != nil {
			logger.Error("release daemon lock", "error", err)
			if exitCode == runExitOK {
				exitCode = runExitError
			}
		}
	}()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Error("create filesystem watcher", "error", err)
		return runExitError
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			logger.Error("close filesystem watcher", "error", err)
			if exitCode == runExitOK {
				exitCode = runExitError
			}
		}
	}()
	configPath, err := config.Path()
	if err != nil {
		logger.Error("resolve config watch path", "error", err)
		return runExitError
	}
	if err := os.MkdirAll(filepath.Dir(configPath), runConfigDirMode); err != nil {
		logger.Error("prepare config watch directory", "error", err)
		return runExitError
	}
	if err := watcher.Add(filepath.Dir(configPath)); err != nil {
		logger.Error("watch config directory", "error", err)
		return runExitError
	}
	cfg, err := preflight.LoadConfig()
	if err != nil {
		logger.Error("preflight failed", "error", err)
		return runExitError
	}
	watchRoots := configuredWatchRoots(cfg)
	watchConditions := make(map[string]state.WatchCondition)
	for _, root := range watchRoots {
		if err := addTree(watcher, root.path); err != nil {
			watchConditions[root.name] = newWatchCondition(root.path, err)
			logger.Error("folder running scan-only", "folder", root.name, "path", root.path, "error", err, "sysctl", inotifyLimitName)
		}
	}
	latest, err := preflight.LoadConfig()
	if err != nil {
		logger.Error("revalidate config after watch registration", "error", err)
		return runExitError
	}
	if latestRoots := configuredWatchRoots(latest); !sameWatchRoots(watchRoots, latestRoots) {
		logger.Error("configured folder registrations or paths changed during daemon startup; restart l2sync run")
		return runExitError
	}
	cfg = latest
	if err := state.SaveWatchConditions(watchConditions); err != nil {
		logger.Error("save watch status", "error", err)
		return runExitError
	}
	logger.Info("daemon started",
		"watch_roots", len(watchRoots),
		"shared_folders", len(latest.Shared),
		"remote_folders", len(latest.Remote),
		"full_scan_interval", runFullScan,
	)
	defer logger.Info("daemon stopped")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	debounce := time.NewTimer(time.Hour)
	if !debounce.Stop() {
		<-debounce.C
	}
	periodic := time.NewTicker(runFullScan)
	defer periodic.Stop()
	watchRetry := time.NewTicker(runWatchRetry)
	defer watchRetry.Stop()
	retry := time.NewTimer(time.Hour)
	if !retry.Stop() {
		<-retry.C
	}
	dirty := false
	backoff := runBackoffStart
	backoff = executeCycle(ctx, logger, retry, backoff, cycleTriggerStartup, RunCycle)
	for {
		select {
		case <-ctx.Done():
			return runExitOK
		case event, ok := <-watcher.Events:
			if !ok {
				logger.Error("filesystem watcher event stream closed")
				return runExitError
			}
			// Every "marked tree dirty" log below is a deliberate, temporary
			// diagnostic for an unresolved question about peer-originated
			// writes reaching this watcher; it is not permanent behavior.
			if filepath.Clean(event.Name) == filepath.Clean(configPath) && event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
				latest, loadErr := preflight.LoadConfig()
				if loadErr != nil {
					logger.Error("reload changed config", "error", loadErr)
					return runExitError
				}
				latestRoots := configuredWatchRoots(latest)
				if !sameWatchRoots(watchRoots, latestRoots) {
					logger.Error("configured folder registrations or paths changed; restart l2sync run to rebuild filesystem watches")
					return runExitError
				}
				cycleChanged := !sameCycleConfiguration(cfg, latest)
				cfg = latest
				if !cycleChanged {
					continue
				}
				logger.Info("filesystem event marked tree dirty", "path", event.Name, "op", event.Op.String())
				dirty = true
				resetTimer(debounce, runDebounce)
				continue
			}
			if eventMarksDirty(event, configPath) {
				logger.Info("filesystem event marked tree dirty", "path", event.Name, "op", event.Op.String())
				dirty = true
				resetTimer(debounce, runDebounce)
			}
			if event.Op&fsnotify.Create != 0 {
				info, statErr := os.Stat(event.Name)
				switch {
				case statErr == nil && info.IsDir():
					if watchErr := addTree(watcher, event.Name); watchErr != nil {
						logger.Error("register filesystem watch", "path", event.Name, "error", watchErr)
						if markWatchFailure(watchConditions, watchRoots, event.Name, watchErr) {
							if err := state.SaveWatchConditions(watchConditions); err != nil {
								logger.Error("save watch status", "error", err)
							}
						}
					}
				case statErr != nil && !os.IsNotExist(statErr):
					logger.Error("inspect created filesystem entry", "path", event.Name, "error", statErr)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				logger.Error("filesystem watcher error stream closed")
				return runExitError
			}
			logger.Error("filesystem watcher error", "error", err)
			dirty = true
			resetTimer(debounce, runDebounce)
		case <-debounce.C:
			if dirty {
				dirty = false
				backoff = executeCycle(ctx, logger, retry, backoff, cycleTriggerFilesystem, RunCycle)
			}
		case <-periodic.C:
			backoff = executeCycle(ctx, logger, retry, backoff, cycleTriggerPeriodic, RunCycle)
		case <-watchRetry.C:
			if retryWatchConditions(watcher, watchRoots, watchConditions, logger) {
				if err := state.SaveWatchConditions(watchConditions); err != nil {
					logger.Error("save watch status", "error", err)
				}
			}
		case <-retry.C:
			backoff = executeCycle(ctx, logger, retry, backoff, cycleTriggerRetry, RunCycle)
		}
	}
}

// sameCycleConfiguration compares only the bindings that decide whether a
// cycle runs (folder path changes are handled separately by
// sameWatchRoots, which triggers a daemon restart).
func sameCycleConfiguration(left, right config.Config) bool {
	leftBindings := cycleBindings(left)
	rightBindings := cycleBindings(right)
	if len(leftBindings) != len(rightBindings) {
		return false
	}
	boundPeers := make(map[string]struct{})
	for name, peers := range leftBindings {
		other, exists := rightBindings[name]
		if !exists || len(peers) != len(other) {
			return false
		}
		for index := range peers {
			if peers[index] != other[index] {
				return false
			}
			boundPeers[peers[index]] = struct{}{}
		}
	}
	for peer := range boundPeers {
		leftPeer, leftExists := left.Peers[peer]
		rightPeer, rightExists := right.Peers[peer]
		if leftExists != rightExists || leftPeer != rightPeer {
			return false
		}
	}
	return true
}

func cycleBindings(cfg config.Config) map[string][]string {
	bindings := make(map[string][]string)
	for name, folder := range cfg.Shared {
		if len(folder.Peers) != 0 {
			bindings[name] = folder.Peers
		}
	}
	for name, folder := range cfg.Remote {
		if len(folder.Peers) != 0 {
			bindings[name] = folder.Peers
		}
	}
	return bindings
}

func sameWatchRoots(left, right []watchRoot) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func executeCycle(ctx context.Context, logger *slog.Logger, retry *time.Timer, delay time.Duration, trigger string, cycle cycleRunner) time.Duration {
	started := time.Now()
	logger.Info("sync cycle started", "trigger", trigger)
	summary, err := cycle(ctx)
	for _, outcome := range summary.Outcomes {
		logger.Info("folder cycle outcome",
			"trigger", trigger,
			"folder", outcome.Name,
			"initiated_locally", outcome.InitiatedLocally,
			"actions", outcome.Actions,
			"committed", outcome.Committed,
		)
	}
	if err != nil {
		logger.Error("sync cycle failed",
			"trigger", trigger,
			"duration", time.Since(started),
			"folders_completed", summary.Folders,
			"actions_completed", summary.Actions,
			"retry_in", delay,
			"error", err,
		)
		resetTimer(retry, delay)
		if delay < runBackoffMax {
			delay *= 2
			if delay > runBackoffMax {
				delay = runBackoffMax
			}
		}
		return delay
	}
	if !retry.Stop() {
		select {
		case <-retry.C:
		default:
		}
	}
	logger.Info("sync cycle completed",
		"trigger", trigger,
		"duration", time.Since(started),
		"folders", summary.Folders,
		"actions", summary.Actions,
	)
	return runBackoffStart
}

func addTree(watcher *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %q: %w", path, err)
		}
		if !entry.IsDir() {
			return nil
		}
		if path != root && guard.DefaultIgnore(entry.Name()) {
			return filepath.SkipDir
		}
		if err := watcher.Add(path); err != nil {
			return fmt.Errorf("watch directory %q: %w", path, err)
		}
		return nil
	})
}

// eventMarksDirty reports whether a filesystem event should mark the sync
// tree dirty and schedule a reconciliation cycle. It excludes events under
// any ignored path component (internal trash and conflict artifacts,
// notably) and config-directory temp files that are not the config file
// itself.
func eventMarksDirty(event fsnotify.Event, configPath string) bool {
	if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
		return false
	}
	if filepath.Dir(event.Name) == filepath.Dir(configPath) && filepath.Clean(event.Name) != filepath.Clean(configPath) {
		return false
	}
	return !guard.DefaultIgnorePath(event.Name)
}

func configuredWatchRoots(cfg config.Config) []watchRoot {
	roots := make([]watchRoot, 0, len(cfg.Shared)+len(cfg.Remote))
	for name, folder := range cfg.Shared {
		roots = append(roots, watchRoot{name: name, path: folder.Path})
	}
	for name, folder := range cfg.Remote {
		roots = append(roots, watchRoot{name: name, path: folder.Path})
	}
	sort.Slice(roots, func(left, right int) bool { return roots[left].name < roots[right].name })
	return roots
}

func newWatchCondition(path string, watchErr error) state.WatchCondition {
	condition := state.WatchCondition{Path: path, Reason: watchErr.Error(), Sysctl: inotifyLimitName}
	contents, err := os.ReadFile(inotifyLimitPath)
	if err != nil {
		return condition
	}
	limit, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err == nil {
		condition.Limit = limit
	}
	return condition
}

func markWatchFailure(conditions map[string]state.WatchCondition, roots []watchRoot, failedPath string, watchErr error) bool {
	for _, root := range roots {
		relative, err := filepath.Rel(root.path, failedPath)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			conditions[root.name] = newWatchCondition(root.path, watchErr)
			return true
		}
	}
	return false
}

func retryWatchConditions(watcher *fsnotify.Watcher, roots []watchRoot, conditions map[string]state.WatchCondition, logger *slog.Logger) bool {
	changed := false
	for _, root := range roots {
		if _, failed := conditions[root.name]; !failed {
			continue
		}
		if err := addTree(watcher, root.path); err != nil {
			updated := newWatchCondition(root.path, err)
			if current := conditions[root.name]; current.Reason != updated.Reason || current.Limit != updated.Limit {
				conditions[root.name] = updated
				changed = true
			}
			continue
		}
		delete(conditions, root.name)
		changed = true
		logger.Info("filesystem watches restored", "folder", root.name, "path", root.path)
	}
	return changed
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
}
