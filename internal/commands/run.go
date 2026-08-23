//go:build linux

package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"l2syncd/internal/config"
	"l2syncd/internal/lock"
	"l2syncd/internal/preflight"
)

const (
	runExitOK       = 0
	runExitError    = 1
	runDebounce     = 500 * time.Millisecond
	runFullScan     = 15 * time.Minute
	runBackoffStart = time.Second
	runBackoffMax   = time.Minute
)

// Run starts the foreground daemon. Filesystem events only mark the tree
// dirty; reconciliation is performed by the same cycle used by `now`.
func Run(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: l2sync run")
		return runExitError
	}
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return runExitError
	}
	lockFile, err := lock.Acquire()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return runExitError
	}
	defer lock.Release(lockFile)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: create watcher: %v\n", err)
		return runExitError
	}
	defer watcher.Close()
	for _, root := range remoteAndSharedPaths(cfg) {
		if err := addTree(watcher, root); err != nil {
			fmt.Fprintf(stderr, "l2sync: watch %q: %v\n", root, err)
			return runExitError
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	debounce := time.NewTimer(time.Hour)
	if !debounce.Stop() {
		<-debounce.C
	}
	periodic := time.NewTicker(runFullScan)
	defer periodic.Stop()
	retry := time.NewTimer(time.Hour)
	if !retry.Stop() {
		<-retry.C
	}
	dirty := false
	backoff := runBackoffStart
	if err := runOnce(ctx, cfg); err != nil {
		fmt.Fprintf(stderr, "l2sync: initial cycle: %v\n", err)
		resetTimer(retry, backoff)
	}
	for {
		select {
		case <-ctx.Done():
			return runExitOK
		case event, ok := <-watcher.Events:
			if !ok {
				return runExitError
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
				dirty = true
				resetTimer(debounce, runDebounce)
			}
			if event.Op&fsnotify.Create != 0 {
				if info, statErr := os.Stat(event.Name); statErr == nil && info.IsDir() {
					if watchErr := addTree(watcher, event.Name); watchErr != nil {
						fmt.Fprintf(stderr, "l2sync: watch %q: %v\n", event.Name, watchErr)
					}
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return runExitError
			}
			fmt.Fprintf(stderr, "l2sync: watcher: %v\n", err)
			dirty = true
		case <-debounce.C:
			if dirty {
				dirty = false
				backoff = executeCycle(ctx, cfg, stderr, retry, backoff)
			}
		case <-periodic.C:
			backoff = executeCycle(ctx, cfg, stderr, retry, backoff)
		case <-retry.C:
			backoff = executeCycle(ctx, cfg, stderr, retry, backoff)
		}
	}
}

func runOnce(ctx context.Context, cfg config.Config) error {
	return RunCycle(ctx, cfg)
}

func executeCycle(ctx context.Context, cfg config.Config, stderr io.Writer, retry *time.Timer, delay time.Duration) time.Duration {
	if err := runOnce(ctx, cfg); err != nil {
		fmt.Fprintf(stderr, "l2sync: cycle: %v\n", err)
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
	return runBackoffStart
}

func addTree(watcher *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		return watcher.Add(path)
	})
}

func remoteAndSharedPaths(cfg config.Config) []string {
	paths := make([]string, 0, len(cfg.Shared)+len(cfg.Remote))
	for _, path := range cfg.Shared {
		paths = append(paths, path)
	}
	for _, path := range cfg.Remote {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
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
