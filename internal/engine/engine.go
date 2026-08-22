//go:build linux

// Package engine plans reconciliation without modifying either replica.
package engine

import (
	"fmt"
	"sort"

	"l2syncd/internal/guard"
	"l2syncd/internal/state"
)

type ActionKind string

const (
	Push      ActionKind = "push"
	Pull      ActionKind = "pull"
	Delete    ActionKind = "delete"
	Resurrect ActionKind = "resurrect"
	Conflict  ActionKind = "conflict"
)

type Action struct {
	Path   string
	Kind   ActionKind
	Source string
	Winner string
	Loser  string
}

type Plan struct {
	Actions []Action
	Halted  bool
	Reason  string
}

// Replica supplies one side's current state to the planner.
type Replica interface {
	Name() string
	Current() (state.Baseline, error)
}

// Reconcile reads both replicas and returns decisions only. It never applies
// an action or writes a baseline.
func Reconcile(left, right Replica, baseline state.Baseline) (Plan, error) {
	if left == nil || right == nil {
		return Plan{}, fmt.Errorf("both replicas are required")
	}
	if left.Name() == "" || right.Name() == "" || left.Name() == right.Name() {
		return Plan{}, fmt.Errorf("replica names must be distinct and non-empty")
	}
	mine, err := left.Current()
	if err != nil {
		return Plan{}, fmt.Errorf("read replica %q: %w", left.Name(), err)
	}
	theirs, err := right.Current()
	if err != nil {
		return Plan{}, fmt.Errorf("read replica %q: %w", right.Name(), err)
	}
	return PlanStates(left.Name(), mine, right.Name(), theirs, baseline), nil
}

// PlanStates plans from already-read states. Hashes are the only cross-peer
// comparison; inode and mtime are used only for local change detection.
func PlanStates(leftName string, left state.Baseline, rightName string, right state.Baseline, baseline state.Baseline) Plan {
	if deletionHalt(left, baseline) || deletionHalt(right, baseline) {
		return Plan{Halted: true, Reason: "deletion threshold exceeded"}
	}
	paths := make(map[string]struct{}, len(left.Files)+len(right.Files)+len(baseline.Files))
	for path := range left.Files {
		paths[path] = struct{}{}
	}
	for path := range right.Files {
		paths[path] = struct{}{}
	}
	for path := range baseline.Files {
		paths[path] = struct{}{}
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	actions := make([]Action, 0)
	for _, path := range ordered {
		if action, ok := decide(path, leftName, left.Files[path], rightName, right.Files[path], baseline.Files[path]); ok {
			actions = append(actions, action)
		}
	}
	return Plan{Actions: actions}
}

func decide(path, leftName string, left state.File, rightName string, right state.File, previous state.File) (Action, bool) {
	leftExists := left.Hash != ""
	rightExists := right.Hash != ""
	previousExists := previous.Hash != ""
	leftChanged := leftExists != previousExists || leftExists && left.Hash != previous.Hash
	rightChanged := rightExists != previousExists || rightExists && right.Hash != previous.Hash
	if !leftChanged && !rightChanged {
		return Action{}, false
	}
	if leftChanged && rightChanged && leftExists && rightExists && left.Hash == right.Hash {
		return Action{}, false
	}
	if leftChanged && rightChanged {
		if !leftExists && !rightExists {
			return Action{}, false
		}
		if !leftExists && rightExists {
			return Action{Path: path, Kind: Resurrect, Source: rightName}, true
		}
		if leftExists && !rightExists {
			return Action{Path: path, Kind: Resurrect, Source: leftName}, true
		}
		winner, loser := resolveConflict(leftName, left, rightName, right)
		return Action{Path: path, Kind: Conflict, Winner: winner, Loser: loser}, true
	}
	if leftChanged {
		if leftExists {
			return Action{Path: path, Kind: Push, Source: leftName}, true
		}
		return Action{Path: path, Kind: Delete, Source: leftName}, true
	}
	if rightExists {
		return Action{Path: path, Kind: Pull, Source: rightName}, true
	}
	return Action{Path: path, Kind: Delete, Source: rightName}, true
}

func resolveConflict(leftName string, left state.File, rightName string, right state.File) (string, string) {
	if left.Mtime.After(right.Mtime) {
		return leftName, rightName
	}
	if right.Mtime.After(left.Mtime) {
		return rightName, leftName
	}
	if leftName < rightName {
		return leftName, rightName
	}
	return rightName, leftName
}

func deletionHalt(current, baseline state.Baseline) bool {
	deletes := 0
	for path := range baseline.Files {
		if _, exists := current.Files[path]; !exists {
			deletes++
		}
	}
	return guard.DeleteThreshold(deletes, len(baseline.Files))
}
