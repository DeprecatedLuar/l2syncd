//go:build linux

// Package engine plans reconciliation without modifying either replica.
package engine

import (
	"fmt"
	"sort"

	"l2syncd/internal/guard"
	"l2syncd/internal/index"
	"l2syncd/internal/metadata"
	"l2syncd/internal/vector"
)

type ActionKind string

const (
	Push      ActionKind = "push"
	Pull      ActionKind = "pull"
	Delete    ActionKind = "delete"
	Resurrect ActionKind = "resurrect"
	Conflict  ActionKind = "conflict"
	// Merge resolves a concurrent pair that needs no byte transfer: both
	// sides already hold the same content (or are both tombstoned). Only
	// the vector advances, silently, with no conflict copy (concept.md 4.2).
	Merge ActionKind = "merge"
)

type Action struct {
	Path      string
	Kind      ActionKind
	Source    string
	Winner    string
	Loser     string
	Directory bool
	// Vector is the version vector both replicas must hold for Path once
	// this action lands. It is the one thing an index-commit function needs
	// to know to persist the result of any action kind uniformly.
	Vector vector.Vector
}

type Plan struct {
	Actions          []Action
	DirectoryActions []Action
	Halted           bool
	Reason           string
}

// ReplicaState is everything engine needs from one replica. Entries are
// version-vector tracked and compared directly, needing no third reference
// point (concept.md 4.2). Directories are not vector-tracked (concept.md 7
// records a plain manifest per directory), so reconciling them still needs
// each side's own last-committed manifests alongside its current ones.
type ReplicaState struct {
	Index               index.Index
	PreviousDirectories map[string]metadata.Manifest
}

// Replica supplies one side's current state to the planner.
type Replica interface {
	Name() string
	Current() (ReplicaState, error)
}

// Reconcile reads both replicas and returns decisions only. It never applies
// an action or writes an index.
func Reconcile(left, right Replica) (Plan, error) {
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
	return PlanStates(left.Name(), mine, right.Name(), theirs), nil
}

// PlanStates plans from already-read states. A version vector comparison is
// the only cross-peer ordering authority (concept.md 4.2); no baseline or
// wall-clock time is consulted anywhere in this function.
func PlanStates(leftName string, left ReplicaState, rightName string, right ReplicaState) Plan {
	if leftName == "" || rightName == "" || leftName == rightName {
		return Plan{Halted: true, Reason: "replica identities must be distinct and non-empty"}
	}
	paths := make(map[string]struct{}, len(left.Index.Entries)+len(right.Index.Entries))
	for path := range left.Index.Entries {
		paths[path] = struct{}{}
	}
	for path := range right.Index.Entries {
		paths[path] = struct{}{}
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	actions := make([]Action, 0, len(ordered))
	deletes := 0
	for _, path := range ordered {
		action, ok := decide(path, leftName, left.Index.Entries[path], rightName, right.Index.Entries[path])
		if !ok {
			continue
		}
		if action.Kind == Delete {
			deletes++
		}
		actions = append(actions, action)
	}
	if guard.DeleteThreshold(deletes, len(ordered)) {
		return Plan{Halted: true, Reason: "deletion threshold exceeded"}
	}
	return Plan{Actions: actions, DirectoryActions: planDirectories(leftName, left, rightName, right)}
}

// decide plans one path from both sides' entries. A missing entry compares
// as an all-zero vector (vector.Compare), so a path one side has never heard
// of is handled by the same Greater/Lesser branches as any other causal
// gap: it is always a creation, never inferred as a deletion (concept.md
// 4.2, 5.2 gate 4).
func decide(path, leftName string, left index.Entry, rightName string, right index.Entry) (Action, bool) {
	switch vector.Compare(left.Version, right.Version) {
	case vector.Equal:
		return Action{}, false
	case vector.Greater:
		return oneSidedAction(path, leftName, left, Push), true
	case vector.Lesser:
		return oneSidedAction(path, rightName, right, Pull), true
	default:
		return concurrentAction(path, leftName, left, rightName, right)
	}
}

func oneSidedAction(path, winnerName string, winner index.Entry, contentKind ActionKind) Action {
	if winner.Deleted {
		return Action{Path: path, Kind: Delete, Source: winnerName, Vector: winner.Version}
	}
	return Action{Path: path, Kind: contentKind, Source: winnerName, Vector: winner.Version}
}

// concurrentAction resolves entries whose vectors are causally incomparable:
// neither side's knowledge is a superset of the other's, so nothing but
// content and deletion state can decide the outcome. This is the only
// branch that can write a conflict copy.
func concurrentAction(path, leftName string, left index.Entry, rightName string, right index.Entry) (Action, bool) {
	merged := vector.Merge(left.Version, right.Version)
	switch {
	case left.Deleted && right.Deleted:
		// Both sides independently tombstoned the same path. Merge the
		// vectors silently; there is nothing left to transfer.
		return Action{Path: path, Kind: Merge, Vector: merged}, true
	case left.Deleted != right.Deleted:
		// Modification concurrent with deletion: the modification wins,
		// without rename, because losing data is worse than keeping an
		// unwanted file (concept.md 4.2).
		if left.Deleted {
			return Action{Path: path, Kind: Resurrect, Source: rightName, Vector: merged}, true
		}
		return Action{Path: path, Kind: Resurrect, Source: leftName, Vector: merged}, true
	case left.Hash == right.Hash:
		// Concurrent edits that happen to produce identical bytes: merge
		// silently, no conflict copy (concept.md 4.2).
		return Action{Path: path, Kind: Merge, Vector: merged}, true
	default:
		winner, loser := resolveConflict(leftName, rightName)
		return Action{Path: path, Kind: Conflict, Winner: winner, Loser: loser, Vector: merged}, true
	}
}

func resolveConflict(leftName, rightName string) (string, string) {
	if leftName < rightName {
		return leftName, rightName
	}
	return rightName, leftName
}

// planDirectories reconciles directory metadata. Directories carry no
// version vector (concept.md 7): each side's own previously committed
// manifest is the only reference available for deciding who changed what,
// exactly as before, just no longer shared between replicas.
func planDirectories(leftName string, left ReplicaState, rightName string, right ReplicaState) []Action {
	paths := make(map[string]struct{}, len(left.Index.Directories)+len(right.Index.Directories)+len(left.PreviousDirectories)+len(right.PreviousDirectories))
	for _, set := range []map[string]metadata.Manifest{left.Index.Directories, right.Index.Directories, left.PreviousDirectories, right.PreviousDirectories} {
		for path := range set {
			paths[path] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	actions := make([]Action, 0)
	for _, path := range ordered {
		leftCurrent, leftExists := left.Index.Directories[path]
		rightCurrent, rightExists := right.Index.Directories[path]
		leftPrevious, leftPreviousExists := left.PreviousDirectories[path]
		rightPrevious, rightPreviousExists := right.PreviousDirectories[path]
		leftChanged := leftExists != leftPreviousExists || leftExists && leftPreviousExists && !metadata.Equal(leftCurrent, leftPrevious)
		rightChanged := rightExists != rightPreviousExists || rightExists && rightPreviousExists && !metadata.Equal(rightCurrent, rightPrevious)
		unchanged := !leftChanged && !rightChanged
		converged := leftChanged && rightChanged && leftExists && rightExists && metadata.Equal(leftCurrent, rightCurrent)
		bothDeleted := leftChanged && rightChanged && !leftExists && !rightExists
		if unchanged || converged || bothDeleted {
			continue
		}
		action := Action{Path: path, Directory: true}
		switch {
		case leftChanged && rightChanged && !leftExists:
			action.Kind, action.Source = Resurrect, rightName
		case leftChanged && rightChanged && !rightExists:
			action.Kind, action.Source = Resurrect, leftName
		case leftChanged && rightChanged:
			winner, _ := resolveConflict(leftName, rightName)
			if winner == leftName {
				action.Kind, action.Source = Push, leftName
			} else {
				action.Kind, action.Source = Pull, rightName
			}
		case leftChanged && leftExists:
			action.Kind, action.Source = Push, leftName
		case leftChanged:
			action.Kind, action.Source = Delete, leftName
		case rightExists:
			action.Kind, action.Source = Pull, rightName
		default:
			action.Kind, action.Source = Delete, rightName
		}
		actions = append(actions, action)
	}
	return actions
}
