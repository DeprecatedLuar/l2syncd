//go:build linux

// Package engine plans reconciliation without modifying either replica.
package engine

import (
	"fmt"
	"sort"

	"l2syncd/internal/guard"
	"l2syncd/internal/metadata"
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
	Path      string
	Kind      ActionKind
	Source    string
	Winner    string
	Loser     string
	Directory bool
}

type Plan struct {
	Actions          []Action
	DirectoryActions []Action
	Halted           bool
	Reason           string
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
// comparison; inode and ctime are used only for local change detection.
func PlanStates(leftName string, left state.Baseline, rightName string, right state.Baseline, baseline state.Baseline) Plan {
	if leftName == "" || rightName == "" || leftName == rightName {
		return Plan{Halted: true, Reason: "replica identities must be distinct and non-empty"}
	}
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
	return Plan{Actions: actions, DirectoryActions: planDirectories(leftName, left, rightName, right, baseline)}
}

func planDirectories(leftName string, left state.Baseline, rightName string, right state.Baseline, baseline state.Baseline) []Action {
	paths := make(map[string]struct{}, len(left.Directories)+len(right.Directories)+len(baseline.Directories))
	for path := range left.Directories {
		paths[path] = struct{}{}
	}
	for path := range right.Directories {
		paths[path] = struct{}{}
	}
	for path := range baseline.Directories {
		paths[path] = struct{}{}
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	actions := make([]Action, 0)
	for _, path := range ordered {
		leftValue, leftExists := left.Directories[path]
		rightValue, rightExists := right.Directories[path]
		previous, previousExists := baseline.Directories[path]
		leftChanged := leftExists != previousExists || leftExists && previousExists && !sameDirectory(leftValue, previous)
		rightChanged := rightExists != previousExists || rightExists && previousExists && !sameDirectory(rightValue, previous)
		unchanged := !leftChanged && !rightChanged
		converged := leftChanged && rightChanged && leftExists && rightExists && sameDirectory(leftValue, rightValue)
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

func decide(path, leftName string, left state.File, rightName string, right state.File, previous state.File) (Action, bool) {
	leftExists := left.Hash != ""
	rightExists := right.Hash != ""
	previousExists := previous.Hash != ""
	if previousExists && !previous.MetadataKnown {
		return decideUnknownMetadata(path, leftName, left, leftExists, rightName, right, rightExists)
	}
	leftChanged := leftExists != previousExists || leftExists && !sameFile(left, previous)
	rightChanged := rightExists != previousExists || rightExists && !sameFile(right, previous)
	if !leftChanged && !rightChanged {
		return Action{}, false
	}
	if leftChanged && rightChanged && leftExists && rightExists && sameFile(left, right) {
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
		winner, loser := resolveConflict(leftName, rightName)
		if left.Hash == right.Hash {
			if winner == leftName {
				return Action{Path: path, Kind: Push, Source: leftName}, true
			}
			return Action{Path: path, Kind: Pull, Source: rightName}, true
		}
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

func decideUnknownMetadata(path, leftName string, left state.File, leftExists bool, rightName string, right state.File, rightExists bool) (Action, bool) {
	switch {
	case !leftExists && !rightExists:
		return Action{}, false
	case !leftExists:
		return Action{Path: path, Kind: Resurrect, Source: rightName}, true
	case !rightExists:
		return Action{Path: path, Kind: Resurrect, Source: leftName}, true
	case sameFile(left, right):
		return Action{}, false
	}
	winner, loser := resolveConflict(leftName, rightName)
	if left.Hash != right.Hash {
		return Action{Path: path, Kind: Conflict, Winner: winner, Loser: loser}, true
	}
	if winner == leftName {
		return Action{Path: path, Kind: Push, Source: leftName}, true
	}
	return Action{Path: path, Kind: Pull, Source: rightName}, true
}

func resolveConflict(leftName, rightName string) (string, string) {
	if leftName < rightName {
		return leftName, rightName
	}
	return rightName, leftName
}

func deletionHalt(current, baseline state.Baseline) bool {
	netLoss := len(baseline.Files) - len(current.Files)
	if netLoss <= 0 {
		return false
	}
	return guard.DeleteThreshold(netLoss, len(baseline.Files))
}

// sameFile reports whether left and right represent the same file content
// and metadata. When either side's metadata is not known (a legacy
// version-1 baseline), only the hash is compared.
func sameFile(left, right state.File) bool {
	if !left.MetadataKnown || !right.MetadataKnown {
		return left.Hash == right.Hash
	}
	return left.Hash == right.Hash && metadata.Equal(left.Metadata, right.Metadata)
}

func sameDirectory(left, right metadata.Manifest) bool {
	if right.Mtime.IsZero() {
		return true
	}
	return metadata.Equal(left, right)
}
