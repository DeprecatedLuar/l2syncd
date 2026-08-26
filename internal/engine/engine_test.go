//go:build linux

package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"l2syncd/internal/index"
	"l2syncd/internal/metadata"
	"l2syncd/internal/vector"
)

type fakeReplica struct {
	name    string
	current ReplicaState
}

func (fake fakeReplica) Name() string                   { return fake.name }
func (fake fakeReplica) Current() (ReplicaState, error) { return fake.current, nil }

func entry(hash string, v vector.Vector) index.Entry {
	return index.Entry{Hash: hash, Version: v, Metadata: metadata.Manifest{Mode: 0o600}}
}

func tombstone(v vector.Vector) index.Entry {
	return index.Entry{Deleted: true, Version: v}
}

func state(entries map[string]index.Entry) ReplicaState {
	idx := index.New("test")
	idx.Entries = entries
	return ReplicaState{Index: idx}
}

func TestDecisionTableAcrossVectorComparisons(t *testing.T) {
	tests := []struct {
		name       string
		left       index.Entry
		right      index.Entry
		want       ActionKind
		wantSource string
	}{
		{"equal vectors", entry("a", vector.Vector{"l": 1}), entry("a", vector.Vector{"l": 1}), "", ""},
		{"left strictly ahead pushes", entry("a", vector.Vector{"l": 2}), entry("old", vector.Vector{"l": 1}), Push, "left"},
		{"right strictly ahead pulls", entry("old", vector.Vector{"l": 1}), entry("a", vector.Vector{"l": 2}), Pull, "right"},
		{"left dominates unseen right creates", entry("a", vector.Vector{"l": 1}), index.Entry{}, Push, "left"},
		{"right dominates unseen left creates", index.Entry{}, entry("a", vector.Vector{"r": 1}), Pull, "right"},
		{"left tombstone dominates pushes delete", tombstone(vector.Vector{"l": 2}), entry("a", vector.Vector{"l": 1}), Delete, "left"},
		{"right tombstone dominates pulls delete", entry("a", vector.Vector{"r": 1}), tombstone(vector.Vector{"r": 2}), Delete, "right"},
		{"concurrent identical hash merges", entry("same", vector.Vector{"l": 1}), entry("same", vector.Vector{"r": 1}), Merge, ""},
		{"concurrent both tombstoned merges", tombstone(vector.Vector{"l": 1}), tombstone(vector.Vector{"r": 1}), Merge, ""},
		{"concurrent differing hash conflicts", entry("left-bytes", vector.Vector{"l": 1}), entry("right-bytes", vector.Vector{"r": 1}), Conflict, ""},
		{"concurrent modify-vs-delete resurrects the modification (left modified)", entry("a", vector.Vector{"l": 1, "r": 1}), tombstone(vector.Vector{"r": 2}), Resurrect, "left"},
		{"concurrent modify-vs-delete resurrects the modification (right modified)", tombstone(vector.Vector{"l": 2}), entry("a", vector.Vector{"l": 1, "r": 1}), Resurrect, "right"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := PlanStates("left", state(map[string]index.Entry{"x": test.left}), "right", state(map[string]index.Entry{"x": test.right}))
			if test.want == "" {
				if len(plan.Actions) != 0 {
					t.Fatalf("actions = %#v, want none", plan.Actions)
				}
				return
			}
			if len(plan.Actions) != 1 || plan.Actions[0].Kind != test.want {
				t.Fatalf("actions = %#v, want %s", plan.Actions, test.want)
			}
			if test.wantSource != "" && plan.Actions[0].Source != test.wantSource {
				t.Fatalf("source = %q, want %q", plan.Actions[0].Source, test.wantSource)
			}
		})
	}
}

func TestCreationOnAPeerNeverSeenIsCreatedNotDeleted(t *testing.T) {
	plan := PlanStates("left", state(map[string]index.Entry{"new.txt": entry("bytes", vector.Vector{"l": 1})}), "right", state(nil))
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != Push || plan.Actions[0].Source != "left" {
		t.Fatalf("plan = %#v, want a push creation, never a delete", plan.Actions)
	}
}

// TestThreePeerResurrectionNeverHappens is the three-peer regression case
// from implementation-plan.md Phase C: A deletes, B applies the delete, and
// C reconnects still holding the file from before the deletion. The file
// must stay deleted on both A and B's perspective when C's stale entry is
// compared, in either pairing.
func TestThreePeerResurrectionNeverHappens(t *testing.T) {
	// A deleted the file after B had already synced the original creation:
	// both A and B's tombstone/knowledge dominates C's untouched copy.
	aTombstone := tombstone(vector.Vector{"a": 2})
	bTombstone := tombstone(vector.Vector{"a": 2})
	cStaleFile := entry("original-bytes", vector.Vector{"a": 1})

	planAC := PlanStates("a", state(map[string]index.Entry{"shared.txt": aTombstone}), "c", state(map[string]index.Entry{"shared.txt": cStaleFile}))
	if len(planAC.Actions) != 1 || planAC.Actions[0].Kind != Delete || planAC.Actions[0].Source != "a" {
		t.Fatalf("A-C plan = %#v, want the tombstone to win and the file to stay deleted", planAC.Actions)
	}

	planBC := PlanStates("b", state(map[string]index.Entry{"shared.txt": bTombstone}), "c", state(map[string]index.Entry{"shared.txt": cStaleFile}))
	if len(planBC.Actions) != 1 || planBC.Actions[0].Kind != Delete || planBC.Actions[0].Source != "b" {
		t.Fatalf("B-C plan = %#v, want the tombstone to win and the file to stay deleted", planBC.Actions)
	}
}

func TestConflictTieBreakIsIndependentOfArgumentOrder(t *testing.T) {
	leftIdentity := strings.Repeat("1", 64)
	rightIdentity := strings.Repeat("f", 64)
	left := entry("left-bytes", vector.Vector{leftIdentity: 1})
	right := entry("right-bytes", vector.Vector{rightIdentity: 1})

	first := PlanStates(leftIdentity, state(map[string]index.Entry{"x": left}), rightIdentity, state(map[string]index.Entry{"x": right}))
	second := PlanStates(rightIdentity, state(map[string]index.Entry{"x": right}), leftIdentity, state(map[string]index.Entry{"x": left}))
	if len(first.Actions) != 1 || len(second.Actions) != 1 {
		t.Fatalf("actions = %#v / %#v", first.Actions, second.Actions)
	}
	if first.Actions[0].Winner != second.Actions[0].Winner || first.Actions[0].Loser != second.Actions[0].Loser {
		t.Fatalf("identity resolution diverged: %#v / %#v", first.Actions[0], second.Actions[0])
	}
}

func TestPlanStatesHaltsForEqualOrEmptyIdentities(t *testing.T) {
	identity := strings.Repeat("a", 64)
	plan := PlanStates(identity, state(nil), identity, state(nil))
	if !plan.Halted || !strings.Contains(plan.Reason, "distinct") {
		t.Fatalf("plan = %#v", plan)
	}
	plan = PlanStates("", state(nil), "right", state(nil))
	if !plan.Halted {
		t.Fatalf("plan = %#v, want halted for empty identity", plan)
	}
}

func TestDeletionThresholdCountsDeleteActionsInThePlan(t *testing.T) {
	entries := make(map[string]index.Entry, 100)
	for i := 0; i < 100; i++ {
		entries[fmt.Sprintf("f/%03d", i)] = entry("h", vector.Vector{"left": 1})
	}
	tombstoned := make(map[string]index.Entry, 100)
	for path, value := range entries {
		tombstoned[path] = value
	}
	// 31% net deletion: comfortably over the ~20% threshold.
	count := 0
	for path := range entries {
		if count == 31 {
			break
		}
		tombstoned[path] = tombstone(vector.Vector{"left": 2})
		count++
	}
	halted := PlanStates("left", state(tombstoned), "right", state(entries))
	if !halted.Halted {
		t.Fatal("genuine 31 percent net deletion did not halt")
	}

	fewDeletes := make(map[string]index.Entry, 100)
	for path, value := range entries {
		fewDeletes[path] = value
	}
	deleteCount := 0
	for path := range entries {
		if deleteCount == 5 {
			break
		}
		fewDeletes[path] = tombstone(vector.Vector{"left": 2})
		deleteCount++
	}
	notHalted := PlanStates("left", state(fewDeletes), "right", state(entries))
	if notHalted.Halted {
		t.Fatalf("5 percent deletion halted: %s", notHalted.Reason)
	}
}

func TestDirectoryMetadataUsesPerReplicaPreviousManifest(t *testing.T) {
	old := metadata.Manifest{Mode: 0o700, Mtime: time.Unix(10, 0)}
	changed := metadata.Manifest{Mode: 0o750, Mtime: time.Unix(20, 0)}
	left := ReplicaState{Index: index.New("left"), PreviousDirectories: map[string]metadata.Manifest{"folder": old}}
	left.Index.Directories = map[string]metadata.Manifest{"folder": changed}
	right := ReplicaState{Index: index.New("right"), PreviousDirectories: map[string]metadata.Manifest{"folder": old}}
	right.Index.Directories = map[string]metadata.Manifest{"folder": old}

	plan := PlanStates("left", left, "right", right)
	if len(plan.DirectoryActions) != 1 || plan.DirectoryActions[0].Kind != Push || !plan.DirectoryActions[0].Directory {
		t.Fatalf("directory actions = %#v", plan.DirectoryActions)
	}
}

func TestDirectoryUnchangedProducesNoAction(t *testing.T) {
	manifest := metadata.Manifest{Mode: 0o700, Mtime: time.Unix(10, 0)}
	left := ReplicaState{Index: index.New("left"), PreviousDirectories: map[string]metadata.Manifest{"folder": manifest}}
	left.Index.Directories = map[string]metadata.Manifest{"folder": manifest}
	right := ReplicaState{Index: index.New("right"), PreviousDirectories: map[string]metadata.Manifest{"folder": manifest}}
	right.Index.Directories = map[string]metadata.Manifest{"folder": manifest}

	plan := PlanStates("left", left, "right", right)
	if len(plan.DirectoryActions) != 0 {
		t.Fatalf("directory actions = %#v, want none", plan.DirectoryActions)
	}
}

func TestReconcileUsesReplicaInterfaces(t *testing.T) {
	plan, err := Reconcile(
		fakeReplica{"left", state(map[string]index.Entry{"x": entry("l", vector.Vector{"left": 2})})},
		fakeReplica{"right", state(map[string]index.Entry{"x": entry("b", vector.Vector{"left": 1})})},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != Push {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestReconcileRejectsNilOrDuplicateIdentities(t *testing.T) {
	if _, err := Reconcile(nil, fakeReplica{"right", state(nil)}); err == nil {
		t.Fatal("Reconcile(nil, ...) = nil error, want error")
	}
	same := fakeReplica{"dup", state(nil)}
	if _, err := Reconcile(same, same); err == nil {
		t.Fatal("Reconcile with duplicate identities = nil error, want error")
	}
}
