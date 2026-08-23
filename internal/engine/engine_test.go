//go:build linux

package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"l2syncd/internal/metadata"
	"l2syncd/internal/state"
)

type fakeReplica struct {
	name    string
	current state.Baseline
}

func (fake fakeReplica) Name() string                     { return fake.name }
func (fake fakeReplica) Current() (state.Baseline, error) { return fake.current, nil }

func file(hash string, mtime time.Time) state.File {
	return state.File{Hash: hash, Metadata: metadata.Manifest{Mode: 0o600, Mtime: mtime}, MetadataKnown: true}
}
func baseline(files map[string]state.File) state.Baseline {
	result := state.New()
	result.Files = files
	return result
}

func TestPlanStatesDecisionTable(t *testing.T) {
	old := time.Unix(10, 0)
	newer := time.Unix(20, 0)
	tests := []struct {
		name                  string
		left, right, previous state.File
		want                  ActionKind
		wantSource            string
	}{
		{"left modified", file("left", newer), file("base", old), file("base", old), Push, "left-peer"},
		{"right modified", file("base", old), file("right", newer), file("base", old), Pull, "right-peer"},
		{"unchanged", file("base", old), file("base", old), file("base", old), "", ""},
		{"same modified content and metadata", file("same", newer), file("same", newer), file("base", old), "", ""},
		{"different modified content", file("left", newer), file("right", old), file("base", old), Conflict, ""},
		{"left deleted", state.File{}, file("base", old), file("base", old), Delete, "left-peer"},
		{"right deleted", file("base", old), state.File{}, file("base", old), Delete, "right-peer"},
		{"left deleted right modified", state.File{}, file("right", newer), file("base", old), Resurrect, "right-peer"},
		{"both deleted", state.File{}, state.File{}, file("base", old), "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := PlanStates("left-peer", baseline(map[string]state.File{"x": test.left}), "right-peer", baseline(map[string]state.File{"x": test.right}), baseline(map[string]state.File{"x": test.previous}))
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

func TestConflictIdentityIsIndependentOfLocalPeerAliases(t *testing.T) {
	leftIdentity := strings.Repeat("1", 64)
	rightIdentity := strings.Repeat("f", 64)
	previous := baseline(map[string]state.File{"x": file("base", time.Unix(1, 0))})
	left := baseline(map[string]state.File{"x": file("left", time.Unix(2, 0))})
	right := baseline(map[string]state.File{"x": file("right", time.Unix(3, 0))})

	first := PlanStates(leftIdentity, left, rightIdentity, right, previous)
	second := PlanStates(rightIdentity, right, leftIdentity, left, previous)
	if len(first.Actions) != 1 || len(second.Actions) != 1 {
		t.Fatalf("actions = %#v / %#v", first.Actions, second.Actions)
	}
	if first.Actions[0].Winner != second.Actions[0].Winner || first.Actions[0].Loser != second.Actions[0].Loser {
		t.Fatalf("identity resolution diverged: %#v / %#v", first.Actions[0], second.Actions[0])
	}
}

func TestPlanStatesHaltsForEqualInstallationIdentities(t *testing.T) {
	identity := strings.Repeat("a", 64)
	plan := PlanStates(identity, state.New(), identity, state.New(), state.New())
	if !plan.Halted || !strings.Contains(plan.Reason, "distinct") {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanConflictTieBreakAndThreshold(t *testing.T) {
	when := time.Unix(10, 0)
	plan := PlanStates("z-peer", baseline(map[string]state.File{"x": file("z", when)}), "a-peer", baseline(map[string]state.File{"x": file("a", when)}), baseline(map[string]state.File{"x": file("base", when)}))
	if len(plan.Actions) != 1 || plan.Actions[0].Winner != "a-peer" || plan.Actions[0].Loser != "z-peer" {
		t.Fatalf("conflict = %#v", plan.Actions)
	}
	files := make(map[string]state.File, 100)
	for i := 0; i < 100; i++ {
		files[string(rune(i))] = file("base", when)
	}
	current := make(map[string]state.File, 100)
	for i := 0; i < 69; i++ {
		current[string(rune(i))] = file("base", when)
	}
	halted := PlanStates("left", baseline(current), "right", baseline(current), baseline(files))
	if !halted.Halted {
		t.Fatal("plan not halted for bulk deletion")
	}
}

func TestConflictIgnoresClockSkewAndMetadataUsesPeerTieBreak(t *testing.T) {
	baselineFile := file("base", time.Unix(10, 0))
	left := file("left", time.Unix(10_000, 0))
	right := file("right", time.Unix(1, 0))
	plan := PlanStates("z-peer", baseline(map[string]state.File{"x": left}), "a-peer", baseline(map[string]state.File{"x": right}), baseline(map[string]state.File{"x": baselineFile}))
	if len(plan.Actions) != 1 || plan.Actions[0].Winner != "a-peer" {
		t.Fatalf("clock-skew conflict = %#v, want lexical a-peer winner", plan.Actions)
	}

	left = file("same", time.Unix(20, 0))
	right = file("same", time.Unix(30, 0))
	previous := file("same", time.Unix(10, 0))
	plan = PlanStates("z-peer", baseline(map[string]state.File{"x": left}), "a-peer", baseline(map[string]state.File{"x": right}), baseline(map[string]state.File{"x": previous}))
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != Pull || plan.Actions[0].Source != "a-peer" {
		t.Fatalf("metadata conflict = %#v, want lexical pull", plan.Actions)
	}
}

func TestOneSidedMetadataOnlyEditPropagates(t *testing.T) {
	previous := file("same", time.Unix(10, 0))
	left := file("same", time.Unix(20, 0))
	plan := PlanStates("left", baseline(map[string]state.File{"x": left}), "right", baseline(map[string]state.File{"x": previous}), baseline(map[string]state.File{"x": previous}))
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != Push || plan.Actions[0].Source != "left" {
		t.Fatalf("metadata-only plan = %#v, want push from left", plan.Actions)
	}
}

func TestUnknownLegacyMetadataComparesCurrentManifestsAndRetainsDeletionHistory(t *testing.T) {
	legacy := state.File{Hash: "same", Size: 4, MetadataKnown: false}
	left := file("same", time.Unix(20, 0))
	right := file("same", time.Unix(20, 0))
	plan := PlanStates("z-peer", baseline(map[string]state.File{"x": left}), "a-peer", baseline(map[string]state.File{"x": right}), baseline(map[string]state.File{"x": legacy}))
	if len(plan.Actions) != 0 {
		t.Fatalf("identical current manifests produced actions: %#v", plan.Actions)
	}

	right.Metadata.Mode = 0o640
	plan = PlanStates("z-peer", baseline(map[string]state.File{"x": left}), "a-peer", baseline(map[string]state.File{"x": right}), baseline(map[string]state.File{"x": legacy}))
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != Pull || plan.Actions[0].Source != "a-peer" {
		t.Fatalf("unknown-metadata disagreement = %#v, want lexical pull", plan.Actions)
	}

	plan = PlanStates("left", baseline(nil), "right", baseline(map[string]state.File{"x": right}), baseline(map[string]state.File{"x": legacy}))
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != Resurrect || plan.Actions[0].Source != "right" {
		t.Fatalf("legacy delete-vs-existing = %#v, want conservative resurrection", plan.Actions)
	}

	modified := file("modified", time.Unix(30, 0))
	plan = PlanStates("left", baseline(nil), "right", baseline(map[string]state.File{"x": modified}), baseline(map[string]state.File{"x": legacy}))
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != Resurrect || plan.Actions[0].Source != "right" {
		t.Fatalf("legacy delete-vs-modified = %#v, want resurrection safety", plan.Actions)
	}
}

func TestUnknownLegacyMetadataDeleteVsSameHashMetadataEditResurrects(t *testing.T) {
	legacy := state.File{Hash: "same", Size: 4, MetadataKnown: false}
	edited := file("same", time.Unix(20, 0))
	edited.Metadata.Mode = 0o640
	plan := PlanStates("deleted-peer", baseline(nil), "existing-peer", baseline(map[string]state.File{"x": edited}), baseline(map[string]state.File{"x": legacy}))
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != Resurrect || plan.Actions[0].Source != "existing-peer" {
		t.Fatalf("plan = %#v, want same-hash metadata-edited survivor resurrected", plan.Actions)
	}
}

func TestRenamePlusEditRemainsDeleteAndCreate(t *testing.T) {
	previousFile := file("old-hash", time.Unix(10, 0))
	previous := baseline(map[string]state.File{"old/name": previousFile})
	left := baseline(map[string]state.File{"new/name": file("edited-hash", time.Unix(20, 0))})
	right := baseline(map[string]state.File{"old/name": previousFile})
	plan := PlanStates("left", left, "right", right, previous)
	if plan.Halted || len(plan.Actions) != 2 {
		t.Fatalf("rename-plus-edit plan = %#v", plan)
	}
	if plan.Actions[0].Path != "new/name" || plan.Actions[0].Kind != Push || plan.Actions[1].Path != "old/name" || plan.Actions[1].Kind != Delete {
		t.Fatalf("actions = %#v, want create plus delete with no rename action", plan.Actions)
	}
}

func TestDeletionThresholdUsesNetTreeLoss(t *testing.T) {
	previous := make(map[string]state.File, 100)
	renamed := make(map[string]state.File, 100)
	for index := 0; index < 100; index++ {
		oldPath := fmt.Sprintf("old/%03d", index)
		previous[oldPath] = file(fmt.Sprintf("hash-%d", index), time.Unix(10, 0))
		if index < 30 {
			renamed[fmt.Sprintf("new/%03d", index)] = previous[oldPath]
		} else {
			renamed[oldPath] = previous[oldPath]
		}
	}
	plan := PlanStates("left", baseline(renamed), "right", baseline(previous), baseline(previous))
	if plan.Halted {
		t.Fatalf("large rename halted: %s", plan.Reason)
	}
	deleted := make(map[string]state.File, 69)
	for path, value := range previous {
		if len(deleted) == 69 {
			break
		}
		deleted[path] = value
	}
	plan = PlanStates("left", baseline(deleted), "right", baseline(deleted), baseline(previous))
	if !plan.Halted {
		t.Fatal("genuine 31 percent net deletion did not halt")
	}
}

func TestDirectoryMetadataUsesPostChildActionPass(t *testing.T) {
	previous := baseline(nil)
	left := baseline(nil)
	right := baseline(nil)
	old := metadata.Manifest{Mode: 0o700, Mtime: time.Unix(10, 0)}
	changed := metadata.Manifest{Mode: 0o750, Mtime: time.Unix(20, 0)}
	previous.Directories["folder"] = old
	left.Directories["folder"] = changed
	right.Directories["folder"] = old
	plan := PlanStates("left", left, "right", right, previous)
	if len(plan.DirectoryActions) != 1 || plan.DirectoryActions[0].Kind != Push || !plan.DirectoryActions[0].Directory {
		t.Fatalf("directory actions = %#v", plan.DirectoryActions)
	}
}

func TestReconcileUsesReplicaInterfaces(t *testing.T) {
	plan, err := Reconcile(fakeReplica{"left", baseline(map[string]state.File{"x": file("l", time.Unix(2, 0))})}, fakeReplica{"right", baseline(map[string]state.File{"x": file("b", time.Unix(1, 0))})}, baseline(map[string]state.File{"x": file("b", time.Unix(1, 0))}))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != Push {
		t.Fatalf("plan = %#v", plan)
	}
}
