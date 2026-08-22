//go:build linux

package engine

import (
	"testing"
	"time"

	"l2syncd/internal/state"
)

type fakeReplica struct {
	name    string
	current state.Baseline
}

func (fake fakeReplica) Name() string                     { return fake.name }
func (fake fakeReplica) Current() (state.Baseline, error) { return fake.current, nil }

func file(hash string, mtime time.Time) state.File { return state.File{Hash: hash, Mtime: mtime} }
func baseline(files map[string]state.File) state.Baseline {
	return state.Baseline{Version: 1, Files: files}
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
		{"same modified content", file("same", newer), file("same", old), file("base", old), "", ""},
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

func TestReconcileUsesReplicaInterfaces(t *testing.T) {
	plan, err := Reconcile(fakeReplica{"left", baseline(map[string]state.File{"x": file("l", time.Unix(2, 0))})}, fakeReplica{"right", baseline(map[string]state.File{"x": file("b", time.Unix(1, 0))})}, baseline(map[string]state.File{"x": file("b", time.Unix(1, 0))}))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != Push {
		t.Fatalf("plan = %#v", plan)
	}
}
