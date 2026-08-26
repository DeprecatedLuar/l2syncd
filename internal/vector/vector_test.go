//go:build linux

package vector

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		name        string
		left, right Vector
		want        Comparison
	}{
		{"both nil", nil, nil, Equal},
		{"both empty", Vector{}, Vector{}, Equal},
		{"nil vs empty", nil, Vector{}, Equal},
		{"identical single", Vector{"a": 3}, Vector{"a": 3}, Equal},
		{"identical multi", Vector{"a": 3, "b": 5}, Vector{"a": 3, "b": 5}, Equal},
		{"left strictly ahead single", Vector{"a": 4}, Vector{"a": 3}, Greater},
		{"right strictly ahead single", Vector{"a": 3}, Vector{"a": 4}, Lesser},
		{"left ahead via new key", Vector{"a": 3, "b": 1}, Vector{"a": 3}, Greater},
		{"right ahead via new key", Vector{"a": 3}, Vector{"a": 3, "b": 1}, Lesser},
		{"left dominates against nil", Vector{"a": 1}, nil, Greater},
		{"nil dominated by right", nil, Vector{"a": 1}, Lesser},
		{"concurrent two-peer disagreement", Vector{"a": 2, "b": 1}, Vector{"a": 1, "b": 2}, Concurrent},
		{"concurrent one ahead one behind", Vector{"a": 5}, Vector{"b": 1}, Concurrent},
		{
			"concurrent three-peer asymmetric",
			Vector{"a": 3, "b": 1, "c": 0},
			Vector{"a": 2, "b": 1, "c": 1},
			Concurrent,
		},
		{
			"greater three-peer superset",
			Vector{"a": 3, "b": 2, "c": 4},
			Vector{"a": 3, "b": 2, "c": 1},
			Greater,
		},
		{
			"lesser three-peer subset",
			Vector{"a": 3, "b": 2, "c": 1},
			Vector{"a": 3, "b": 2, "c": 4},
			Lesser,
		},
		{"zero counters equal zero counters", Vector{"a": 0}, Vector{}, Equal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Compare(test.left, test.right); got != test.want {
				t.Fatalf("Compare(%v, %v) = %v, want %v", test.left, test.right, got, test.want)
			}
		})
	}
}

func TestCompareIsAntisymmetric(t *testing.T) {
	pairs := []struct {
		left, right Vector
	}{
		{Vector{"a": 3}, Vector{"a": 3}},
		{Vector{"a": 4}, Vector{"a": 3}},
		{Vector{"a": 2, "b": 1}, Vector{"a": 1, "b": 2}},
		{Vector{"a": 3, "b": 2, "c": 4}, Vector{"a": 3, "b": 2, "c": 1}},
		{nil, Vector{"a": 1}},
	}
	swap := map[Comparison]Comparison{Equal: Equal, Greater: Lesser, Lesser: Greater, Concurrent: Concurrent}
	for _, pair := range pairs {
		forward := Compare(pair.left, pair.right)
		backward := Compare(pair.right, pair.left)
		if swap[forward] != backward {
			t.Fatalf("Compare(%v, %v) = %v but Compare(%v, %v) = %v, want mirrored", pair.left, pair.right, forward, pair.right, pair.left, backward)
		}
	}
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name        string
		left, right Vector
		want        Vector
	}{
		{"both nil", nil, nil, Vector{}},
		{"disjoint keys", Vector{"a": 1}, Vector{"b": 2}, Vector{"a": 1, "b": 2}},
		{"overlapping keys takes max", Vector{"a": 1, "b": 5}, Vector{"a": 3, "b": 2}, Vector{"a": 3, "b": 5}},
		{"identical vectors", Vector{"a": 2}, Vector{"a": 2}, Vector{"a": 2}},
		{"left dominates", Vector{"a": 5, "b": 5}, Vector{"a": 1}, Vector{"a": 5, "b": 5}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Merge(test.left, test.right)
			if len(got) != len(test.want) {
				t.Fatalf("Merge(%v, %v) = %v, want %v", test.left, test.right, got, test.want)
			}
			for fingerprint, count := range test.want {
				if got[fingerprint] != count {
					t.Fatalf("Merge(%v, %v) = %v, want %v", test.left, test.right, got, test.want)
				}
			}
		})
	}
}

func TestMergeIsCommutativeAndDominatesBothInputs(t *testing.T) {
	left := Vector{"a": 3, "b": 1}
	right := Vector{"a": 1, "b": 4, "c": 2}
	forward := Merge(left, right)
	backward := Merge(right, left)
	if Compare(forward, backward) != Equal {
		t.Fatalf("Merge is not commutative: %v vs %v", forward, backward)
	}
	if cmp := Compare(forward, left); cmp != Greater && cmp != Equal {
		t.Fatalf("merged vector does not dominate left input: %v", cmp)
	}
	if cmp := Compare(forward, right); cmp != Greater && cmp != Equal {
		t.Fatalf("merged vector does not dominate right input: %v", cmp)
	}
}

func TestIncrement(t *testing.T) {
	original := Vector{"a": 3, "b": 1}
	incremented := Increment(original, "a")
	if incremented["a"] != 4 || incremented["b"] != 1 {
		t.Fatalf("Increment(%v, a) = %v, want a=4 b=1", original, incremented)
	}
	if original["a"] != 3 {
		t.Fatalf("Increment mutated its input: %v", original)
	}
	incrementedNewKey := Increment(original, "c")
	if incrementedNewKey["c"] != 1 {
		t.Fatalf("Increment(%v, c) = %v, want c=1", original, incrementedNewKey)
	}

	incrementedNil := Increment(nil, "a")
	if len(incrementedNil) != 1 || incrementedNil["a"] != 1 {
		t.Fatalf("Increment(nil, a) = %v, want a=1", incrementedNil)
	}
}

func TestCloneIsIndependentCopy(t *testing.T) {
	original := Vector{"a": 1}
	cloned := Clone(original)
	cloned["a"] = 99
	cloned["b"] = 2
	if original["a"] != 1 {
		t.Fatalf("Clone shares backing storage with its source: %v", original)
	}
	if _, exists := original["b"]; exists {
		t.Fatalf("Clone shares backing storage with its source: %v", original)
	}
	if Clone(nil) != nil {
		t.Fatalf("Clone(nil) = %v, want nil", Clone(nil))
	}
}
