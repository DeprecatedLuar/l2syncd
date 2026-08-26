//go:build linux

// Package vector implements version vectors: the sole cross-machine
// ordering authority for reconciliation (concept.md 4.2). A vector is a map
// of installation fingerprint to a monotonically increasing counter. It is
// pure and has no I/O; the index package is responsible for persistence.
package vector

import "maps"

// Vector maps an installation fingerprint to its change counter. A missing
// key is equivalent to a counter of zero, so an empty or nil Vector compares
// as "nothing known yet" against any non-empty one.
type Vector map[string]uint64

// Comparison is the result of comparing two vectors.
type Comparison int

const (
	// Equal means both vectors record exactly the same knowledge.
	Equal Comparison = iota
	// Greater means the left vector's knowledge is a strict superset of the
	// right vector's: everything the right side knows, the left side
	// already knows, plus more.
	Greater
	// Lesser is the mirror of Greater: the right vector strictly dominates.
	Lesser
	// Concurrent means neither vector's knowledge is a superset of the
	// other's. This is the only case requiring conflict handling (5.5).
	Concurrent
)

// Compare reports the causal relationship between left and right. A nil or
// empty vector is treated as all-zero, so comparing against one is
// equivalent to comparing against a vector with every counter at zero.
func Compare(left, right Vector) Comparison {
	leftGreaterSomewhere := false
	rightGreaterSomewhere := false
	for fingerprint, count := range left {
		other := right[fingerprint]
		if count > other {
			leftGreaterSomewhere = true
		} else if count < other {
			rightGreaterSomewhere = true
		}
	}
	for fingerprint, count := range right {
		if _, seen := left[fingerprint]; seen {
			continue
		}
		if count > 0 {
			rightGreaterSomewhere = true
		}
	}
	switch {
	case !leftGreaterSomewhere && !rightGreaterSomewhere:
		return Equal
	case leftGreaterSomewhere && !rightGreaterSomewhere:
		return Greater
	case !leftGreaterSomewhere && rightGreaterSomewhere:
		return Lesser
	default:
		return Concurrent
	}
}

// Merge returns the element-wise maximum of left and right: the smallest
// vector that dominates both. This is the vector two replicas agree on after
// resolving a concurrent conflict or a silent same-content merge.
func Merge(left, right Vector) Vector {
	merged := make(Vector, len(left)+len(right))
	maps.Copy(merged, left)
	for fingerprint, count := range right {
		if count > merged[fingerprint] {
			merged[fingerprint] = count
		}
	}
	return merged
}

// Increment returns a copy of v with fingerprint's counter incremented by
// one. v is never mutated: callers hold vectors read from a loaded index and
// must not let one entry's increment alias another's map.
func Increment(v Vector, fingerprint string) Vector {
	result := make(Vector, len(v)+1)
	maps.Copy(result, v)
	result[fingerprint] = result[fingerprint] + 1
	return result
}

// Clone returns a copy of v so callers can hand out a vector without letting
// the recipient mutate the original.
func Clone(v Vector) Vector {
	if v == nil {
		return nil
	}
	result := make(Vector, len(v))
	maps.Copy(result, v)
	return result
}
