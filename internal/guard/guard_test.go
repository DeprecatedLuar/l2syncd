//go:build linux

package guard

import "testing"

func TestDeleteThreshold(t *testing.T) {
	tests := []struct {
		name    string
		deletes int
		total   int
		halt    bool
	}{
		{name: "small share below floor", deletes: 5, total: 5, halt: false},
		{name: "floor boundary", deletes: 10, total: 5, halt: false},
		{name: "floor exceeded", deletes: 11, total: 5, halt: true},
		{name: "ratio exceeded", deletes: 21, total: 100, halt: true},
		{name: "ratio boundary", deletes: 20, total: 100, halt: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := DeleteThreshold(test.deletes, test.total); got != test.halt {
				t.Fatalf("DeleteThreshold(%d, %d) = %t, want %t", test.deletes, test.total, got, test.halt)
			}
		})
	}
}
