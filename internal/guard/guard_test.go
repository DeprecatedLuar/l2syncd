//go:build linux

package guard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMarkerRoundTrip(t *testing.T) {
	root := t.TempDir()
	want := Marker{Name: "notes", Ignore: []string{"node_modules", "*.swp"}}
	if err := WriteMarker(root, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMarker(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != want.Name || len(got.Ignore) != len(want.Ignore) {
		t.Fatalf("marker = %#v, want %#v", got, want)
	}
}

func TestReadMarkerRejectsMissingAndInvalidFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := ReadMarker(root); err == nil {
		t.Fatal("ReadMarker() error = nil for missing marker")
	}
	if err := os.WriteFile(filepath.Join(root, markerFilename), []byte("name = \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMarker(root); err == nil {
		t.Fatal("ReadMarker() error = nil for empty marker name")
	}
}

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
