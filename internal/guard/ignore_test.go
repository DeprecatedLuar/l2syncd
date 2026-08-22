//go:build linux

package guard

import "testing"

func TestIgnorePatterns(t *testing.T) {
	ignore, err := NewIgnore([]string{"node_modules", "cache/tmp", "*.swp", "build/**", "dist/"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path  string
		dir   bool
		match bool
	}{
		{path: "node_modules", dir: true, match: true},
		{path: "a/node_modules/pkg.json", match: true},
		{path: "cache/tmp", match: true},
		{path: "other/cache/tmp", match: false},
		{path: "editor.swp", match: true},
		{path: "a/editor.swp", match: true},
		{path: "build/a/b.txt", match: true},
		{path: "dist", dir: true, match: true},
		{path: "dist/file.txt", match: false},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			if got := ignore.Match(test.path, test.dir); got != test.match {
				t.Fatalf("Match(%q, %t) = %t, want %t", test.path, test.dir, got, test.match)
			}
		})
	}
}

func TestIgnoreRejectsNegation(t *testing.T) {
	if _, err := NewIgnore([]string{"!keep.txt"}); err == nil {
		t.Fatal("NewIgnore() error = nil, want negation rejection")
	}
}
