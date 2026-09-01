//go:build linux

package guard

import (
	"os"
	"path/filepath"
	"testing"
)

func writeGitignore(t *testing.T, root, relative, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGitIgnoreAnchoring(t *testing.T) {
	root := t.TempDir()
	writeGitignore(t, root, ".gitignore", "/build/\nbuild\n")
	gi := NewGitIgnore(root)

	// "/build/" anchors to the root and is directory-only.
	matched, err := gi.Match("build", true)
	if err != nil || !matched {
		t.Fatalf("Match(build, dir) = %t, %v, want true, nil", matched, err)
	}
	matched, err = gi.Match("sub/build", true)
	if err != nil || !matched {
		// "build" (no slash) is unanchored and matches at any depth too.
		t.Fatalf("Match(sub/build, dir) = %t, %v, want true, nil", matched, err)
	}
}

func TestGitIgnoreNestedScoping(t *testing.T) {
	root := t.TempDir()
	writeGitignore(t, root, ".gitignore", "*.log\n")
	writeGitignore(t, root, "data/.gitignore", "cache\n")
	gi := NewGitIgnore(root)

	cases := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{"app.log", false, true},
		{"data/app.log", false, true},
		{"data/cache", true, true},
		{"other/cache", true, false},
	}
	for _, c := range cases {
		got, err := gi.Match(c.path, c.isDir)
		if err != nil {
			t.Fatalf("Match(%q) error: %v", c.path, err)
		}
		if got != c.want {
			t.Errorf("Match(%q, %t) = %t, want %t", c.path, c.isDir, got, c.want)
		}
	}
}

func TestGitIgnoreNegationLastMatchWins(t *testing.T) {
	root := t.TempDir()
	writeGitignore(t, root, ".gitignore", "*.log\n!important.log\n")
	gi := NewGitIgnore(root)

	matched, err := gi.Match("important.log", false)
	if err != nil || matched {
		t.Fatalf("Match(important.log) = %t, %v, want false (negated), nil", matched, err)
	}
	matched, err = gi.Match("other.log", false)
	if err != nil || !matched {
		t.Fatalf("Match(other.log) = %t, %v, want true, nil", matched, err)
	}
}

func TestGitIgnoreDirectoryOnlyPattern(t *testing.T) {
	root := t.TempDir()
	writeGitignore(t, root, ".gitignore", "dist/\n")
	gi := NewGitIgnore(root)

	matched, err := gi.Match("dist", true)
	if err != nil || !matched {
		t.Fatalf("Match(dist, dir) = %t, %v, want true, nil", matched, err)
	}
	matched, err = gi.Match("dist", false)
	if err != nil || matched {
		t.Fatalf("Match(dist, file) = %t, %v, want false: directory-only pattern must not match a file", matched, err)
	}
}

func TestGitIgnoreDoubleStarGlob(t *testing.T) {
	root := t.TempDir()
	writeGitignore(t, root, ".gitignore", "logs/**/debug.txt\n")
	gi := NewGitIgnore(root)

	matched, err := gi.Match("logs/debug.txt", false)
	if err != nil || !matched {
		t.Fatalf("Match(logs/debug.txt) = %t, %v, want true, nil", matched, err)
	}
	matched, err = gi.Match("logs/a/b/debug.txt", false)
	if err != nil || !matched {
		t.Fatalf("Match(logs/a/b/debug.txt) = %t, %v, want true, nil", matched, err)
	}
	matched, err = gi.Match("other/debug.txt", false)
	if err != nil || matched {
		t.Fatalf("Match(other/debug.txt) = %t, %v, want false, nil", matched, err)
	}
}

func TestGitIgnoreCommentsEscapesAndWhitespace(t *testing.T) {
	root := t.TempDir()
	writeGitignore(t, root, ".gitignore", "# comment\n\\#literal\n\\!bang\ntrailing.txt   \n")
	gi := NewGitIgnore(root)

	matched, err := gi.Match("#literal", false)
	if err != nil || !matched {
		t.Fatalf("Match(#literal) = %t, %v, want true, nil", matched, err)
	}
	matched, err = gi.Match("!bang", false)
	if err != nil || !matched {
		t.Fatalf("Match(!bang) = %t, %v, want true, nil", matched, err)
	}
	matched, err = gi.Match("trailing.txt", false)
	if err != nil || !matched {
		t.Fatalf("Match(trailing.txt) = %t, %v, want true (trailing whitespace trimmed), nil", matched, err)
	}
}

func TestGitIgnoreMissingFileIsNotIgnored(t *testing.T) {
	root := t.TempDir()
	gi := NewGitIgnore(root)
	matched, err := gi.Match("anything.txt", false)
	if err != nil || matched {
		t.Fatalf("Match() with no .gitignore = %t, %v, want false, nil", matched, err)
	}
}

func TestGitIgnoreCannotOverrideDefaultOrMarkerLayer(t *testing.T) {
	// GitIgnore itself never knows about DefaultIgnore or marker patterns;
	// it only reports its own layer's verdict. Precedence is enforced by
	// the caller ORing DefaultIgnorePath and Ignore.Match ahead of it, so a
	// negation here can never flip those.
	root := t.TempDir()
	writeGitignore(t, root, ".gitignore", "!node_modules\n!.l2sync\n")
	gi := NewGitIgnore(root)

	if DefaultIgnore("node_modules") != true || DefaultIgnore(".l2sync") != true {
		t.Fatal("setup: node_modules and .l2sync must remain in the default ignore list")
	}
	matched, err := gi.Match("node_modules", true)
	if err != nil || matched {
		t.Fatalf("Match(node_modules) = %t, %v, want false: no positive rule exists to negate", matched, err)
	}
}
