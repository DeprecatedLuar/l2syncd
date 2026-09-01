//go:build linux

package guard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// gitignoreRule is one parsed line from a .gitignore file.
type gitignoreRule struct {
	pattern
	negate bool
}

// GitIgnore matches share-relative paths against every .gitignore file found
// along their ancestor directories, applying git's own precedence: a deeper
// directory's rules outrank a shallower one's, and within one file the last
// matching line wins (negation included). Rulesets are read lazily and
// cached per directory, so construction never touches the filesystem.
type GitIgnore struct {
	root  string
	cache map[string][]gitignoreRule
}

// NewGitIgnore returns a matcher scoped to root. It performs no I/O.
func NewGitIgnore(root string) *GitIgnore {
	return &GitIgnore{root: root, cache: make(map[string][]gitignoreRule)}
}

// Match reports whether relative (a root-relative, slash-separated path) is
// excluded by any .gitignore found along its ancestor directories.
func (g *GitIgnore) Match(relative string, isDir bool) (bool, error) {
	relative = strings.Trim(relative, "/")
	if relative == "" {
		return false, nil
	}
	dir := path.Dir(relative)
	if dir == "." {
		dir = ""
	}
	matched := false
	for _, ancestor := range ancestorDirs(dir) {
		rules, err := g.rulesFor(ancestor)
		if err != nil {
			return false, err
		}
		if len(rules) == 0 {
			continue
		}
		scoped := relative
		if ancestor != "" {
			scoped = strings.TrimPrefix(relative, ancestor+"/")
		}
		parts := strings.Split(scoped, "/")
		for _, rule := range rules {
			if rule.directory && !isDir {
				continue
			}
			if matchPatternParts(rule.pattern, parts) {
				matched = !rule.negate
			}
		}
	}
	return matched, nil
}

// rulesFor reads and caches the .gitignore in the given root-relative
// directory ("" for the share root). A missing file caches as no rules.
func (g *GitIgnore) rulesFor(dir string) ([]gitignoreRule, error) {
	if rules, ok := g.cache[dir]; ok {
		return rules, nil
	}
	full := filepath.Join(g.root, filepath.FromSlash(dir), ".gitignore")
	data, err := os.ReadFile(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			g.cache[dir] = nil
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", full, err)
	}
	var rules []gitignoreRule
	for line := range strings.SplitSeq(string(data), "\n") {
		rule, ok, err := parseGitignoreLine(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", full, err)
		}
		if ok {
			rules = append(rules, rule)
		}
	}
	g.cache[dir] = rules
	return rules, nil
}

// ancestorDirs returns dir's ancestor directories root-first, ending with dir
// itself. ancestorDirs("") is [""]; ancestorDirs("a/b") is ["", "a", "a/b"].
func ancestorDirs(dir string) []string {
	if dir == "" {
		return []string{""}
	}
	segments := strings.Split(dir, "/")
	dirs := make([]string, 0, len(segments)+1)
	dirs = append(dirs, "")
	accumulated := ""
	for _, segment := range segments {
		if accumulated == "" {
			accumulated = segment
		} else {
			accumulated = accumulated + "/" + segment
		}
		dirs = append(dirs, accumulated)
	}
	return dirs
}

// parseGitignoreLine parses one .gitignore line. ok is false for a blank
// line or comment. Escaping (`\#`, `\!`, `\ `, `\\`) follows git's own rules:
// a leading `#` is a comment unless escaped, a leading `!` negates unless
// escaped, and trailing whitespace is trimmed unless escaped.
func parseGitignoreLine(raw string) (gitignoreRule, bool, error) {
	line := strings.TrimRight(raw, "\r")
	if strings.TrimSpace(line) == "" {
		return gitignoreRule{}, false, nil
	}
	if strings.HasPrefix(line, "#") {
		return gitignoreRule{}, false, nil
	}
	negate := false
	if strings.HasPrefix(line, "!") {
		negate = true
		line = line[1:]
	}
	line = trimTrailingUnescapedSpaces(line)
	line = unescapeGitignoreLine(line)
	if line == "" {
		return gitignoreRule{}, false, fmt.Errorf("empty gitignore pattern")
	}
	directory := strings.HasSuffix(line, "/")
	if directory {
		line = strings.TrimSuffix(line, "/")
	}
	anchored := strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")
	if line == "" {
		return gitignoreRule{}, false, fmt.Errorf("invalid gitignore pattern")
	}
	parts := strings.Split(path.Clean(line), "/")
	return gitignoreRule{
		pattern: pattern{parts: parts, directory: directory, anySegment: !anchored},
		negate:  negate,
	}, true, nil
}

// trimTrailingUnescapedSpaces removes trailing spaces that are not preceded
// by an odd number of backslashes (i.e. not themselves escaped).
func trimTrailingUnescapedSpaces(s string) string {
	end := len(s)
	for end > 0 && s[end-1] == ' ' {
		backslashes := 0
		for j := end - 2; j >= 0 && s[j] == '\\'; j-- {
			backslashes++
		}
		if backslashes%2 == 1 {
			break
		}
		end--
	}
	return s[:end]
}

// unescapeGitignoreLine resolves backslash escapes, leaving glob
// metacharacters (`*`, `?`, `[`, `]`) untouched for later matching.
func unescapeGitignoreLine(s string) string {
	var builder strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			builder.WriteByte(s[i])
			continue
		}
		builder.WriteByte(s[i])
	}
	return builder.String()
}
