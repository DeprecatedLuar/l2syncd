//go:build linux

package guard

import (
	"fmt"
	"path"
	"strings"
)

// Ignore matches local, share-relative ignore patterns.
type Ignore struct {
	patterns []pattern
}

type pattern struct {
	parts      []string
	directory  bool
	anySegment bool
}

// NewIgnore creates an ignore matcher from user patterns.
func NewIgnore(patterns []string) (Ignore, error) {
	compiled := make([]pattern, 0, len(patterns))
	for _, raw := range patterns {
		if raw == "" || strings.HasPrefix(raw, "!") {
			return Ignore{}, fmt.Errorf("invalid ignore pattern %q", raw)
		}
		directory := strings.HasSuffix(raw, "/")
		if directory {
			raw = strings.TrimSuffix(raw, "/")
		}
		raw = strings.TrimPrefix(raw, "./")
		if raw == "" {
			return Ignore{}, fmt.Errorf("invalid ignore pattern")
		}
		parts := strings.Split(path.Clean(raw), "/")
		compiled = append(compiled, pattern{parts: parts, directory: directory, anySegment: !strings.Contains(raw, "/")})
	}
	return Ignore{patterns: compiled}, nil
}

// Match reports whether relative is ignored. relative must use slash paths.
func (ignore Ignore) Match(relative string, isDir bool) bool {
	parts := strings.Split(strings.Trim(relative, "/"), "/")
	if len(parts) == 1 && parts[0] == "" {
		return false
	}
	for _, candidate := range ignore.patterns {
		if candidate.directory && !isDir {
			continue
		}
		if matchPatternParts(candidate, parts) {
			return true
		}
	}
	return false
}

// matchPatternParts reports whether parts match p, dispatching to the
// any-depth basename form or the full anchored form. Shared with GitIgnore,
// whose rules reuse the same pattern representation.
func matchPatternParts(p pattern, parts []string) bool {
	if p.anySegment {
		for _, part := range parts {
			if matchSegment(p.parts[0], part) {
				return true
			}
		}
		return false
	}
	return matchParts(p.parts, parts)
}

func matchParts(patterns, values []string) bool {
	if len(patterns) == 0 {
		return len(values) == 0
	}
	if patterns[0] == "**" {
		return matchParts(patterns[1:], values) || (len(values) > 0 && matchParts(patterns, values[1:]))
	}
	return len(values) > 0 && matchSegment(patterns[0], values[0]) && matchParts(patterns[1:], values[1:])
}

func matchSegment(pattern, value string) bool {
	matched, err := path.Match(pattern, value)
	return err == nil && matched
}
