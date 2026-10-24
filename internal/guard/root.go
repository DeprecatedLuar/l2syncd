//go:build linux

package guard

import (
	"fmt"
	"os"
	"path/filepath"
)

// ResolveRoot returns the real directory a share root names. A symlink at the
// root is followed; nothing below the root ever is. Callers resolve once per
// cycle or watch and use the result for every operation on that share.
func ResolveRoot(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve share root %q: %w", path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat share root %q: %w", resolved, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("share root %q is not a directory", resolved)
	}
	return resolved, nil
}
