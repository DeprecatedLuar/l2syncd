//go:build linux

package commands

import (
	"errors"
	"fmt"
	"os"

	"l2syncd/internal/index"
)

// pruneIndex deletes folder id's index file, if any. Both leave and remove
// call it: the index is meaningful only while the pairing exists (concept.md
// 8.1 "Both leave and remove prune the local index"). A missing file is not
// an error.
func pruneIndex(id string) error {
	if id == "" {
		return nil
	}
	path, err := index.Path(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove index file: %w", err)
	}
	return nil
}
