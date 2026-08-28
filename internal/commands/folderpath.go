//go:build linux

package commands

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// resolveFolderPath stats path, which the caller already resolved to an
// absolute form; rawPath is the original argument, used only for error text.
// A missing path is created outright when createMissing is set (the -p
// flag); otherwise, on an interactive terminal, the user is prompted to
// create it, mirroring the rejoin-divergence prompt's non-interactive
// refusal (concept.md 8.1: never silently choose a default without a
// terminal to ask on).
func resolveFolderPath(path, rawPath string, createMissing bool, stderr io.Writer) (os.FileInfo, error) {
	info, err := os.Stat(path)
	if err == nil {
		return info, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	create := createMissing
	if !create {
		var promptErr error
		create, promptErr = promptCreateFolder(stderr, rawPath)
		if promptErr != nil {
			return nil, promptErr
		}
	}
	if !create {
		return nil, err
	}
	if mkdirErr := os.MkdirAll(path, 0o755); mkdirErr != nil {
		return nil, fmt.Errorf("create folder %q: %w", rawPath, mkdirErr)
	}
	return os.Stat(path)
}

// promptCreateFolder asks whether to create a missing folder path. It never
// prompts when stdin is not a terminal, returning false so the caller falls
// back to its usual missing-path error.
func promptCreateFolder(stderr io.Writer, rawPath string) (bool, error) {
	info, statErr := os.Stdin.Stat()
	if statErr != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false, nil
	}
	fmt.Fprintf(stderr, "l2sync: folder %q does not exist. Create it? [y/N]: ", rawPath)
	reader := bufio.NewReader(os.Stdin)
	line, readErr := reader.ReadString('\n')
	if readErr != nil && line == "" {
		return false, nil
	}
	switch answer := strings.ToLower(strings.TrimSpace(line)); answer {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
