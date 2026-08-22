//go:build linux

package commands

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"l2syncd/internal/config"
	"l2syncd/internal/preflight"
)

const (
	configEditExitOK    = 0
	configEditExitError = 1
	configEditFileMode  = 0o600
	defaultEditor       = "vi"
	defaultConfig       = `# l2sync configuration
#
# Addresses may refer to an alias in ~/.ssh/config or be a raw SSH address.
# Remove the leading '#' from an example section and customize its values.

# [peers]
# example = "example-host"

# Folders offered to peers.
# [shared]
# example = "/path/to/share"

# Folders consumed from a peer.
# [remote]
# example = "/path/to/local/folder"
`
)

// ConfigEdit opens the l2sync configuration file in the user's editor.
func ConfigEdit(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: l2sync config")
		return configEditExitError
	}

	path, err := config.Path()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: find config file: %v\n", err)
		return configEditExitError
	}
	if err := ensureConfigFile(path); err != nil {
		fmt.Fprintf(stderr, "l2sync: prepare config file: %v\n", err)
		return configEditExitError
	}
	original, originalErr := os.ReadFile(path)

	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = defaultEditor
	}
	command := exec.Command("sh", "-c", editor+" \"$1\"", "l2sync", path)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fmt.Fprintf(stderr, "l2sync: open config in editor: %v\n", err)
		return configEditExitError
	}
	if cfg, loadErr := config.Load(); loadErr != nil {
		restoreConfig(path, original, originalErr)
		fmt.Fprintf(stderr, "l2sync: edited config is invalid: %v\n", loadErr)
		return configEditExitError
	} else if checkErr := preflight.Validate(cfg); checkErr != nil {
		restoreConfig(path, original, originalErr)
		fmt.Fprintf(stderr, "l2sync: edited config is invalid: %v\n", checkErr)
		return configEditExitError
	}
	return configEditExitOK
}

func restoreConfig(path string, original []byte, originalErr error) {
	if originalErr == nil {
		_ = os.WriteFile(path, original, configEditFileMode)
		return
	}
	_ = os.Remove(path)
}

func ensureConfigFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, configEditFileMode)
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := file.WriteString(defaultConfig); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return nil
}
