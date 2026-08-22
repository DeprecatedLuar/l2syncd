//go:build linux

package commands

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"l2syncd/internal/config"
)

const (
	configEditExitOK    = 0
	configEditExitError = 1
	configEditFileMode  = 0o600
	defaultEditor       = "vi"
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
	return configEditExitOK
}

func ensureConfigFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, configEditFileMode)
	if err != nil {
		return err
	}
	return file.Close()
}
