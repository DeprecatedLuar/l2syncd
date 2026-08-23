//go:build linux

package commands

import (
	"bytes"
	"context"
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

# [peers.example]
# address = "example-host"
# status = "pending"
# public_key = "ssh-ed25519 AAAA..."

# [bindings]
# example = ["peer-name"]

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
	original, err := snapshotConfigForEdit(path)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: prepare config snapshot: %v\n", err)
		return configEditExitError
	}
	editFile, err := os.CreateTemp(filepath.Dir(path), ".config-edit-*.toml")
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: create editable config snapshot: %v\n", err)
		return configEditExitError
	}
	editPath := editFile.Name()
	defer os.Remove(editPath)
	if err := editFile.Chmod(configEditFileMode); err != nil {
		editFile.Close()
		fmt.Fprintf(stderr, "l2sync: secure editable config snapshot: %v\n", err)
		return configEditExitError
	}
	if _, err := editFile.Write(original); err != nil {
		editFile.Close()
		fmt.Fprintf(stderr, "l2sync: write editable config snapshot: %v\n", err)
		return configEditExitError
	}
	if err := editFile.Close(); err != nil {
		fmt.Fprintf(stderr, "l2sync: close editable config snapshot: %v\n", err)
		return configEditExitError
	}

	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = defaultEditor
	}
	command := exec.Command("sh", "-c", editor+" \"$1\"", "l2sync", editPath)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fmt.Fprintf(stderr, "l2sync: open config in editor: %v\n", err)
		return configEditExitError
	}
	if cfg, loadErr := config.LoadFile(editPath); loadErr != nil {
		fmt.Fprintf(stderr, "l2sync: edited config is invalid: %v\n", loadErr)
		return configEditExitError
	} else if checkErr := preflight.Validate(cfg); checkErr != nil {
		fmt.Fprintf(stderr, "l2sync: edited config is invalid: %v\n", checkErr)
		return configEditExitError
	}
	edited, err := os.ReadFile(editPath)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: read edited config: %v\n", err)
		return configEditExitError
	}
	if err := installEditedConfig(path, original, edited); err != nil {
		fmt.Fprintf(stderr, "l2sync: save edited config: %v\n", err)
		return configEditExitError
	}
	return configEditExitOK
}

func snapshotConfigForEdit(path string) (contents []byte, err error) {
	if err := ensureConfigFile(path); err != nil {
		return nil, err
	}
	err = withConfigLocked(context.Background(), func(*config.Config) error {
		var readErr error
		contents, readErr = os.ReadFile(path)
		return readErr
	})
	return contents, err
}

func installEditedConfig(path string, original, edited []byte) (err error) {
	return withConfigLocked(context.Background(), func(*config.Config) error {
		current, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read current config: %w", err)
		}
		if !bytes.Equal(current, original) {
			return fmt.Errorf("configuration changed while the editor was open; edited snapshot was not installed")
		}
		if bytes.Equal(current, edited) {
			return nil
		}
		return config.Replace(edited)
	})
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
