//go:build linux

package transport

import (
	"context"
	"os/exec"

	"l2syncd/internal/androidexec"
	"l2syncd/internal/config"
)

// LoginSSHCommand runs remoteArgs on destination through the user's own SSH
// access (their keys and ~/.ssh/config), never prompting and never reusing a
// shared control connection.
func LoginSSHCommand(ctx context.Context, destination string, remoteArgs ...string) (*exec.Cmd, error) {
	if err := config.ValidatePeerAddress(destination); err != nil {
		return nil, err
	}
	arguments := []string{
		"-T",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=" + sshConnectTimeout,
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		destination,
	}
	return androidexec.CommandContext(ctx, sshCommand, append(arguments, remoteArgs...)...)
}
