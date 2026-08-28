//go:build linux

package commands

import (
	"fmt"
	"io"
)

const folderExitError = 1

// Folder dispatches the folder subcommand tree: share/unshare/attach/detach.
func Folder(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: l2sync folder <share|unshare|attach|detach> ...")
		return folderExitError
	}
	switch args[0] {
	case "share":
		return Share(args[1:], stderr)
	case "unshare":
		return Unshare(args[1:], stderr)
	case "attach":
		return Attach(args[1:], stderr)
	case "detach":
		return Detach(args[1:], stderr)
	default:
		fmt.Fprintf(stderr, "l2sync: unknown folder command %q\n", args[0])
		return folderExitError
	}
}
