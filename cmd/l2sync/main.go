//go:build linux

// Command l2sync is the entrypoint for the two-way synchronization daemon.
package main

import (
	"fmt"
	"io"
	"os"

	"l2syncd/internal/commands"
	"l2syncd/internal/commands/help"
)

const (
	exitOK    = 0
	exitError = 1
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		help.Run(args)
		return exitOK
	}

	switch args[0] {
	case "config", "conf":
		return commands.ConfigEdit(args[1:], stderr)
	case "add", "a":
		return commands.Add(args[1:], stderr)
	case "remove", "rm":
		return commands.Remove(args[1:], stderr)
	case "list", "ls":
		if len(args) > 1 {
			return commands.ListPeer(args[1:], stdout, stderr)
		}
		return commands.List(stdout, stderr)
	case "join":
		return commands.Join(args[1:], stderr)
	case "serve":
		return commands.Serve(os.Stdin, stdout, stderr)
	case "status":
		return commands.Status(stdout, stderr)
	case "now":
		return commands.Now(args[1:], stdout, stderr)
	case "run":
		return commands.Run(args[1:], stderr)
	case "baseline":
		if len(args) > 1 && args[1] == "commit" {
			return commands.BaselineCommit(args[2:], stderr)
		}
		fmt.Fprintln(stderr, "l2sync: unknown baseline command")
		return exitError
	default:
		fmt.Fprintf(stderr, "l2sync: command %q is not implemented yet\n", args[0])
		return exitError
	}
}
