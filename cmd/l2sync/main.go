//go:build linux

// Command l2sync is the entrypoint for the two-way synchronization daemon.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"l2syncd/internal/commands"
	"l2syncd/internal/commands/help"
)

const (
	exitOK    = 0
	exitError = 1
)

const githubRepo = "DeprecatedLuar/l2syncd"

// Android forbids executing files under an app's data directory, so Termux
// runs them through the system dynamic linker instead. Its exec interceptor
// builds the argument list as [original argv[0], resolved executable path,
// original argv[1:]...] (termux-exec's modifyExecArgs), and the linker does not
// strip the path it was handed, so the process sees it ahead of the first real
// argument. os.Executable() resolves to the linker on such a launch, which is
// what distinguishes it from a direct exec.
var androidLinkerNames = []string{"linker64", "linker"}

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	executable, err := os.Executable()
	if err != nil {
		executable = ""
	}
	args := normalizeArgs(os.Args, executable)
	os.Exit(run(args[1:], os.Stdout, os.Stderr))
}

// normalizeArgs removes the executable path that the Android system linker
// inserts at argv[1], so argv has the same shape on every supported platform.
// It rewrites argv only when the executable resolves to the linker rather than
// to us and the inserted element is the absolute path it has to be. On a direct
// exec, and on every non-Android platform, argv is returned unchanged.
func normalizeArgs(argv []string, executable string) []string {
	if len(argv) < 2 || !filepath.IsAbs(argv[1]) {
		return argv
	}
	if !slices.Contains(androidLinkerNames, filepath.Base(executable)) {
		return argv
	}
	return append(argv[:1:1], argv[2:]...)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		help.Run(args)
		return exitOK
	}

	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "l2sync %s (%s)\n", version, githubRepo)
		return exitOK
	case "config", "conf":
		return commands.ConfigEdit(args[1:], stderr)
	case "add", "a":
		return commands.Add(args[1:], stderr)
	case "remove", "rm":
		return commands.Remove(args[1:], stderr)
	case "list", "ls":
		if len(args) > 1 && args[1] == "connections" {
			return commands.Connection(append([]string{"ls"}, args[2:]...), stdout, stderr)
		}
		if len(args) > 1 {
			return commands.ListPeer(args[1:], stdout, stderr)
		}
		return commands.List(stdout, stderr)
	case "join":
		return commands.Join(args[1:], stderr)
	case "leave":
		return commands.Leave(args[1:], stderr)
	case "ignore":
		return commands.Ignore(args[1:], stdout, stderr)
	case "serve":
		return commands.Serve(args[1:], os.Stdin, stdout, stderr)
	case "connection", "connections":
		return commands.Connection(args[1:], stdout, stderr)
	case "status":
		return commands.Status(stdout, stderr)
	case "now":
		return commands.Now(args[1:], stdout, stderr)
	case "run":
		return commands.Run(args[1:], stderr)
	case "index":
		if len(args) > 1 && args[1] == "commit" {
			return commands.IndexCommit(args[2:], stderr)
		}
		fmt.Fprintln(stderr, "l2sync: unknown index command")
		return exitError
	default:
		fmt.Fprintf(stderr, "l2sync: command %q is not implemented yet\n", args[0])
		return exitError
	}
}
