//go:build linux

// Package help defines and renders the l2sync command help.
package help

import gohelp "github.com/DeprecatedLuar/gohelp-luar"

const (
	binaryName        = "l2sync"
	binaryDescription = "two-way directory synchronization daemon"
)

// Run renders l2sync help for the supplied command-line arguments.
func Run(args []string) {
	root := gohelp.NewPage(binaryName, binaryDescription).
		Usage("l2sync <command> [arguments]").
		Section("Commands",
			gohelp.Item("config, conf", "Open the configuration file in an editor"),
			gohelp.Item("add <name> <path>", "Register a shared folder"),
			gohelp.Item("remove <name>", "Remove a registered folder"),
			gohelp.Item("list, ls [peer]", "List registered folders"),
			gohelp.Item("status", "Show synchronization status"),
			gohelp.Item("join", "Join a remote peer"),
			gohelp.Item("run", "Run synchronization"),
		).
		Section("Help",
			gohelp.Item("help, -h, --help", "Show this help message"),
		)

	gohelp.Run(args, root)
}
