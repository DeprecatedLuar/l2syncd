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
			gohelp.Item("connection <add|ls|rm|edit>", "Manage peer credentials"),
			gohelp.Item("add <name> <path>", "Offer a shared folder to the network"),
			gohelp.Item("remove <name>", "Withdraw an offered folder; cuts every consumer"),
			gohelp.Item("list, ls [peer]", "List local and network folders"),
			gohelp.Item("status", "Show synchronization status"),
			gohelp.Item("join <name> <path>", "Join a folder offered by a peer"),
			gohelp.Item("leave <name>", "Detach from a joined folder"),
			gohelp.Item("ignore <name> [add|rm <pattern>...]", "View or edit a folder's local ignore rules"),
			gohelp.Item("run", "Run synchronization"),
		).
		Section("Help",
			gohelp.Item("help, -h, --help", "Show this help message"),
		)

	gohelp.Run(args, root)
}
