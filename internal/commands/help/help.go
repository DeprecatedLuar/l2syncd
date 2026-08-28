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
			gohelp.Item("folder <share|unshare|attach|detach>", "Manage shared and attached folders"),
			gohelp.Item("share <name> <path> [-p]", "Offer a shared folder to the network"),
			gohelp.Item("unshare <name>", "Withdraw an offered folder; cuts every consumer"),
			gohelp.Item("list, ls [peer]", "List local and network folders"),
			gohelp.Item("status", "Show synchronization status"),
			gohelp.Item("attach <name> <path> [-p]", "Attach to a folder offered by a peer"),
			gohelp.Item("detach <name>", "Detach from an attached folder"),
			gohelp.Item("ignore <name> [add|rm <pattern>...]", "View or edit a folder's local ignore rules"),
			gohelp.Item("run", "Run synchronization"),
		).
		Section("Help",
			gohelp.Item("help, -h, --help", "Show this help message"),
			gohelp.Item("version, -v, --version", "Show the l2sync version"),
		)

	gohelp.Run(args, root)
}
