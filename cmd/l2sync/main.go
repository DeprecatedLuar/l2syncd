// Command l2sync is the entrypoint for the two-way synchronization daemon.
package main

import (
	"os"

	"l2syncd/internal/commands"
)

func main() {
	os.Exit(commands.Run(os.Args[1:], os.Stdout, os.Stderr))
}
