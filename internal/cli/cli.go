package cli

import (
	"fmt"
	"io"
)

const version = "0.1.0-dev"

// Execute runs the vpnctl command and returns a process exit code.
func Execute(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		printHelp(stdout)
		return 0
	}

	switch args[0] {
	case "help", "-h", "--help":
		printHelp(stdout)
		return 0
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "vpnctl %s\n", version)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		printHelp(stderr)
		return 2
	}
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, `vpnctl manages a personal WireGuard VPN.

Usage:
  vpnctl <command>

Commands:
  help       Show this help text
  version    Show version information

Planned commands:
  init
  server add
  server render
  server apply
  client create
  client revoke
  client rotate-keys
  client regenerate-config
  client delete
  delivery export
`)
}
