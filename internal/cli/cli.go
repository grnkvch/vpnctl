package cli

import (
	"fmt"
	"io"

	"github.com/vgrinkevich/vpnctl/internal/state"
)

const version = "0.1.0-dev"

// Execute runs the vpnctl command and returns a process exit code.
func Execute(args []string, stdout io.Writer, stderr io.Writer) int {
	stateDir := state.DefaultDir
	args, ok := parseGlobalFlags(args, &stateDir, stderr)
	if !ok {
		return 2
	}

	if len(args) == 0 {
		printHelp(stdout)
		return 0
	}

	switch args[0] {
	case "help", "-h", "--help":
		printHelp(stdout)
		return 0
	case "init":
		return executeInit(args[1:], stateDir, stdout, stderr)
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "vpnctl %s\n", version)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		printHelp(stderr)
		return 2
	}
}

func parseGlobalFlags(args []string, stateDir *string, stderr io.Writer) ([]string, bool) {
	for len(args) > 0 {
		switch args[0] {
		case "--state-dir":
			if len(args) < 2 {
				fmt.Fprintln(stderr, "missing value for --state-dir")
				return nil, false
			}
			*stateDir = args[1]
			args = args[2:]
		default:
			return args, true
		}
	}
	return args, true
}

func executeInit(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	force := false
	for _, arg := range args {
		switch arg {
		case "--force":
			force = true
		case "-h", "--help":
			printInitHelp(stdout)
			return 0
		default:
			fmt.Fprintf(stderr, "unknown init flag: %s\n", arg)
			return 2
		}
	}

	result, err := state.Init(stateDir, force)
	if err != nil {
		fmt.Fprintf(stderr, "init failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "initialized vpnctl state in %s\n", result.StateDir)
	return 0
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, `vpnctl manages a personal WireGuard VPN.

Usage:
  vpnctl [--state-dir <path>] <command>

Commands:
  init       Initialize local vpnctl state
  help       Show this help text
  version    Show version information

Planned commands:
  setup
  server init
  server show
  ruleset add
  client create
  client revoke
  client rotate-keys
  client delete
  client export
  apply
`)
}

func printInitHelp(w io.Writer) {
	fmt.Fprint(w, `Initialize local vpnctl state.

Usage:
  vpnctl init [--force]

Flags:
  --force    Rewrite default non-secret files
`)
}
