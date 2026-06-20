package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/setup"
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
	case "setup":
		return executeSetup(args[1:], stateDir, stdout, stderr)
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

func executeSetup(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	opts := setup.Defaults(stateDir)
	dryRun := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--endpoint":
			value, ok := nextValue(args, &i, "--endpoint", stderr)
			if !ok {
				return 2
			}
			opts.Endpoint = value
		case "--name":
			value, ok := nextValue(args, &i, "--name", stderr)
			if !ok {
				return 2
			}
			opts.Name = value
		case "--port":
			value, ok := parsePortFlag(args, &i, "--port", stderr)
			if !ok {
				return 2
			}
			opts.Port = value
		case "--interface":
			value, ok := nextValue(args, &i, "--interface", stderr)
			if !ok {
				return 2
			}
			opts.Interface = value
		case "--subnet":
			value, ok := nextValue(args, &i, "--subnet", stderr)
			if !ok {
				return 2
			}
			opts.Subnet = value
		case "--dns":
			value, ok := nextValue(args, &i, "--dns", stderr)
			if !ok {
				return 2
			}
			opts.DNS = splitCSV(value)
		case "--external-interface":
			value, ok := nextValue(args, &i, "--external-interface", stderr)
			if !ok {
				return 2
			}
			opts.ExternalInterface = value
		case "--ssh-port":
			value, ok := parsePortFlag(args, &i, "--ssh-port", stderr)
			if !ok {
				return 2
			}
			opts.SSHPort = value
		case "--no-enable-ufw":
			opts.EnableUFW = false
		case "--dry-run":
			dryRun = true
		case "--yes":
		case "-h", "--help":
			printSetupHelp(stdout)
			return 0
		default:
			fmt.Fprintf(stderr, "unknown setup flag: %s\n", args[i])
			return 2
		}
	}

	if err := opts.Validate(); err != nil {
		fmt.Fprintf(stderr, "setup failed: %v\n", err)
		return 2
	}
	if dryRun {
		setup.PrintDryRun(stdout, opts)
		return 0
	}

	fmt.Fprintln(stderr, "setup without --dry-run is not implemented yet")
	return 1
}

func nextValue(args []string, index *int, flag string, stderr io.Writer) (string, bool) {
	if *index+1 >= len(args) {
		fmt.Fprintf(stderr, "missing value for %s\n", flag)
		return "", false
	}
	*index = *index + 1
	return args[*index], true
}

func parsePortFlag(args []string, index *int, flag string, stderr io.Writer) (int, bool) {
	value, ok := nextValue(args, index, flag, stderr)
	if !ok {
		return 0, false
	}
	port, err := strconv.Atoi(value)
	if err != nil {
		fmt.Fprintf(stderr, "invalid value for %s: %s\n", flag, value)
		return 0, false
	}
	return port, true
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, `vpnctl manages a personal WireGuard VPN.

Usage:
  vpnctl [--state-dir <path>] <command>

Commands:
  init       Initialize local vpnctl state
  setup      Preview or perform one-shot server setup
  help       Show this help text
  version    Show version information

Planned commands:
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

func printSetupHelp(w io.Writer) {
	fmt.Fprint(w, `Perform one-shot initial setup of the local Ubuntu VPN server.

Usage:
  vpnctl setup --endpoint <host-or-ip> [--dry-run]

Flags:
  --endpoint <host-or-ip>       Public endpoint used by clients
  --subnet <cidr>               WireGuard subnet (default 10.66.0.0/24)
  --port <port>                 WireGuard UDP port (default 51820)
  --interface <name>            WireGuard interface (default wg0)
  --dns <ip-list>               Comma-separated client DNS servers
  --external-interface <name>   External interface for NAT
  --ssh-port <port>             SSH port to allow in firewall (default 22)
  --no-enable-ufw               Do not enable firewall
  --dry-run                     Show planned actions without changing system
`)
}
