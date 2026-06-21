package cli

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/setup"
	"github.com/vgrinkevich/vpnctl/internal/state"
)

const version = "0.1.0-dev"

var newClientKeyGenerator = func() state.ClientKeyGenerator {
	return setup.ClientKeyGenerator{}
}

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
	case "server":
		return executeServer(args[1:], stateDir, stdout, stderr)
	case "client":
		return executeClient(args[1:], stateDir, stdout, stderr)
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

func executeServer(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "missing server command")
		return 2
	}

	switch args[0] {
	case "init":
		return executeServerInit(args[1:], stateDir, stdout, stderr)
	case "-h", "--help", "help":
		printServerHelp(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown server command: %s\n", args[0])
		return 2
	}
}

func executeServerInit(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	opts := setup.Defaults(stateDir)
	force := false

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
		case "--force":
			force = true
		case "-h", "--help":
			printServerInitHelp(stdout)
			return 0
		default:
			fmt.Fprintf(stderr, "unknown server init flag: %s\n", args[i])
			return 2
		}
	}

	cfg := setup.ServerConfig(opts)
	if err := state.ConfigureServer(stateDir, cfg, force); err != nil {
		fmt.Fprintf(stderr, "server init failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "configured server %s in %s\n", cfg.Name, stateDir)
	return 0
}

func executeClient(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "missing client command")
		return 2
	}

	switch args[0] {
	case "create":
		return executeClientCreate(args[1:], stateDir, stdout, stderr)
	case "-h", "--help", "help":
		printClientHelp(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown client command: %s\n", args[0])
		return 2
	}
}

func executeClientCreate(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "missing client id")
		return 2
	}
	cfg := state.ClientConfig{
		ID:       args[0],
		Platform: state.DefaultClientPlatform,
	}

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--name":
			value, ok := nextValue(args, &i, "--name", stderr)
			if !ok {
				return 2
			}
			cfg.Name = value
		case "--platform":
			value, ok := nextValue(args, &i, "--platform", stderr)
			if !ok {
				return 2
			}
			cfg.Platform = value
		case "--tags":
			value, ok := nextValue(args, &i, "--tags", stderr)
			if !ok {
				return 2
			}
			cfg.Tags = splitCSV(value)
		case "-h", "--help":
			printClientCreateHelp(stdout)
			return 0
		default:
			fmt.Fprintf(stderr, "unknown client create flag: %s\n", args[i])
			return 2
		}
	}

	client, err := state.CreateClient(context.Background(), stateDir, cfg, newClientKeyGenerator())
	if err != nil {
		fmt.Fprintf(stderr, "client create failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "created client %s with ip %s\n", client.ID, client.AssignedIP)
	return 0
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
  client     Manage clients
  help       Show this help text
  version    Show version information

Planned commands:
  server show
  ruleset add
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

func printServerHelp(w io.Writer) {
	fmt.Fprint(w, `Manage local server settings.

Usage:
  vpnctl server <command>

Commands:
  init    Configure server settings in local state
`)
}

func printServerInitHelp(w io.Writer) {
	fmt.Fprint(w, `Configure server settings in local state.

Usage:
  vpnctl server init --endpoint <host-or-ip> [flags]

Flags:
  --endpoint <host-or-ip>       Public endpoint used by clients
  --name <name>                 Server name (default main)
  --subnet <cidr>               WireGuard subnet (default 10.66.0.0/24)
  --port <port>                 WireGuard UDP port (default 51820)
  --interface <name>            WireGuard interface (default wg0)
  --dns <ip-list>               Comma-separated client DNS servers
  --external-interface <name>   External interface for NAT
  --force                       Replace existing server settings
`)
}

func printClientHelp(w io.Writer) {
	fmt.Fprint(w, `Manage clients.

Usage:
  vpnctl client <command>

Commands:
  create    Create a new client
`)
}

func printClientCreateHelp(w io.Writer) {
	fmt.Fprint(w, `Create a new client.

Usage:
  vpnctl client create <client-id> [flags]

Flags:
  --name <name>           Display name (default client id)
  --platform <platform>   Platform metadata (default generic)
  --tags <tag-list>       Comma-separated tags
`)
}
