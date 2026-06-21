package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/app"
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
	case "ruleset":
		return executeRuleset(args[1:], stateDir, stdout, stderr)
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
	fs := newFlagSet("vpnctl")
	fs.StringVar(stateDir, "state-dir", state.DefaultDir, "state directory")
	var help bool
	fs.BoolVar(&help, "h", false, "show help")
	fs.BoolVar(&help, "help", false, "show help")
	if err := parseFlags(fs, args, stderr); err != nil {
		return nil, false
	}
	if help {
		return []string{"help"}, true
	}
	return fs.Args(), true
}

func executeInit(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	fs := newFlagSet("init")
	force := fs.Bool("force", false, "rewrite default non-secret files")
	var help bool
	fs.BoolVar(&help, "h", false, "show help")
	fs.BoolVar(&help, "help", false, "show help")
	if err := parseFlags(fs, args, stderr); err != nil {
		return 2
	}
	if help {
		printInitHelp(stdout)
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected init argument: %s\n", fs.Arg(0))
		return 2
	}

	result, err := state.Init(stateDir, *force)
	if err != nil {
		fmt.Fprintf(stderr, "init failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "initialized vpnctl state in %s\n", result.StateDir)
	return 0
}

func executeSetup(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	opts := setup.Defaults(stateDir)
	fs := newFlagSet("setup")
	fs.StringVar(&opts.Endpoint, "endpoint", opts.Endpoint, "public endpoint")
	fs.StringVar(&opts.Name, "name", opts.Name, "server name")
	fs.IntVar(&opts.Port, "port", opts.Port, "WireGuard UDP port")
	fs.StringVar(&opts.Interface, "interface", opts.Interface, "WireGuard interface")
	fs.StringVar(&opts.Subnet, "subnet", opts.Subnet, "WireGuard subnet")
	dns := fs.String("dns", "", "comma-separated client DNS servers")
	fs.StringVar(&opts.ExternalInterface, "external-interface", opts.ExternalInterface, "external interface")
	fs.IntVar(&opts.SSHPort, "ssh-port", opts.SSHPort, "SSH port to allow in firewall")
	noEnableUFW := fs.Bool("no-enable-ufw", false, "do not enable firewall")
	dryRun := fs.Bool("dry-run", false, "show planned actions without changing system")
	fs.Bool("yes", false, "skip confirmation")
	var help bool
	fs.BoolVar(&help, "h", false, "show help")
	fs.BoolVar(&help, "help", false, "show help")
	if err := parseFlags(fs, args, stderr); err != nil {
		return 2
	}
	if help {
		printSetupHelp(stdout)
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected setup argument: %s\n", fs.Arg(0))
		return 2
	}
	opts.DNS = splitCSV(*dns)
	if *noEnableUFW {
		opts.EnableUFW = false
	}

	if err := opts.Validate(); err != nil {
		fmt.Fprintf(stderr, "setup failed: %v\n", err)
		return 2
	}
	if *dryRun {
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
	fs := newFlagSet("server init")
	fs.StringVar(&opts.Endpoint, "endpoint", opts.Endpoint, "public endpoint")
	fs.StringVar(&opts.Name, "name", opts.Name, "server name")
	fs.IntVar(&opts.Port, "port", opts.Port, "WireGuard UDP port")
	fs.StringVar(&opts.Interface, "interface", opts.Interface, "WireGuard interface")
	fs.StringVar(&opts.Subnet, "subnet", opts.Subnet, "WireGuard subnet")
	dns := fs.String("dns", "", "comma-separated client DNS servers")
	fs.StringVar(&opts.ExternalInterface, "external-interface", opts.ExternalInterface, "external interface")
	force := fs.Bool("force", false, "replace existing server settings")
	var help bool
	fs.BoolVar(&help, "h", false, "show help")
	fs.BoolVar(&help, "help", false, "show help")
	if err := parseFlags(fs, args, stderr); err != nil {
		return 2
	}
	if help {
		printServerInitHelp(stdout)
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected server init argument: %s\n", fs.Arg(0))
		return 2
	}
	opts.DNS = splitCSV(*dns)

	cfg := setup.ServerConfig(opts)
	if err := state.ConfigureServer(stateDir, cfg, *force); err != nil {
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
	case "export":
		return executeClientExport(args[1:], stateDir, stdout, stderr)
	case "-h", "--help", "help":
		printClientHelp(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown client command: %s\n", args[0])
		return 2
	}
}

func executeClientCreate(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	clientID := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		clientID = args[0]
		args = args[1:]
	}

	fs := newFlagSet("client create")
	name := fs.String("name", "", "display name")
	platform := fs.String("platform", state.DefaultClientPlatform, "platform metadata")
	tags := fs.String("tags", "", "comma-separated tags")
	var help bool
	fs.BoolVar(&help, "h", false, "show help")
	fs.BoolVar(&help, "help", false, "show help")
	if err := parseFlags(fs, args, stderr); err != nil {
		return 2
	}
	if help {
		printClientCreateHelp(stdout)
		return 0
	}
	if clientID == "" && fs.NArg() > 0 {
		clientID = fs.Arg(0)
	}
	if clientID == "" {
		fmt.Fprintln(stderr, "missing client id")
		return 2
	}
	if fs.NArg() > 0 && fs.Arg(0) != clientID {
		fmt.Fprintf(stderr, "unexpected client create argument: %s\n", fs.Arg(0))
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "unexpected client create argument: %s\n", fs.Arg(1))
		return 2
	}
	cfg := state.ClientConfig{
		ID:       clientID,
		Name:     *name,
		Platform: *platform,
		Tags:     splitCSV(*tags),
	}

	client, err := state.CreateClient(context.Background(), stateDir, cfg, newClientKeyGenerator())
	if err != nil {
		fmt.Fprintf(stderr, "client create failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "created client %s with ip %s\n", client.ID, client.AssignedIP)
	return 0
}

func executeClientExport(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	clientID := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		clientID = args[0]
		args = args[1:]
	}

	fs := newFlagSet("client export")
	exportType := fs.String("type", "", "export type")
	output := fs.String("output", "", "output path")
	qr := fs.Bool("qr", false, "render QR output")
	fs.String("ruleset", "default", "ruleset id")
	noSCPHint := fs.Bool("no-scp-hint", false, "do not print scp hint")
	var help bool
	fs.BoolVar(&help, "h", false, "show help")
	fs.BoolVar(&help, "help", false, "show help")
	if err := parseFlags(fs, args, stderr); err != nil {
		return 2
	}
	if help {
		printClientExportHelp(stdout)
		return 0
	}
	if clientID == "" && fs.NArg() > 0 {
		clientID = fs.Arg(0)
	}
	if clientID == "" {
		fmt.Fprintln(stderr, "missing client id")
		return 2
	}
	if fs.NArg() > 0 && fs.Arg(0) != clientID {
		fmt.Fprintf(stderr, "unexpected client export argument: %s\n", fs.Arg(0))
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "unexpected client export argument: %s\n", fs.Arg(1))
		return 2
	}
	if strings.TrimSpace(*exportType) == "" {
		fmt.Fprintln(stderr, "--type is required")
		return 2
	}
	if *qr {
		fmt.Fprintln(stderr, "client export --qr is not implemented yet")
		return 1
	}

	result, err := app.ExportClient(app.ExportClientInput{
		StateDir: dirOrDefault(stateDir),
		ClientID: clientID,
		Type:     *exportType,
		Output:   *output,
		SCPHint:  !*noSCPHint,
	})
	if err != nil {
		fmt.Fprintf(stderr, "client export failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s config to %s\n", *exportType, result.Path)
	if result.SCPHint != "" {
		fmt.Fprintf(stdout, "copy with: %s\n", result.SCPHint)
	}
	return 0
}

func executeRuleset(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "missing ruleset command")
		return 2
	}

	switch args[0] {
	case "add":
		return executeRulesetAdd(args[1:], stateDir, stdout, stderr)
	case "show":
		return executeRulesetShow(args[1:], stateDir, stdout, stderr)
	case "list":
		return executeRulesetList(args[1:], stateDir, stdout, stderr)
	case "-h", "--help", "help":
		printRulesetHelp(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown ruleset command: %s\n", args[0])
		return 2
	}
}

func executeRulesetAdd(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	rulesetID := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		rulesetID = args[0]
		args = args[1:]
	}

	fs := newFlagSet("ruleset add")
	name := fs.String("name", "", "display name")
	rulesetType := fs.String("type", state.RulesetTypeDomainSuffix, "ruleset type")
	domains := fs.String("domain", "", "comma-separated domains")
	var help bool
	fs.BoolVar(&help, "h", false, "show help")
	fs.BoolVar(&help, "help", false, "show help")
	if err := parseFlags(fs, args, stderr); err != nil {
		return 2
	}
	if help {
		printRulesetAddHelp(stdout)
		return 0
	}
	if rulesetID == "" && fs.NArg() > 0 {
		rulesetID = fs.Arg(0)
	}
	if rulesetID == "" {
		fmt.Fprintln(stderr, "missing ruleset id")
		return 2
	}
	if fs.NArg() > 0 && fs.Arg(0) != rulesetID {
		fmt.Fprintf(stderr, "unexpected ruleset add argument: %s\n", fs.Arg(0))
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "unexpected ruleset add argument: %s\n", fs.Arg(1))
		return 2
	}
	if strings.TrimSpace(*domains) == "" {
		fmt.Fprintln(stderr, "--domain is required")
		return 2
	}

	ruleset, err := state.SaveRuleset(stateDir, state.RulesetConfig{
		ID:      rulesetID,
		Name:    *name,
		Type:    *rulesetType,
		Domains: splitCSV(*domains),
	})
	if err != nil {
		fmt.Fprintf(stderr, "ruleset add failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "saved ruleset %s with %d domains\n", ruleset.ID, len(ruleset.Domains))
	return 0
}

func executeRulesetShow(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "missing ruleset id")
		return 2
	}
	if len(args) > 1 {
		fmt.Fprintf(stderr, "unexpected ruleset show argument: %s\n", args[1])
		return 2
	}
	ruleset, err := state.LoadRuleset(stateDir, args[0])
	if err != nil {
		fmt.Fprintf(stderr, "ruleset show failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "id: %s\n", ruleset.ID)
	fmt.Fprintf(stdout, "name: %s\n", ruleset.Name)
	fmt.Fprintf(stdout, "type: %s\n", ruleset.Type)
	fmt.Fprintf(stdout, "domains: %s\n", strings.Join(ruleset.Domains, ", "))
	return 0
}

func executeRulesetList(args []string, stateDir string, stdout io.Writer, stderr io.Writer) int {
	fs := newFlagSet("ruleset list")
	var help bool
	fs.BoolVar(&help, "h", false, "show help")
	fs.BoolVar(&help, "help", false, "show help")
	if err := parseFlags(fs, args, stderr); err != nil {
		return 2
	}
	if help {
		printRulesetListHelp(stdout)
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected ruleset list argument: %s\n", fs.Arg(0))
		return 2
	}
	rulesets, err := state.ListRulesets(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "ruleset list failed: %v\n", err)
		return 1
	}
	for _, ruleset := range rulesets {
		fmt.Fprintf(stdout, "%s\t%s\t%d domains\n", ruleset.ID, ruleset.Type, len(ruleset.Domains))
	}
	return 0
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

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) error {
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return err
	}
	return nil
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, `vpnctl manages a personal WireGuard VPN.

Usage:
  vpnctl [--state-dir <path>] <command>

Commands:
  init       Initialize local vpnctl state
  setup      Preview or perform one-shot server setup
  client     Manage clients
  ruleset    Manage routing rulesets
  help       Show this help text
  version    Show version information

Planned commands:
  server show
  client revoke
  client rotate-keys
  client delete
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
  export    Export a client config
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

func printClientExportHelp(w io.Writer) {
	fmt.Fprint(w, `Export a client config.

Usage:
  vpnctl client export <client-id> --type <type> [flags]

Flags:
  --type <type>       Export type: wireguard
  --output <path>     Output path
  --qr                Render QR output (not implemented yet)
  --ruleset <id>      Ruleset id for Clash export (default default)
  --no-scp-hint       Do not print scp copy hint
`)
}

func printRulesetHelp(w io.Writer) {
	fmt.Fprint(w, `Manage routing rulesets.

Usage:
  vpnctl ruleset <command>

Commands:
  add     Create or replace a ruleset
  show    Show one ruleset
  list    List rulesets
`)
}

func printRulesetAddHelp(w io.Writer) {
	fmt.Fprint(w, `Create or replace a ruleset.

Usage:
  vpnctl ruleset add <ruleset-id> --domain <domains> [flags]

Flags:
  --domain <domains>   Comma-separated domains
  --name <name>        Display name
  --type <type>        Ruleset type (default domain-suffix)
`)
}

func printRulesetListHelp(w io.Writer) {
	fmt.Fprint(w, `List rulesets.

Usage:
  vpnctl ruleset list
`)
}

func dirOrDefault(dir string) string {
	if dir == "" {
		return state.DefaultDir
	}
	return dir
}
