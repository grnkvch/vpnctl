package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type migrationOptions struct {
	workspace       string
	systemRoot      string
	bundle          string
	maintenanceRoot string
	publicIPv4      string
	nodeCIDR        string
	rollback        bool
	accept          bool
	dryRun          bool
	yes             bool
	json            bool
}

type optionalPort struct {
	value *int
}

func (port *optionalPort) String() string {
	if port == nil || port.value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *port.value)
}

func (port *optionalPort) Set(value string) error {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 || parsed > 65535 {
		return fmt.Errorf("must be an integer between 1 and 65535")
	}
	port.value = &parsed
	return nil
}

func run(arguments []string, stdout, stderr io.Writer) int {
	options, explicitPort, help, err := parseOptions(arguments)
	if help {
		printHelp(stdout)
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "migration validation failed: %v\n", err)
		return 2
	}
	recoveryAction, recoveryMode := options.recoveryAction()
	if recoveryMode && !options.yes {
		fmt.Fprintln(stderr, "migration validation failed: rollback or acceptance requires --yes")
		return 2
	}
	if !recoveryMode && !options.dryRun && !options.yes {
		fmt.Fprintln(stderr, "migration validation failed: applying accepted downtime requires --yes after reviewing --dry-run")
		return 2
	}
	workspace, err := filepath.Abs(options.workspace)
	if err != nil {
		fmt.Fprintf(stderr, "migration validation failed: resolve workspace: %v\n", err)
		return 2
	}
	systemRoot, err := filepath.Abs(options.systemRoot)
	if err != nil {
		fmt.Fprintf(stderr, "migration validation failed: resolve system root: %v\n", err)
		return 2
	}
	maintenance := options.maintenanceRoot
	if maintenance == "" {
		maintenance = filepath.Join(systemRoot, "var", "lib", "vpnctl-v1-migration")
	} else {
		maintenance, err = filepath.Abs(maintenance)
		if err != nil {
			fmt.Fprintf(stderr, "migration validation failed: resolve maintenance root: %v\n", err)
			return 2
		}
	}

	discoverer, err := linuxplatform.NewDiscoverer(systemRoot)
	if err != nil {
		fmt.Fprintf(stderr, "migration preflight failed: %v\n", err)
		return 2
	}
	snapshot, err := discoverer.Discover(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "migration preflight failed: %v\n", err)
		return 2
	}
	if !recoveryMode {
		if err := snapshot.ValidateMandatoryCapabilities(); err != nil {
			fmt.Fprintf(stderr, "migration preflight failed: %v\n", err)
			return 2
		}
	}
	var ssh linuxplatform.SSHPortPlan
	if !recoveryMode {
		ssh, err = linuxplatform.ResolveSSHPort(linuxplatform.SSHPortInput{
			ExplicitPort: explicitPort.value, SSHConnection: os.Getenv("SSH_CONNECTION"),
		}, snapshot)
	}
	if err != nil {
		fmt.Fprintf(stderr, "migration preflight failed: %v\n", err)
		return 2
	}
	watchdog, err := newSystemV1MigrationWatchdog(systemRoot)
	if err != nil {
		fmt.Fprintf(stderr, "migration setup failed: %v\n", err)
		return 5
	}
	driver, err := lifecycle.NewSystemV1MigrationDriver(systemRoot, lifecycle.ReleasePlatform{
		OperatingSystem: snapshot.OS.ID, Version: snapshot.OS.VersionID, Architecture: snapshot.Architecture,
	}, linuxplatform.DefaultVPNCTLBinaryPath, watchdog)
	if err != nil {
		fmt.Fprintf(stderr, "migration setup failed: %v\n", err)
		return 5
	}
	if recoveryMode {
		result, recoveryErr := driver.RecoverV1Migration(context.Background(), lifecycle.V1MigrationRecoveryInput{
			MaintenanceRoot: maintenance, WorkspaceRoot: workspace, Action: recoveryAction, Confirmed: options.yes,
		})
		if result.SchemaVersion != 0 {
			if emitErr := emitRecoveryResult(stdout, result, options.json); emitErr != nil {
				fmt.Fprintf(stderr, "migration output failed: %v\n", emitErr)
				return 5
			}
		}
		if recoveryErr != nil {
			fmt.Fprintf(stderr, "migration recovery failed: %v\n", recoveryErr)
			if errors.Is(recoveryErr, lifecycle.ErrV1MigrationConflict) || errors.Is(recoveryErr, lifecycle.ErrV1MigrationTerminal) {
				return 3
			}
			return 5
		}
		return 0
	}
	bundle, err := filepath.Abs(options.bundle)
	if err != nil {
		fmt.Fprintf(stderr, "migration validation failed: resolve bundle: %v\n", err)
		return 2
	}
	inspector, err := lifecycle.NewV1InstallationInspector(workspace, systemRoot)
	if err != nil {
		fmt.Fprintf(stderr, "migration setup failed: %v\n", err)
		return 2
	}
	migrator, err := lifecycle.NewV1Migrator(inspector, driver)
	if err != nil {
		fmt.Fprintf(stderr, "migration setup failed: %v\n", err)
		return 5
	}
	result, err := migrator.Run(context.Background(), lifecycle.V1MigrationInput{
		BundlePath: bundle, MaintenanceRoot: maintenance, PublicIPv4: options.publicIPv4,
		NodeCIDR: options.nodeCIDR, SSHPort: ssh.Port, SSHConnection: os.Getenv("SSH_CONNECTION"),
		DryRun: options.dryRun,
	})
	if result.SchemaVersion != 0 {
		if emitErr := emitResult(stdout, result, options.json); emitErr != nil {
			fmt.Fprintf(stderr, "migration output failed: %v\n", emitErr)
			return 5
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "migration failed: %v\n", err)
		switch {
		case errors.Is(err, lifecycle.ErrV1MigrationBlocked), errors.Is(err, lifecycle.ErrV1MigrationConflict):
			return 3
		case errors.Is(err, lifecycle.ErrV1MigrationRolledBack):
			return 4
		default:
			return 5
		}
	}
	return 0
}

func parseOptions(arguments []string) (migrationOptions, optionalPort, bool, error) {
	options := migrationOptions{workspace: ".", systemRoot: "/"}
	port := optionalPort{}
	flags := flag.NewFlagSet("vpnctl-v1-migrate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.workspace, "workspace", options.workspace, "v1 workspace containing .vpnctl")
	flags.StringVar(&options.systemRoot, "system-root", options.systemRoot, "system root (test fixtures only unless /)")
	flags.StringVar(&options.bundle, "bundle", "", "checksum-governed local v2 release bundle")
	flags.StringVar(&options.maintenanceRoot, "maintenance-root", "", "root-only resumable migration directory")
	flags.StringVar(&options.publicIPv4, "public-ip", "", "explicit public gateway IPv4")
	flags.StringVar(&options.nodeCIDR, "node-cidr", "", "v2 private-node pool")
	flags.Var(&port, "ssh-port", "verified SSH listener port")
	flags.BoolVar(&options.rollback, "rollback", false, "restore the retained v1 maintenance snapshot")
	flags.BoolVar(&options.accept, "accept", false, "accept v2 and remove the v1 rollback payload")
	flags.BoolVar(&options.dryRun, "dry-run", false, "verify and report without mutation")
	flags.BoolVar(&options.yes, "yes", false, "confirm the selected mutating maintenance action")
	flags.BoolVar(&options.json, "json", false, "emit one JSON result")
	help := false
	flags.BoolVar(&help, "help", false, "show help")
	flags.BoolVar(&help, "h", false, "show help")
	if err := flags.Parse(arguments); err != nil {
		return options, port, false, err
	}
	if help {
		return options, port, true, nil
	}
	if flags.NArg() != 0 {
		return options, port, false, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if options.rollback && options.accept {
		return options, port, false, fmt.Errorf("--rollback and --accept are mutually exclusive")
	}
	_, recoveryMode := options.recoveryAction()
	if recoveryMode {
		if options.dryRun {
			return options, port, false, fmt.Errorf("recovery actions do not support --dry-run")
		}
		if strings.TrimSpace(options.bundle) != "" || strings.TrimSpace(options.publicIPv4) != "" || strings.TrimSpace(options.nodeCIDR) != "" || port.value != nil {
			return options, port, false, fmt.Errorf("--rollback and --accept do not accept migration target options")
		}
		return options, port, false, nil
	}
	if strings.TrimSpace(options.bundle) == "" || strings.TrimSpace(options.publicIPv4) == "" {
		return options, port, false, fmt.Errorf("--bundle and --public-ip are required")
	}
	if options.dryRun && options.yes {
		return options, port, false, fmt.Errorf("--dry-run and --yes are mutually exclusive")
	}
	return options, port, false, nil
}

func (options migrationOptions) recoveryAction() (lifecycle.V1MigrationRecoveryAction, bool) {
	if options.rollback {
		return lifecycle.V1MigrationRecoveryRollback, true
	}
	if options.accept {
		return lifecycle.V1MigrationRecoveryAccept, true
	}
	return "", false
}

func emitResult(writer io.Writer, result lifecycle.V1MigrationResult, jsonMode bool) error {
	if jsonMode {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	fmt.Fprintf(writer, "v1 migration %s (%s)\n", result.Status, result.MigrationID)
	fmt.Fprintf(writer, "release: %s; accepted downtime: %t\n", result.ReleaseVersion, result.DowntimeAccepted)
	if len(result.CompletedPhases) != 0 {
		values := make([]string, len(result.CompletedPhases))
		for index, phase := range result.CompletedPhases {
			values[index] = string(phase)
		}
		fmt.Fprintf(writer, "completed: %s\n", strings.Join(values, ", "))
	}
	if result.NextPhase != "" {
		fmt.Fprintf(writer, "next: %s\n", result.NextPhase)
	}
	for _, action := range result.RequiresAction {
		fmt.Fprintf(writer, "action: %s\n", action)
	}
	return nil
}

func emitRecoveryResult(writer io.Writer, result lifecycle.V1MigrationRecoveryResult, jsonMode bool) error {
	if jsonMode {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	fmt.Fprintf(writer, "v1 migration %s (%s)\n", result.Status, result.MigrationID)
	fmt.Fprintf(writer, "action: %s\n", result.Action)
	if len(result.CompletedPhases) != 0 {
		values := make([]string, len(result.CompletedPhases))
		for index, phase := range result.CompletedPhases {
			values[index] = string(phase)
		}
		fmt.Fprintf(writer, "completed: %s\n", strings.Join(values, ", "))
	}
	for _, action := range result.RequiresAction {
		fmt.Fprintf(writer, "required: %s\n", action)
	}
	return nil
}

func printHelp(writer io.Writer) {
	fmt.Fprint(writer, `One-time, resumable vpnctl v1 to v2 gateway migration.

Usage:
  vpnctl-v1-migrate --bundle <local.bundle> --public-ip <IPv4> [--workspace <dir>]
    [--maintenance-root <dir>] [--node-cidr <CIDR>] [--ssh-port <port>]
    [--dry-run | --yes] [--json]
  vpnctl-v1-migrate --rollback --yes [--workspace <dir>]
    [--maintenance-root <dir>] [--json]
  vpnctl-v1-migrate --accept --yes [--workspace <dir>]
    [--maintenance-root <dir>] [--json]

Run --dry-run first. Applying requires --yes and intentionally stops/disables
the v1 WireGuard unit during the accepted maintenance window. After v2 network
activation, open a new SSH session, run the reported vpnctl confirm command,
then rerun this exact migration command to finish UFW and client validation.

Use --rollback --yes before acceptance to restore the retained v1 binary,
state, WireGuard unit, network, and known UFW behavior. After validating all
migrated clients, use --accept --yes to keep v2 and remove that rollback payload.
`)
}
