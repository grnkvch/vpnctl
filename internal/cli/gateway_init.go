package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/releasetrust"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

type gatewayInitializerAPI interface {
	Plan(context.Context, lifecycle.GatewayInitInput) (lifecycle.GatewayInitPlan, error)
	Apply(context.Context, lifecycle.GatewayInitPlan) (lifecycle.GatewayInitResult, error)
}

var (
	gatewayInitSystemPaths = store.DefaultPaths
	gatewayInitLookupEnv   = os.LookupEnv
	gatewayInitLoadRole    = loadSystemHostRole
	gatewayInitBuilder     = buildSystemGatewayInitializer
	gatewayInitOpenTTY     = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, err
	}
)

func isGatewayInitInvocation(args []string) bool {
	hasInit := false
	hasGateway := false
	for _, argument := range args {
		if argument == "init" {
			hasInit = true
		}
		if argument == "--gateway" || strings.HasPrefix(argument, "--gateway=") {
			hasGateway = true
		}
	}
	return hasInit && hasGateway
}

func executeGatewayInit(args []string, stdout, stderr io.Writer) int {
	parsed, help, err := parseGatewayInitArguments(args)
	if help {
		printGatewayInitHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "init failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitGatewayInitFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}

	paths := gatewayInitSystemPaths()
	role, err := gatewayInitLoadRole(paths)
	if err != nil {
		return emitGatewayInitFailure(emitter, output.CategoryValidation, "invalid_host_state", "vpnctl host state is invalid")
	}
	if role == RoleNode {
		return emitGatewayInitFailure(emitter, output.CategoryConflict, "init_conflict", "host is already initialized as node; role changes require an explicit migration or reinitialization")
	}
	initializer, err := gatewayInitBuilder(context.Background(), paths)
	if err != nil {
		category, code, message := classifyGatewayInitError(err)
		return emitGatewayInitFailure(emitter, category, code, message)
	}
	sshConnection, _ := gatewayInitLookupEnv("SSH_CONNECTION")
	var terminal PromptIO
	var closer io.Closer
	if !parsed.Yes && !parsed.DryRun {
		terminal, closer, _ = gatewayInitOpenTTY()
		if closer != nil {
			defer closer.Close()
		}
	}
	workflow := &gatewayInitWorkflow{
		initializer: initializer, terminal: terminal, yes: parsed.Yes, dryRun: parsed.DryRun,
		input: lifecycle.GatewayInitInput{
			PublicIPv4: parsed.PublicIPv4, ClientCIDR: parsed.ClientCIDR, NodeCIDR: parsed.NodeCIDR,
			ExternalInterface: parsed.ExternalInterface, ExplicitSSHPort: parsed.SSHPort.pointer(), SSHConnection: sshConnection,
		},
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "init.gateway", Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes, JSON: parsed.JSON,
	}, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyGatewayInitError(err)
		return emitGatewayInitFailure(emitter, category, code, message)
	}
	code, emitErr := emitter.Emit(outcome.Result)
	if emitErr != nil {
		fmt.Fprintf(stderr, "init failed: %v\n", emitErr)
		return ExitInternal
	}
	return code
}

type gatewayInitArguments struct {
	PublicIPv4        string
	ClientCIDR        string
	NodeCIDR          string
	ExternalInterface string
	SSHPort           optionalIntFlag
	DryRun            bool
	Yes               bool
	JSON              bool
}

type optionalIntFlag struct {
	set   bool
	value int
}

func (value *optionalIntFlag) String() string {
	if value == nil || !value.set {
		return ""
	}
	return strconv.Itoa(value.value)
}

func (value *optionalIntFlag) Set(raw string) error {
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("must be an integer")
	}
	value.set = true
	value.value = parsed
	return nil
}

func (value optionalIntFlag) pointer() *int {
	if !value.set {
		return nil
	}
	copy := value.value
	return &copy
}

func parseGatewayInitArguments(args []string) (gatewayInitArguments, bool, error) {
	parsed := gatewayInitArguments{}
	normalized := make([]string, 0, len(args))
	seenJSON := false
	seenInit := false
	for _, argument := range args {
		switch argument {
		case "--json":
			if seenJSON {
				return parsed, false, fmt.Errorf("--json may be supplied only once")
			}
			seenJSON = true
			parsed.JSON = true
		case "init":
			if seenInit {
				normalized = append(normalized, argument)
				continue
			}
			seenInit = true
		default:
			normalized = append(normalized, argument)
		}
	}
	if !seenInit {
		return parsed, false, fmt.Errorf("gateway init command is missing")
	}
	flags := flag.NewFlagSet("init --gateway", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	gateway := flags.Bool("gateway", false, "initialize gateway role")
	node := flags.Bool("node", false, "initialize node role")
	flags.StringVar(&parsed.PublicIPv4, "public-ip", "", "explicit public IPv4")
	flags.StringVar(&parsed.ClientCIDR, "client-cidr", "", "client IPv4 pool")
	flags.StringVar(&parsed.NodeCIDR, "node-cidr", "", "node IPv4 pool")
	flags.StringVar(&parsed.ExternalInterface, "external-interface", "", "external interface")
	flags.Var(&parsed.SSHPort, "ssh-port", "verified SSH listener port")
	flags.BoolVar(&parsed.DryRun, "dry-run", false, "show plan without mutation")
	flags.BoolVar(&parsed.Yes, "yes", false, "skip ordinary confirmation")
	var help bool
	flags.BoolVar(&help, "h", false, "show help")
	flags.BoolVar(&help, "help", false, "show help")
	if err := flags.Parse(normalized); err != nil {
		return parsed, false, err
	}
	if help {
		return parsed, true, nil
	}
	if flags.NArg() != 0 {
		return parsed, false, fmt.Errorf("unexpected init argument: %s", flags.Arg(0))
	}
	if !*gateway || *node {
		return parsed, false, fmt.Errorf("init requires exactly one of --gateway or --node")
	}
	return parsed, false, nil
}

type gatewayInitWorkflow struct {
	initializer gatewayInitializerAPI
	input       lifecycle.GatewayInitInput
	terminal    PromptIO
	yes         bool
	dryRun      bool
	plan        lifecycle.GatewayInitPlan
	planned     bool
}

func (workflow *gatewayInitWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	plan, err := workflow.initializer.Plan(ctx, workflow.input)
	if err != nil {
		return MutationPlan{}, err
	}
	if plan.ManagedSwap.Offered && !workflow.dryRun {
		accept := workflow.yes
		if !workflow.yes {
			if workflow.terminal == nil {
				return MutationPlan{}, fmt.Errorf("%w: managed swap confirmation requires a controlling TTY or --yes", ErrInteractionRefused)
			}
			step := InteractionStep{
				ID: StepManagedSwap, Phase: InteractionConsent, Prompt: PromptConfirm,
				Decision: PromptDecision{Action: "prompt", Channel: controllingTTYPath, Reads: 1},
			}
			answer, err := workflow.terminal.ReadVisible(step)
			if err != nil {
				return MutationPlan{}, fmt.Errorf("%w: %s: %v", ErrPromptInput, StepManagedSwap, err)
			}
			var valid bool
			accept, valid = parseConfirmation(answer)
			if !valid {
				return MutationPlan{}, fmt.Errorf("%w: %s accepts only y/yes/n/no", ErrPromptInput, StepManagedSwap)
			}
		}
		plan, err = plan.SelectManagedSwap(accept)
		if err != nil {
			return MutationPlan{}, err
		}
	}
	workflow.plan = plan
	workflow.planned = true
	return MutationPlan{Impact: ImpactAvailability, Result: gatewayInitOutput(plan, lifecycle.GatewayInitResult{}, false)}, nil
}

func (workflow *gatewayInitWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("gateway init was not planned")
	}
	result, err := workflow.initializer.Apply(ctx, workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: gatewayInitOutput(workflow.plan, result, true)}, nil
}

func gatewayInitOutput(plan lifecycle.GatewayInitPlan, applied lifecycle.GatewayInitResult, appliedResult bool) output.Result {
	changed := plan.Changed
	if appliedResult {
		changed = applied.Changed
	}
	disposition := plan.ManagedSwap.Disposition
	if disposition == "" {
		disposition = linuxplatform.ManagedSwapUnknownResources
	}
	result := output.NewResult("init.gateway", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": changed, "role": "gateway", "public_ipv4": plan.Network.PublicIPv4,
		"client_cidr": plan.Network.ClientCIDR, "node_cidr": plan.Network.NodeCIDR,
		"external_interface": plan.Network.ExternalInterface, "ssh_port": plan.SSH.Port,
		"handshake_host":  output.SafeObject{"list_version": plan.HandshakeHost.ListVersion, "candidate_id": plan.HandshakeHost.CandidateID, "hostname": plan.HandshakeHost.Hostname},
		"fixed_listeners": output.SafeList{"443/tcp", "8443/tcp", "51820/udp"},
		"managed_swap": output.SafeObject{
			"status": string(disposition), "offered": plan.ManagedSwap.Offered,
			"selected": plan.ManagedSwapSelected, "file_path": linuxplatform.ManagedSwapLogicalPath,
			"size_bytes": linuxplatform.ManagedSwapSizeBytes,
		},
	})
	if plan.HostID != "" {
		result.ResourceIDs["host_id"] = plan.HostID
	}
	if appliedResult && operations.ValidWatchdogID(applied.TransactionID) {
		result.ResourceIDs["transaction_id"] = applied.TransactionID
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "confirm_network", Message: "Confirm the network change from a newly established SSH session before the 120-second rollback deadline.",
			Command: "vpnctl confirm " + applied.TransactionID, ResourceIDs: map[string]string{"transaction_id": applied.TransactionID},
		})
	}
	if plan.ManagedSwap.Disposition == linuxplatform.ManagedSwapInsufficientDisk {
		result.Warnings = append(result.Warnings, output.Message{
			Code: "managed_swap_unavailable", Message: "Managed swap was not offered because creating 1 GB would leave less than 512 MB of free disk.",
		})
	} else if plan.ManagedSwap.Disposition == linuxplatform.ManagedSwapUnknownResources {
		result.Warnings = append(result.Warnings, output.Message{
			Code: "managed_swap_capacity_unknown", Message: "Managed swap was not offered because memory or free-disk capacity could not be verified.",
		})
	}
	return result
}

func buildSystemGatewayInitializer(ctx context.Context, paths store.Paths) (gatewayInitializerAPI, error) {
	discoverer, err := linuxplatform.NewDiscoverer(paths.Root)
	if err != nil {
		return nil, err
	}
	snapshot, err := discoverer.Discover(ctx)
	if err != nil {
		return nil, err
	}
	release, err := buildSystemInitRelease(paths, snapshot)
	if err != nil {
		return nil, err
	}
	return controller.NewSystemGatewayInitializer(paths, snapshot, release, linuxplatform.DefaultVPNCTLBinaryPath)
}

func buildSystemInitRelease(paths store.Paths, snapshot linuxplatform.HostSnapshot) (lifecycle.InitReleaseSource, error) {
	publicKey, err := releasetrust.PublicKey()
	if err != nil {
		return nil, err
	}
	installer, err := lifecycle.NewReleaseBundleInstaller(paths.Root, publicKey, lifecycle.ReleasePlatform{
		OperatingSystem: snapshot.OS.ID, Version: snapshot.OS.VersionID, Architecture: snapshot.Architecture,
	})
	if err != nil {
		return nil, err
	}
	bundlePath := filepath.Join(paths.Root, strings.TrimPrefix(lifecycle.ReleaseInstalledBundlePath, "/"))
	return lifecycle.NewLocalInitReleaseSource(installer, bundlePath)
}

func developmentComponentManifest() model.ComponentManifest {
	return model.ComponentManifest{
		SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: version,
		ControlProtocols: []string{"1.0"}, StateSchemaMinimum: model.StateSchemaVersion, StateSchemaMaximum: model.StateSchemaVersion,
		TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1, MigrationReversible: true,
		Components: []model.ComponentPin{{
			Name: "vpnctl", Version: version, Source: "installed:vpnctl", Bundled: false, Capabilities: []string{"cli", "controller"},
		}, {
			Name: transport.RestrictedProviderName, Version: transport.RestrictedProviderVersion, Source: "vpnctl-release-bundle", Bundled: true,
			SHA256:       transport.RestrictedProviderSHA256,
			Capabilities: []string{"tun-routing", "redir-host-split-dns", "shadowsocks-2022-blake3-aes-256-gcm", "shadowtls-v3-strict", "uot-v2"},
		}, {
			Name: tunnel.FRPProviderName, Version: tunnel.FRPProviderVersion, Source: "vpnctl-release-bundle", Bundled: true,
			SHA256:       tunnel.FRPProviderSHA256,
			Capabilities: []string{"dynamic-reload", "http-plugin-authorization", "tcp-mux", "tls-server-verification"},
		}},
	}
}

func classifyGatewayInitError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, lifecycle.ErrGatewayRoleConflict), errors.Is(err, lifecycle.ErrGatewayInitConflict),
		errors.Is(err, lifecycle.ErrGatewayLayoutConflict), errors.Is(err, linuxplatform.ErrGatewayPreflightConflict),
		errors.Is(err, linuxplatform.ErrManagedSwapConflict):
		return output.CategoryConflict, "init_conflict", err.Error()
	case errors.Is(err, linuxplatform.ErrUnsupportedHost), errors.Is(err, linuxplatform.ErrInvalidGatewayNetwork),
		errors.Is(err, linuxplatform.ErrSSHPortUnverified), errors.Is(err, ErrInteractionRefused), errors.Is(err, ErrConsentDeclined),
		errors.Is(err, ErrPromptInput), errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags),
		errors.Is(err, linuxplatform.ErrManagedSwapPlan):
		return output.CategoryValidation, "init_validation", err.Error()
	case errors.Is(err, transport.ErrNoHandshakeHostCandidate):
		return output.CategoryUnavailable, "handshake_host_unavailable", "no signed handshake-host candidate passed reachability, TLS 1.3, certificate, and latency validation"
	default:
		return output.CategoryInternal, "init_internal_error", "vpnctl could not initialize the gateway"
	}
}

func emitGatewayInitFailure(emitter *ResultEmitter, category output.ExitCategory, warningCode, warningMessage string) int {
	result := output.NewResult("init.gateway", output.StatusFailed, category, output.SafeObject{"changed": false, "role": "gateway"})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func singleLineGatewayInitMessage(message string) string {
	message = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ", "\x00", " ").Replace(message))
	if message == "" {
		return "vpnctl could not initialize the gateway"
	}
	if len(message) > output.MaximumSafeString {
		message = message[:output.MaximumSafeString]
	}
	return message
}

func printGatewayInitHelp(writer io.Writer) {
	fmt.Fprint(writer, `Initialize this dedicated host as a vpnctl gateway.

Usage:
  vpnctl init --gateway --public-ip <IPv4> [--client-cidr <CIDR>] [--node-cidr <CIDR>]
              [--external-interface <name>] [--ssh-port <port>] [--dry-run] [--yes] [--json]

On a low-memory gateway, the plan may offer a managed 1 GB swap file. Declining
that optional prompt continues initialization; --yes accepts the offer.
`)
}
