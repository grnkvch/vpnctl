package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const (
	GatewayRepairOperation         = "repair.gateway"
	GatewayRepairPlanSchemaVersion = 1
	gatewayRepairApplyTimeout      = 45 * time.Second
)

var (
	ErrGatewayRepairInvalid        = errors.New("gateway repair plan is invalid")
	ErrGatewayRepairStale          = errors.New("gateway repair plan is stale")
	ErrGatewayRepairWatchdogActive = errors.New("another gateway network watchdog transaction is pending")
	ErrGatewayRepairNetworkState   = errors.New("gateway network differs from its pre-vpnctl snapshot")
)

type GatewayRepairArtifact struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// GatewayRepairPlan binds operator consent to the exact committed generation
// and rendered artifact hashes. It never contains rendered configuration or
// credential bytes.
type GatewayRepairPlan struct {
	SchemaVersion             int                     `json:"schema_version"`
	Generation                uint64                  `json:"generation"`
	HostID                    string                  `json:"host_id"`
	TunnelActive              bool                    `json:"tunnel_active"`
	NetworkActivationRequired bool                    `json:"network_activation_required"`
	Services                  []string                `json:"services"`
	Artifacts                 []GatewayRepairArtifact `json:"artifacts"`
	FirewallSHA256            string                  `json:"firewall_sha256,omitempty"`
	InitialNetworkSHA256      string                  `json:"initial_network_sha256,omitempty"`
}

type GatewayRepairPayload struct {
	Plan GatewayRepairPlan `json:"plan"`
}

type GatewayRepairData struct {
	Changed                   bool   `json:"changed"`
	NetworkActivationRequired bool   `json:"network_activation_required"`
	TransactionID             string `json:"transaction_id,omitempty"`
}

func (plan GatewayRepairPlan) Validate() error {
	if plan.SchemaVersion != GatewayRepairPlanSchemaVersion || plan.Generation == 0 || plan.HostID == "" {
		return ErrGatewayRepairInvalid
	}
	wantServices := linuxplatform.RoleUnitNames(model.RoleGateway)
	sort.Strings(wantServices)
	if !reflect.DeepEqual(plan.Services, wantServices) {
		return ErrGatewayRepairInvalid
	}
	wantArtifacts := make(map[string]struct{}, len(wantServices)+12)
	for _, name := range wantServices {
		wantArtifacts[gatewayRepairArtifactKey("unit", name)] = struct{}{}
	}
	configNames := append([]string{"bootstrap.conf", "gateway-controller.ready", routing.GatewayDNSConfigFileName, routing.GatewayDNSReadyFileName}, transport.GatewayListenerFileNames()...)
	if plan.TunnelActive {
		configNames = append(configNames, tunnel.FRPServerConfigFileName, tunnel.FRPServerReadyFileName, tunnel.FRPServerCertificateName, tunnel.FRPServerPrivateKeyName)
	}
	for _, name := range configNames {
		wantArtifacts[gatewayRepairArtifactKey("config", name)] = struct{}{}
	}
	if plan.NetworkActivationRequired {
		wantArtifacts[gatewayRepairArtifactKey("watchdog_unit", linuxplatform.WatchdogServiceUnitName)] = struct{}{}
		wantArtifacts[gatewayRepairArtifactKey("watchdog_unit", linuxplatform.WatchdogTimerUnitName)] = struct{}{}
		if !validGatewayRepairHash(plan.FirewallSHA256) || !validGatewayRepairHash(plan.InitialNetworkSHA256) {
			return ErrGatewayRepairInvalid
		}
	} else if plan.FirewallSHA256 != "" || plan.InitialNetworkSHA256 != "" {
		return ErrGatewayRepairInvalid
	}
	if len(plan.Artifacts) != len(wantArtifacts) {
		return ErrGatewayRepairInvalid
	}
	previous := ""
	for _, artifact := range plan.Artifacts {
		key := gatewayRepairArtifactKey(artifact.Kind, artifact.Name)
		if _, ok := wantArtifacts[key]; !ok || !validGatewayRepairHash(artifact.SHA256) || key <= previous {
			return ErrGatewayRepairInvalid
		}
		delete(wantArtifacts, key)
		previous = key
	}
	if len(wantArtifacts) != 0 {
		return ErrGatewayRepairInvalid
	}
	return nil
}

type gatewayRepairRoleCandidate interface {
	Generation() uint64
	TunnelActive() bool
	RoleRequest() linuxplatform.RoleInstallationRequest
	Destroy()
}

type gatewayRepairRoleRuntime interface {
	Compile(context.Context, model.State) (gatewayRepairRoleCandidate, error)
	Apply(context.Context, gatewayRepairRoleCandidate) error
}

type gatewayRepairConvergence interface {
	PublishActiveGatewayGeneration(context.Context, uint64, linuxplatform.RoleInstallationRequest) error
	PublishInactiveGatewayGeneration(context.Context, uint64, linuxplatform.RoleInstallationRequest) error
}

type gatewayRepairWatchdogUnits interface {
	Plan(string) (linuxplatform.WatchdogUnitInstallationPlan, error)
	Apply(context.Context, linuxplatform.WatchdogUnitInstallationPlan) ([]string, error)
}

type gatewayRepairWatchdog interface {
	Arm(context.Context, operations.WatchdogArmInput) (operations.WatchdogTransaction, error)
	MarkActivated(context.Context, string) error
	RollbackNow(context.Context, string) error
}

type gatewayRepairWatchdogStore interface {
	TransactionIDs() ([]string, error)
	Status(string) (operations.WatchdogTransactionStatus, error)
	InitialNetworkSnapshot() (linuxplatform.NetworkSnapshot, error)
}

type gatewayRepairNetwork interface {
	ActivateGateway(context.Context, linuxplatform.GatewayFirewallArtifact) error
}

type GatewayRepairDispatcher struct {
	roles         gatewayRepairRoleRuntime
	convergence   gatewayRepairConvergence
	watchdogUnits gatewayRepairWatchdogUnits
	watchdog      gatewayRepairWatchdog
	watchdogStore gatewayRepairWatchdogStore
	network       gatewayRepairNetwork
	binaryPath    string
}

func newGatewayRepairDispatcher(
	roles gatewayRepairRoleRuntime,
	convergence gatewayRepairConvergence,
	watchdogUnits gatewayRepairWatchdogUnits,
	watchdog gatewayRepairWatchdog,
	watchdogStore gatewayRepairWatchdogStore,
	network gatewayRepairNetwork,
	binaryPath string,
) (*GatewayRepairDispatcher, error) {
	if roles == nil || convergence == nil || watchdogUnits == nil || watchdog == nil || watchdogStore == nil || network == nil || binaryPath == "" {
		return nil, fmt.Errorf("gateway repair dependencies are incomplete")
	}
	return &GatewayRepairDispatcher{
		roles: roles, convergence: convergence, watchdogUnits: watchdogUnits,
		watchdog: watchdog, watchdogStore: watchdogStore, network: network, binaryPath: binaryPath,
	}, nil
}

func NewSystemGatewayRepairDispatcher(paths store.Paths) (*GatewayRepairDispatcher, error) {
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, err
	}
	roles, err := enrollment.NewSystemGatewayRepairRuntime(paths, secrets)
	if err != nil {
		return nil, err
	}
	convergenceStore, err := operations.NewFileConvergenceSnapshotStore(paths.ConvergenceFile)
	if err != nil {
		return nil, err
	}
	convergence, err := operations.NewGatewayServiceConvergencePublisher(convergenceStore)
	if err != nil {
		return nil, err
	}
	watchdogUnits, err := linuxplatform.NewWatchdogUnitInstaller(paths.Root, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, err
	}
	watchdog, err := operations.NewSystemWatchdog(paths)
	if err != nil {
		return nil, err
	}
	watchdogStore, err := operations.NewWatchdogStore(paths)
	if err != nil {
		return nil, err
	}
	return newGatewayRepairDispatcher(
		systemGatewayRepairRoleRuntime{runtime: roles}, convergence, watchdogUnits, watchdog,
		watchdogStore, linuxplatform.NewOSNetworkManager(), linuxplatform.DefaultVPNCTLBinaryPath,
	)
}

// Plan is read-only. The compiled candidate is destroyed after its hashes are
// retained, and no role, convergence, watchdog, or network mutation is called.
func (dispatcher *GatewayRepairDispatcher) Plan(ctx context.Context, state model.State) (GatewayRepairPlan, error) {
	plan, candidate, _, _, err := dispatcher.compile(ctx, state)
	if candidate != nil {
		candidate.Destroy()
	}
	return plan, err
}

func (dispatcher *GatewayRepairDispatcher) Prepare(ctx context.Context, state model.State, operation string, payload json.RawMessage) (PreparedMutation, error) {
	if ctx == nil || dispatcher == nil || operation != GatewayRepairOperation {
		return PreparedMutation{}, ErrGatewayRepairInvalid
	}
	var request GatewayRepairPayload
	if err := decodeGatewayRepairPayload(payload, &request); err != nil {
		return PreparedMutation{}, err
	}
	if err := request.Plan.Validate(); err != nil {
		return PreparedMutation{}, err
	}
	fresh, candidate, watchdogPlan, initialNetwork, err := dispatcher.compile(ctx, state)
	if err != nil {
		if candidate != nil {
			candidate.Destroy()
		}
		return PreparedMutation{}, err
	}
	if !reflect.DeepEqual(fresh, request.Plan) {
		candidate.Destroy()
		return PreparedMutation{}, ErrGatewayRepairStale
	}
	var result GatewayRepairData
	return PreparedMutation{
		Candidate:   state,
		Changed:     true,
		RuntimeOnly: true,
		Timeout:     gatewayRepairApplyTimeout,
		Apply: func(applyContext context.Context) error {
			defer candidate.Destroy()
			result, err = dispatcher.apply(applyContext, state, candidate, watchdogPlan, initialNetwork)
			return err
		},
		Rollback: func(context.Context) error { return nil },
		Result: func() json.RawMessage {
			encoded, _ := json.Marshal(result)
			return encoded
		},
	}, nil
}

func (dispatcher *GatewayRepairDispatcher) compile(
	ctx context.Context,
	state model.State,
) (GatewayRepairPlan, gatewayRepairRoleCandidate, linuxplatform.WatchdogUnitInstallationPlan, linuxplatform.NetworkSnapshot, error) {
	if ctx == nil || dispatcher == nil || dispatcher.roles == nil || dispatcher.watchdogStore == nil {
		return GatewayRepairPlan{}, nil, linuxplatform.WatchdogUnitInstallationPlan{}, linuxplatform.NetworkSnapshot{}, ErrGatewayRepairInvalid
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return GatewayRepairPlan{}, nil, linuxplatform.WatchdogUnitInstallationPlan{}, linuxplatform.NetworkSnapshot{}, errors.Join(ErrGatewayRepairInvalid, err)
	}
	candidate, err := dispatcher.roles.Compile(ctx, state)
	if err != nil {
		return GatewayRepairPlan{}, nil, linuxplatform.WatchdogUnitInstallationPlan{}, linuxplatform.NetworkSnapshot{}, err
	}
	fail := func(err error) (GatewayRepairPlan, gatewayRepairRoleCandidate, linuxplatform.WatchdogUnitInstallationPlan, linuxplatform.NetworkSnapshot, error) {
		candidate.Destroy()
		return GatewayRepairPlan{}, nil, linuxplatform.WatchdogUnitInstallationPlan{}, linuxplatform.NetworkSnapshot{}, err
	}
	if candidate.Generation() != state.Generation {
		return fail(ErrGatewayRepairInvalid)
	}
	request := candidate.RoleRequest()
	defer clearGatewayRepairRoleRequest(&request)
	services := linuxplatform.RoleUnitNames(model.RoleGateway)
	sort.Strings(services)
	artifacts := gatewayRepairRoleArtifacts(request)
	networkRequired, initialNetwork, err := dispatcher.networkRequirement()
	if err != nil {
		return fail(err)
	}
	plan := GatewayRepairPlan{
		SchemaVersion: GatewayRepairPlanSchemaVersion, Generation: state.Generation, HostID: state.Host.ID,
		TunnelActive: candidate.TunnelActive(), NetworkActivationRequired: networkRequired,
		Services: services, Artifacts: artifacts,
	}
	var watchdogPlan linuxplatform.WatchdogUnitInstallationPlan
	if networkRequired {
		watchdogPlan, err = dispatcher.watchdogUnits.Plan(dispatcher.binaryPath)
		if err != nil {
			return fail(err)
		}
		for _, unit := range watchdogPlan.Units {
			plan.Artifacts = append(plan.Artifacts, GatewayRepairArtifact{Kind: "watchdog_unit", Name: unit.Name, SHA256: gatewayRepairHash(unit.Content)})
		}
		firewall, err := gatewayRepairFirewall(state)
		if err != nil {
			return fail(err)
		}
		plan.FirewallSHA256 = gatewayRepairHash(firewall.Definition())
		plan.InitialNetworkSHA256 = gatewayRepairNetworkHash(initialNetwork)
	}
	sortGatewayRepairArtifacts(plan.Artifacts)
	if err := plan.Validate(); err != nil {
		return fail(err)
	}
	return plan, candidate, watchdogPlan, initialNetwork, nil
}

func (dispatcher *GatewayRepairDispatcher) networkRequirement() (bool, linuxplatform.NetworkSnapshot, error) {
	ids, err := dispatcher.watchdogStore.TransactionIDs()
	if err != nil {
		return false, linuxplatform.NetworkSnapshot{}, err
	}
	if len(ids) == 0 {
		return false, linuxplatform.NetworkSnapshot{}, fmt.Errorf("%w: retained initialization watchdog snapshot is missing", ErrGatewayRepairInvalid)
	}
	committed := false
	for _, id := range ids {
		status, err := dispatcher.watchdogStore.Status(id)
		if err != nil {
			return false, linuxplatform.NetworkSnapshot{}, err
		}
		switch status {
		case operations.WatchdogStatusArmed, operations.WatchdogStatusActive:
			return false, linuxplatform.NetworkSnapshot{}, ErrGatewayRepairWatchdogActive
		case operations.WatchdogStatusCommitted:
			committed = true
		case operations.WatchdogStatusRolledBack:
		default:
			return false, linuxplatform.NetworkSnapshot{}, ErrGatewayRepairInvalid
		}
	}
	if committed {
		return false, linuxplatform.NetworkSnapshot{}, nil
	}
	initial, err := dispatcher.watchdogStore.InitialNetworkSnapshot()
	if err != nil {
		return false, linuxplatform.NetworkSnapshot{}, err
	}
	if err := initial.Validate(); err != nil {
		return false, linuxplatform.NetworkSnapshot{}, err
	}
	return true, initial, nil
}

func (dispatcher *GatewayRepairDispatcher) apply(
	ctx context.Context,
	state model.State,
	candidate gatewayRepairRoleCandidate,
	watchdogPlan linuxplatform.WatchdogUnitInstallationPlan,
	initialNetwork linuxplatform.NetworkSnapshot,
) (GatewayRepairData, error) {
	result := GatewayRepairData{Changed: true}
	if candidate == nil || candidate.Generation() != state.Generation {
		return result, ErrGatewayRepairStale
	}
	if len(watchdogPlan.Units) != 0 {
		if _, err := dispatcher.watchdogUnits.Apply(ctx, watchdogPlan); err != nil {
			return result, fmt.Errorf("repair gateway watchdog units: %w", err)
		}
	}
	if err := dispatcher.roles.Apply(ctx, candidate); err != nil {
		return result, fmt.Errorf("repair committed gateway services: %w", err)
	}
	request := candidate.RoleRequest()
	defer clearGatewayRepairRoleRequest(&request)
	var err error
	if candidate.TunnelActive() {
		err = dispatcher.convergence.PublishActiveGatewayGeneration(ctx, state.Generation, request)
	} else {
		err = dispatcher.convergence.PublishInactiveGatewayGeneration(ctx, state.Generation, request)
	}
	if err != nil {
		return result, fmt.Errorf("publish repaired gateway convergence: %w", err)
	}
	if len(watchdogPlan.Units) == 0 {
		return result, nil
	}
	result.NetworkActivationRequired = true
	transaction, err := dispatcher.watchdog.Arm(ctx, operations.WatchdogArmInput{
		AllowedSSHPort: state.Host.SSHPort,
		NetworkScope:   linuxplatform.GatewayInitNetworkScope(),
	})
	if err != nil {
		return result, fmt.Errorf("arm gateway repair watchdog: %w", err)
	}
	failNetwork := func(cause error) (GatewayRepairData, error) {
		rollbackContext, cancel := context.WithTimeout(context.Background(), control.LocalTimeout)
		defer cancel()
		return result, errors.Join(cause, dispatcher.watchdog.RollbackNow(rollbackContext, transaction.ID))
	}
	if !reflect.DeepEqual(transaction.Network, initialNetwork) {
		return failNetwork(ErrGatewayRepairNetworkState)
	}
	firewall, err := gatewayRepairFirewall(state)
	if err != nil {
		return failNetwork(err)
	}
	if err := dispatcher.network.ActivateGateway(ctx, firewall); err != nil {
		return failNetwork(fmt.Errorf("activate repaired gateway network: %w", err))
	}
	if err := dispatcher.watchdog.MarkActivated(ctx, transaction.ID); err != nil {
		return failNetwork(fmt.Errorf("mark repaired gateway network active: %w", err))
	}
	result.TransactionID = transaction.ID
	return result, nil
}

func gatewayRepairFirewall(state model.State) (linuxplatform.GatewayFirewallArtifact, error) {
	return lifecycle.RenderGatewayIdentityFirewall(state, lifecycle.GatewayIdentityFirewallServices{
		ClientTCPPorts: []int{routing.GatewayDNSPort}, ClientUDPPorts: []int{routing.GatewayDNSPort},
		NodeTCPPorts: []int{routing.GatewayDNSPort, control.RPCControlTCPPort, tunnel.FRPServerPort}, NodeUDPPorts: []int{routing.GatewayDNSPort},
	})
}

func gatewayRepairRoleArtifacts(request linuxplatform.RoleInstallationRequest) []GatewayRepairArtifact {
	result := make([]GatewayRepairArtifact, 0, len(request.Units)+len(request.Configs))
	for _, unit := range request.Units {
		result = append(result, GatewayRepairArtifact{Kind: "unit", Name: unit.Name, SHA256: gatewayRepairHash(unit.Content)})
	}
	for _, config := range request.Configs {
		result = append(result, GatewayRepairArtifact{Kind: "config", Name: config.Name, SHA256: gatewayRepairHash(config.Content)})
	}
	sortGatewayRepairArtifacts(result)
	return result
}

func sortGatewayRepairArtifacts(artifacts []GatewayRepairArtifact) {
	sort.Slice(artifacts, func(left, right int) bool {
		return gatewayRepairArtifactKey(artifacts[left].Kind, artifacts[left].Name) < gatewayRepairArtifactKey(artifacts[right].Kind, artifacts[right].Name)
	})
}

func gatewayRepairArtifactKey(kind, name string) string { return kind + "\x00" + name }

func gatewayRepairHash(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func gatewayRepairNetworkHash(snapshot linuxplatform.NetworkSnapshot) string {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return ""
	}
	return gatewayRepairHash(encoded)
}

func validGatewayRepairHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == hex.EncodeToString(decoded)
}

func decodeGatewayRepairPayload(payload json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode gateway repair mutation: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decode gateway repair mutation: trailing data")
	}
	return nil
}

func clearGatewayRepairRoleRequest(request *linuxplatform.RoleInstallationRequest) {
	if request == nil {
		return
	}
	for index := range request.Units {
		clear(request.Units[index].Content)
	}
	for index := range request.Configs {
		clear(request.Configs[index].Content)
	}
	*request = linuxplatform.RoleInstallationRequest{}
}

type systemGatewayRepairRoleRuntime struct {
	runtime *enrollment.SystemGatewayRepairRuntime
}

func (runtime systemGatewayRepairRoleRuntime) Compile(ctx context.Context, state model.State) (gatewayRepairRoleCandidate, error) {
	return runtime.runtime.Compile(ctx, state)
}

func (runtime systemGatewayRepairRoleRuntime) Apply(ctx context.Context, candidate gatewayRepairRoleCandidate) error {
	concrete, ok := candidate.(*enrollment.SystemGatewayRepairCandidate)
	if !ok {
		return ErrGatewayRepairInvalid
	}
	return runtime.runtime.Apply(ctx, concrete)
}

var _ PreparedMutationDispatcher = (*GatewayRepairDispatcher)(nil)
