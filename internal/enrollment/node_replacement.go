package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

var ErrNodeConfigurationReplacementPending = errors.New("node configuration replacement is pending compensation")

// NodeConfigurationReplacementHost is the transactional host surface used to
// replace an already active node generation. RoleSystemdInstaller implements
// it with exact file snapshots, ordered unit restarts, and local rollback on
// every failed host mutation.
type NodeConfigurationReplacementHost interface {
	PlanRepair(context.Context, linuxplatform.RoleRepairRequest) (*linuxplatform.RoleRepairPlan, error)
	ApplyRepair(context.Context, *linuxplatform.RoleRepairPlan) (linuxplatform.RoleRepairResult, error)
}

// PreparedNodeConfigurationReplacement is an opaque, single-use host plan.
// It retains a private copy of the generation-bound configuration until apply
// so readiness can be checked against the same bytes that passed preflight.
type PreparedNodeConfigurationReplacement struct {
	mu            sync.Mutex
	configuration NodeConfiguration
	plan          *linuxplatform.RoleRepairPlan
	consumed      bool
}

// NodeConfigurationReplacer updates all node service configs as one role
// transaction and restarts the fail-closed stack in dependency order. It does
// not change authoritative state; the surrounding transport workflow owns the
// state CAS and compensates by activating the previously rendered generation.
type NodeConfigurationReplacer struct {
	host      NodeConfigurationReplacementHost
	readiness NodeConfigurationReadinessChecker
}

func NewNodeConfigurationReplacer(
	host NodeConfigurationReplacementHost,
	readiness NodeConfigurationReadinessChecker,
) (*NodeConfigurationReplacer, error) {
	if host == nil || readiness == nil {
		return nil, fmt.Errorf("node configuration replacement dependencies are incomplete")
	}
	return &NodeConfigurationReplacer{host: host, readiness: readiness}, nil
}

// Prepare performs the complete read-only host preflight. The returned plan
// becomes stale if any selected file or unit runtime changes before Activate.
func (replacer *NodeConfigurationReplacer) Prepare(
	ctx context.Context,
	configuration NodeConfiguration,
) (*PreparedNodeConfigurationReplacement, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if replacer == nil || replacer.host == nil || replacer.readiness == nil {
		return nil, fmt.Errorf("node configuration replacer is incomplete")
	}
	if err := validateNodeConfigurationForActivation(configuration); err != nil {
		return nil, err
	}
	request, err := nodeConfigurationReplacementRequest(configuration)
	if err != nil {
		return nil, err
	}
	defer wipeNodeConfigurationReplacementRequest(&request)
	plan, err := replacer.host.PlanRepair(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("preflight node service generation replacement: %w", err)
	}
	return &PreparedNodeConfigurationReplacement{
		configuration: cloneNodeConfiguration(configuration),
		plan:          plan,
	}, nil
}

// Activate consumes a prepared plan on every path. A host-level failure is
// already rolled back by RoleSystemdInstaller. A later readiness failure means
// the new bytes are active and requires the surrounding workflow to reactivate
// its exact previous candidate before cleaning the failed target.
func (replacer *NodeConfigurationReplacer) Activate(
	ctx context.Context,
	prepared *PreparedNodeConfigurationReplacement,
) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if replacer == nil || replacer.host == nil || replacer.readiness == nil || prepared == nil {
		return fmt.Errorf("node configuration replacement is incomplete")
	}
	prepared.mu.Lock()
	if prepared.consumed || prepared.plan == nil {
		prepared.mu.Unlock()
		return fmt.Errorf("node configuration replacement plan is already consumed")
	}
	prepared.consumed = true
	plan := prepared.plan
	configuration := prepared.configuration
	prepared.plan = nil
	prepared.configuration = NodeConfiguration{}
	prepared.mu.Unlock()
	defer destroyNodeConfiguration(&configuration)

	if _, err := replacer.host.ApplyRepair(ctx, plan); err != nil {
		return fmt.Errorf("replace node service generation: %w", err)
	}
	if err := replacer.readiness.Check(ctx, configuration); err != nil {
		return errors.Join(
			ErrNodeConfigurationReplacementPending,
			fmt.Errorf("verify replaced node service generation: %w", err),
		)
	}
	return nil
}

// Replace is the compensation path used for an already rendered candidate:
// preflight is repeated against the current host state and then consumed
// immediately. It is safe for restoring a previous generation after target
// activation because the same transactional host boundary is used both ways.
func (replacer *NodeConfigurationReplacer) Replace(ctx context.Context, configuration NodeConfiguration) error {
	prepared, err := replacer.Prepare(ctx, configuration)
	if err != nil {
		return err
	}
	return replacer.Activate(ctx, prepared)
}

// Destroy releases a prepared plan without mutating the host. It is
// idempotent and is used when validation/testing fails before activation.
func (prepared *PreparedNodeConfigurationReplacement) Destroy() {
	if prepared == nil {
		return
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.plan != nil {
		prepared.plan.Destroy()
	}
	destroyNodeConfiguration(&prepared.configuration)
	prepared.plan = nil
	prepared.configuration = NodeConfiguration{}
	prepared.consumed = true
}

func nodeConfigurationReplacementRequest(configuration NodeConfiguration) (linuxplatform.RoleRepairRequest, error) {
	if err := validateNodeConfigurationForActivation(configuration); err != nil {
		return linuxplatform.RoleRepairRequest{}, err
	}
	configs := configuration.ConfigFiles()
	request := linuxplatform.RoleRepairRequest{
		Role:         model.RoleNode,
		Resources:    make([]linuxplatform.RoleRepairResource, 0, len(configs)),
		RestartUnits: append([]string(nil), nodeActivationOrder...),
	}
	for _, config := range configs {
		digest := sha256.Sum256(config.Content)
		request.Resources = append(request.Resources, linuxplatform.RoleRepairResource{
			Kind:          linuxplatform.RoleRepairConfig,
			Name:          config.Name,
			Content:       config.Content,
			ContentSHA256: hex.EncodeToString(digest[:]),
		})
	}
	return request, nil
}

func cloneNodeConfiguration(configuration NodeConfiguration) NodeConfiguration {
	configuration.configs = configuration.ConfigFiles()
	return configuration
}

func destroyNodeConfiguration(configuration *NodeConfiguration) {
	if configuration == nil {
		return
	}
	for index := range configuration.configs {
		clear(configuration.configs[index].Content)
		configuration.configs[index].Content = nil
	}
	*configuration = NodeConfiguration{}
}

func wipeNodeConfigurationReplacementRequest(request *linuxplatform.RoleRepairRequest) {
	if request == nil {
		return
	}
	for index := range request.Resources {
		clear(request.Resources[index].Content)
		request.Resources[index].Content = nil
	}
	*request = linuxplatform.RoleRepairRequest{}
}
