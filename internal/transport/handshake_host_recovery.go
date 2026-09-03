package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

var (
	ErrHandshakeHostRecoveryStale           = errors.New("handshake-host recovery plan is stale")
	ErrHandshakeHostRecoveryUnauthorized    = errors.New("gateway did not authorize the requested handshake host")
	ErrHandshakeHostRecoveryCommitUncertain = errors.New("handshake-host recovery state commit is uncertain")
)

type HandshakeHostRecoveryPlan struct {
	NodeID                  string
	Current                 model.HandshakeHost
	Candidate               model.HandshakeHost
	ExpectedStateGeneration uint64
	NextStateGeneration     uint64
	CredentialGeneration    uint64

	candidate       model.State
	beforeRaw       []byte
	oldCandidate    Candidate
	targetCandidate Candidate
}

type HandshakeHostRecoveryResult struct {
	NodeID               string
	Active               model.HandshakeHost
	StateGeneration      uint64
	CredentialGeneration uint64
	Health               Health
}

type NodeHandshakeHostRecovery struct {
	state    HandshakeHostStateStore
	provider Provider
	limits   SwitchLimits
	now      func() time.Time
}

func NewNodeHandshakeHostRecovery(state HandshakeHostStateStore, provider Provider, limits SwitchLimits, now func() time.Time) (*NodeHandshakeHostRecovery, error) {
	if state == nil || nilProvider(provider) {
		return nil, fmt.Errorf("handshake-host recovery dependencies are incomplete")
	}
	if provider.Kind() != model.TransportRestricted {
		return nil, fmt.Errorf("handshake-host recovery requires the restricted provider")
	}
	normalized, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &NodeHandshakeHostRecovery{state: state, provider: provider, limits: normalized, now: now}, nil
}

// Plan is local and render-only. It neither calls the gateway control API nor
// changes the active provider; the later isolated four-path probe proves that
// the already-prepared gateway accepts this node's existing credentials
// through exactly the operator-supplied host.
func (recovery *NodeHandshakeHostRecovery) Plan(ctx context.Context, hostname string) (HandshakeHostRecoveryPlan, error) {
	if ctx == nil {
		return HandshakeHostRecoveryPlan{}, fmt.Errorf("context is required")
	}
	state, err := recovery.loadNodeState()
	if err != nil {
		return HandshakeHostRecoveryPlan{}, err
	}
	node, restricted, err := activeRestrictedNode(state)
	if err != nil {
		return HandshakeHostRecoveryPlan{}, err
	}
	explicit, err := explicitHandshakeHostCandidate(hostname)
	if err != nil {
		return HandshakeHostRecoveryPlan{}, err
	}
	if explicit.Hostname == state.HandshakeHost.Hostname {
		return HandshakeHostRecoveryPlan{}, fmt.Errorf("requested handshake host is already active locally")
	}
	selected := model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: state.HandshakeHost.ListVersion,
		CandidateID: explicit.ID, Hostname: explicit.Hostname, SelectedAt: recovery.now().UTC(),
	}
	overallContext, cancelOverall := context.WithTimeout(ctx, recovery.limits.Total)
	defer cancelOverall()
	oldCandidate, err := switchCandidate(overallContext, recovery.limits.Step, recovery.provider, restricted)
	if err != nil {
		return HandshakeHostRecoveryPlan{}, fmt.Errorf("render current restricted recovery candidate: %w", err)
	}
	targetTransport := restricted
	targetTransport.HandshakeHost = selected.Hostname
	targetCandidate, err := runTransportTestStep(overallContext, recovery.limits.Step, func(stepContext context.Context) (Candidate, error) {
		return recovery.provider.Render(stepContext, RenderRequest{Transport: targetTransport})
	})
	if err != nil {
		return HandshakeHostRecoveryPlan{}, fmt.Errorf("render requested handshake-host recovery candidate: %w", err)
	}
	if nilCandidate(targetCandidate) {
		return HandshakeHostRecoveryPlan{}, fmt.Errorf("render requested handshake-host recovery candidate: provider returned nil candidate")
	}
	descriptor := targetCandidate.Descriptor()
	if err := descriptor.Validate(); err != nil {
		return HandshakeHostRecoveryPlan{}, fmt.Errorf("validate requested handshake-host recovery candidate: %w", err)
	}
	identity := IdentityFromTransport(restricted)
	if descriptor.OwnerKind != identity.OwnerKind || descriptor.OwnerID != identity.OwnerID || descriptor.CredentialGeneration != identity.CredentialGeneration || descriptor.Kind != model.TransportRestricted {
		return HandshakeHostRecoveryPlan{}, fmt.Errorf("requested handshake-host recovery candidate changed node identity or credentials")
	}
	if descriptor.ConfigHash == restricted.ConfigHash {
		return HandshakeHostRecoveryPlan{}, fmt.Errorf("requested handshake-host recovery candidate did not change restricted configuration")
	}
	candidate := state
	nextGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return HandshakeHostRecoveryPlan{}, err
	}
	candidate.Generation = nextGeneration
	candidate.Transports = append([]model.Transport(nil), state.Transports...)
	for index := range candidate.Transports {
		if candidate.Transports[index].OwnerKind == model.TargetNode && candidate.Transports[index].OwnerID == node.ID && candidate.Transports[index].Kind == model.TransportRestricted {
			candidate.Transports[index].HandshakeHost = selected.Hostname
			candidate.Transports[index].ConfigHash = descriptor.ConfigHash
		}
	}
	candidate.HandshakeHost = &selected
	if err := model.ValidateTransition(state, candidate); err != nil {
		return HandshakeHostRecoveryPlan{}, fmt.Errorf("build local handshake-host recovery state: %w", err)
	}
	raw, err := model.EncodeState(state)
	if err != nil {
		return HandshakeHostRecoveryPlan{}, err
	}
	return HandshakeHostRecoveryPlan{
		NodeID: node.ID, Current: *state.HandshakeHost, Candidate: selected,
		ExpectedStateGeneration: state.Generation, NextStateGeneration: nextGeneration, CredentialGeneration: node.CredentialGeneration,
		candidate: candidate, beforeRaw: raw, oldCandidate: oldCandidate, targetCandidate: targetCandidate,
	}, nil
}

func (recovery *NodeHandshakeHostRecovery) Apply(ctx context.Context, plan HandshakeHostRecoveryPlan) (result HandshakeHostRecoveryResult, resultErr error) {
	if ctx == nil {
		return HandshakeHostRecoveryResult{}, fmt.Errorf("context is required")
	}
	state, err := recovery.loadNodeState()
	if err != nil {
		return HandshakeHostRecoveryResult{}, err
	}
	raw, err := model.EncodeState(state)
	if err != nil {
		return HandshakeHostRecoveryResult{}, err
	}
	if len(plan.beforeRaw) == 0 || !bytes.Equal(raw, plan.beforeRaw) || plan.ExpectedStateGeneration != state.Generation {
		return HandshakeHostRecoveryResult{}, ErrHandshakeHostRecoveryStale
	}
	node, restricted, err := activeRestrictedNode(state)
	if err != nil {
		return HandshakeHostRecoveryResult{}, err
	}
	if plan.NodeID != node.ID || plan.Current != *state.HandshakeHost || plan.CredentialGeneration != node.CredentialGeneration ||
		plan.NextStateGeneration != state.Generation+1 || plan.candidate.HandshakeHost == nil || plan.Candidate != *plan.candidate.HandshakeHost ||
		nilCandidate(plan.oldCandidate) || nilCandidate(plan.targetCandidate) {
		return HandshakeHostRecoveryResult{}, fmt.Errorf("handshake-host recovery plan is invalid")
	}
	targetDescriptor := plan.targetCandidate.Descriptor()
	if targetDescriptor.OwnerKind != model.TargetNode || targetDescriptor.OwnerID != node.ID ||
		targetDescriptor.CredentialGeneration != node.CredentialGeneration || targetDescriptor.Kind != model.TransportRestricted {
		return HandshakeHostRecoveryResult{}, fmt.Errorf("handshake-host recovery plan changed node identity or credentials")
	}
	candidateTransport, found := restrictedTransportForNode(plan.candidate.Transports, node.ID)
	if !found || candidateTransport.HandshakeHost != plan.Candidate.Hostname || candidateTransport.ConfigHash != targetDescriptor.ConfigHash {
		return HandshakeHostRecoveryResult{}, fmt.Errorf("handshake-host recovery plan does not match its rendered candidate")
	}
	if err := model.ValidateTransition(state, plan.candidate); err != nil {
		return HandshakeHostRecoveryResult{}, fmt.Errorf("handshake-host recovery candidate is invalid: %w", err)
	}
	overallContext, cancelOverall := context.WithTimeout(ctx, recovery.limits.Total)
	defer cancelOverall()
	prepared := true
	activated := false
	defer func() {
		if prepared && !activated {
			rollbackContext, rollbackCancel := context.WithTimeout(context.Background(), recovery.limits.Rollback)
			defer rollbackCancel()
			if rollbackErr := recovery.provider.Rollback(rollbackContext, plan.targetCandidate); rollbackErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove staged handshake-host recovery candidate: %w", rollbackErr))
			}
		}
	}()
	if err := runTransportTestAction(overallContext, recovery.limits.Step, func(stepContext context.Context) error {
		return recovery.provider.Prepare(stepContext, plan.targetCandidate)
	}); err != nil {
		return HandshakeHostRecoveryResult{}, fmt.Errorf("prepare handshake-host recovery candidate: %w", err)
	}
	if err := runTransportTestAction(overallContext, recovery.limits.Step, func(stepContext context.Context) error {
		return recovery.provider.Validate(stepContext, plan.targetCandidate)
	}); err != nil {
		return HandshakeHostRecoveryResult{}, fmt.Errorf("validate handshake-host recovery candidate: %w", err)
	}
	checks, err := runTransportTestStep(overallContext, recovery.limits.Step, func(stepContext context.Context) (TestResult, error) {
		return recovery.provider.StartTest(stepContext, plan.targetCandidate)
	})
	if err != nil {
		return HandshakeHostRecoveryResult{}, fmt.Errorf("authenticate gateway through requested handshake host: %w", err)
	}
	if err := checks.Validate(); err != nil {
		return HandshakeHostRecoveryResult{}, fmt.Errorf("validate handshake-host recovery gateway probes: %w", err)
	}
	if !checks.Ready() {
		return HandshakeHostRecoveryResult{}, ErrHandshakeHostRecoveryUnauthorized
	}
	activated = true
	if err := runTransportTestAction(overallContext, recovery.limits.Step, func(stepContext context.Context) error {
		return recovery.provider.Activate(stepContext, plan.targetCandidate)
	}); err != nil {
		return HandshakeHostRecoveryResult{}, recovery.compensate(plan, fmt.Errorf("activate handshake-host recovery candidate: %w", err))
	}
	identity := IdentityFromTransport(restricted)
	health, err := runTransportTestStep(overallContext, recovery.limits.Step, func(stepContext context.Context) (Health, error) {
		return recovery.provider.Health(stepContext, HealthRequest{Identity: identity})
	})
	if err != nil {
		return HandshakeHostRecoveryResult{}, recovery.compensate(plan, fmt.Errorf("health-check recovered restricted transport: %w", err))
	}
	if err := health.Validate(); err != nil || health.Identity != identity || health.Kind != model.TransportRestricted || health.Role != RuntimeActive || health.Condition != HealthHealthy {
		if err == nil {
			err = fmt.Errorf("recovered restricted transport did not report active and healthy")
		}
		return HandshakeHostRecoveryResult{}, recovery.compensate(plan, fmt.Errorf("health-check recovered restricted transport: %w", err))
	}
	if err := recovery.state.Save(state.Generation, plan.candidate); err != nil {
		loaded, loadErr := recovery.state.Load()
		if loadErr == nil {
			loadedRaw, encodeErr := model.EncodeState(loaded)
			candidateRaw, candidateErr := model.EncodeState(plan.candidate)
			beforeRaw, beforeErr := model.EncodeState(state)
			if encodeErr == nil && candidateErr == nil && bytes.Equal(loadedRaw, candidateRaw) {
				return HandshakeHostRecoveryResult{}, fmt.Errorf("%w: candidate generation is active after save error: %v", ErrHandshakeHostRecoveryCommitUncertain, err)
			}
			if encodeErr == nil && beforeErr == nil && bytes.Equal(loadedRaw, beforeRaw) {
				return HandshakeHostRecoveryResult{}, recovery.compensate(plan, fmt.Errorf("persist local handshake-host recovery: %w", err))
			}
		}
		return HandshakeHostRecoveryResult{}, errors.Join(ErrHandshakeHostRecoveryCommitUncertain, err, loadErr)
	}
	return HandshakeHostRecoveryResult{
		NodeID: node.ID, Active: plan.Candidate, StateGeneration: plan.candidate.Generation,
		CredentialGeneration: node.CredentialGeneration, Health: health,
	}, nil
}

func (recovery *NodeHandshakeHostRecovery) compensate(plan HandshakeHostRecoveryPlan, cause error) error {
	rollbackContext, rollbackCancel := context.WithTimeout(context.Background(), recovery.limits.Rollback)
	defer rollbackCancel()
	if err := recovery.provider.Activate(rollbackContext, plan.oldCandidate); err != nil {
		return errors.Join(cause, fmt.Errorf("restore prior local handshake host before candidate cleanup: %w", err))
	}
	if err := recovery.provider.Rollback(rollbackContext, plan.targetCandidate); err != nil {
		return errors.Join(cause, fmt.Errorf("remove failed handshake-host recovery candidate: %w", err))
	}
	return cause
}

func (recovery *NodeHandshakeHostRecovery) loadNodeState() (model.State, error) {
	if recovery == nil || recovery.state == nil || nilProvider(recovery.provider) || recovery.now == nil {
		return model.State{}, fmt.Errorf("node handshake-host recovery is incomplete")
	}
	state, err := recovery.state.Load()
	if err != nil {
		return model.State{}, fmt.Errorf("load local handshake-host recovery state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return model.State{}, fmt.Errorf("validate local handshake-host recovery state: %w", err)
	}
	if state.Host.Role != model.RoleNode || state.HandshakeHost == nil || state.HandshakeHostChange != nil {
		return model.State{}, fmt.Errorf("handshake-host recovery requires initialized node-local state")
	}
	return state, nil
}

func activeRestrictedNode(state model.State) (model.Node, model.Transport, error) {
	if len(state.Nodes) != 1 || state.Nodes[0].Lifecycle != model.LifecycleActive || state.Nodes[0].Gateway == nil || state.Nodes[0].ActiveTransport != model.TransportRestricted {
		return model.Node{}, model.Transport{}, fmt.Errorf("handshake-host recovery requires one joined node with restricted transport active")
	}
	node := state.Nodes[0]
	for _, transport := range state.Transports {
		if transport.OwnerKind == model.TargetNode && transport.OwnerID == node.ID && transport.Kind == model.TransportRestricted &&
			(transport.State == model.TransportActive || transport.State == model.TransportDegraded) {
			return node, transport, nil
		}
	}
	return model.Node{}, model.Transport{}, fmt.Errorf("active restricted transport record is missing")
}

func restrictedTransportForNode(transports []model.Transport, nodeID string) (model.Transport, bool) {
	for _, transport := range transports {
		if transport.OwnerKind == model.TargetNode && transport.OwnerID == nodeID && transport.Kind == model.TransportRestricted {
			return transport, true
		}
	}
	return model.Transport{}, false
}
