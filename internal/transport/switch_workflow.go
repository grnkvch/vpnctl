package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	DefaultTransportSwitchTimeout         = 90 * time.Second
	DefaultTransportSwitchStepTimeout     = 30 * time.Second
	DefaultTransportSwitchDrainTimeout    = 10 * time.Second
	DefaultTransportSwitchRollbackTimeout = 10 * time.Second
)

var (
	ErrTransportSwitchStale           = errors.New("transport switch plan is stale")
	ErrTransportSwitchTargetNotReady  = errors.New("transport switch target is not ready")
	ErrTransportSwitchCommitUncertain = errors.New("transport switch state commit is uncertain")
)

// SwitchLimits bounds the complete switch, each provider action, the old-path
// drain, and compensation. Rollback has an independent context because the
// caller or overall switch deadline may already have expired.
type SwitchLimits struct {
	Total    time.Duration
	Step     time.Duration
	Drain    time.Duration
	Rollback time.Duration
}

func (limits SwitchLimits) normalized() (SwitchLimits, error) {
	if limits.Total == 0 {
		limits.Total = DefaultTransportSwitchTimeout
	}
	if limits.Step == 0 {
		limits.Step = DefaultTransportSwitchStepTimeout
	}
	if limits.Drain == 0 {
		limits.Drain = DefaultTransportSwitchDrainTimeout
	}
	if limits.Rollback == 0 {
		limits.Rollback = DefaultTransportSwitchRollbackTimeout
	}
	for _, value := range []struct {
		name    string
		timeout time.Duration
	}{
		{name: "total", timeout: limits.Total},
		{name: "step", timeout: limits.Step},
		{name: "drain", timeout: limits.Drain},
		{name: "rollback", timeout: limits.Rollback},
	} {
		if value.timeout < minimumTransportTestTimeout || value.timeout > maximumTransportTestTimeout {
			return SwitchLimits{}, fmt.Errorf("transport switch %s timeout must be between %s and %s", value.name, minimumTransportTestTimeout, maximumTransportTestTimeout)
		}
	}
	if limits.Step > limits.Total || limits.Drain > limits.Total {
		return SwitchLimits{}, fmt.Errorf("transport switch step and drain timeouts must not exceed total timeout")
	}
	return limits, nil
}

type SwitchStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

// SwitchPlan is a read-only, confirmation-ready description. The complete
// canonical snapshots remain private so Apply can reject a plan if any local
// state, pending operation, configuration, or generation changed after the
// operator reviewed it.
type SwitchPlan struct {
	NodeID                  string
	Current                 model.TransportKind
	Target                  model.TransportKind
	ExpectedStateGeneration uint64
	NextStateGeneration     uint64
	Changed                 bool

	before    model.State
	candidate model.State
	beforeRaw []byte
}

type SwitchResult struct {
	NodeID          string
	Previous        model.TransportKind
	Active          model.TransportKind
	Changed         bool
	StateGeneration uint64
	ActiveHealth    Health
}

type NodeSwitcher struct {
	state    SwitchStateStore
	registry *Registry
	limits   SwitchLimits
}

func NewNodeSwitcher(state SwitchStateStore, registry *Registry, limits SwitchLimits) (*NodeSwitcher, error) {
	if state == nil {
		return nil, fmt.Errorf("transport switch state store is required")
	}
	if registry == nil {
		return nil, fmt.Errorf("transport switch provider registry is required")
	}
	normalized, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	return &NodeSwitcher{state: state, registry: registry, limits: normalized}, nil
}

func (switcher *NodeSwitcher) Plan(targetKind model.TransportKind) (SwitchPlan, error) {
	if switcher == nil || switcher.state == nil || switcher.registry == nil {
		return SwitchPlan{}, fmt.Errorf("node transport switcher is incomplete")
	}
	if !isTransportKind(targetKind) {
		return SwitchPlan{}, fmt.Errorf("unsupported transport switch target %q", targetKind)
	}
	before, err := switcher.state.Load()
	if err != nil {
		return SwitchPlan{}, fmt.Errorf("load node state before transport switch: %w", err)
	}
	beforeRaw, err := model.EncodeState(before)
	if err != nil {
		return SwitchPlan{}, fmt.Errorf("validate node state before transport switch: %w", err)
	}
	node, transports, err := localNodeSwitchPair(before)
	if err != nil {
		return SwitchPlan{}, err
	}
	plan := SwitchPlan{
		NodeID: node.ID, Current: node.ActiveTransport, Target: targetKind,
		ExpectedStateGeneration: before.Generation, NextStateGeneration: before.Generation,
		Changed: targetKind != node.ActiveTransport, before: before, beforeRaw: beforeRaw,
	}
	if !plan.Changed {
		plan.candidate = before
		return plan, nil
	}
	if transports[targetKind].State != model.TransportStandby {
		return SwitchPlan{}, fmt.Errorf("transport switch target %s must be standby", targetKind)
	}
	candidate, err := switchedNodeState(before, node.ID, node.ActiveTransport, targetKind)
	if err != nil {
		return SwitchPlan{}, err
	}
	plan.NextStateGeneration = candidate.Generation
	plan.candidate = candidate
	return plan, nil
}

// Apply runs only after the common CLI consent boundary. Activate is the
// provider's single atomic production selector for control, reverse tunnel,
// selected TCP, and selected UDP; the shared workflow exposes no per-path
// switch methods that could produce a split selection.
func (switcher *NodeSwitcher) Apply(ctx context.Context, plan SwitchPlan) (result SwitchResult, resultErr error) {
	if ctx == nil {
		return SwitchResult{}, fmt.Errorf("context is required")
	}
	if switcher == nil || switcher.state == nil || switcher.registry == nil {
		return SwitchResult{}, fmt.Errorf("node transport switcher is incomplete")
	}
	current, err := switcher.state.Load()
	if err != nil {
		return SwitchResult{}, fmt.Errorf("load node state before applying transport switch: %w", err)
	}
	currentRaw, err := model.EncodeState(current)
	if err != nil {
		return SwitchResult{}, fmt.Errorf("validate node state before applying transport switch: %w", err)
	}
	if len(plan.beforeRaw) == 0 || !bytes.Equal(currentRaw, plan.beforeRaw) || plan.ExpectedStateGeneration != current.Generation {
		return SwitchResult{}, ErrTransportSwitchStale
	}
	node, transports, err := localNodeSwitchPair(current)
	if err != nil {
		return SwitchResult{}, err
	}
	if plan.NodeID != node.ID || plan.Current != node.ActiveTransport || !isTransportKind(plan.Target) || plan.Changed != (plan.Target != plan.Current) {
		return SwitchResult{}, fmt.Errorf("transport switch plan is invalid")
	}
	selection, err := NewSelection(node.ActiveTransport)
	if err != nil {
		return SwitchResult{}, err
	}
	manager, err := NewManager(Identity{
		OwnerKind: model.TargetNode, OwnerID: node.ID, CredentialGeneration: node.CredentialGeneration,
	}, selection, switcher.registry)
	if err != nil {
		return SwitchResult{}, err
	}
	if !plan.Changed {
		healthContext, cancelHealth := context.WithTimeout(ctx, switcher.limits.Step)
		health, healthErr := manager.ObserveActive(healthContext)
		cancelHealth()
		if healthErr != nil {
			return SwitchResult{}, healthErr
		}
		return SwitchResult{
			NodeID: node.ID, Previous: plan.Current, Active: plan.Current, Changed: false,
			StateGeneration: current.Generation, ActiveHealth: health,
		}, nil
	}
	if plan.NextStateGeneration != current.Generation+1 || transports[plan.Target].State != model.TransportStandby {
		return SwitchResult{}, fmt.Errorf("transport switch plan is invalid")
	}
	if err := model.ValidateTransition(current, plan.candidate); err != nil {
		return SwitchResult{}, fmt.Errorf("transport switch candidate is invalid: %w", err)
	}

	overallContext, cancelOverall := context.WithTimeout(ctx, switcher.limits.Total)
	defer cancelOverall()
	oldProvider, err := switcher.registry.Provider(plan.Current)
	if err != nil {
		return SwitchResult{}, err
	}
	targetProvider, err := switcher.registry.Provider(plan.Target)
	if err != nil {
		return SwitchResult{}, err
	}
	oldCandidate, err := switchCandidate(overallContext, switcher.limits.Step, oldProvider, transports[plan.Current])
	if err != nil {
		return SwitchResult{}, fmt.Errorf("render current %s transport rollback candidate: %w", plan.Current, err)
	}
	targetCandidate, err := switchCandidate(overallContext, switcher.limits.Step, targetProvider, transports[plan.Target])
	if err != nil {
		return SwitchResult{}, fmt.Errorf("render target %s transport candidate: %w", plan.Target, err)
	}

	prepared := false
	activated := false
	committed := false
	defer func() {
		// The named compensation below handles all errors after provider
		// mutation. This guard is intentionally only a safety net for future
		// returns added before activation.
		if prepared && !activated && !committed {
			rollbackContext, rollbackCancel := context.WithTimeout(context.Background(), switcher.limits.Rollback)
			defer rollbackCancel()
			if rollbackErr := targetProvider.Rollback(rollbackContext, targetCandidate); rollbackErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove staged target transport candidate: %w", rollbackErr))
			}
		}
	}()

	prepared = true
	if err := runTransportTestAction(overallContext, switcher.limits.Step, func(stepContext context.Context) error {
		return targetProvider.Prepare(stepContext, targetCandidate)
	}); err != nil {
		return SwitchResult{}, fmt.Errorf("prepare target %s transport: %w", plan.Target, err)
	}
	if err := runTransportTestAction(overallContext, switcher.limits.Step, func(stepContext context.Context) error {
		return targetProvider.Validate(stepContext, targetCandidate)
	}); err != nil {
		return SwitchResult{}, fmt.Errorf("validate target %s transport: %w", plan.Target, err)
	}
	checks, err := runTransportTestStep(overallContext, switcher.limits.Step, func(stepContext context.Context) (TestResult, error) {
		return targetProvider.StartTest(stepContext, targetCandidate)
	})
	if err != nil {
		return SwitchResult{}, fmt.Errorf("test target %s transport: %w", plan.Target, err)
	}
	if err := checks.Validate(); err != nil {
		return SwitchResult{}, fmt.Errorf("validate target %s transport checks: %w", plan.Target, err)
	}
	if !checks.Ready() {
		return SwitchResult{}, fmt.Errorf("%w: %s", ErrTransportSwitchTargetNotReady, plan.Target)
	}

	activated = true
	if err := runTransportTestAction(overallContext, switcher.limits.Step, func(stepContext context.Context) error {
		return targetProvider.Activate(stepContext, targetCandidate)
	}); err != nil {
		return SwitchResult{}, switcher.compensate(oldProvider, oldCandidate, targetProvider, targetCandidate, fmt.Errorf("activate target %s transport: %w", plan.Target, err))
	}
	targetHealth, err := runTransportTestStep(overallContext, switcher.limits.Step, func(stepContext context.Context) (Health, error) {
		return targetProvider.Health(stepContext, HealthRequest{Identity: manager.identity})
	})
	if err != nil {
		return SwitchResult{}, switcher.compensate(oldProvider, oldCandidate, targetProvider, targetCandidate, fmt.Errorf("health-check active target %s transport: %w", plan.Target, err))
	}
	if err := manager.validateHealth(targetHealth, plan.Target, RuntimeActive); err != nil {
		return SwitchResult{}, switcher.compensate(oldProvider, oldCandidate, targetProvider, targetCandidate, fmt.Errorf("health-check active target %s transport: %w", plan.Target, err))
	}
	if targetHealth.Condition != HealthHealthy {
		return SwitchResult{}, switcher.compensate(oldProvider, oldCandidate, targetProvider, targetCandidate, fmt.Errorf("%w: %s reports %s", ErrTransportSwitchTargetNotReady, plan.Target, targetHealth.Condition))
	}

	drainStarted := time.Now()
	drainRequest := DrainRequest{Identity: manager.identity, Deadline: drainStarted.Add(switcher.limits.Drain)}
	if err := drainRequest.Validate(drainStarted); err != nil {
		return SwitchResult{}, switcher.compensate(oldProvider, oldCandidate, targetProvider, targetCandidate, err)
	}
	drainContext, cancelDrain := context.WithDeadline(overallContext, drainRequest.Deadline)
	drainErr := oldProvider.Drain(drainContext, drainRequest)
	cancelDrain()
	if drainErr != nil {
		return SwitchResult{}, switcher.compensate(oldProvider, oldCandidate, targetProvider, targetCandidate, fmt.Errorf("drain previous %s transport: %w", plan.Current, drainErr))
	}
	targetSelection, err := NewSelection(plan.Target)
	if err != nil {
		return SwitchResult{}, switcher.compensate(oldProvider, oldCandidate, targetProvider, targetCandidate, err)
	}
	targetManager, err := NewManager(manager.identity, targetSelection, switcher.registry)
	if err != nil {
		return SwitchResult{}, switcher.compensate(oldProvider, oldCandidate, targetProvider, targetCandidate, err)
	}
	steadyContext, cancelSteady := context.WithTimeout(overallContext, switcher.limits.Step)
	steadyHealth, steadyErr := targetManager.CheckSteadyState(steadyContext)
	cancelSteady()
	if steadyErr != nil {
		return SwitchResult{}, switcher.compensate(oldProvider, oldCandidate, targetProvider, targetCandidate, fmt.Errorf("verify switched transport roles: %w", steadyErr))
	}
	if steadyHealth[0].Condition != HealthHealthy {
		return SwitchResult{}, switcher.compensate(oldProvider, oldCandidate, targetProvider, targetCandidate, fmt.Errorf("%w: %s reports %s after old-path drain", ErrTransportSwitchTargetNotReady, plan.Target, steadyHealth[0].Condition))
	}
	targetHealth = steadyHealth[0]
	if err := switcher.state.Save(current.Generation, plan.candidate); err != nil {
		return SwitchResult{}, switcher.reconcileCommitFailure(oldProvider, oldCandidate, targetProvider, targetCandidate, current, plan.candidate, err)
	}
	committed = true
	return SwitchResult{
		NodeID: node.ID, Previous: plan.Current, Active: plan.Target, Changed: true,
		StateGeneration: plan.candidate.Generation, ActiveHealth: targetHealth,
	}, nil
}

func (switcher *NodeSwitcher) compensate(oldProvider Provider, oldCandidate Candidate, targetProvider Provider, targetCandidate Candidate, cause error) error {
	rollbackContext, rollbackCancel := context.WithTimeout(context.Background(), switcher.limits.Rollback)
	defer rollbackCancel()
	restoreErr := oldProvider.Activate(rollbackContext, oldCandidate)
	if restoreErr != nil {
		return errors.Join(cause, fmt.Errorf("restore previous transport before target cleanup: %w", restoreErr))
	}
	cleanupErr := targetProvider.Rollback(rollbackContext, targetCandidate)
	if cleanupErr != nil {
		return errors.Join(cause, fmt.Errorf("remove failed target transport candidate: %w", cleanupErr))
	}
	return cause
}

func (switcher *NodeSwitcher) reconcileCommitFailure(oldProvider Provider, oldCandidate Candidate, targetProvider Provider, targetCandidate Candidate, before, candidate model.State, saveErr error) error {
	loaded, loadErr := switcher.state.Load()
	if loadErr == nil {
		loadedRaw, encodeErr := model.EncodeState(loaded)
		candidateRaw, candidateErr := model.EncodeState(candidate)
		beforeRaw, beforeErr := model.EncodeState(before)
		switch {
		case encodeErr == nil && candidateErr == nil && bytes.Equal(loadedRaw, candidateRaw):
			return fmt.Errorf("%w: candidate generation is active after save error: %v", ErrTransportSwitchCommitUncertain, saveErr)
		case encodeErr == nil && beforeErr == nil && bytes.Equal(loadedRaw, beforeRaw):
			return switcher.compensate(oldProvider, oldCandidate, targetProvider, targetCandidate, fmt.Errorf("commit transport switch state: %w", saveErr))
		}
	}
	return errors.Join(ErrTransportSwitchCommitUncertain, saveErr, loadErr)
}

func switchCandidate(ctx context.Context, timeout time.Duration, provider Provider, transport model.Transport) (Candidate, error) {
	candidate, err := runTransportTestStep(ctx, timeout, func(stepContext context.Context) (Candidate, error) {
		return provider.Render(stepContext, RenderRequest{Transport: transport})
	})
	if err != nil {
		return nil, err
	}
	if nilCandidate(candidate) {
		return nil, fmt.Errorf("provider returned nil candidate")
	}
	if descriptor := candidate.Descriptor(); descriptor != DescriptorFromTransport(transport) {
		return nil, fmt.Errorf("provider returned a different candidate descriptor")
	}
	return candidate, nil
}

func localNodeSwitchPair(state model.State) (model.Node, map[model.TransportKind]model.Transport, error) {
	if state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Lifecycle != model.LifecycleActive || state.Nodes[0].Gateway == nil {
		return model.Node{}, nil, fmt.Errorf("transport switch requires one joined active local node")
	}
	node := state.Nodes[0]
	transports := make(map[model.TransportKind]model.Transport, 2)
	for _, candidate := range state.Transports {
		if candidate.OwnerKind != model.TargetNode || candidate.OwnerID != node.ID || candidate.State == model.TransportDisabled {
			continue
		}
		transports[candidate.Kind] = candidate
	}
	for _, required := range []model.TransportKind{model.TransportStandard, model.TransportRestricted} {
		if _, found := transports[required]; !found {
			return model.Node{}, nil, fmt.Errorf("joined node transport switch requires configured standard and restricted transports")
		}
	}
	return node, transports, nil
}

func switchedNodeState(before model.State, nodeID string, previous, target model.TransportKind) (model.State, error) {
	nextGeneration, err := model.NextGeneration(before.Generation)
	if err != nil {
		return model.State{}, fmt.Errorf("advance transport switch state generation: %w", err)
	}
	candidate := before
	candidate.Generation = nextGeneration
	candidate.Nodes = append([]model.Node(nil), before.Nodes...)
	candidate.Transports = append([]model.Transport(nil), before.Transports...)
	for index := range candidate.Nodes {
		if candidate.Nodes[index].ID == nodeID {
			candidate.Nodes[index].ActiveTransport = target
		}
	}
	for index := range candidate.Transports {
		transport := &candidate.Transports[index]
		if transport.OwnerKind != model.TargetNode || transport.OwnerID != nodeID {
			continue
		}
		switch transport.Kind {
		case previous:
			transport.State = model.TransportStandby
		case target:
			transport.State = model.TransportActive
		}
	}
	if err := model.ValidateTransition(before, candidate); err != nil {
		return model.State{}, fmt.Errorf("build transport switch state: %w", err)
	}
	return candidate, nil
}
