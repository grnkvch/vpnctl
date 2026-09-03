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
	DefaultTransportTestTimeout        = 45 * time.Second
	DefaultTransportTestStepTimeout    = 30 * time.Second
	DefaultTransportTestCleanupTimeout = 10 * time.Second
	minimumTransportTestTimeout        = 10 * time.Millisecond
	maximumTransportTestTimeout        = 5 * time.Minute
)

// TestLimits bounds the complete diagnostic, each provider stage, and the
// mandatory cleanup that runs even after the caller or test context expires.
type TestLimits struct {
	Total   time.Duration
	Step    time.Duration
	Cleanup time.Duration
}

func (limits TestLimits) normalized() (TestLimits, error) {
	if limits.Total == 0 {
		limits.Total = DefaultTransportTestTimeout
	}
	if limits.Step == 0 {
		limits.Step = DefaultTransportTestStepTimeout
	}
	if limits.Cleanup == 0 {
		limits.Cleanup = DefaultTransportTestCleanupTimeout
	}
	for _, value := range []struct {
		name    string
		timeout time.Duration
	}{
		{name: "total", timeout: limits.Total},
		{name: "step", timeout: limits.Step},
		{name: "cleanup", timeout: limits.Cleanup},
	} {
		if value.timeout < minimumTransportTestTimeout || value.timeout > maximumTransportTestTimeout {
			return TestLimits{}, fmt.Errorf("transport test %s timeout must be between %s and %s", value.name, minimumTransportTestTimeout, maximumTransportTestTimeout)
		}
	}
	if limits.Step > limits.Total {
		return TestLimits{}, fmt.Errorf("transport test step timeout must not exceed total timeout")
	}
	return limits, nil
}

// TestExecution contains only non-secret diagnostic evidence. Selection and
// CredentialGeneration are the immutable intent observed by this Manager;
// Cleaned confirms that the provider removed its transient candidate.
type TestExecution struct {
	Target               CandidateDescriptor
	Selection            Selection
	StateGeneration      uint64
	CredentialGeneration uint64
	Checks               TestResult
	Cleaned              bool
}

var ErrTransportTestStateChanged = errors.New("authoritative node state changed during transport test")

type TestStateReader interface {
	Load() (model.State, error)
}

// NodeTester resolves the local node and target from authoritative read-only
// state. It compares canonical state bytes after cleanup, so the diagnostic
// cannot claim success if any concurrent operation changed active intent,
// pending state, configuration, or a generation while probes were running.
type NodeTester struct {
	state    TestStateReader
	registry *Registry
	limits   TestLimits
}

func NewNodeTester(state TestStateReader, registry *Registry, limits TestLimits) (*NodeTester, error) {
	if state == nil {
		return nil, fmt.Errorf("transport test state reader is required")
	}
	if registry == nil {
		return nil, fmt.Errorf("transport test provider registry is required")
	}
	normalized, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	return &NodeTester{state: state, registry: registry, limits: normalized}, nil
}

func (tester *NodeTester) Test(ctx context.Context, targetKind model.TransportKind) (execution TestExecution, resultErr error) {
	if ctx == nil {
		return TestExecution{}, fmt.Errorf("context is required")
	}
	if tester == nil || tester.state == nil || tester.registry == nil {
		return TestExecution{}, fmt.Errorf("node transport tester is incomplete")
	}
	if !isTransportKind(targetKind) {
		return TestExecution{}, fmt.Errorf("unsupported transport test target %q", targetKind)
	}
	before, err := tester.state.Load()
	if err != nil {
		return TestExecution{}, fmt.Errorf("load node state before transport test: %w", err)
	}
	beforeBytes, err := model.EncodeState(before)
	if err != nil {
		return TestExecution{}, fmt.Errorf("validate node state before transport test: %w", err)
	}
	node, target, err := localNodeTestTarget(before, targetKind)
	if err != nil {
		return TestExecution{}, err
	}
	selection, err := NewSelection(node.ActiveTransport)
	if err != nil {
		return TestExecution{}, err
	}
	manager, err := NewManager(Identity{
		OwnerKind: model.TargetNode, OwnerID: node.ID, CredentialGeneration: node.CredentialGeneration,
	}, selection, tester.registry)
	if err != nil {
		return TestExecution{}, err
	}
	execution, resultErr = manager.TestTransport(ctx, target, tester.limits)
	execution.StateGeneration = before.Generation

	after, loadErr := tester.state.Load()
	if loadErr != nil {
		return execution, errors.Join(resultErr, fmt.Errorf("load node state after transport test: %w", loadErr))
	}
	afterBytes, encodeErr := model.EncodeState(after)
	if encodeErr != nil {
		return execution, errors.Join(resultErr, fmt.Errorf("validate node state after transport test: %w", encodeErr))
	}
	if !bytes.Equal(afterBytes, beforeBytes) {
		return execution, errors.Join(resultErr, ErrTransportTestStateChanged)
	}
	return execution, resultErr
}

func localNodeTestTarget(state model.State, targetKind model.TransportKind) (model.Node, model.Transport, error) {
	if state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Lifecycle != model.LifecycleActive || state.Nodes[0].Gateway == nil {
		return model.Node{}, model.Transport{}, fmt.Errorf("transport test requires one joined active local node")
	}
	node := state.Nodes[0]
	foundKinds := make(map[model.TransportKind]model.Transport, 2)
	for _, candidate := range state.Transports {
		if candidate.OwnerKind != model.TargetNode || candidate.OwnerID != node.ID || candidate.State == model.TransportDisabled {
			continue
		}
		foundKinds[candidate.Kind] = candidate
	}
	for _, required := range []model.TransportKind{model.TransportStandard, model.TransportRestricted} {
		if _, found := foundKinds[required]; !found {
			return model.Node{}, model.Transport{}, fmt.Errorf("joined node transport test requires configured standard and restricted transports")
		}
	}
	target, found := foundKinds[targetKind]
	if !found {
		return model.Node{}, model.Transport{}, fmt.Errorf("transport test target %s is not configured", targetKind)
	}
	return node, target, nil
}

func (execution TestExecution) Ready() bool {
	return execution.Cleaned && execution.Checks.Ready()
}

// TestTransport temporarily establishes exactly the requested provider and
// always rolls it back. It has no state-store, routing, Activate, Drain, or
// standby-fallback capability, so success and failure preserve production
// selection and credential generation by construction.
func (manager *Manager) TestTransport(ctx context.Context, target model.Transport, limits TestLimits) (execution TestExecution, resultErr error) {
	if ctx == nil {
		return TestExecution{}, fmt.Errorf("context is required")
	}
	if manager == nil || manager.registry == nil {
		return TestExecution{}, fmt.Errorf("transport manager is incomplete")
	}
	normalized, err := limits.normalized()
	if err != nil {
		return TestExecution{}, err
	}
	if err := manager.validateTestTarget(target); err != nil {
		return TestExecution{}, err
	}

	execution = TestExecution{
		Target: DescriptorFromTransport(target), Selection: manager.selection,
		CredentialGeneration: manager.identity.CredentialGeneration,
	}
	provider, err := manager.registry.Provider(target.Kind)
	if err != nil {
		return execution, err
	}
	overallContext, cancelOverall := context.WithTimeout(ctx, normalized.Total)
	defer cancelOverall()

	candidate, err := runTransportTestStep(overallContext, normalized.Step, func(stepContext context.Context) (Candidate, error) {
		return provider.Render(stepContext, RenderRequest{Transport: target})
	})
	if err != nil {
		return execution, fmt.Errorf("render %s transport test candidate: %w", target.Kind, err)
	}
	if nilCandidate(candidate) {
		return execution, fmt.Errorf("render %s transport test candidate: provider returned nil candidate", target.Kind)
	}
	if descriptor := candidate.Descriptor(); descriptor != execution.Target {
		return execution, fmt.Errorf("render %s transport test candidate: provider returned a different candidate descriptor", target.Kind)
	}

	cleanupRequired := false
	defer func() {
		if !cleanupRequired {
			return
		}
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), normalized.Cleanup)
		defer cleanupCancel()
		if rollbackErr := provider.Rollback(cleanupContext, candidate); rollbackErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove %s transport test candidate: %w", target.Kind, rollbackErr))
			return
		}
		execution.Cleaned = true
	}()

	cleanupRequired = true
	if err := runTransportTestAction(overallContext, normalized.Step, func(stepContext context.Context) error {
		return provider.Prepare(stepContext, candidate)
	}); err != nil {
		return execution, fmt.Errorf("prepare %s transport test candidate: %w", target.Kind, err)
	}
	if err := runTransportTestAction(overallContext, normalized.Step, func(stepContext context.Context) error {
		return provider.Validate(stepContext, candidate)
	}); err != nil {
		return execution, fmt.Errorf("validate %s transport test candidate: %w", target.Kind, err)
	}
	execution.Checks, err = runTransportTestStep(overallContext, normalized.Step, func(stepContext context.Context) (TestResult, error) {
		return provider.StartTest(stepContext, candidate)
	})
	if err != nil {
		return execution, fmt.Errorf("run %s transport test probes: %w", target.Kind, err)
	}
	if err := execution.Checks.Validate(); err != nil {
		return execution, fmt.Errorf("validate %s transport test result: %w", target.Kind, err)
	}
	return execution, nil
}

func (manager *Manager) validateTestTarget(target model.Transport) error {
	if err := target.Validate(); err != nil {
		return fmt.Errorf("validate transport test target: %w", err)
	}
	if target.OwnerKind != manager.identity.OwnerKind || target.OwnerID != manager.identity.OwnerID || target.CredentialGeneration != manager.identity.CredentialGeneration {
		return fmt.Errorf("transport test target does not belong to the manager identity and credential generation")
	}
	wantedState := model.TransportStandby
	if target.Kind == manager.selection.Active {
		if target.State != model.TransportActive && target.State != model.TransportDegraded {
			return fmt.Errorf("selected active transport test target must be active or degraded")
		}
		return nil
	}
	if target.Kind != manager.selection.Standby {
		return fmt.Errorf("transport test target is outside the configured active/standby pair")
	}
	if target.State != wantedState {
		return fmt.Errorf("selected standby transport test target must be standby")
	}
	return nil
}

func runTransportTestAction(ctx context.Context, timeout time.Duration, action func(context.Context) error) error {
	_, err := runTransportTestStep(ctx, timeout, func(stepContext context.Context) (struct{}, error) {
		return struct{}{}, action(stepContext)
	})
	return err
}

func runTransportTestStep[T any](ctx context.Context, timeout time.Duration, action func(context.Context) (T, error)) (T, error) {
	stepContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return action(stepContext)
}
