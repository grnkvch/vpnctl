package enrollment

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

// SystemGatewayRecoveryRuntime is the gateway runtime used only by public
// expired-certificate recovery. Stage retains a validated replacement config
// without publication. Activate installs the replacement under the shared
// controller mutation boundary; Rollback restores its exact predecessor when
// the authoritative CAS is known old. Ordinary online rotation has a separate
// make-before-break composition and must not use this recovery-only adapter.
type SystemGatewayRecoveryRuntime struct {
	paths      store.Paths
	secrets    NodeCredentialSecretStore
	roles      *linuxplatform.RoleSystemdInstaller
	runner     linuxplatform.ProbeRunner
	keyRunner  wireguard.Runner
	mutationMu *sync.Mutex
	binaryPath string

	mu           sync.Mutex
	transactions map[string]*systemGatewayRecoveryTransaction
}

type systemGatewayRecoveryTransaction struct {
	nodeID              string
	currentGeneration   uint64
	requestedGeneration uint64
	stateGeneration     uint64
	request             linuxplatform.RoleInstallationRequest
	snapshots           []gatewayJoinConfigSnapshot
	activated           bool
	mutationLocked      bool
}

func NewSystemGatewayRecoveryRuntime(
	paths store.Paths,
	secrets NodeCredentialSecretStore,
	mutationMu *sync.Mutex,
) (*SystemGatewayRecoveryRuntime, error) {
	return newSystemGatewayRecoveryRuntime(
		paths, secrets, mutationMu, linuxplatform.OSProbeRunner{}, wireguard.ExecRunner{}, linuxplatform.DefaultVPNCTLBinaryPath,
	)
}

func newSystemGatewayRecoveryRuntime(
	paths store.Paths,
	secrets NodeCredentialSecretStore,
	mutationMu *sync.Mutex,
	runner linuxplatform.ProbeRunner,
	keyRunner wireguard.Runner,
	binaryPath string,
) (*SystemGatewayRecoveryRuntime, error) {
	if secrets == nil || mutationMu == nil || runner == nil || keyRunner == nil {
		return nil, fmt.Errorf("system gateway recovery dependencies are incomplete")
	}
	roles, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, runner)
	if err != nil {
		return nil, err
	}
	if _, err := linuxplatform.RenderGatewayRoleInstallation(binaryPath); err != nil {
		return nil, err
	}
	return &SystemGatewayRecoveryRuntime{
		paths: paths, secrets: secrets, roles: roles, runner: runner, keyRunner: keyRunner,
		mutationMu: mutationMu, binaryPath: binaryPath,
		transactions: make(map[string]*systemGatewayRecoveryTransaction),
	}, nil
}

func (runtime *SystemGatewayRecoveryRuntime) Stage(ctx context.Context, candidate GatewayNodeRotationCandidate) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if runtime == nil || runtime.secrets == nil || runtime.roles == nil || runtime.runner == nil || runtime.keyRunner == nil {
		return fmt.Errorf("system gateway recovery runtime is incomplete")
	}
	if err := validateSystemGatewayRecoveryCandidate(candidate); err != nil {
		return err
	}
	certificate, err := systemGatewayJoinTunnelCertificate(candidate.Candidate)
	if err != nil {
		return err
	}
	certificatePEM, err := runtime.secrets.Get(model.SecretRef(certificate.CertificateRef))
	if err != nil {
		return fmt.Errorf("read gateway recovery tunnel certificate: %w", err)
	}
	defer clear(certificatePEM)
	request, err := renderSystemGatewayCandidate(
		ctx, runtime.paths, runtime.secrets, runtime.keyRunner, runtime.binaryPath, candidate.Candidate, certificatePEM,
	)
	if err != nil {
		return fmt.Errorf("render staged gateway recovery candidate: %w", err)
	}
	transaction := &systemGatewayRecoveryTransaction{
		nodeID: candidate.NodeID, currentGeneration: candidate.CurrentGeneration,
		requestedGeneration: candidate.RequestedGeneration, stateGeneration: candidate.Candidate.Generation,
		request: request,
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if _, exists := runtime.transactions[candidate.RequestID]; exists {
		clearGatewayJoinRoleRequest(&transaction.request)
		return fmt.Errorf("gateway recovery request %s is already staged", candidate.RequestID)
	}
	runtime.transactions[candidate.RequestID] = transaction
	return nil
}

func (runtime *SystemGatewayRecoveryRuntime) Check(
	ctx context.Context,
	candidate GatewayNodeRotationCandidate,
) (NodeRotationReadinessReport, error) {
	if ctx == nil {
		return NodeRotationReadinessReport{}, fmt.Errorf("context is required")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	transaction, err := runtime.transactionLocked(candidate)
	if err != nil {
		return NodeRotationReadinessReport{}, err
	}
	if transaction.activated {
		return NodeRotationReadinessReport{}, fmt.Errorf("gateway recovery candidate was activated before staging readiness")
	}
	if _, err := runtime.roles.Plan(transaction.request); err != nil {
		return NodeRotationReadinessReport{}, fmt.Errorf("validate staged gateway recovery publication: %w", err)
	}
	return NodeRotationReadinessReport{Control: true, Standard: true, Restricted: true, Tunnel: true}, nil
}

func (runtime *SystemGatewayRecoveryRuntime) ActivateParallel(ctx context.Context, candidate GatewayNodeRotationCandidate) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	runtime.mu.Lock()
	transaction, err := runtime.transactionLocked(candidate)
	if err != nil {
		runtime.mu.Unlock()
		return err
	}
	if transaction.activated {
		runtime.mu.Unlock()
		return nil
	}
	runtime.mu.Unlock()

	runtime.mutationMu.Lock()
	if err := ctx.Err(); err != nil {
		runtime.mutationMu.Unlock()
		return err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	transaction, err = runtime.transactionLocked(candidate)
	if err != nil {
		runtime.mutationMu.Unlock()
		return err
	}
	if transaction.activated {
		runtime.mutationMu.Unlock()
		return nil
	}
	snapshots, err := snapshotGatewayJoinConfigs(runtime.paths, transaction.request.Configs)
	if err != nil {
		runtime.mutationMu.Unlock()
		return err
	}
	keepSnapshots := false
	defer func() {
		if !keepSnapshots {
			clearGatewayJoinSnapshots(snapshots)
		}
	}()
	rollback := func(cause error) error {
		err := errors.Join(cause, restoreGatewayJoinRuntime(ctx, snapshots, runtime.runner))
		runtime.mutationMu.Unlock()
		return err
	}
	if _, err := runtime.roles.Apply(ctx, transaction.request); err != nil {
		return rollback(fmt.Errorf("publish gateway recovery candidate: %w", err))
	}
	if err := restartGatewayJoinServices(ctx, runtime.runner); err != nil {
		return rollback(err)
	}
	if err := runtime.checkActivatedCandidate(ctx, candidate); err != nil {
		return rollback(err)
	}
	transaction.snapshots = snapshots
	transaction.activated = true
	transaction.mutationLocked = true
	keepSnapshots = true
	return nil
}

func (runtime *SystemGatewayRecoveryRuntime) Rollback(ctx context.Context, candidate GatewayNodeRotationCandidate) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if runtime == nil || runtime.mutationMu == nil {
		return fmt.Errorf("system gateway recovery runtime is incomplete")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	transaction, exists := runtime.transactions[candidate.RequestID]
	if !exists {
		return nil
	}
	if err := runtime.matchesTransaction(transaction, candidate); err != nil {
		return err
	}
	var result error
	if transaction.activated {
		result = restoreGatewayJoinRuntime(ctx, transaction.snapshots, runtime.runner)
		if transaction.mutationLocked {
			transaction.mutationLocked = false
			runtime.mutationMu.Unlock()
		}
	}
	runtime.destroyTransactionLocked(candidate.RequestID, transaction)
	return result
}

func (runtime *SystemGatewayRecoveryRuntime) Drain(ctx context.Context, request NodeRotationDrainRequest) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for requestID, transaction := range runtime.transactions {
		if transaction.nodeID != request.NodeID || transaction.currentGeneration != request.PreviousGeneration ||
			transaction.requestedGeneration != request.ActiveGeneration || !transaction.activated {
			continue
		}
		validationErr := request.Validate(time.Now())
		if transaction.mutationLocked {
			transaction.mutationLocked = false
			runtime.mutationMu.Unlock()
		}
		runtime.destroyTransactionLocked(requestID, transaction)
		return validationErr
	}
	return fmt.Errorf("activated gateway recovery transaction is unavailable")
}

func (runtime *SystemGatewayRecoveryRuntime) checkActivatedCandidate(
	ctx context.Context,
	candidate GatewayNodeRotationCandidate,
) error {
	node, err := systemGatewayRecoveryNode(candidate.Candidate, candidate.NodeID, candidate.RequestedGeneration)
	if err != nil {
		return err
	}
	privateKey, err := runtime.secrets.Get(transport.GatewayStandardCredentialRef)
	if err != nil {
		return fmt.Errorf("read gateway standard key for recovery readiness: %w", err)
	}
	defer clear(privateKey)
	publicKey, err := wireguard.PublicKey(ctx, runtime.keyRunner, string(privateKey))
	if err != nil {
		return err
	}
	joinReadiness := &SystemGatewayJoinReadiness{runner: runtime.runner}
	report, err := joinReadiness.checkCandidate(ctx, GatewayJoinCandidate{
		State: candidate.Candidate, Node: node, GatewayWireGuardPublicKey: publicKey,
	})
	if err != nil {
		return err
	}
	return report.Validate()
}

func (runtime *SystemGatewayRecoveryRuntime) transactionLocked(
	candidate GatewayNodeRotationCandidate,
) (*systemGatewayRecoveryTransaction, error) {
	if runtime == nil || runtime.transactions == nil {
		return nil, fmt.Errorf("system gateway recovery runtime is incomplete")
	}
	transaction, exists := runtime.transactions[candidate.RequestID]
	if !exists {
		return nil, fmt.Errorf("gateway recovery request %s is not staged", candidate.RequestID)
	}
	if err := runtime.matchesTransaction(transaction, candidate); err != nil {
		return nil, err
	}
	return transaction, nil
}

func (*SystemGatewayRecoveryRuntime) matchesTransaction(
	transaction *systemGatewayRecoveryTransaction,
	candidate GatewayNodeRotationCandidate,
) error {
	if transaction == nil || transaction.nodeID != candidate.NodeID ||
		transaction.currentGeneration != candidate.CurrentGeneration ||
		transaction.requestedGeneration != candidate.RequestedGeneration ||
		transaction.stateGeneration != candidate.Candidate.Generation {
		return fmt.Errorf("gateway recovery candidate differs from staged transaction")
	}
	return nil
}

func (runtime *SystemGatewayRecoveryRuntime) destroyTransactionLocked(
	requestID string,
	transaction *systemGatewayRecoveryTransaction,
) {
	clearGatewayJoinRoleRequest(&transaction.request)
	clearGatewayJoinSnapshots(transaction.snapshots)
	transaction.snapshots = nil
	delete(runtime.transactions, requestID)
}

func validateSystemGatewayRecoveryCandidate(candidate GatewayNodeRotationCandidate) error {
	if candidate.RequestID == "" || candidate.NodeID == "" || candidate.CurrentGeneration == 0 ||
		candidate.RequestedGeneration != candidate.CurrentGeneration+1 {
		return fmt.Errorf("gateway recovery candidate identity is invalid")
	}
	if err := candidate.Before.Validate(); err != nil {
		return fmt.Errorf("validate gateway recovery predecessor: %w", err)
	}
	if err := candidate.Candidate.Validate(); err != nil {
		return fmt.Errorf("validate gateway recovery candidate: %w", err)
	}
	if candidate.Before.Host.Role != model.RoleGateway || candidate.Candidate.Host.Role != model.RoleGateway ||
		candidate.Candidate.Generation != candidate.Before.Generation+1 || !reflect.DeepEqual(candidate.Before.Host, candidate.Candidate.Host) {
		return fmt.Errorf("gateway recovery candidate host/generation is invalid")
	}
	if err := candidate.PublicExchange.Validate(); err != nil ||
		candidate.PublicExchange.NodeID != candidate.NodeID ||
		candidate.PublicExchange.CredentialGeneration != candidate.RequestedGeneration {
		return errors.Join(fmt.Errorf("gateway recovery public exchange is invalid"), err)
	}
	if _, err := systemGatewayRecoveryNode(candidate.Before, candidate.NodeID, candidate.CurrentGeneration); err != nil {
		return err
	}
	if _, err := systemGatewayRecoveryNode(candidate.Candidate, candidate.NodeID, candidate.RequestedGeneration); err != nil {
		return err
	}
	if len(candidate.ControlCertificatePEM) == 0 {
		return fmt.Errorf("gateway recovery control certificate is unavailable")
	}
	return nil
}

func systemGatewayRecoveryNode(state model.State, nodeID string, generation uint64) (model.Node, error) {
	for _, node := range state.Nodes {
		if node.ID != nodeID {
			continue
		}
		if node.Lifecycle != model.LifecycleActive || node.CredentialGeneration != generation {
			return model.Node{}, fmt.Errorf("gateway recovery node generation is not active")
		}
		return node, nil
	}
	return model.Node{}, ErrNodeNotFound
}

func restartGatewayJoinServices(ctx context.Context, runner linuxplatform.ProbeRunner) error {
	for _, unit := range gatewayJoinCandidateUnits() {
		result, err := runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"restart", unit}})
		if err != nil || result.ExitCode != 0 {
			return errors.Join(fmt.Errorf("restart gateway service %s", unit), err)
		}
	}
	return nil
}

func restoreGatewayJoinRuntime(
	ctx context.Context,
	snapshots []gatewayJoinConfigSnapshot,
	runner linuxplatform.ProbeRunner,
) error {
	var result error
	for _, snapshot := range snapshots {
		if err := restoreGatewayJoinConfig(snapshot); err != nil {
			result = errors.Join(result, err)
		}
	}
	return errors.Join(result, restartGatewayJoinServices(ctx, runner))
}

var _ GatewayNodeRotationRuntime = (*SystemGatewayRecoveryRuntime)(nil)
