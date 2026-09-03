package enrollment

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const nodeLifecyclePlanMarker = "<redacted-node-lifecycle-plan>"

var (
	ErrNodeLifecycleStale       = errors.New("node lifecycle plan is stale")
	ErrNodeDeleteRequiresRevoke = errors.New("node must be revoked before deletion")
	ErrNodeRevocationIncomplete = errors.New("node revocation did not close every connection class")
	ErrNodeLifecycleUncertain   = errors.New("node lifecycle commit outcome is uncertain")
	ErrNodeCleanupPending       = errors.New("node lifecycle cleanup remains pending")
)

type NodeLifecycleCommand string

const (
	NodeRevoke NodeLifecycleCommand = "node.revoke"
	NodeDelete NodeLifecycleCommand = "node.delete"
)

// NodeLifecyclePlan contains only reviewable impact metadata publicly, but it
// retains exact credential references as a private stale-plan precondition.
// Serializing the aggregate is forbidden so storage layout cannot reach CLI
// output or a deferred-operation payload. Revoke and delete are immediate.
type NodeLifecyclePlan struct {
	Command                 NodeLifecycleCommand
	NodeID                  string
	NodeName                string
	Changed                 bool
	ExpectedStateGeneration uint64
	NextStateGeneration     uint64
	CredentialGeneration    uint64
	ExposeIDs               []string
	RevokedAt               *time.Time

	reference      string
	credentialRefs []model.SecretRef
	revocationTime *time.Time
}

func (NodeLifecyclePlan) String() string   { return nodeLifecyclePlanMarker }
func (NodeLifecyclePlan) GoString() string { return nodeLifecyclePlanMarker }
func (NodeLifecyclePlan) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

// NodeRevocationReport is exhaustive by design. A runtime adapter must remove
// the node from both gateway transport configurations, deny/close control,
// close the reverse tunnel, and withdraw every expose mapping. An incomplete
// result is never reported as a successful revocation even though committed
// authoritative state remains fail-closed.
type NodeRevocationReport struct {
	ControlClosed    bool
	StandardClosed   bool
	RestrictedClosed bool
	TunnelClosed     bool
	ExposesDisabled  bool
}

func (report NodeRevocationReport) Validate() error {
	if !report.ControlClosed || !report.StandardClosed || !report.RestrictedClosed || !report.TunnelClosed || !report.ExposesDisabled {
		return fmt.Errorf("%w: control=%t standard=%t restricted=%t tunnel=%t exposes=%t",
			ErrNodeRevocationIncomplete, report.ControlClosed, report.StandardClosed,
			report.RestrictedClosed, report.TunnelClosed, report.ExposesDisabled)
	}
	return nil
}

type NodeGatewayLifecycleRuntime interface {
	Revoke(context.Context, model.State, string) (NodeRevocationReport, error)
	Delete(context.Context, model.State, string) error
}

type NodeLifecycleStateStore interface {
	Load() (model.State, error)
	Save(uint64, model.State) error
}

type NodeLifecycleResult struct {
	Command                 NodeLifecycleCommand
	NodeID                  string
	NodeName                string
	Changed                 bool
	StateGeneration         uint64
	CredentialGeneration    uint64
	DisabledExposeIDs       []string
	ConnectionsClosed       bool
	RuntimeReconcileNeeded  bool
	CredentialCleanupNeeded bool
}

func (result NodeLifecycleResult) OutputResult() output.Result {
	status := output.StatusOK
	if result.RuntimeReconcileNeeded || result.CredentialCleanupNeeded {
		status = output.StatusPending
	}
	public := output.NewResult(string(result.Command), status, output.CategorySuccess, output.SafeObject{
		"changed": result.Changed, "generation": result.StateGeneration,
	})
	public.ResourceIDs["node_id"] = result.NodeID
	if result.RuntimeReconcileNeeded {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "repair_node_runtime", Message: "Run repair to finish closing revoked node connections and mappings.",
			ResourceIDs: map[string]string{"node_id": result.NodeID},
		})
	}
	if result.CredentialCleanupNeeded {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "repair_node_credentials", Message: "Run repair to remove retained revoked node credential material.",
			ResourceIDs: map[string]string{"node_id": result.NodeID},
		})
	}
	return public
}

type NodeLifecycleManager struct {
	state   NodeLifecycleStateStore
	secrets NodeCredentialSecretStore
	runtime NodeGatewayLifecycleRuntime
	now     func() time.Time
}

func NewNodeLifecycleManager(
	state NodeLifecycleStateStore,
	secrets NodeCredentialSecretStore,
	runtime NodeGatewayLifecycleRuntime,
	now func() time.Time,
) (*NodeLifecycleManager, error) {
	if state == nil || secrets == nil || runtime == nil {
		return nil, fmt.Errorf("node lifecycle requires state, secret, and gateway runtime services")
	}
	if now == nil {
		now = time.Now
	}
	return &NodeLifecycleManager{state: state, secrets: secrets, runtime: runtime, now: now}, nil
}

func (manager *NodeLifecycleManager) PlanRevoke(reference string) (NodeLifecyclePlan, error) {
	if manager == nil {
		return NodeLifecyclePlan{}, fmt.Errorf("node lifecycle manager is required")
	}
	at := manager.now().UTC()
	return manager.plan(reference, NodeRevoke, &at)
}

func (manager *NodeLifecycleManager) PlanDelete(reference string) (NodeLifecyclePlan, error) {
	return manager.plan(reference, NodeDelete, nil)
}

func (manager *NodeLifecycleManager) plan(
	reference string,
	command NodeLifecycleCommand,
	requestedRevocation *time.Time,
) (NodeLifecyclePlan, error) {
	if manager == nil || manager.state == nil {
		return NodeLifecyclePlan{}, fmt.Errorf("node lifecycle manager is incomplete")
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return NodeLifecyclePlan{}, err
	}
	node, err := resolveVisibleNode(state.Nodes, reference)
	if err != nil {
		return NodeLifecyclePlan{}, err
	}
	credentialRefs, err := gatewayNodeCredentialReferences(state, node)
	if err != nil {
		return NodeLifecyclePlan{}, err
	}
	plan := NodeLifecyclePlan{
		Command: command, NodeID: node.ID, NodeName: node.Name,
		ExpectedStateGeneration: state.Generation, NextStateGeneration: state.Generation,
		CredentialGeneration: node.CredentialGeneration, ExposeIDs: nodeExposeIDs(state.Exposes, node.ID),
		reference: reference, credentialRefs: credentialRefs,
	}
	switch command {
	case NodeRevoke:
		switch node.Lifecycle {
		case model.LifecycleActive:
			if requestedRevocation == nil {
				return NodeLifecyclePlan{}, fmt.Errorf("node revocation time is required")
			}
			revoked, revokeErr := node.Revoke(requestedRevocation.UTC())
			if revokeErr != nil {
				return NodeLifecyclePlan{}, revokeErr
			}
			plan.Changed = true
			plan.RevokedAt = cloneNodeLifecycleTime(revoked.RevokedAt)
			plan.revocationTime = cloneNodeLifecycleTime(revoked.RevokedAt)
		case model.LifecycleRevoked:
			plan.RevokedAt = cloneNodeLifecycleTime(node.RevokedAt)
			plan.revocationTime = cloneNodeLifecycleTime(node.RevokedAt)
		default:
			return NodeLifecyclePlan{}, fmt.Errorf("%w: %s", ErrNodeNotFound, reference)
		}
	case NodeDelete:
		if node.Lifecycle != model.LifecycleRevoked {
			return NodeLifecyclePlan{}, fmt.Errorf("%w: %s", ErrNodeDeleteRequiresRevoke, node.Name)
		}
		plan.Changed = true
		plan.RevokedAt = cloneNodeLifecycleTime(node.RevokedAt)
	default:
		return NodeLifecyclePlan{}, fmt.Errorf("unsupported node lifecycle command %q", command)
	}
	if plan.Changed {
		plan.NextStateGeneration, err = model.NextGeneration(state.Generation)
		if err != nil {
			return NodeLifecyclePlan{}, err
		}
	}
	return plan, nil
}

func (manager *NodeLifecycleManager) CommitRevoke(ctx context.Context, plan NodeLifecyclePlan) (NodeLifecycleResult, error) {
	if manager == nil || manager.runtime == nil || manager.secrets == nil || ctx == nil {
		return NodeLifecycleResult{}, fmt.Errorf("node revocation services and context are required")
	}
	fresh, err := manager.plan(plan.reference, NodeRevoke, plan.revocationTime)
	if err != nil {
		return NodeLifecycleResult{}, err
	}
	if !sameNodeLifecycleReview(plan, fresh) {
		return NodeLifecycleResult{}, ErrNodeLifecycleStale
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return NodeLifecycleResult{}, err
	}
	if state.Generation != fresh.ExpectedStateGeneration {
		return NodeLifecycleResult{}, ErrNodeLifecycleStale
	}
	if err := ctx.Err(); err != nil {
		return NodeLifecycleResult{}, err
	}
	candidate := state
	if fresh.Changed {
		candidate, err = buildNodeRevocationCandidate(state, fresh.NodeID, *fresh.RevokedAt)
		if err != nil {
			return NodeLifecycleResult{}, err
		}
		committed, known, saveErr := manager.save(state, candidate)
		if !committed {
			if known {
				return NodeLifecycleResult{}, saveErr
			}
			return nodeLifecycleResult(fresh, fresh.NextStateGeneration), fmt.Errorf("%w: %v", ErrNodeLifecycleUncertain, saveErr)
		}
		if saveErr != nil {
			err = fmt.Errorf("%w: state is revoked but durability confirmation failed: %v", ErrNodeLifecycleUncertain, saveErr)
		}
	}
	result := nodeLifecycleResult(fresh, candidate.Generation)
	report, runtimeErr := manager.runtime.Revoke(ctx, candidate, fresh.NodeID)
	if runtimeErr == nil {
		runtimeErr = report.Validate()
	}
	result.ConnectionsClosed = runtimeErr == nil
	result.RuntimeReconcileNeeded = runtimeErr != nil
	credentialErr := deleteGatewayNodeCredentials(manager.secrets, fresh.credentialRefs)
	result.CredentialCleanupNeeded = credentialErr != nil
	cleanupErr := errors.Join(runtimeErr, credentialErr)
	if cleanupErr != nil {
		return result, errors.Join(err, ErrNodeCleanupPending, cleanupErr)
	}
	return result, err
}

func (manager *NodeLifecycleManager) CommitDelete(ctx context.Context, plan NodeLifecyclePlan) (NodeLifecycleResult, error) {
	if manager == nil || manager.runtime == nil || manager.secrets == nil || ctx == nil {
		return NodeLifecycleResult{}, fmt.Errorf("node deletion services and context are required")
	}
	fresh, err := manager.plan(plan.reference, NodeDelete, nil)
	if err != nil {
		return NodeLifecycleResult{}, err
	}
	if !sameNodeLifecycleReview(plan, fresh) {
		return NodeLifecycleResult{}, ErrNodeLifecycleStale
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return NodeLifecycleResult{}, err
	}
	if state.Generation != fresh.ExpectedStateGeneration {
		return NodeLifecycleResult{}, ErrNodeLifecycleStale
	}
	if err := ctx.Err(); err != nil {
		return NodeLifecycleResult{}, err
	}
	candidate, err := buildNodeDeletionCandidate(state, fresh.NodeID)
	if err != nil {
		return NodeLifecycleResult{}, err
	}
	result := nodeLifecycleResult(fresh, candidate.Generation)
	committed, known, saveErr := manager.save(state, candidate)
	if !committed {
		if known {
			return NodeLifecycleResult{}, saveErr
		}
		return result, fmt.Errorf("%w: %v", ErrNodeLifecycleUncertain, saveErr)
	}
	runtimeErr := manager.runtime.Delete(ctx, candidate, fresh.NodeID)
	result.RuntimeReconcileNeeded = runtimeErr != nil
	credentialErr := deleteGatewayNodeCredentials(manager.secrets, fresh.credentialRefs)
	result.CredentialCleanupNeeded = credentialErr != nil
	cleanupErr := errors.Join(runtimeErr, credentialErr)
	if saveErr != nil {
		err = fmt.Errorf("%w: state is deleted but durability confirmation failed: %v", ErrNodeLifecycleUncertain, saveErr)
	}
	if cleanupErr != nil {
		return result, errors.Join(err, ErrNodeCleanupPending, cleanupErr)
	}
	return result, err
}

func (manager *NodeLifecycleManager) loadGatewayState() (model.State, error) {
	state, err := manager.state.Load()
	if err != nil {
		return model.State{}, fmt.Errorf("load authoritative node lifecycle state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return model.State{}, fmt.Errorf("validate authoritative node lifecycle state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return model.State{}, fmt.Errorf("node lifecycle requires gateway state")
	}
	return state, nil
}

func nodeLifecycleResult(plan NodeLifecyclePlan, generation uint64) NodeLifecycleResult {
	return NodeLifecycleResult{
		Command: plan.Command, NodeID: plan.NodeID, NodeName: plan.NodeName, Changed: plan.Changed,
		StateGeneration: generation, CredentialGeneration: plan.CredentialGeneration,
		DisabledExposeIDs: append([]string{}, plan.ExposeIDs...),
	}
}

func sameNodeLifecycleReview(left, right NodeLifecyclePlan) bool {
	return left.Command == right.Command && left.NodeID == right.NodeID && left.NodeName == right.NodeName &&
		left.Changed == right.Changed && left.ExpectedStateGeneration == right.ExpectedStateGeneration &&
		left.NextStateGeneration == right.NextStateGeneration && left.CredentialGeneration == right.CredentialGeneration &&
		equalNodeLifecycleTimes(left.RevokedAt, right.RevokedAt) &&
		reflect.DeepEqual(left.ExposeIDs, right.ExposeIDs) && reflect.DeepEqual(left.credentialRefs, right.credentialRefs)
}

func equalNodeLifecycleTimes(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func cloneNodeLifecycleTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func nodeExposeIDs(exposes []model.Expose, nodeID string) []string {
	result := make([]string, 0)
	for _, expose := range exposes {
		if expose.NodeID == nodeID {
			result = append(result, expose.ID)
		}
	}
	sort.Strings(result)
	return result
}

func gatewayNodeCredentialReferences(state model.State, node model.Node) ([]model.SecretRef, error) {
	unique := make(map[model.SecretRef]struct{})
	for _, record := range state.Transports {
		if record.OwnerKind == model.TargetNode && record.OwnerID == node.ID && record.CredentialRef != "" {
			unique[record.CredentialRef] = struct{}{}
		}
	}
	for _, certificate := range state.Certificates {
		if certificate.OwnerKind != "node" || certificate.OwnerID != node.ID {
			continue
		}
		if certificate.CertificateRef != "" {
			unique[model.SecretRef(certificate.CertificateRef)] = struct{}{}
		}
		if certificate.PrivateKeyRef != "" {
			unique[certificate.PrivateKeyRef] = struct{}{}
		}
	}
	references, err := NewNodeCredentialReferences(node.ID, node.CredentialGeneration)
	if err != nil {
		return nil, err
	}
	unique[references.RestrictedCredential] = struct{}{}
	unique[references.TunnelCredential] = struct{}{}
	ordered := make([]string, 0, len(unique))
	for reference := range unique {
		ordered = append(ordered, reference.String())
	}
	sort.Strings(ordered)
	result := make([]model.SecretRef, 0, len(ordered))
	for _, reference := range ordered {
		result = append(result, model.SecretRef(reference))
	}
	return result, nil
}

func buildNodeRevocationCandidate(state model.State, nodeID string, at time.Time) (model.State, error) {
	candidate := state
	next, err := model.NextGeneration(state.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate.Generation = next
	candidate.Nodes = append([]model.Node{}, state.Nodes...)
	candidate.Transports = append([]model.Transport{}, state.Transports...)
	candidate.Exposes = append([]model.Expose{}, state.Exposes...)
	found := false
	for index := range candidate.Nodes {
		if candidate.Nodes[index].ID != nodeID {
			continue
		}
		revoked, revokeErr := candidate.Nodes[index].Revoke(at)
		if revokeErr != nil {
			return model.State{}, revokeErr
		}
		candidate.Nodes[index] = revoked
		found = true
	}
	for index := range candidate.Transports {
		if candidate.Transports[index].OwnerKind == model.TargetNode && candidate.Transports[index].OwnerID == nodeID {
			candidate.Transports[index].State = model.TransportDisabled
		}
	}
	for index := range candidate.Exposes {
		if candidate.Exposes[index].NodeID != nodeID || candidate.Exposes[index].State == model.ExposeDisabled {
			continue
		}
		candidate.Exposes[index].State = model.ExposeDisabled
		candidate.Exposes[index].Generation, err = model.NextGeneration(candidate.Exposes[index].Generation)
		if err != nil {
			return model.State{}, err
		}
	}
	if !found {
		return model.State{}, ErrNodeNotFound
	}
	if err := model.ValidateTransition(state, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate node revocation transition: %w", err)
	}
	return candidate, nil
}

func buildNodeDeletionCandidate(state model.State, nodeID string) (model.State, error) {
	candidate := state
	next, err := model.NextGeneration(state.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate.Generation = next
	candidate.Nodes = append([]model.Node{}, state.Nodes...)
	found := false
	for index := range candidate.Nodes {
		if candidate.Nodes[index].ID != nodeID {
			continue
		}
		deleted, deleteErr := candidate.Nodes[index].Delete()
		if deleteErr != nil {
			return model.State{}, deleteErr
		}
		deleted.AssignedPresets = []string{}
		candidate.Nodes[index] = deleted
		found = true
	}
	if !found {
		return model.State{}, ErrNodeNotFound
	}
	candidate.Policies = removeNodePolicies(state.Policies, nodeID)
	candidate.Transports = removeNodeTransports(state.Transports, nodeID)
	candidate.Exposes = removeNodeExposes(state.Exposes, nodeID)
	candidate.Certificates = removeNodeCertificates(state.Certificates, nodeID)
	if err := model.ValidateTransition(state, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate node deletion transition: %w", err)
	}
	return candidate, nil
}

func removeNodePolicies(values []model.Policy, nodeID string) []model.Policy {
	result := make([]model.Policy, 0, len(values))
	for _, value := range values {
		if value.TargetKind != model.TargetNode || value.TargetID != nodeID {
			result = append(result, value)
		}
	}
	return result
}

func removeNodeTransports(values []model.Transport, nodeID string) []model.Transport {
	result := make([]model.Transport, 0, len(values))
	for _, value := range values {
		if value.OwnerKind != model.TargetNode || value.OwnerID != nodeID {
			result = append(result, value)
		}
	}
	return result
}

func removeNodeExposes(values []model.Expose, nodeID string) []model.Expose {
	result := make([]model.Expose, 0, len(values))
	for _, value := range values {
		if value.NodeID != nodeID {
			result = append(result, value)
		}
	}
	return result
}

func removeNodeCertificates(values []model.Certificate, nodeID string) []model.Certificate {
	result := make([]model.Certificate, 0, len(values))
	for _, value := range values {
		if value.OwnerKind != "node" || value.OwnerID != nodeID {
			result = append(result, value)
		}
	}
	return result
}

func (manager *NodeLifecycleManager) save(before, candidate model.State) (committed, known bool, saveErr error) {
	if err := manager.state.Save(before.Generation, candidate); err == nil {
		return true, true, nil
	} else {
		saveErr = err
	}
	loaded, loadErr := manager.state.Load()
	if loadErr == nil && reflect.DeepEqual(loaded, candidate) {
		return true, true, saveErr
	}
	if loadErr == nil && reflect.DeepEqual(loaded, before) {
		return false, true, saveErr
	}
	return false, false, errors.Join(saveErr, loadErr)
}

func deleteGatewayNodeCredentials(secrets NodeCredentialSecretStore, references []model.SecretRef) error {
	var failures []error
	for _, reference := range references {
		if _, err := secrets.Delete(reference); err != nil {
			failures = append(failures, fmt.Errorf("delete revoked node credential %s: %w", reference, err))
		}
	}
	return errors.Join(failures...)
}
