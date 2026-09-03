package routing

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	ErrPolicyTargetNotFound = errors.New("policy target does not exist")
	ErrPolicyTargetInactive = errors.New("policy target is not active")
	ErrPolicyEmptySet       = errors.New("policy set requires at least one preset")
	ErrPolicyUnknownPreset  = errors.New("policy references an unknown effective preset")
	ErrPolicyInvalidPreset  = errors.New("policy references an invalid preset source")
	ErrPolicyStalePlan      = errors.New("policy replacement plan is stale")
	ErrPolicyLocalApply     = errors.New("gateway policy committed but node-local apply failed")
)

type PolicyStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

type PolicyCommand string

const (
	PolicySet   PolicyCommand = "set"
	PolicyClear PolicyCommand = "clear"
)

type DesiredPolicy struct {
	TargetKind              model.TargetKind
	TargetID                string
	PresetNames             []string
	Selectors               []model.Selector
	EffectiveHash           string
	GatewayPolicyGeneration uint64
	GatewayStateGeneration  uint64
}

type PolicyReplacementPlan struct {
	Command                 PolicyCommand
	TargetKind              model.TargetKind
	TargetID                string
	TargetName              string
	PreviousPresetNames     []string
	PresetNames             []string
	ExpectedStateGeneration uint64
	NextStateGeneration     uint64
	Changed                 bool
	Deferred                bool
	RequiresClientReExport  bool
	Desired                 DesiredPolicy

	sourceSetHash string
	candidate     model.State
}

type PolicyCommitResult struct {
	Command                PolicyCommand
	Changed                bool
	Pending                bool
	StateGeneration        uint64
	RequiresClientReExport bool
	Desired                DesiredPolicy
}

// ResolveEffectiveAssignment maps an explicit set of requested preset names
// to the gateway's already-applied effective preset generation. It accepts an
// explicit empty slice for an all-direct assignment and never reads editable
// source files, whose unapplied contents are not authoritative.
func ResolveEffectiveAssignment(presets []model.Preset, requested []string) ([]string, []model.Selector, string, error) {
	if presets == nil || requested == nil {
		return nil, nil, "", fmt.Errorf("effective presets and requested assignment must be present arrays")
	}
	effective := make(map[string]model.Preset, len(presets))
	for _, preset := range presets {
		if err := preset.Validate(); err != nil {
			return nil, nil, "", fmt.Errorf("invalid effective preset %s: %w", preset.Name, err)
		}
		key := strings.ToLower(preset.Name)
		if _, duplicate := effective[key]; duplicate {
			return nil, nil, "", fmt.Errorf("effective presets duplicate %s", preset.Name)
		}
		effective[key] = preset
	}
	seen := make(map[string]struct{}, len(requested))
	names := make([]string, 0, len(requested))
	for _, requestedName := range requested {
		if err := validatePresetName(requestedName); err != nil {
			return nil, nil, "", err
		}
		key := strings.ToLower(requestedName)
		if _, duplicate := seen[key]; duplicate {
			return nil, nil, "", fmt.Errorf("policy assignment duplicates preset %s", requestedName)
		}
		preset, found := effective[key]
		if !found {
			return nil, nil, "", fmt.Errorf("%w: %s", ErrPolicyUnknownPreset, requestedName)
		}
		seen[key] = struct{}{}
		names = append(names, preset.Name)
	}
	sort.Slice(names, func(left, right int) bool { return presetNameLess(names[left], names[right]) })
	selectors, effectiveHash, err := effectivePolicy(names, effective)
	if err != nil {
		return nil, nil, "", err
	}
	if selectors == nil {
		selectors = []model.Selector{}
	}
	return names, selectors, effectiveHash, nil
}

func (result PolicyCommitResult) OutputResult() output.Result {
	status := output.StatusOK
	if result.Pending {
		status = output.StatusPending
	}
	public := output.NewResult("policy."+string(result.Command), status, output.CategorySuccess, output.SafeObject{
		"changed":    result.Changed,
		"generation": result.StateGeneration,
	})
	resourceKey := "node_id"
	if result.Desired.TargetKind == model.TargetClient {
		resourceKey = "client_id"
	}
	public.ResourceIDs = map[string]string{resourceKey: result.Desired.TargetID}
	if result.RequiresClientReExport {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code:    "re_export_client",
			Message: "Export a fresh Clash profile and replace the client device profile manually.",
			Command: "vpnctl client export " + result.Desired.TargetID + " clash",
			ResourceIDs: map[string]string{
				"client_id": result.Desired.TargetID,
			},
		})
	}
	if len(result.Desired.Selectors) != 0 {
		if boundary, err := InspectClassificationBoundary(result.Desired.Selectors); err == nil {
			public.Data["classification_boundary"] = boundary.SafeObject()
			public.Warnings = append(public.Warnings, boundary.Warnings()...)
		}
	}
	return public
}

type PolicyManager struct {
	paths store.Paths
	state PolicyStateStore
}

func NewPolicyManager(paths store.Paths, state PolicyStateStore) (*PolicyManager, error) {
	if state == nil {
		return nil, fmt.Errorf("policy manager state store is required")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths {
		return nil, fmt.Errorf("policy manager paths do not match the system root")
	}
	return &PolicyManager{paths: paths, state: state}, nil
}

func (manager *PolicyManager) PlanClientSet(clientReference string, presetNames []string) (PolicyReplacementPlan, error) {
	return manager.planGatewayPolicy(model.TargetClient, clientReference, presetNames, PolicySet, false)
}

func (manager *PolicyManager) PlanClientClear(clientReference string) (PolicyReplacementPlan, error) {
	return manager.planGatewayPolicy(model.TargetClient, clientReference, []string{}, PolicyClear, false)
}

// Node identity comes from the authenticated control peer. It is deliberately
// an immutable ID rather than a public CLI target argument.
func (manager *PolicyManager) PlanCurrentNodeSet(nodeID string, presetNames []string, deferred bool) (PolicyReplacementPlan, error) {
	return manager.planGatewayPolicy(model.TargetNode, nodeID, presetNames, PolicySet, deferred)
}

func (manager *PolicyManager) PlanCurrentNodeClear(nodeID string, deferred bool) (PolicyReplacementPlan, error) {
	return manager.planGatewayPolicy(model.TargetNode, nodeID, []string{}, PolicyClear, deferred)
}

func (manager *PolicyManager) planGatewayPolicy(kind model.TargetKind, reference string, requested []string, command PolicyCommand, deferred bool) (PolicyReplacementPlan, error) {
	if manager == nil {
		return PolicyReplacementPlan{}, fmt.Errorf("policy manager is required")
	}
	if command != PolicySet && command != PolicyClear {
		return PolicyReplacementPlan{}, fmt.Errorf("unsupported policy command %q", command)
	}
	if kind == model.TargetClient && deferred {
		return PolicyReplacementPlan{}, fmt.Errorf("client policy replacement cannot be deferred")
	}
	if command == PolicySet && len(requested) == 0 {
		return PolicyReplacementPlan{}, ErrPolicyEmptySet
	}
	if command == PolicyClear && len(requested) != 0 {
		return PolicyReplacementPlan{}, fmt.Errorf("policy clear cannot contain preset names")
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return PolicyReplacementPlan{}, err
	}
	targetID, targetName, previousNames, err := resolvePolicyTarget(state, kind, reference)
	if err != nil {
		return PolicyReplacementPlan{}, err
	}
	names := []string{}
	sourceSetHash := ""
	if command == PolicySet {
		sources, setIssues, inspectErr := inspectPresetSources(manager.paths.PresetsDir)
		if inspectErr != nil {
			return PolicyReplacementPlan{}, inspectErr
		}
		sourceSetHash = presetSourceSetHash(sources, setIssues)
		names, err = resolvePolicyPresetNames(state, sources, requested)
		if err != nil {
			return PolicyReplacementPlan{}, err
		}
	}
	candidate, desired, changed, err := replacePolicyInGatewayState(state, kind, targetID, names)
	if err != nil {
		return PolicyReplacementPlan{}, err
	}
	nextGeneration := state.Generation
	if changed {
		nextGeneration = candidate.Generation
	}
	return PolicyReplacementPlan{
		Command: command, TargetKind: kind, TargetID: targetID, TargetName: targetName,
		PreviousPresetNames: append([]string{}, previousNames...), PresetNames: append([]string{}, names...),
		ExpectedStateGeneration: state.Generation, NextStateGeneration: nextGeneration,
		Changed: changed, Deferred: deferred, RequiresClientReExport: changed && kind == model.TargetClient,
		Desired: cloneDesiredPolicy(desired), sourceSetHash: sourceSetHash, candidate: candidate,
	}, nil
}

func (manager *PolicyManager) Commit(plan PolicyReplacementPlan) (PolicyCommitResult, error) {
	if manager == nil {
		return PolicyCommitResult{}, fmt.Errorf("policy manager is required")
	}
	if err := validatePolicyPlan(plan); err != nil {
		return PolicyCommitResult{}, err
	}
	current, err := manager.loadGatewayState()
	if err != nil {
		return PolicyCommitResult{}, err
	}
	if current.Generation != plan.ExpectedStateGeneration {
		return PolicyCommitResult{}, fmt.Errorf("%w: expected state generation %d, current %d", ErrPolicyStalePlan, plan.ExpectedStateGeneration, current.Generation)
	}
	if plan.Command == PolicySet {
		sources, setIssues, inspectErr := inspectPresetSources(manager.paths.PresetsDir)
		if inspectErr != nil {
			return PolicyCommitResult{}, inspectErr
		}
		if presetSourceSetHash(sources, setIssues) != plan.sourceSetHash {
			return PolicyCommitResult{}, fmt.Errorf("%w: preset source set changed after planning", ErrPolicyStalePlan)
		}
		if _, resolveErr := resolvePolicyPresetNames(current, sources, plan.PresetNames); resolveErr != nil {
			return PolicyCommitResult{}, resolveErr
		}
	}
	if !plan.Changed {
		if !reflect.DeepEqual(current, plan.candidate) {
			return PolicyCommitResult{}, fmt.Errorf("%w: no-op candidate differs from current state", ErrPolicyStalePlan)
		}
		return policyCommitResult(plan, current.Generation), nil
	}
	if err := model.ValidateTransition(current, plan.candidate); err != nil {
		return PolicyCommitResult{}, fmt.Errorf("%w: candidate transition is no longer valid: %v", ErrPolicyStalePlan, err)
	}
	if err := manager.state.Save(current.Generation, plan.candidate); err != nil {
		return PolicyCommitResult{}, err
	}
	return policyCommitResult(plan, plan.candidate.Generation), nil
}

func policyCommitResult(plan PolicyReplacementPlan, generation uint64) PolicyCommitResult {
	desired := cloneDesiredPolicy(plan.Desired)
	desired.GatewayStateGeneration = generation
	return PolicyCommitResult{
		Command: plan.Command, Changed: plan.Changed, Pending: plan.Changed && plan.TargetKind == model.TargetNode && plan.Deferred,
		StateGeneration: generation, RequiresClientReExport: plan.RequiresClientReExport, Desired: desired,
	}
}

func (manager *PolicyManager) loadGatewayState() (model.State, error) {
	state, err := manager.state.Load()
	if err != nil {
		return model.State{}, fmt.Errorf("load authoritative policy state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return model.State{}, fmt.Errorf("validate authoritative policy state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return model.State{}, fmt.Errorf("policy manager requires gateway state")
	}
	return state, nil
}

func resolvePolicyTarget(state model.State, kind model.TargetKind, reference string) (string, string, []string, error) {
	if reference == "" || strings.TrimSpace(reference) != reference || strings.ContainsAny(reference, "\x00\r\n") {
		return "", "", nil, fmt.Errorf("%w: an explicit target is required", ErrPolicyTargetNotFound)
	}
	switch kind {
	case model.TargetClient:
		matches := make([]model.Client, 0, 1)
		for _, client := range state.Clients {
			if client.ID == reference || strings.EqualFold(client.Name, reference) {
				matches = append(matches, client)
			}
		}
		if len(matches) != 1 {
			return "", "", nil, fmt.Errorf("%w: client %s", ErrPolicyTargetNotFound, reference)
		}
		if matches[0].Lifecycle != model.LifecycleActive {
			return "", "", nil, fmt.Errorf("%w: client %s", ErrPolicyTargetInactive, matches[0].Name)
		}
		return matches[0].ID, matches[0].Name, append([]string(nil), matches[0].AssignedPresets...), nil
	case model.TargetNode:
		for _, node := range state.Nodes {
			if node.ID != reference {
				continue
			}
			if node.Lifecycle != model.LifecycleActive {
				return "", "", nil, fmt.Errorf("%w: node %s", ErrPolicyTargetInactive, node.Name)
			}
			return node.ID, node.Name, append([]string(nil), node.AssignedPresets...), nil
		}
		return "", "", nil, fmt.Errorf("%w: authenticated node ID", ErrPolicyTargetNotFound)
	default:
		return "", "", nil, fmt.Errorf("unsupported policy target kind %q", kind)
	}
}

func resolvePolicyPresetNames(state model.State, sources []inspectedPresetSource, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, ErrPolicyEmptySet
	}
	effective := make(map[string]model.Preset, len(state.Presets))
	for _, preset := range state.Presets {
		effective[strings.ToLower(preset.Name)] = preset
	}
	sourceByName := make(map[string][]inspectedPresetSource)
	for _, source := range sources {
		if source.key != "" {
			sourceByName[source.key] = append(sourceByName[source.key], source)
		}
	}
	seen := make(map[string]struct{}, len(requested))
	names := make([]string, 0, len(requested))
	for _, requestedName := range requested {
		if err := validatePresetName(requestedName); err != nil {
			return nil, err
		}
		key := strings.ToLower(requestedName)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("policy set duplicates preset %s", requestedName)
		}
		seen[key] = struct{}{}
		preset, found := effective[key]
		if !found {
			return nil, fmt.Errorf("%w: %s", ErrPolicyUnknownPreset, requestedName)
		}
		candidates := sourceByName[key]
		if len(candidates) != 1 || !candidates[0].view.Valid {
			return nil, fmt.Errorf("%w: %s", ErrPolicyInvalidPreset, preset.Name)
		}
		names = append(names, preset.Name)
	}
	sort.Slice(names, func(left, right int) bool { return presetNameLess(names[left], names[right]) })
	return names, nil
}

func replacePolicyInGatewayState(state model.State, kind model.TargetKind, targetID string, names []string) (model.State, DesiredPolicy, bool, error) {
	presets := make(map[string]model.Preset, len(state.Presets))
	for _, preset := range state.Presets {
		presets[strings.ToLower(preset.Name)] = preset
	}
	selectors, effectiveHash, err := effectivePolicy(names, presets)
	if err != nil {
		return model.State{}, DesiredPolicy{}, false, err
	}
	if names == nil {
		names = []string{}
	}
	if selectors == nil {
		selectors = []model.Selector{}
	}

	policyIndex := -1
	var currentPolicy model.Policy
	for index, policy := range state.Policies {
		if policy.TargetKind == kind && policy.TargetID == targetID {
			policyIndex = index
			currentPolicy = policy
			break
		}
	}
	assignments, err := targetPresetNames(state, kind, targetID)
	if err != nil {
		return model.State{}, DesiredPolicy{}, false, err
	}
	policyMatches := policyIndex >= 0 &&
		equalPolicyPresetNames(currentPolicy.PresetNames, names) &&
		presetSelectorsEqual(currentPolicy.Selectors, selectors) &&
		currentPolicy.EffectiveHash == effectiveHash
	changed := !equalPolicyPresetNames(assignments, names) ||
		(policyIndex < 0 && len(names) > 0) ||
		(policyIndex >= 0 && !policyMatches)

	desired := DesiredPolicy{
		TargetKind: kind, TargetID: targetID,
		PresetNames: append([]string{}, names...), Selectors: append([]model.Selector{}, selectors...),
		EffectiveHash: effectiveHash, GatewayStateGeneration: state.Generation,
	}
	if policyIndex >= 0 {
		desired.GatewayPolicyGeneration = currentPolicy.Generation
	}
	if !changed {
		return state, desired, false, nil
	}

	candidate := state
	candidate.Nodes = append([]model.Node{}, state.Nodes...)
	candidate.Clients = append([]model.Client{}, state.Clients...)
	candidate.Policies = append([]model.Policy{}, state.Policies...)
	nextStateGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return model.State{}, DesiredPolicy{}, false, err
	}
	candidate.Generation = nextStateGeneration
	if err := setTargetPresetNames(&candidate, kind, targetID, names); err != nil {
		return model.State{}, DesiredPolicy{}, false, err
	}

	nextPolicyGeneration := uint64(1)
	if policyIndex >= 0 {
		nextPolicyGeneration, err = model.NextGeneration(currentPolicy.Generation)
		if err != nil {
			return model.State{}, DesiredPolicy{}, false, err
		}
	}
	replacement := model.Policy{
		SchemaVersion: model.ResourceSchemaVersion,
		TargetKind:    kind, TargetID: targetID,
		PresetNames: append([]string{}, names...), Selectors: append([]model.Selector{}, selectors...),
		EffectiveHash: effectiveHash, Generation: nextPolicyGeneration,
	}
	if policyIndex >= 0 {
		candidate.Policies[policyIndex] = replacement
	} else {
		candidate.Policies = append(candidate.Policies, replacement)
	}
	sort.SliceStable(candidate.Policies, func(left, right int) bool {
		if candidate.Policies[left].TargetKind != candidate.Policies[right].TargetKind {
			return candidate.Policies[left].TargetKind < candidate.Policies[right].TargetKind
		}
		return candidate.Policies[left].TargetID < candidate.Policies[right].TargetID
	})
	desired.GatewayPolicyGeneration = nextPolicyGeneration
	desired.GatewayStateGeneration = nextStateGeneration
	if err := model.ValidateTransition(state, candidate); err != nil {
		return model.State{}, DesiredPolicy{}, false, err
	}
	return candidate, desired, true, nil
}

func targetPresetNames(state model.State, kind model.TargetKind, targetID string) ([]string, error) {
	switch kind {
	case model.TargetNode:
		for _, node := range state.Nodes {
			if node.ID == targetID {
				return append([]string(nil), node.AssignedPresets...), nil
			}
		}
	case model.TargetClient:
		for _, client := range state.Clients {
			if client.ID == targetID {
				return append([]string(nil), client.AssignedPresets...), nil
			}
		}
	}
	return nil, fmt.Errorf("%w: %s %s", ErrPolicyTargetNotFound, kind, targetID)
}

func setTargetPresetNames(state *model.State, kind model.TargetKind, targetID string, names []string) error {
	switch kind {
	case model.TargetNode:
		for index := range state.Nodes {
			if state.Nodes[index].ID == targetID {
				state.Nodes[index].AssignedPresets = append([]string{}, names...)
				return nil
			}
		}
	case model.TargetClient:
		for index := range state.Clients {
			if state.Clients[index].ID == targetID {
				state.Clients[index].AssignedPresets = append([]string{}, names...)
				return nil
			}
		}
	}
	return fmt.Errorf("%w: %s %s", ErrPolicyTargetNotFound, kind, targetID)
}

func equalPolicyPresetNames(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftKeys := make([]string, len(left))
	rightKeys := make([]string, len(right))
	for index := range left {
		leftKeys[index] = strings.ToLower(left[index])
	}
	for index := range right {
		rightKeys[index] = strings.ToLower(right[index])
	}
	sort.Strings(leftKeys)
	sort.Strings(rightKeys)
	return reflect.DeepEqual(leftKeys, rightKeys)
}

func validatePolicyPlan(plan PolicyReplacementPlan) error {
	if plan.Command != PolicySet && plan.Command != PolicyClear {
		return fmt.Errorf("invalid policy plan command %q", plan.Command)
	}
	if plan.TargetKind != model.TargetNode && plan.TargetKind != model.TargetClient {
		return fmt.Errorf("invalid policy plan target kind %q", plan.TargetKind)
	}
	if plan.TargetID == "" || plan.TargetName == "" || plan.ExpectedStateGeneration == 0 {
		return fmt.Errorf("policy plan target identity and generation are required")
	}
	if plan.TargetKind == model.TargetClient && plan.Deferred {
		return fmt.Errorf("client policy replacement cannot be deferred")
	}
	if plan.Command == PolicySet {
		if len(plan.PresetNames) == 0 {
			return ErrPolicyEmptySet
		}
		if plan.sourceSetHash == "" {
			return fmt.Errorf("policy set plan lacks its preset source snapshot")
		}
	} else if len(plan.PresetNames) != 0 || plan.sourceSetHash != "" {
		return fmt.Errorf("policy clear plan cannot contain presets or a source snapshot")
	}
	if plan.Desired.TargetKind != plan.TargetKind || plan.Desired.TargetID != plan.TargetID ||
		!equalPolicyPresetNames(plan.Desired.PresetNames, plan.PresetNames) || plan.Desired.PresetNames == nil || plan.Desired.Selectors == nil {
		return fmt.Errorf("policy plan desired state does not match its target or preset set")
	}
	probe := model.Policy{
		SchemaVersion: model.ResourceSchemaVersion, TargetKind: plan.Desired.TargetKind, TargetID: plan.Desired.TargetID,
		PresetNames: plan.Desired.PresetNames, Selectors: plan.Desired.Selectors, EffectiveHash: plan.Desired.EffectiveHash, Generation: 1,
	}
	if err := probe.Validate(); err != nil {
		return fmt.Errorf("policy plan has invalid desired policy: %w", err)
	}
	wantNext := plan.ExpectedStateGeneration
	if plan.Changed {
		var err error
		wantNext, err = model.NextGeneration(plan.ExpectedStateGeneration)
		if err != nil {
			return err
		}
	}
	if plan.NextStateGeneration != wantNext || plan.Desired.GatewayStateGeneration != wantNext || plan.candidate.Generation != wantNext {
		return fmt.Errorf("policy plan has inconsistent state generations")
	}
	if plan.RequiresClientReExport != (plan.Changed && plan.TargetKind == model.TargetClient) {
		return fmt.Errorf("policy plan has inconsistent client re-export action")
	}
	if err := plan.candidate.Validate(); err != nil {
		return fmt.Errorf("invalid policy plan candidate: %w", err)
	}
	candidatePolicy, found := findTargetPolicy(plan.candidate.Policies, plan.TargetKind, plan.TargetID)
	if plan.Desired.GatewayPolicyGeneration == 0 {
		if found {
			return fmt.Errorf("policy plan desired generation omits its candidate policy")
		}
	} else if !found || candidatePolicy.Generation != plan.Desired.GatewayPolicyGeneration ||
		!equalPolicyPresetNames(candidatePolicy.PresetNames, plan.Desired.PresetNames) ||
		!presetSelectorsEqual(candidatePolicy.Selectors, plan.Desired.Selectors) ||
		candidatePolicy.EffectiveHash != plan.Desired.EffectiveHash {
		return fmt.Errorf("policy plan desired policy differs from its candidate")
	}
	return nil
}

func findTargetPolicy(policies []model.Policy, kind model.TargetKind, id string) (model.Policy, bool) {
	for _, policy := range policies {
		if policy.TargetKind == kind && policy.TargetID == id {
			return policy, true
		}
	}
	return model.Policy{}, false
}

func cloneDesiredPolicy(desired DesiredPolicy) DesiredPolicy {
	desired.PresetNames = append([]string(nil), desired.PresetNames...)
	desired.Selectors = append([]model.Selector(nil), desired.Selectors...)
	if desired.PresetNames == nil {
		desired.PresetNames = []string{}
	}
	if desired.Selectors == nil {
		desired.Selectors = []model.Selector{}
	}
	return desired
}

type NodePolicyApplyResult struct {
	Changed          bool
	RoutingChanged   bool
	StateGeneration  uint64
	PolicyGeneration uint64
}

type NodePolicyApplier struct {
	state PolicyStateStore
}

func NewNodePolicyApplier(state PolicyStateStore) (*NodePolicyApplier, error) {
	if state == nil {
		return nil, fmt.Errorf("node policy state store is required")
	}
	return &NodePolicyApplier{state: state}, nil
}

func (applier *NodePolicyApplier) Apply(desired DesiredPolicy) (NodePolicyApplyResult, error) {
	if applier == nil {
		return NodePolicyApplyResult{}, fmt.Errorf("node policy applier is required")
	}
	desired = cloneDesiredPolicy(desired)
	if err := validateDesiredNodePolicy(desired); err != nil {
		return NodePolicyApplyResult{}, err
	}
	state, err := applier.state.Load()
	if err != nil {
		return NodePolicyApplyResult{}, fmt.Errorf("load node-local policy state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return NodePolicyApplyResult{}, fmt.Errorf("validate node-local policy state: %w", err)
	}
	if state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].ID != desired.TargetID || state.Nodes[0].Gateway == nil {
		return NodePolicyApplyResult{}, fmt.Errorf("node-local state does not match desired policy target")
	}
	if desired.GatewayStateGeneration < state.Nodes[0].Gateway.LastKnownGatewayGeneration {
		return NodePolicyApplyResult{}, fmt.Errorf("%w: desired gateway generation %d is older than local trust generation %d", ErrPolicyStalePlan, desired.GatewayStateGeneration, state.Nodes[0].Gateway.LastKnownGatewayGeneration)
	}

	policyIndex := -1
	for index, policy := range state.Policies {
		if policy.TargetKind == model.TargetNode && policy.TargetID == desired.TargetID {
			policyIndex = index
			break
		}
	}
	routingChanged := !equalPolicyPresetNames(state.Nodes[0].AssignedPresets, desired.PresetNames)
	if desired.GatewayPolicyGeneration == 0 {
		routingChanged = routingChanged || policyIndex >= 0
	} else if policyIndex < 0 {
		routingChanged = true
	} else {
		current := state.Policies[policyIndex]
		routingChanged = routingChanged || !equalPolicyPresetNames(current.PresetNames, desired.PresetNames) ||
			!presetSelectorsEqual(current.Selectors, desired.Selectors) || current.EffectiveHash != desired.EffectiveHash
	}
	trustChanged := desired.GatewayStateGeneration > state.Nodes[0].Gateway.LastKnownGatewayGeneration
	if !routingChanged && !trustChanged {
		generation := uint64(0)
		if policyIndex >= 0 {
			generation = state.Policies[policyIndex].Generation
		}
		return NodePolicyApplyResult{StateGeneration: state.Generation, PolicyGeneration: generation}, nil
	}

	candidate := state
	candidate.Nodes = append([]model.Node{}, state.Nodes...)
	candidate.Policies = append([]model.Policy{}, state.Policies...)
	gateway := *state.Nodes[0].Gateway
	candidate.Nodes[0].Gateway = &gateway
	candidate.Nodes[0].AssignedPresets = append([]string{}, state.Nodes[0].AssignedPresets...)
	nextStateGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return NodePolicyApplyResult{}, err
	}
	candidate.Generation = nextStateGeneration
	if trustChanged {
		candidate.Nodes[0].Gateway.LastKnownGatewayGeneration = desired.GatewayStateGeneration
	}
	policyGeneration := uint64(0)
	if routingChanged {
		candidate.Nodes[0].AssignedPresets = append([]string{}, desired.PresetNames...)
		if desired.GatewayPolicyGeneration == 0 {
			candidate.Policies = []model.Policy{}
		} else {
			policyGeneration = 1
			if policyIndex >= 0 {
				policyGeneration, err = model.NextGeneration(state.Policies[policyIndex].Generation)
				if err != nil {
					return NodePolicyApplyResult{}, err
				}
			}
			replacement := model.Policy{
				SchemaVersion: model.ResourceSchemaVersion, TargetKind: model.TargetNode, TargetID: desired.TargetID,
				PresetNames: append([]string{}, desired.PresetNames...), Selectors: append([]model.Selector{}, desired.Selectors...),
				EffectiveHash: desired.EffectiveHash, Generation: policyGeneration,
			}
			if policyIndex >= 0 {
				candidate.Policies[policyIndex] = replacement
			} else {
				candidate.Policies = append(candidate.Policies, replacement)
			}
		}
	} else if policyIndex >= 0 {
		policyGeneration = state.Policies[policyIndex].Generation
	}
	if err := model.ValidateTransition(state, candidate); err != nil {
		return NodePolicyApplyResult{}, fmt.Errorf("validate node-local policy transition: %w", err)
	}
	if err := applier.state.Save(state.Generation, candidate); err != nil {
		return NodePolicyApplyResult{}, err
	}
	return NodePolicyApplyResult{
		Changed: true, RoutingChanged: routingChanged, StateGeneration: nextStateGeneration, PolicyGeneration: policyGeneration,
	}, nil
}

func validateDesiredNodePolicy(desired DesiredPolicy) error {
	if desired.TargetKind != model.TargetNode || desired.TargetID == "" || desired.PresetNames == nil || desired.Selectors == nil || desired.GatewayStateGeneration == 0 {
		return fmt.Errorf("desired node policy target, arrays, and gateway generation are required")
	}
	if desired.GatewayPolicyGeneration == 0 && (len(desired.PresetNames) != 0 || len(desired.Selectors) != 0) {
		return fmt.Errorf("desired node policy without a gateway policy generation must be empty")
	}
	probe := model.Policy{
		SchemaVersion: model.ResourceSchemaVersion, TargetKind: desired.TargetKind, TargetID: desired.TargetID,
		PresetNames: desired.PresetNames, Selectors: desired.Selectors, EffectiveHash: desired.EffectiveHash, Generation: 1,
	}
	if err := probe.Validate(); err != nil {
		return fmt.Errorf("invalid desired node policy: %w", err)
	}
	return nil
}

type NodePolicyResult struct {
	Gateway PolicyCommitResult
	Local   NodePolicyApplyResult
	Pending bool
}

type NodePolicyCoordinator struct {
	Gateway *PolicyManager
	Local   *NodePolicyApplier
}

func (coordinator NodePolicyCoordinator) Commit(plan PolicyReplacementPlan) (NodePolicyResult, error) {
	if coordinator.Gateway == nil || coordinator.Local == nil {
		return NodePolicyResult{}, fmt.Errorf("node policy coordinator requires gateway manager and local applier")
	}
	if plan.TargetKind != model.TargetNode {
		return NodePolicyResult{}, fmt.Errorf("node policy coordinator requires a node plan")
	}
	gateway, err := coordinator.Gateway.Commit(plan)
	if err != nil {
		return NodePolicyResult{}, err
	}
	result := NodePolicyResult{Gateway: gateway, Pending: gateway.Pending}
	if plan.Deferred {
		return result, nil
	}
	local, err := coordinator.Local.Apply(gateway.Desired)
	result.Local = local
	if err != nil {
		result.Pending = true
		return result, fmt.Errorf("%w: %v", ErrPolicyLocalApply, err)
	}
	return result, nil
}
