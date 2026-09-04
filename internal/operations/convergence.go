package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/render"
)

const ConvergenceManifestSchemaVersion = 1

var (
	ErrConvergencePlanInvalid = errors.New("invalid convergence plan input")
	resourceComponentPattern  = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)
	operationTypePattern      = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
)

// ConvergenceImpact is ordered from no interruption through destructive loss.
// It deliberately matches the public plan-v1 vocabulary.
type ConvergenceImpact string

const (
	ConvergenceImpactNone         ConvergenceImpact = "none"
	ConvergenceImpactAvailability ConvergenceImpact = "availability"
	ConvergenceImpactDestructive  ConvergenceImpact = "destructive"
)

type ManagedResourceKind string

const (
	ManagedResourceState   ManagedResourceKind = "state"
	ManagedResourceFile    ManagedResourceKind = "file"
	ManagedResourceUnit    ManagedResourceKind = "unit"
	ManagedResourceNetwork ManagedResourceKind = "network"
)

// ManagedResourceKey is a stable, non-secret identifier inside a component's
// vpnctl-owned scope. A path may be used as ID for a generated file; sensitive
// webhook paths must never be resource identifiers.
type ManagedResourceKey struct {
	Component string              `json:"component"`
	Kind      ManagedResourceKind `json:"kind"`
	ID        string              `json:"id"`
}

// ManagedResource is a content-free desired or applied expectation.
// RevisionSHA256 also covers dependency generations and therefore drives the
// desired/applied diff. RuntimeSHA256 covers only observable runtime shape and
// therefore drives applied/actual drift. Neither digest contains plaintext.
type ManagedResource struct {
	Key            ManagedResourceKey `json:"key"`
	RevisionSHA256 string             `json:"revision_sha256"`
	RuntimeSHA256  string             `json:"runtime_sha256"`
	ApplyImpact    ConvergenceImpact  `json:"apply_impact"`
	RemoveImpact   ConvergenceImpact  `json:"remove_impact"`
}

// OwnedResourceObservation is returned only for positively owned resources.
// RemoveImpact is needed solely for an unexpected owned resource; expected
// resources take their repair impact from the applied manifest.
type OwnedResourceObservation struct {
	Key           ManagedResourceKey `json:"key"`
	RuntimeSHA256 string             `json:"runtime_sha256"`
	RemoveImpact  ConvergenceImpact  `json:"remove_impact"`
}

type ConvergenceManifest struct {
	SchemaVersion int               `json:"schema_version"`
	Generation    uint64            `json:"generation"`
	Resources     []ManagedResource `json:"resources"`
}

// PendingOperation binds every desired/applied resource difference to an
// authoritative registered operation. A desired diff without this binding is
// rejected rather than being silently treated as eligible for apply.
type PendingOperation struct {
	ID                 string               `json:"id"`
	Type               string               `json:"type"`
	TargetKind         string               `json:"target_kind,omitempty"`
	TargetID           string               `json:"target_id,omitempty"`
	ExpectedGeneration uint64               `json:"expected_generation"`
	DesiredGeneration  uint64               `json:"desired_generation"`
	Resources          []ManagedResourceKey `json:"resources"`
}

type ConvergenceSnapshot struct {
	Desired ConvergenceManifest `json:"desired"`
	Applied ConvergenceManifest `json:"applied"`
	Pending []PendingOperation  `json:"pending"`
}

// ConvergenceSnapshotSource exposes no persistence method. Implementations
// load authoritative desired/applied metadata but cannot be asked by planning
// to save state.
type ConvergenceSnapshotSource interface {
	ReadConvergenceSnapshot(context.Context) (ConvergenceSnapshot, error)
}

// OwnedResourceDiscoverer may inspect only the vpnctl-owned scopes represented
// by the applied manifest. Returned extras must have positive vpnctl ownership
// evidence (for example an owner marker); unknown external resources must not
// be returned and therefore can never become repair targets.
type OwnedResourceDiscoverer interface {
	DiscoverOwnedResources(context.Context, ConvergenceManifest) ([]OwnedResourceObservation, error)
}

type ConvergencePlanner struct {
	source     ConvergenceSnapshotSource
	discoverer OwnedResourceDiscoverer
}

type DesiredChangeKind string

const (
	DesiredCreate DesiredChangeKind = "create"
	DesiredUpdate DesiredChangeKind = "update"
	DesiredDelete DesiredChangeKind = "delete"
)

type DesiredChange struct {
	OperationID   string             `json:"operation_id"`
	OperationType string             `json:"operation_type"`
	TargetKind    string             `json:"target_kind,omitempty"`
	TargetID      string             `json:"target_id,omitempty"`
	Resource      ManagedResourceKey `json:"resource"`
	Kind          DesiredChangeKind  `json:"kind"`
	Impact        ConvergenceImpact  `json:"impact"`
	FromSHA256    string             `json:"from_sha256,omitempty"`
	ToSHA256      string             `json:"to_sha256,omitempty"`
}

type OwnedDriftKind string

const (
	OwnedDriftMissing    OwnedDriftKind = "missing"
	OwnedDriftModified   OwnedDriftKind = "modified"
	OwnedDriftUnexpected OwnedDriftKind = "unexpected"
)

type OwnedDrift struct {
	Resource       ManagedResourceKey `json:"resource"`
	Kind           OwnedDriftKind     `json:"kind"`
	Impact         ConvergenceImpact  `json:"impact"`
	ExpectedSHA256 string             `json:"expected_sha256,omitempty"`
	ActualSHA256   string             `json:"actual_sha256,omitempty"`
}

type ConvergencePlan struct {
	DesiredGeneration uint64            `json:"desired_generation"`
	AppliedGeneration uint64            `json:"applied_generation"`
	Impact            ConvergenceImpact `json:"impact"`
	Changes           []DesiredChange   `json:"changes"`
	Drift             []OwnedDrift      `json:"drift"`
}

func NewConvergencePlanner(source ConvergenceSnapshotSource, discoverer OwnedResourceDiscoverer) (*ConvergencePlanner, error) {
	if source == nil || discoverer == nil {
		return nil, fmt.Errorf("convergence planner dependencies are incomplete")
	}
	return &ConvergencePlanner{source: source, discoverer: discoverer}, nil
}

// Plan performs only authoritative reads and vpnctl-owned observation. Pending
// changes always compare desired to the last applied manifest; drift always
// compares that applied manifest to actual observations. The two comparisons
// are intentionally independent even if actual bytes happen to match desired.
func (planner *ConvergencePlanner) Plan(ctx context.Context) (ConvergencePlan, error) {
	if ctx == nil {
		return ConvergencePlan{}, fmt.Errorf("context is required")
	}
	if planner == nil || planner.source == nil || planner.discoverer == nil {
		return ConvergencePlan{}, fmt.Errorf("convergence planner is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return ConvergencePlan{}, err
	}

	snapshot, err := planner.source.ReadConvergenceSnapshot(ctx)
	if err != nil {
		return ConvergencePlan{}, fmt.Errorf("read convergence snapshot: %w", err)
	}
	canonical, err := canonicalSnapshot(snapshot)
	if err != nil {
		return ConvergencePlan{}, err
	}

	appliedForDiscovery := cloneManifest(canonical.Applied)
	observed, err := planner.discoverer.DiscoverOwnedResources(ctx, appliedForDiscovery)
	if err != nil {
		return ConvergencePlan{}, fmt.Errorf("discover vpnctl-owned resources: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return ConvergencePlan{}, err
	}
	observed, err = canonicalObservations(observed)
	if err != nil {
		return ConvergencePlan{}, err
	}

	changes, err := desiredChanges(canonical)
	if err != nil {
		return ConvergencePlan{}, err
	}
	drift := ownedDrift(canonical.Applied.Resources, observed)
	plan := ConvergencePlan{
		DesiredGeneration: canonical.Desired.Generation,
		AppliedGeneration: canonical.Applied.Generation,
		Impact:            ConvergenceImpactNone,
		Changes:           changes,
		Drift:             drift,
	}
	for _, change := range changes {
		plan.Impact = maximumConvergenceImpact(plan.Impact, change.Impact)
	}
	for _, item := range drift {
		plan.Impact = maximumConvergenceImpact(plan.Impact, item.Impact)
	}
	if err := plan.Validate(); err != nil {
		return ConvergencePlan{}, fmt.Errorf("%w: result: %v", ErrConvergencePlanInvalid, err)
	}
	return plan, nil
}

func NewConvergenceManifest(generation uint64, resources []ManagedResource) (ConvergenceManifest, error) {
	canonical, err := canonicalResources(resources, "manifest resources")
	if err != nil {
		return ConvergenceManifest{}, err
	}
	manifest := ConvergenceManifest{
		SchemaVersion: ConvergenceManifestSchemaVersion,
		Generation:    generation,
		Resources:     canonical,
	}
	if err := manifest.Validate(); err != nil {
		return ConvergenceManifest{}, err
	}
	return manifest, nil
}

// BindPendingOperation accepts only a validated authoritative operation still
// in the pending state. Resource compilers supply the exact managed resources
// affected by its retained desired intent.
func BindPendingOperation(operation model.Operation, resources []ManagedResourceKey) (PendingOperation, error) {
	if err := operation.Validate(); err != nil {
		return PendingOperation{}, fmt.Errorf("validate authoritative operation: %w", err)
	}
	if operation.State != model.OperationPending {
		return PendingOperation{}, fmt.Errorf("%w: operation %s is %s, not pending", ErrConvergencePlanInvalid, operation.ID, operation.State)
	}
	pending := PendingOperation{
		ID: operation.ID, Type: string(operation.Type), TargetKind: operation.TargetKind, TargetID: operation.TargetID,
		ExpectedGeneration: operation.ExpectedGeneration, DesiredGeneration: operation.DesiredGeneration,
		Resources: append([]ManagedResourceKey(nil), resources...),
	}
	if err := pending.validate(operation.DesiredGeneration); err != nil {
		return PendingOperation{}, fmt.Errorf("%w: bind operation %s: %v", ErrConvergencePlanInvalid, operation.ID, err)
	}
	sort.Slice(pending.Resources, func(left, right int) bool {
		return resourceOrder(pending.Resources[left]) < resourceOrder(pending.Resources[right])
	})
	return pending, nil
}

func (manifest ConvergenceManifest) Validate() error {
	if manifest.SchemaVersion != ConvergenceManifestSchemaVersion {
		return fmt.Errorf("schema version must be %d", ConvergenceManifestSchemaVersion)
	}
	if manifest.Generation == 0 {
		return fmt.Errorf("generation must be positive")
	}
	if manifest.Resources == nil {
		return fmt.Errorf("resources must be present")
	}
	_, err := canonicalResources(manifest.Resources, "manifest resources")
	return err
}

// ManagedFingerprint hashes normalized non-secret material. It is provided so
// state/unit/network adapters do not invent incompatible digest encodings.
func ManagedFingerprint(material []byte) string {
	digest := sha256.Sum256(material)
	return hex.EncodeToString(digest[:])
}

// ArtifactConvergenceManifest converts the existing deterministic renderer
// manifest into the common file-resource representation. Mode, content hash,
// and direct source/policy/credential generations are all covered.
func ArtifactConvergenceManifest(
	component string,
	manifest render.ArtifactManifest,
	applyImpact ConvergenceImpact,
	removeImpact ConvergenceImpact,
) (ConvergenceManifest, error) {
	if err := manifest.Validate(); err != nil {
		return ConvergenceManifest{}, fmt.Errorf("validate artifact manifest: %w", err)
	}
	resources := make([]ManagedResource, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		revisionMaterial, err := json.Marshal(artifact)
		if err != nil {
			return ConvergenceManifest{}, fmt.Errorf("encode artifact fingerprint material: %w", err)
		}
		runtimeMaterial, err := json.Marshal(struct {
			Type          string `json:"type"`
			Mode          string `json:"mode"`
			ContentSHA256 string `json:"content_sha256"`
		}{Type: "regular", Mode: artifact.Mode, ContentSHA256: artifact.ContentSHA256})
		if err != nil {
			return ConvergenceManifest{}, fmt.Errorf("encode artifact runtime fingerprint material: %w", err)
		}
		resources = append(resources, ManagedResource{
			Key:            ManagedResourceKey{Component: component, Kind: ManagedResourceFile, ID: artifact.Path},
			RevisionSHA256: ManagedFingerprint(revisionMaterial), RuntimeSHA256: ManagedFingerprint(runtimeMaterial),
			ApplyImpact: applyImpact, RemoveImpact: removeImpact,
		})
	}
	return NewConvergenceManifest(manifest.SourceStateGeneration, resources)
}

func (plan ConvergencePlan) Validate() error {
	if plan.DesiredGeneration == 0 || plan.AppliedGeneration == 0 {
		return fmt.Errorf("desired and applied generations must be positive")
	}
	if plan.DesiredGeneration < plan.AppliedGeneration {
		return fmt.Errorf("desired generation precedes applied generation")
	}
	if !validConvergenceImpact(plan.Impact) {
		return fmt.Errorf("unsupported aggregate impact %q", plan.Impact)
	}
	if plan.Changes == nil || plan.Drift == nil {
		return fmt.Errorf("changes and drift must be present")
	}
	wantImpact := ConvergenceImpactNone
	previous := ""
	for index, change := range plan.Changes {
		if err := change.validate(); err != nil {
			return fmt.Errorf("change %d: %w", index, err)
		}
		order := resourceOrder(change.Resource)
		if index > 0 && order <= previous {
			return fmt.Errorf("changes must have unique resources in ascending order")
		}
		previous = order
		wantImpact = maximumConvergenceImpact(wantImpact, change.Impact)
	}
	previous = ""
	for index, item := range plan.Drift {
		if err := item.validate(); err != nil {
			return fmt.Errorf("drift %d: %w", index, err)
		}
		order := resourceOrder(item.Resource)
		if index > 0 && order <= previous {
			return fmt.Errorf("drift must have unique resources in ascending order")
		}
		previous = order
		wantImpact = maximumConvergenceImpact(wantImpact, item.Impact)
	}
	if plan.Impact != wantImpact {
		return fmt.Errorf("aggregate impact %q does not match %q", plan.Impact, wantImpact)
	}
	return nil
}

func canonicalSnapshot(snapshot ConvergenceSnapshot) (ConvergenceSnapshot, error) {
	desired, err := NewConvergenceManifest(snapshot.Desired.Generation, snapshot.Desired.Resources)
	if err != nil || snapshot.Desired.SchemaVersion != ConvergenceManifestSchemaVersion {
		if err == nil {
			err = fmt.Errorf("schema version must be %d", ConvergenceManifestSchemaVersion)
		}
		return ConvergenceSnapshot{}, fmt.Errorf("%w: desired manifest: %v", ErrConvergencePlanInvalid, err)
	}
	applied, err := NewConvergenceManifest(snapshot.Applied.Generation, snapshot.Applied.Resources)
	if err != nil || snapshot.Applied.SchemaVersion != ConvergenceManifestSchemaVersion {
		if err == nil {
			err = fmt.Errorf("schema version must be %d", ConvergenceManifestSchemaVersion)
		}
		return ConvergenceSnapshot{}, fmt.Errorf("%w: applied manifest: %v", ErrConvergencePlanInvalid, err)
	}
	if desired.Generation < applied.Generation {
		return ConvergenceSnapshot{}, fmt.Errorf("%w: desired generation precedes applied generation", ErrConvergencePlanInvalid)
	}
	if snapshot.Pending == nil {
		return ConvergenceSnapshot{}, fmt.Errorf("%w: pending operations must be present", ErrConvergencePlanInvalid)
	}
	pending := append([]PendingOperation(nil), snapshot.Pending...)
	for index := range pending {
		pending[index].Resources = append([]ManagedResourceKey(nil), pending[index].Resources...)
		if err := pending[index].validate(desired.Generation); err != nil {
			return ConvergenceSnapshot{}, fmt.Errorf("%w: pending operation %d: %v", ErrConvergencePlanInvalid, index, err)
		}
		sort.Slice(pending[index].Resources, func(left, right int) bool {
			return resourceOrder(pending[index].Resources[left]) < resourceOrder(pending[index].Resources[right])
		})
	}
	sort.Slice(pending, func(left, right int) bool { return pending[left].ID < pending[right].ID })
	for index := 1; index < len(pending); index++ {
		if pending[index].ID == pending[index-1].ID {
			return ConvergenceSnapshot{}, fmt.Errorf("%w: duplicate pending operation %q", ErrConvergencePlanInvalid, pending[index].ID)
		}
	}
	return ConvergenceSnapshot{Desired: desired, Applied: applied, Pending: pending}, nil
}

func desiredChanges(snapshot ConvergenceSnapshot) ([]DesiredChange, error) {
	desired := resourcesByKey(snapshot.Desired.Resources)
	applied := resourcesByKey(snapshot.Applied.Resources)
	keys := unionResourceKeys(desired, applied)
	differences := make(map[string]DesiredChangeKind)
	for _, key := range keys {
		before, hadBefore := applied[key]
		after, hasAfter := desired[key]
		switch {
		case !hadBefore:
			differences[key] = DesiredCreate
		case !hasAfter:
			differences[key] = DesiredDelete
		case before.RevisionSHA256 != after.RevisionSHA256:
			differences[key] = DesiredUpdate
		}
	}

	bindings := make(map[string]PendingOperation, len(differences))
	for _, operation := range snapshot.Pending {
		boundDifference := false
		for _, resource := range operation.Resources {
			key := resourceOrder(resource)
			if _, changed := differences[key]; !changed {
				return nil, fmt.Errorf("%w: pending operation %s binds unchanged resource %s", ErrConvergencePlanInvalid, operation.ID, key)
			}
			if prior, duplicate := bindings[key]; duplicate {
				return nil, fmt.Errorf("%w: resource %s is bound by pending operations %s and %s", ErrConvergencePlanInvalid, key, prior.ID, operation.ID)
			}
			bindings[key] = operation
			boundDifference = true
		}
		if !boundDifference {
			return nil, fmt.Errorf("%w: pending operation %s has no desired difference", ErrConvergencePlanInvalid, operation.ID)
		}
	}

	changes := make([]DesiredChange, 0, len(differences))
	for _, key := range keys {
		kind, changed := differences[key]
		if !changed {
			continue
		}
		operation, registered := bindings[key]
		if !registered {
			return nil, fmt.Errorf("%w: desired difference %s has no registered pending operation", ErrConvergencePlanInvalid, key)
		}
		before, hadBefore := applied[key]
		after, hasAfter := desired[key]
		change := DesiredChange{
			OperationID: operation.ID, OperationType: operation.Type,
			TargetKind: operation.TargetKind, TargetID: operation.TargetID,
			Kind: kind,
		}
		switch kind {
		case DesiredCreate:
			change.Resource = after.Key
			change.Impact = after.ApplyImpact
			change.ToSHA256 = after.RevisionSHA256
		case DesiredUpdate:
			change.Resource = after.Key
			change.Impact = after.ApplyImpact
			change.FromSHA256 = before.RevisionSHA256
			change.ToSHA256 = after.RevisionSHA256
		case DesiredDelete:
			change.Resource = before.Key
			change.Impact = before.RemoveImpact
			change.FromSHA256 = before.RevisionSHA256
		}
		if !hadBefore && kind != DesiredCreate || !hasAfter && kind != DesiredDelete {
			return nil, fmt.Errorf("%w: inconsistent desired difference %s", ErrConvergencePlanInvalid, key)
		}
		changes = append(changes, change)
	}
	return changes, nil
}

func ownedDrift(applied []ManagedResource, observed []OwnedResourceObservation) []OwnedDrift {
	expected := resourcesByKey(applied)
	actual := observationsByKey(observed)
	keys := unionObservationKeys(expected, actual)
	drift := make([]OwnedDrift, 0)
	for _, key := range keys {
		want, expectedResource := expected[key]
		got, observedResource := actual[key]
		switch {
		case !expectedResource:
			drift = append(drift, OwnedDrift{
				Resource: got.Key, Kind: OwnedDriftUnexpected,
				Impact: got.RemoveImpact, ActualSHA256: got.RuntimeSHA256,
			})
		case !observedResource:
			drift = append(drift, OwnedDrift{
				Resource: want.Key, Kind: OwnedDriftMissing,
				Impact: want.ApplyImpact, ExpectedSHA256: want.RuntimeSHA256,
			})
		case want.RuntimeSHA256 != got.RuntimeSHA256:
			drift = append(drift, OwnedDrift{
				Resource: want.Key, Kind: OwnedDriftModified,
				Impact: want.ApplyImpact, ExpectedSHA256: want.RuntimeSHA256, ActualSHA256: got.RuntimeSHA256,
			})
		}
	}
	return drift
}

func canonicalResources(resources []ManagedResource, label string) ([]ManagedResource, error) {
	if resources == nil {
		return nil, fmt.Errorf("%w: %s must be present", ErrConvergencePlanInvalid, label)
	}
	result := append([]ManagedResource(nil), resources...)
	for index, resource := range result {
		if err := resource.validate(); err != nil {
			return nil, fmt.Errorf("%w: %s %d: %v", ErrConvergencePlanInvalid, label, index, err)
		}
	}
	sort.Slice(result, func(left, right int) bool { return resourceOrder(result[left].Key) < resourceOrder(result[right].Key) })
	for index := 1; index < len(result); index++ {
		if resourceOrder(result[index].Key) == resourceOrder(result[index-1].Key) {
			return nil, fmt.Errorf("%w: %s duplicates resource %s", ErrConvergencePlanInvalid, label, resourceOrder(result[index].Key))
		}
	}
	return result, nil
}

func (resource ManagedResource) validate() error {
	if err := resource.Key.validate(); err != nil {
		return err
	}
	if err := validateFingerprint(resource.RevisionSHA256); err != nil {
		return fmt.Errorf("revision: %w", err)
	}
	if err := validateFingerprint(resource.RuntimeSHA256); err != nil {
		return fmt.Errorf("runtime: %w", err)
	}
	if !validConvergenceImpact(resource.ApplyImpact) || !validConvergenceImpact(resource.RemoveImpact) {
		return fmt.Errorf("resource impacts are unsupported")
	}
	return nil
}

func canonicalObservations(observed []OwnedResourceObservation) ([]OwnedResourceObservation, error) {
	if observed == nil {
		return nil, fmt.Errorf("%w: owned observations must be present", ErrConvergencePlanInvalid)
	}
	result := append([]OwnedResourceObservation(nil), observed...)
	for index, observation := range result {
		if err := observation.Key.validate(); err != nil {
			return nil, fmt.Errorf("%w: owned observation %d: %v", ErrConvergencePlanInvalid, index, err)
		}
		if err := validateFingerprint(observation.RuntimeSHA256); err != nil {
			return nil, fmt.Errorf("%w: owned observation %d runtime: %v", ErrConvergencePlanInvalid, index, err)
		}
		if !validConvergenceImpact(observation.RemoveImpact) {
			return nil, fmt.Errorf("%w: owned observation %d removal impact is unsupported", ErrConvergencePlanInvalid, index)
		}
	}
	sort.Slice(result, func(left, right int) bool { return resourceOrder(result[left].Key) < resourceOrder(result[right].Key) })
	for index := 1; index < len(result); index++ {
		if resourceOrder(result[index].Key) == resourceOrder(result[index-1].Key) {
			return nil, fmt.Errorf("%w: owned observations duplicate resource %s", ErrConvergencePlanInvalid, resourceOrder(result[index].Key))
		}
	}
	return result, nil
}

func (key ManagedResourceKey) validate() error {
	if !resourceComponentPattern.MatchString(key.Component) {
		return fmt.Errorf("component must be a stable lower-case identifier")
	}
	switch key.Kind {
	case ManagedResourceState, ManagedResourceFile, ManagedResourceUnit, ManagedResourceNetwork:
	default:
		return fmt.Errorf("resource kind %q is unsupported", key.Kind)
	}
	if key.ID == "" || len(key.ID) > 4096 || strings.TrimSpace(key.ID) != key.ID || strings.ContainsAny(key.ID, "\x00\r\n") {
		return fmt.Errorf("resource ID must be a non-empty trimmed single line of at most 4096 bytes")
	}
	return nil
}

func (operation PendingOperation) validate(maximumGeneration uint64) error {
	if err := validateOperationID(operation.ID); err != nil {
		return err
	}
	if !operationTypePattern.MatchString(operation.Type) {
		return fmt.Errorf("type must be a stable lower-case identifier")
	}
	if err := validateOperationTarget(operation.TargetKind, operation.TargetID); err != nil {
		return err
	}
	if operation.ExpectedGeneration == 0 || operation.DesiredGeneration < operation.ExpectedGeneration || operation.DesiredGeneration > maximumGeneration {
		return fmt.Errorf("operation generations are invalid")
	}
	if operation.Resources == nil || len(operation.Resources) == 0 {
		return fmt.Errorf("resources must be present and non-empty")
	}
	seen := make(map[string]struct{}, len(operation.Resources))
	for index, resource := range operation.Resources {
		if err := resource.validate(); err != nil {
			return fmt.Errorf("resource %d: %w", index, err)
		}
		key := resourceOrder(resource)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("resource %s is duplicated", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (change DesiredChange) validate() error {
	if validateOperationID(change.OperationID) != nil || !operationTypePattern.MatchString(change.OperationType) {
		return fmt.Errorf("operation identity is invalid")
	}
	if err := validateOperationTarget(change.TargetKind, change.TargetID); err != nil {
		return err
	}
	if err := change.Resource.validate(); err != nil {
		return err
	}
	if !validConvergenceImpact(change.Impact) {
		return fmt.Errorf("impact is unsupported")
	}
	switch change.Kind {
	case DesiredCreate:
		if change.FromSHA256 != "" || validateFingerprint(change.ToSHA256) != nil {
			return fmt.Errorf("create hashes are invalid")
		}
	case DesiredUpdate:
		if validateFingerprint(change.FromSHA256) != nil || validateFingerprint(change.ToSHA256) != nil || change.FromSHA256 == change.ToSHA256 {
			return fmt.Errorf("update hashes are invalid")
		}
	case DesiredDelete:
		if validateFingerprint(change.FromSHA256) != nil || change.ToSHA256 != "" {
			return fmt.Errorf("delete hashes are invalid")
		}
	default:
		return fmt.Errorf("change kind %q is unsupported", change.Kind)
	}
	return nil
}

func (drift OwnedDrift) validate() error {
	if err := drift.Resource.validate(); err != nil {
		return err
	}
	if !validConvergenceImpact(drift.Impact) {
		return fmt.Errorf("impact is unsupported")
	}
	switch drift.Kind {
	case OwnedDriftMissing:
		if validateFingerprint(drift.ExpectedSHA256) != nil || drift.ActualSHA256 != "" {
			return fmt.Errorf("missing drift hashes are invalid")
		}
	case OwnedDriftModified:
		if validateFingerprint(drift.ExpectedSHA256) != nil || validateFingerprint(drift.ActualSHA256) != nil || drift.ExpectedSHA256 == drift.ActualSHA256 {
			return fmt.Errorf("modified drift hashes are invalid")
		}
	case OwnedDriftUnexpected:
		if drift.ExpectedSHA256 != "" || validateFingerprint(drift.ActualSHA256) != nil {
			return fmt.Errorf("unexpected drift hashes are invalid")
		}
	default:
		return fmt.Errorf("drift kind %q is unsupported", drift.Kind)
	}
	return nil
}

func cloneManifest(manifest ConvergenceManifest) ConvergenceManifest {
	manifest.Resources = append([]ManagedResource(nil), manifest.Resources...)
	return manifest
}

func resourcesByKey(resources []ManagedResource) map[string]ManagedResource {
	result := make(map[string]ManagedResource, len(resources))
	for _, resource := range resources {
		result[resourceOrder(resource.Key)] = resource
	}
	return result
}

func observationsByKey(observations []OwnedResourceObservation) map[string]OwnedResourceObservation {
	result := make(map[string]OwnedResourceObservation, len(observations))
	for _, observation := range observations {
		result[resourceOrder(observation.Key)] = observation
	}
	return result
}

func unionResourceKeys(left, right map[string]ManagedResource) []string {
	keys := make([]string, 0, len(left)+len(right))
	for key := range left {
		keys = append(keys, key)
	}
	for key := range right {
		if _, exists := left[key]; !exists {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func unionObservationKeys(left map[string]ManagedResource, right map[string]OwnedResourceObservation) []string {
	keys := make([]string, 0, len(left)+len(right))
	for key := range left {
		keys = append(keys, key)
	}
	for key := range right {
		if _, exists := left[key]; !exists {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func resourceOrder(key ManagedResourceKey) string {
	return key.Component + "\x00" + string(key.Kind) + "\x00" + key.ID
}

func validateFingerprint(value string) error {
	if len(value) != sha256.Size*2 {
		return fmt.Errorf("fingerprint must be a lowercase SHA-256")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("fingerprint must be a lowercase SHA-256")
	}
	return nil
}

func validateOperationID(value string) error {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("operation ID must be a non-empty trimmed single line of at most 128 bytes")
	}
	return nil
}

func validateOperationTarget(kind, id string) error {
	if (kind == "") != (id == "") {
		return fmt.Errorf("target kind and ID must be present together")
	}
	if kind != "" && (!resourceComponentPattern.MatchString(kind) || len(id) > 128 || strings.TrimSpace(id) == "" || strings.ContainsAny(id, "\x00\r\n")) {
		return fmt.Errorf("target is invalid")
	}
	return nil
}

func validConvergenceImpact(impact ConvergenceImpact) bool {
	return impact == ConvergenceImpactNone || impact == ConvergenceImpactAvailability || impact == ConvergenceImpactDestructive
}

func maximumConvergenceImpact(left, right ConvergenceImpact) ConvergenceImpact {
	if convergenceImpactRank(right) > convergenceImpactRank(left) {
		return right
	}
	return left
}

func convergenceImpactRank(impact ConvergenceImpact) int {
	switch impact {
	case ConvergenceImpactAvailability:
		return 1
	case ConvergenceImpactDestructive:
		return 2
	default:
		return 0
	}
}
