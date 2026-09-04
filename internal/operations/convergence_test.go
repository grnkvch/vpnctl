package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/render"
)

func TestConvergencePlannerSeparatesPendingDesiredDiffFromOwnedDriftDeterministically(t *testing.T) {
	t.Parallel()

	stateKey := ManagedResourceKey{Component: "control", Kind: ManagedResourceState, ID: "fleet"}
	extraKey := ManagedResourceKey{Component: "ingress", Kind: ManagedResourceFile, ID: "/etc/vpnctl/extra.conf"}
	ingressKey := ManagedResourceKey{Component: "ingress", Kind: ManagedResourceFile, ID: "/etc/vpnctl/nginx.conf"}
	networkKey := ManagedResourceKey{Component: "routing", Kind: ManagedResourceNetwork, ID: "table-inet-vpnctl"}
	unitKey := ManagedResourceKey{Component: "transport", Kind: ManagedResourceUnit, ID: "vpnctl-standard.service"}
	orphanKey := ManagedResourceKey{Component: "ingress", Kind: ManagedResourceFile, ID: "/etc/vpnctl/orphan.conf"}

	applied := convergenceManifest(t, 7, []ManagedResource{
		resource(stateKey, "state-applied", ConvergenceImpactNone, ConvergenceImpactDestructive),
		resource(ingressKey, "ingress-applied", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
		resource(networkKey, "network-applied", ConvergenceImpactAvailability, ConvergenceImpactDestructive),
		resource(unitKey, "unit-applied", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	})
	desired := convergenceManifest(t, 9, []ManagedResource{
		resource(unitKey, "unit-applied", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
		resource(ingressKey, "ingress-desired", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
		resource(extraKey, "extra-desired", ConvergenceImpactNone, ConvergenceImpactNone),
		resource(stateKey, "state-desired", ConvergenceImpactNone, ConvergenceImpactDestructive),
	})
	pending := []PendingOperation{
		{
			ID: "operation-2", Type: "expose-remove", TargetKind: "expose", TargetID: "telegram",
			ExpectedGeneration: 8, DesiredGeneration: 9, Resources: []ManagedResourceKey{networkKey, extraKey},
		},
		{
			ID: "operation-1", Type: "apply", ExpectedGeneration: 7, DesiredGeneration: 8,
			Resources: []ManagedResourceKey{ingressKey, stateKey},
		},
	}
	observed := []OwnedResourceObservation{
		observation(networkKey, "network-applied", ConvergenceImpactDestructive),
		// Actual matching future desired remains drift from the applied baseline.
		observation(ingressKey, "ingress-desired", ConvergenceImpactAvailability),
		observation(orphanKey, "owned-orphan", ConvergenceImpactNone),
		observation(stateKey, "state-applied", ConvergenceImpactDestructive),
	}

	first := planConvergence(t, ConvergenceSnapshot{Desired: desired, Applied: applied, Pending: pending}, observed)
	second := planConvergence(t, ConvergenceSnapshot{
		Desired: reverseManifest(desired), Applied: reverseManifest(applied), Pending: reversePending(pending),
	}, reverseObservations(observed))
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("input order changed plan:\n%s\n%s", firstJSON, secondJSON)
	}

	if first.Impact != ConvergenceImpactDestructive || first.DesiredGeneration != 9 || first.AppliedGeneration != 7 {
		t.Fatalf("plan header = %+v", first)
	}
	if got := desiredChangeSummary(first.Changes); got != "control/state/fleet:update:none,ingress/file//etc/vpnctl/extra.conf:create:none,ingress/file//etc/vpnctl/nginx.conf:update:availability,routing/network/table-inet-vpnctl:delete:destructive" {
		t.Fatalf("changes = %q", got)
	}
	if got := driftSummary(first.Drift); got != "ingress/file//etc/vpnctl/nginx.conf:modified:availability,ingress/file//etc/vpnctl/orphan.conf:unexpected:none,transport/unit/vpnctl-standard.service:missing:availability" {
		t.Fatalf("drift = %q", got)
	}
	if first.Changes[2].ToSHA256 != first.Drift[0].ActualSHA256 {
		t.Fatal("actual bytes matching desired incorrectly removed overlapping drift")
	}
	if first.Changes[2].FromSHA256 != first.Drift[0].ExpectedSHA256 {
		t.Fatal("pending and drift did not retain the same applied baseline")
	}
}

func TestConvergencePlanExposesOnlyReadDependenciesAndDoesNotMutateHost(t *testing.T) {
	t.Parallel()

	sentinelPath := t.TempDir() + "/sentinel"
	if err := os.WriteFile(sentinelPath, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := ManagedResourceKey{Component: "routing", Kind: ManagedResourceNetwork, ID: "policy-rule"}
	manifest := convergenceManifest(t, 3, []ManagedResource{
		resource(key, "same", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	})
	audit := &convergenceMutationAudit{}
	source := &auditedConvergenceSource{
		audit:    audit,
		snapshot: ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}},
	}
	discovery := &auditedOwnedDiscovery{
		audit: audit, sentinelPath: sentinelPath,
		observed: []OwnedResourceObservation{observation(key, "same", ConvergenceImpactAvailability)},
	}
	beforeSnapshot := source.snapshot
	planner, err := NewConvergencePlanner(source, discovery)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 0 || len(plan.Drift) != 0 || plan.Impact != ConvergenceImpactNone {
		t.Fatalf("no-op plan = %+v", plan)
	}
	if audit.stateReads != 1 || audit.fileReads != 1 || audit.unitReads != 1 || audit.networkReads != 1 {
		t.Fatalf("read audit = %+v", audit)
	}
	if audit.stateWrites != 0 || audit.fileWrites != 0 || audit.unitMutations != 0 || audit.networkMutations != 0 {
		t.Fatalf("planning mutated a host boundary: %+v", audit)
	}
	if content, err := os.ReadFile(sentinelPath); err != nil || string(content) != "unchanged" {
		t.Fatalf("sentinel after plan = %q, %v", content, err)
	}
	if !reflect.DeepEqual(source.snapshot, beforeSnapshot) {
		t.Fatal("planner mutated its authoritative source snapshot")
	}
}

func TestConvergencePlannerKeepsRevisionOnlyPendingChangeOutOfRuntimeDrift(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "transport", Kind: ManagedResourceFile, ID: "/etc/vpnctl/transport.json"}
	runtimeFingerprint := ManagedFingerprint([]byte("same-runtime"))
	appliedResource := ManagedResource{
		Key: key, RevisionSHA256: ManagedFingerprint([]byte("source-generation-1")), RuntimeSHA256: runtimeFingerprint,
		ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
	}
	desiredResource := appliedResource
	desiredResource.RevisionSHA256 = ManagedFingerprint([]byte("source-generation-2"))
	applied := convergenceManifest(t, 10, []ManagedResource{appliedResource})
	desired := convergenceManifest(t, 11, []ManagedResource{desiredResource})
	plan := planConvergence(t, ConvergenceSnapshot{
		Desired: desired, Applied: applied,
		Pending: []PendingOperation{{
			ID: "operation-1", Type: "apply", ExpectedGeneration: 10, DesiredGeneration: 11,
			Resources: []ManagedResourceKey{key},
		}},
	}, []OwnedResourceObservation{{Key: key, RuntimeSHA256: runtimeFingerprint, RemoveImpact: ConvergenceImpactAvailability}})
	if len(plan.Changes) != 1 || plan.Changes[0].Kind != DesiredUpdate || len(plan.Drift) != 0 {
		t.Fatalf("revision-only plan = %+v", plan)
	}
}

func TestConvergencePlannerRejectsUnregisteredOrAmbiguousDesiredDiff(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "dns", Kind: ManagedResourceFile, ID: "/etc/vpnctl/dns.conf"}
	before := convergenceManifest(t, 1, []ManagedResource{resource(key, "before", ConvergenceImpactAvailability, ConvergenceImpactAvailability)})
	after := convergenceManifest(t, 2, []ManagedResource{resource(key, "after", ConvergenceImpactAvailability, ConvergenceImpactAvailability)})
	validOperation := PendingOperation{
		ID: "operation-1", Type: "apply", ExpectedGeneration: 1, DesiredGeneration: 2,
		Resources: []ManagedResourceKey{key},
	}
	tests := []struct {
		name    string
		pending []PendingOperation
	}{
		{name: "unregistered", pending: []PendingOperation{}},
		{name: "duplicate binding", pending: []PendingOperation{validOperation, {
			ID: "operation-2", Type: "repair", ExpectedGeneration: 1, DesiredGeneration: 2,
			Resources: []ManagedResourceKey{key},
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := staticConvergenceSource{snapshot: ConvergenceSnapshot{Desired: after, Applied: before, Pending: test.pending}}
			planner, _ := NewConvergencePlanner(source, staticOwnedDiscovery{observed: observationsFromResources(before.Resources)})
			if _, err := planner.Plan(context.Background()); !errors.Is(err, ErrConvergencePlanInvalid) {
				t.Fatalf("Plan() error = %v", err)
			}
		})
	}
}

func TestBindPendingOperationAcceptsOnlyAuthoritativePendingState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	operation := model.Operation{
		SchemaVersion:      model.ResourceSchemaVersion,
		ID:                 "00000000-0000-4000-8000-000000000001",
		Type:               model.OperationApply,
		State:              model.OperationPending,
		ExpectedGeneration: 4, DesiredGeneration: 5,
		Steps: []model.OperationStep{}, CreatedAt: now, UpdatedAt: now,
	}
	key := ManagedResourceKey{Component: "dns", Kind: ManagedResourceFile, ID: "/etc/vpnctl/dns.conf"}
	pending, err := BindPendingOperation(operation, []ManagedResourceKey{key})
	if err != nil {
		t.Fatal(err)
	}
	if pending.ID != operation.ID || pending.Type != "apply" || len(pending.Resources) != 1 || pending.Resources[0] != key {
		t.Fatalf("binding = %+v", pending)
	}
	operation.State = model.OperationActive
	operation.Steps = []model.OperationStep{{Name: "stage", State: model.OperationActive, UpdatedAt: now}}
	if _, err := BindPendingOperation(operation, []ManagedResourceKey{key}); !errors.Is(err, ErrConvergencePlanInvalid) {
		t.Fatalf("active operation binding error = %v", err)
	}
}

func TestConvergencePlannerRejectsInvalidOwnedObservationAndPropagatesReadFailures(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "dns", Kind: ManagedResourceFile, ID: "/etc/vpnctl/dns.conf"}
	manifest := convergenceManifest(t, 1, []ManagedResource{resource(key, "same", ConvergenceImpactNone, ConvergenceImpactNone)})
	snapshot := ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}}
	sourceFailure := errors.New("state unavailable")
	discoveryFailure := errors.New("inspection unavailable")

	planner, _ := NewConvergencePlanner(staticConvergenceSource{err: sourceFailure}, staticOwnedDiscovery{})
	if _, err := planner.Plan(context.Background()); !errors.Is(err, sourceFailure) {
		t.Fatalf("source failure = %v", err)
	}
	planner, _ = NewConvergencePlanner(staticConvergenceSource{snapshot: snapshot}, staticOwnedDiscovery{err: discoveryFailure})
	if _, err := planner.Plan(context.Background()); !errors.Is(err, discoveryFailure) {
		t.Fatalf("discovery failure = %v", err)
	}
	planner, _ = NewConvergencePlanner(staticConvergenceSource{snapshot: snapshot}, staticOwnedDiscovery{observed: []OwnedResourceObservation{
		observation(key, "same", ConvergenceImpactNone),
		observation(key, "same", ConvergenceImpactNone),
	}})
	if _, err := planner.Plan(context.Background()); !errors.Is(err, ErrConvergencePlanInvalid) {
		t.Fatalf("duplicate observation error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := planner.Plan(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled plan error = %v", err)
	}
}

func TestArtifactConvergenceManifestCoversModeAndGenerationsWithoutPlaintext(t *testing.T) {
	t.Parallel()

	artifact := render.ArtifactInput{
		Path: "/etc/vpnctl/private.conf", Mode: 0o600, Content: []byte("plaintext-secret-canary"),
		SourceGenerations: []render.SourceGeneration{{Kind: "node", ID: "node-1", Generation: 2}},
	}
	firstArtifacts, err := render.BuildManifest(5, []render.ArtifactInput{artifact})
	if err != nil {
		t.Fatal(err)
	}
	first, err := ArtifactConvergenceManifest("transport", firstArtifacts, ConvergenceImpactAvailability, ConvergenceImpactAvailability)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Mode = 0o640
	secondArtifacts, err := render.BuildManifest(6, []render.ArtifactInput{artifact})
	if err != nil {
		t.Fatal(err)
	}
	second, err := ArtifactConvergenceManifest("transport", secondArtifacts, ConvergenceImpactAvailability, ConvergenceImpactAvailability)
	if err != nil {
		t.Fatal(err)
	}
	if first.Resources[0].RevisionSHA256 == second.Resources[0].RevisionSHA256 || first.Resources[0].RuntimeSHA256 == second.Resources[0].RuntimeSHA256 {
		t.Fatal("mode change did not alter convergence fingerprint")
	}
	artifact.Mode = 0o600
	artifact.SourceGenerations[0].Generation++
	thirdArtifacts, err := render.BuildManifest(7, []render.ArtifactInput{artifact})
	if err != nil {
		t.Fatal(err)
	}
	third, err := ArtifactConvergenceManifest("transport", thirdArtifacts, ConvergenceImpactAvailability, ConvergenceImpactAvailability)
	if err != nil {
		t.Fatal(err)
	}
	if first.Resources[0].RevisionSHA256 == third.Resources[0].RevisionSHA256 || first.Resources[0].RuntimeSHA256 != third.Resources[0].RuntimeSHA256 {
		t.Fatal("dependency generation must change revision but not observable runtime fingerprint")
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, artifact.Content) || bytes.Contains(encoded, []byte("plaintext-secret-canary")) {
		t.Fatal("convergence manifest contains artifact plaintext")
	}
}

type staticConvergenceSource struct {
	snapshot ConvergenceSnapshot
	err      error
}

func (source staticConvergenceSource) ReadConvergenceSnapshot(context.Context) (ConvergenceSnapshot, error) {
	return source.snapshot, source.err
}

type staticOwnedDiscovery struct {
	observed []OwnedResourceObservation
	err      error
}

func (discovery staticOwnedDiscovery) DiscoverOwnedResources(context.Context, ConvergenceManifest) ([]OwnedResourceObservation, error) {
	return append([]OwnedResourceObservation(nil), discovery.observed...), discovery.err
}

type convergenceMutationAudit struct {
	stateReads, fileReads, unitReads, networkReads           int
	stateWrites, fileWrites, unitMutations, networkMutations int
}

type auditedConvergenceSource struct {
	audit    *convergenceMutationAudit
	snapshot ConvergenceSnapshot
}

func (source *auditedConvergenceSource) ReadConvergenceSnapshot(context.Context) (ConvergenceSnapshot, error) {
	source.audit.stateReads++
	return source.snapshot, nil
}

// These mutation methods deliberately are not part of ConvergenceSnapshotSource.
func (source *auditedConvergenceSource) SaveConvergenceSnapshot(ConvergenceSnapshot) {
	source.audit.stateWrites++
}

type auditedOwnedDiscovery struct {
	audit        *convergenceMutationAudit
	sentinelPath string
	observed     []OwnedResourceObservation
}

func (discovery *auditedOwnedDiscovery) DiscoverOwnedResources(_ context.Context, applied ConvergenceManifest) ([]OwnedResourceObservation, error) {
	discovery.audit.fileReads++
	if _, err := os.ReadFile(discovery.sentinelPath); err != nil {
		return nil, err
	}
	discovery.audit.unitReads++
	discovery.audit.networkReads++
	// Mutating this input proves the planner passed an isolated manifest copy.
	if len(applied.Resources) != 0 {
		applied.Resources[0].RevisionSHA256 = ManagedFingerprint([]byte("observer-local-change"))
	}
	return append([]OwnedResourceObservation(nil), discovery.observed...), nil
}

// These methods model forbidden capabilities and are intentionally absent from
// OwnedResourceDiscoverer.
func (discovery *auditedOwnedDiscovery) WriteFile()     { discovery.audit.fileWrites++ }
func (discovery *auditedOwnedDiscovery) MutateUnit()    { discovery.audit.unitMutations++ }
func (discovery *auditedOwnedDiscovery) MutateNetwork() { discovery.audit.networkMutations++ }

func convergenceManifest(t *testing.T, generation uint64, resources []ManagedResource) ConvergenceManifest {
	t.Helper()
	manifest, err := NewConvergenceManifest(generation, resources)
	if err != nil {
		t.Fatalf("NewConvergenceManifest() error = %v", err)
	}
	return manifest
}

func resource(key ManagedResourceKey, material string, apply, remove ConvergenceImpact) ManagedResource {
	fingerprint := ManagedFingerprint([]byte(material))
	return ManagedResource{Key: key, RevisionSHA256: fingerprint, RuntimeSHA256: fingerprint, ApplyImpact: apply, RemoveImpact: remove}
}

func observation(key ManagedResourceKey, material string, remove ConvergenceImpact) OwnedResourceObservation {
	return OwnedResourceObservation{Key: key, RuntimeSHA256: ManagedFingerprint([]byte(material)), RemoveImpact: remove}
}

func observationsFromResources(resources []ManagedResource) []OwnedResourceObservation {
	result := make([]OwnedResourceObservation, len(resources))
	for index, resource := range resources {
		result[index] = OwnedResourceObservation{Key: resource.Key, RuntimeSHA256: resource.RuntimeSHA256, RemoveImpact: resource.RemoveImpact}
	}
	return result
}

func planConvergence(t *testing.T, snapshot ConvergenceSnapshot, observed []OwnedResourceObservation) ConvergencePlan {
	t.Helper()
	planner, err := NewConvergencePlanner(staticConvergenceSource{snapshot: snapshot}, staticOwnedDiscovery{observed: observed})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	return plan
}

func reverseManifest(manifest ConvergenceManifest) ConvergenceManifest {
	manifest.Resources = reverseResources(manifest.Resources)
	return manifest
}

func reverseResources(resources []ManagedResource) []ManagedResource {
	result := append([]ManagedResource(nil), resources...)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func reverseObservations(observations []OwnedResourceObservation) []OwnedResourceObservation {
	result := append([]OwnedResourceObservation(nil), observations...)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func reversePending(pending []PendingOperation) []PendingOperation {
	result := append([]PendingOperation(nil), pending...)
	for index := range result {
		resources := append([]ManagedResourceKey(nil), result[index].Resources...)
		for left, right := 0, len(resources)-1; left < right; left, right = left+1, right-1 {
			resources[left], resources[right] = resources[right], resources[left]
		}
		result[index].Resources = resources
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func desiredChangeSummary(changes []DesiredChange) string {
	parts := make([]string, 0, len(changes))
	for _, change := range changes {
		parts = append(parts, change.Resource.Component+"/"+string(change.Resource.Kind)+"/"+change.Resource.ID+":"+string(change.Kind)+":"+string(change.Impact))
	}
	return stringsJoin(parts, ",")
}

func driftSummary(drift []OwnedDrift) string {
	parts := make([]string, 0, len(drift))
	for _, item := range drift {
		parts = append(parts, item.Resource.Component+"/"+string(item.Resource.Kind)+"/"+item.Resource.ID+":"+string(item.Kind)+":"+string(item.Impact))
	}
	return stringsJoin(parts, ",")
}

func stringsJoin(values []string, separator string) string {
	var buffer bytes.Buffer
	for index, value := range values {
		if index != 0 {
			buffer.WriteString(separator)
		}
		buffer.WriteString(value)
	}
	return buffer.String()
}
