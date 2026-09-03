package routing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestClientExportStateTracksPolicyCredentialAndFileStaleness(t *testing.T) {
	t.Parallel()

	t.Run("Clash follows policy and credential generations", func(t *testing.T) {
		fixture := newClientLifecycleFixture(t)
		if shown := showLifecycleClient(t, fixture.manager); shown.Resource.ExportState != ClientExportNotCreated {
			t.Fatalf("new client export state = %s", shown.Resource.ExportState)
		}
		clash := exportLifecycleProfile(t, fixture, ClientExportClash, "")
		if shown := showLifecycleClient(t, fixture.manager); shown.Resource.ExportState != ClientExportCurrent {
			t.Fatalf("exported Clash state = %s", shown.Resource.ExportState)
		}
		replaceLifecyclePolicy(t, fixture, []string{"openai"})
		if shown := showLifecycleClient(t, fixture.manager); shown.Resource.ExportState != ClientExportStale {
			t.Fatalf("policy-edited Clash state = %s", shown.Resource.ExportState)
		}
		if _, err := os.Stat(clash.OutputPath); err != nil {
			t.Fatalf("policy edit removed copied profile: %v", err)
		}

		plan, err := fixture.manager.PlanRotate("iphone")
		if err != nil {
			t.Fatalf("PlanRotate() error = %v", err)
		}
		if _, err := fixture.manager.CommitRotate(context.Background(), plan); err != nil {
			t.Fatalf("CommitRotate() error = %v", err)
		}
		if shown := showLifecycleClient(t, fixture.manager); shown.Resource.ExportState != ClientExportStale || shown.Resource.CredentialGeneration != 2 {
			t.Fatalf("rotated Clash view = %#v", shown.Resource)
		}
	})

	t.Run("full-tunnel WireGuard ignores policy-only edits", func(t *testing.T) {
		fixture := newClientLifecycleFixture(t)
		wireGuard := exportLifecycleProfile(t, fixture, ClientExportWireGuard, "")
		before := readExportFile(t, wireGuard.OutputPath, clientExportFileMode)
		replaceLifecyclePolicy(t, fixture, []string{"openai"})
		shown := showLifecycleClient(t, fixture.manager)
		if shown.Resource.ExportState != ClientExportCurrent {
			t.Fatalf("WireGuard became stale after policy edit: %#v", shown.Resource)
		}
		if after := readExportFile(t, wireGuard.OutputPath, clientExportFileMode); !bytes.Equal(after, before) {
			t.Fatal("policy edit modified exported WireGuard bytes")
		}
		if err := os.Chmod(wireGuard.OutputPath, 0o640); err != nil {
			t.Fatalf("change WireGuard mode: %v", err)
		}
		if shown := showLifecycleClient(t, fixture.manager); shown.Resource.ExportState != ClientExportStale {
			t.Fatalf("mode-drifted WireGuard state = %s", shown.Resource.ExportState)
		}
	})
}

func TestClientRotationPreservesIdentityRejectsOldCredentialAndRequiresExport(t *testing.T) {
	t.Parallel()

	fixture := newClientLifecycleFixture(t)
	clash := exportLifecycleProfile(t, fixture, ClientExportClash, "")
	wireGuard := exportLifecycleProfile(t, fixture, ClientExportWireGuard, "")
	clashBefore := readExportFile(t, clash.OutputPath, clientExportFileMode)
	wireGuardBefore := readExportFile(t, wireGuard.OutputPath, clientExportFileMode)
	stateBefore := loadPolicyState(t, fixture.stateStore)
	clientBefore := findClientByID(t, stateBefore.Clients, fixture.clientID)
	transportBefore := findClientTransport(t, stateBefore.Transports, fixture.clientID)
	restrictedBefore, found := findClientRestrictedTransport(stateBefore.Transports, fixture.clientID)
	if !found {
		t.Fatal("client has no restricted transport before rotation")
	}
	accepted, err := ClientStandardCredentialAccepted(stateBefore, fixture.clientID, transportBefore.PublicKey)
	if err != nil || !accepted {
		t.Fatalf("old credential was not initially accepted: %t, %v", accepted, err)
	}
	stateBytesBefore := readPolicyStateBytes(t, fixture.paths)
	credentialCallsBefore := fixture.credentials.calls
	restrictedCallsBefore := fixture.credentials.restrictedCalls

	plan, err := fixture.manager.PlanRotate("IPHONE")
	if err != nil {
		t.Fatalf("PlanRotate() error = %v", err)
	}
	if !plan.Changed || plan.ExpectedStateGeneration != 2 || plan.NextStateGeneration != 3 ||
		plan.CredentialGeneration != 1 || plan.NextCredentialGeneration != 2 || plan.ExportState != ClientExportCurrent || len(plan.ArtifactPaths) != 2 {
		t.Fatalf("PlanRotate() = %#v", plan)
	}
	if fixture.credentials.calls != credentialCallsBefore || fixture.credentials.restrictedCalls != restrictedCallsBefore ||
		!bytes.Equal(readPolicyStateBytes(t, fixture.paths), stateBytesBefore) {
		t.Fatal("PlanRotate() generated credentials or changed state")
	}
	newReference, _ := clientStandardCredentialReference(fixture.clientID, 2)
	newRestrictedReference, _ := clientRestrictedCredentialReference(fixture.clientID, 2)
	if _, err := fixture.secretStore.Get(newReference); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("PlanRotate() created next secret: %v", err)
	}
	if _, err := fixture.secretStore.Get(newRestrictedReference); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("PlanRotate() created next restricted secret: %v", err)
	}
	if formatted := fmt.Sprintf("%s %v %q %#v %+v", plan, plan, plan, plan, plan); strings.Count(formatted, clientLifecyclePlanMarker) != 5 {
		t.Fatalf("lifecycle plan formatting is not redacted: %s", formatted)
	}

	result, err := fixture.manager.CommitRotate(context.Background(), plan)
	if err != nil {
		t.Fatalf("CommitRotate() error = %v", err)
	}
	if !result.Changed || result.StateGeneration != 3 || result.CredentialGeneration != 2 || !result.RequiresClientReExport {
		t.Fatalf("CommitRotate() = %#v", result)
	}
	public := result.OutputResult()
	if err := public.Validate(); err != nil || len(public.RequiresAction) != 1 || public.RequiresAction[0].Code != "re_export_client" {
		t.Fatalf("rotation output = %#v, %v", public, err)
	}
	stateAfter := loadPolicyState(t, fixture.stateStore)
	clientAfter := findClientByID(t, stateAfter.Clients, fixture.clientID)
	transportAfter := findClientTransport(t, stateAfter.Transports, fixture.clientID)
	restrictedAfter, found := findClientRestrictedTransport(stateAfter.Transports, fixture.clientID)
	if clientAfter.ID != clientBefore.ID || clientAfter.Name != clientBefore.Name || clientAfter.OverlayIPv4 != clientBefore.OverlayIPv4 ||
		!reflect.DeepEqual(clientAfter.AssignedPresets, clientBefore.AssignedPresets) || clientAfter.CredentialGeneration != 2 ||
		transportAfter.CredentialGeneration != 2 || transportAfter.PublicKey == transportBefore.PublicKey || transportAfter.CredentialRef != newReference ||
		!found || restrictedAfter.CredentialGeneration != 2 || restrictedAfter.CredentialRef != newRestrictedReference ||
		restrictedAfter.HandshakeHost != restrictedBefore.HandshakeHost || restrictedAfter.ConfigHash == restrictedBefore.ConfigHash {
		t.Fatalf("rotation changed identity/policy or failed to replace credential:\nbefore=%#v/%#v\nafter=%#v/%#v", clientBefore, transportBefore, clientAfter, transportAfter)
	}
	oldAccepted, err := ClientStandardCredentialAccepted(stateAfter, fixture.clientID, transportBefore.PublicKey)
	if err != nil || oldAccepted {
		t.Fatalf("old profile credential accepted after rotation: %t, %v", oldAccepted, err)
	}
	newAccepted, err := ClientStandardCredentialAccepted(stateAfter, fixture.clientID, transportAfter.PublicKey)
	if err != nil || !newAccepted {
		t.Fatalf("new credential rejected after rotation: %t, %v", newAccepted, err)
	}
	if _, err := fixture.secretStore.Get(transportBefore.CredentialRef); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("old private key retained after rotation: %v", err)
	}
	if _, err := fixture.secretStore.Get(restrictedBefore.CredentialRef); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("old restricted credential retained after rotation: %v", err)
	}
	newPrivate, err := fixture.secretStore.Get(newReference)
	if err != nil || string(newPrivate) != fixture.credentials.generated[1].PrivateKey {
		t.Fatalf("new private key = %q, %v", newPrivate, err)
	}
	newRestricted, err := fixture.secretStore.Get(newRestrictedReference)
	if err != nil || !bytes.Equal(newRestricted, fixture.credentials.generatedRestricted[1]) {
		t.Fatalf("new restricted credential = %q, %v", newRestricted, err)
	}
	if !bytes.Equal(readExportFile(t, clash.OutputPath, clientExportFileMode), clashBefore) ||
		!bytes.Equal(readExportFile(t, wireGuard.OutputPath, clientExportFileMode), wireGuardBefore) {
		t.Fatal("rotation modified already copied artifacts")
	}
	if shown := showLifecycleClient(t, fixture.manager); shown.Resource.ExportState != ClientExportStale {
		t.Fatalf("rotated client export state = %s", shown.Resource.ExportState)
	}
}

func TestClientRevokeImmediatelyDisablesAcceptanceAndRetainsArtifacts(t *testing.T) {
	t.Parallel()

	fixture := newClientLifecycleFixture(t)
	clash := exportLifecycleProfile(t, fixture, ClientExportClash, "")
	before := loadPolicyState(t, fixture.stateStore)
	transport := findClientTransport(t, before.Transports, fixture.clientID)
	restrictedTransport, found := findClientRestrictedTransport(before.Transports, fixture.clientID)
	if !found {
		t.Fatal("client has no restricted transport before revoke")
	}
	plan, err := fixture.manager.PlanRevoke("iphone")
	if err != nil {
		t.Fatalf("PlanRevoke() error = %v", err)
	}
	if !plan.Changed || plan.RevokedAt == nil || plan.NextStateGeneration != 3 || plan.ExportState != ClientExportCurrent {
		t.Fatalf("PlanRevoke() = %#v", plan)
	}
	modifiedArtifact := []byte("operator changed the copied profile after review\n")
	if err := os.WriteFile(clash.OutputPath, modifiedArtifact, clientExportFileMode); err != nil {
		t.Fatalf("modify copied profile after revoke plan: %v", err)
	}
	result, err := fixture.manager.CommitRevoke(plan)
	if err != nil {
		t.Fatalf("CommitRevoke() error = %v", err)
	}
	if !result.Changed || result.StateGeneration != 3 || result.RequiresClientReExport {
		t.Fatalf("CommitRevoke() = %#v", result)
	}
	state := loadPolicyState(t, fixture.stateStore)
	client := findClientByID(t, state.Clients, fixture.clientID)
	disabled := findClientTransport(t, state.Transports, fixture.clientID)
	disabledRestricted, found := findClientRestrictedTransport(state.Transports, fixture.clientID)
	if client.Lifecycle != model.LifecycleRevoked || client.RevokedAt == nil || disabled.State != model.TransportDisabled ||
		!found || disabledRestricted.State != model.TransportDisabled {
		t.Fatalf("revoked state = %#v / %#v", client, disabled)
	}
	accepted, err := ClientStandardCredentialAccepted(state, fixture.clientID, transport.PublicKey)
	if err != nil || accepted {
		t.Fatalf("revoked credential accepted: %t, %v", accepted, err)
	}
	if _, err := fixture.secretStore.Get(transport.CredentialRef); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("revoked client private key retained: %v", err)
	}
	if _, err := fixture.secretStore.Get(restrictedTransport.CredentialRef); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("revoked client restricted credential retained: %v", err)
	}
	if got := readExportFile(t, clash.OutputPath, clientExportFileMode); !bytes.Equal(got, modifiedArtifact) {
		t.Fatalf("revoke changed stored export: %q", got)
	}
	shown := showLifecycleClient(t, fixture.manager)
	if shown.Resource.Lifecycle != model.LifecycleRevoked || shown.Resource.Health != ClientHealthDisabled || shown.Resource.ExportState != ClientExportStale {
		t.Fatalf("revoked client view = %#v", shown.Resource)
	}

	repeatedPlan, err := fixture.manager.PlanRevoke(fixture.clientID)
	if err != nil || repeatedPlan.Changed || repeatedPlan.NextStateGeneration != state.Generation {
		t.Fatalf("idempotent PlanRevoke() = %#v, %v", repeatedPlan, err)
	}
	repeated, err := fixture.manager.CommitRevoke(repeatedPlan)
	if err != nil || repeated.Changed || repeated.StateGeneration != state.Generation {
		t.Fatalf("idempotent CommitRevoke() = %#v, %v", repeated, err)
	}
}

func TestClientDeleteRequiresRevokeAndRemovesManagedCustomArtifacts(t *testing.T) {
	t.Parallel()

	fixture := newClientLifecycleFixture(t)
	customClash := filepath.Join(fixture.paths.Root, "operator", "iphone.yaml")
	clash := exportLifecycleProfile(t, fixture, ClientExportClash, customClash)
	wireGuard := exportLifecycleProfile(t, fixture, ClientExportWireGuard, "")
	if _, err := fixture.manager.PlanDelete("iphone"); !errors.Is(err, ErrClientDeleteRequiresRevoke) {
		t.Fatalf("PlanDelete(active) error = %v", err)
	}
	revoke, err := fixture.manager.PlanRevoke("iphone")
	if err != nil {
		t.Fatalf("PlanRevoke() error = %v", err)
	}
	if _, err := fixture.manager.CommitRevoke(revoke); err != nil {
		t.Fatalf("CommitRevoke() error = %v", err)
	}
	plan, err := fixture.manager.PlanDelete(fixture.clientID)
	if err != nil {
		t.Fatalf("PlanDelete() error = %v", err)
	}
	if !plan.Changed || plan.NextStateGeneration != 4 || !reflect.DeepEqual(plan.ArtifactPaths, []string{clash.OutputPath, wireGuard.OutputPath}) {
		t.Fatalf("PlanDelete() = %#v", plan)
	}
	result, err := fixture.manager.CommitDelete(plan)
	if err != nil {
		t.Fatalf("CommitDelete() error = %v", err)
	}
	if !result.Changed || result.StateGeneration != 4 || !result.ExternalProfilesRemain ||
		!reflect.DeepEqual(result.RemovedArtifactPaths, plan.ArtifactPaths) || len(result.PendingCleanupPaths) != 0 {
		t.Fatalf("CommitDelete() = %#v", result)
	}
	public := result.OutputResult()
	if err := public.Validate(); err != nil || len(public.Warnings) != 1 || public.Warnings[0].Code != "external_profiles_remain" {
		t.Fatalf("delete output = %#v, %v", public, err)
	}
	state := loadPolicyState(t, fixture.stateStore)
	client := findClientByID(t, state.Clients, fixture.clientID)
	if client.Lifecycle != model.LifecycleDeleted || len(client.AssignedPresets) != 0 || len(state.Policies) != 0 || len(state.Transports) != 0 {
		t.Fatalf("deleted authoritative state = %#v / policies=%#v transports=%#v", client, state.Policies, state.Transports)
	}
	if _, err := fixture.manager.Show("iphone"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("Show(deleted) error = %v", err)
	}
	list, err := fixture.manager.List()
	if err != nil || len(list.Items) != 0 {
		t.Fatalf("List(deleted) = %#v, %v", list, err)
	}
	for _, path := range []string{
		clash.OutputPath, wireGuard.OutputPath,
		clientExportMetadataPath(fixture.paths, fixture.clientID, ClientExportClash),
		clientExportMetadataPath(fixture.paths, fixture.clientID, ClientExportWireGuard),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("deleted client retained %s: %v", path, err)
		}
	}
}

func TestClientDeleteRefusesModifiedCustomArtifactBeforeStateMutation(t *testing.T) {
	t.Parallel()

	fixture := newClientLifecycleFixture(t)
	custom := filepath.Join(fixture.paths.Root, "operator", "iphone.yaml")
	exported := exportLifecycleProfile(t, fixture, ClientExportClash, custom)
	revoke, _ := fixture.manager.PlanRevoke("iphone")
	if _, err := fixture.manager.CommitRevoke(revoke); err != nil {
		t.Fatalf("CommitRevoke() error = %v", err)
	}
	modified := []byte("operator replacement\n")
	if err := os.WriteFile(custom, modified, clientExportFileMode); err != nil {
		t.Fatalf("modify custom artifact: %v", err)
	}
	stateBefore := readPolicyStateBytes(t, fixture.paths)
	if _, err := fixture.manager.PlanDelete("iphone"); !errors.Is(err, ErrClientExportDrift) {
		t.Fatalf("PlanDelete(drift) error = %v, want ErrClientExportDrift", err)
	}
	if !bytes.Equal(readPolicyStateBytes(t, fixture.paths), stateBefore) || !bytes.Equal(readExportFile(t, exported.OutputPath, clientExportFileMode), modified) {
		t.Fatal("rejected delete changed state or custom artifact")
	}
}

func TestClientLifecycleKnownAndUncertainStateFailuresKeepSafeCredentialSet(t *testing.T) {
	t.Parallel()

	t.Run("known rotation failure", func(t *testing.T) {
		fixture := newClientLifecycleFixture(t)
		before := loadPolicyState(t, fixture.stateStore)
		old := findClientTransport(t, before.Transports, fixture.clientID)
		oldRestricted, _ := findClientRestrictedTransport(before.Transports, fixture.clientID)
		manager, credentials := lifecycleManagerWithStateFailure(t, fixture, errors.New("state write failed"))
		plan, err := manager.PlanRotate("iphone")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.CommitRotate(context.Background(), plan); err == nil || errors.Is(err, ErrClientLifecycleUncertain) {
			t.Fatalf("CommitRotate(known failure) error = %v", err)
		}
		state := loadPolicyState(t, fixture.stateStore)
		current := findClientTransport(t, state.Transports, fixture.clientID)
		currentRestricted, _ := findClientRestrictedTransport(state.Transports, fixture.clientID)
		if state.Generation != 2 || current.PublicKey != old.PublicKey || currentRestricted.CredentialRef != oldRestricted.CredentialRef ||
			credentials.calls != 2 || credentials.restrictedCalls != 2 {
			t.Fatalf("known failure state/credentials = generation %d, transport %#v, calls %d", state.Generation, current, credentials.calls)
		}
		if _, err := fixture.secretStore.Get(old.CredentialRef); err != nil {
			t.Fatalf("known failure removed active old secret: %v", err)
		}
		if _, err := fixture.secretStore.Get(oldRestricted.CredentialRef); err != nil {
			t.Fatalf("known failure removed active old restricted secret: %v", err)
		}
		newReference, _ := clientStandardCredentialReference(fixture.clientID, 2)
		newRestrictedReference, _ := clientRestrictedCredentialReference(fixture.clientID, 2)
		if _, err := fixture.secretStore.Get(newReference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("known failure retained staged new secret: %v", err)
		}
		if _, err := fixture.secretStore.Get(newRestrictedReference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("known failure retained staged new restricted secret: %v", err)
		}
	})

	t.Run("committed uncertain rotation", func(t *testing.T) {
		fixture := newClientLifecycleFixture(t)
		before := loadPolicyState(t, fixture.stateStore)
		old := findClientTransport(t, before.Transports, fixture.clientID)
		oldRestricted, _ := findClientRestrictedTransport(before.Transports, fixture.clientID)
		manager, _ := lifecycleManagerWithStateFailure(t, fixture, errAfterClientCommit)
		plan, err := manager.PlanRotate("iphone")
		if err != nil {
			t.Fatal(err)
		}
		result, err := manager.CommitRotate(context.Background(), plan)
		if !errors.Is(err, ErrClientLifecycleUncertain) || !result.Changed {
			t.Fatalf("CommitRotate(committed uncertain) = %#v, %v", result, err)
		}
		state := loadPolicyState(t, fixture.stateStore)
		current := findClientTransport(t, state.Transports, fixture.clientID)
		currentRestricted, found := findClientRestrictedTransport(state.Transports, fixture.clientID)
		if state.Generation != 3 || current.CredentialGeneration != 2 || current.PublicKey == old.PublicKey || !found ||
			currentRestricted.CredentialGeneration != 2 || currentRestricted.CredentialRef == oldRestricted.CredentialRef {
			t.Fatalf("committed uncertain state = %#v", state)
		}
		if _, err := fixture.secretStore.Get(old.CredentialRef); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("committed uncertain retained obsolete old secret: %v", err)
		}
		if _, err := fixture.secretStore.Get(oldRestricted.CredentialRef); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("committed uncertain retained obsolete old restricted secret: %v", err)
		}
		if _, err := fixture.secretStore.Get(current.CredentialRef); err != nil {
			t.Fatalf("committed uncertain lost active new secret: %v", err)
		}
		if _, err := fixture.secretStore.Get(currentRestricted.CredentialRef); err != nil {
			t.Fatalf("committed uncertain lost active new restricted secret: %v", err)
		}
	})
}

func TestClientRotationRejectsStateAdvanceBetweenReplanAndCredentialGeneration(t *testing.T) {
	t.Parallel()

	fixture := newClientLifecycleFixture(t)
	advancing := &clientLifecycleAdvancingLoadStore{base: fixture.stateStore, advanceOnLoad: 3}
	manager, err := NewClientManager(fixture.paths, advancing, fixture.secretStore, ClientManagerRuntime{
		Now: fixture.now, NewUUID: fixture.uuid.New, Credentials: fixture.credentials,
	})
	if err != nil {
		t.Fatalf("NewClientManager() error = %v", err)
	}
	before := readPolicyStateBytes(t, fixture.paths)
	credentialCalls := fixture.credentials.calls
	restrictedCalls := fixture.credentials.restrictedCalls
	plan, err := manager.PlanRotate("iphone")
	if err != nil {
		t.Fatalf("PlanRotate() error = %v", err)
	}
	if _, err := manager.CommitRotate(context.Background(), plan); !errors.Is(err, ErrClientLifecycleStale) {
		t.Fatalf("CommitRotate(concurrent advance) error = %v, want ErrClientLifecycleStale", err)
	}
	if advancing.saveCalls != 0 || fixture.credentials.calls != credentialCalls || fixture.credentials.restrictedCalls != restrictedCalls ||
		!bytes.Equal(readPolicyStateBytes(t, fixture.paths), before) {
		t.Fatal("stale lifecycle commit generated credentials or mutated state")
	}
	newReference, _ := clientStandardCredentialReference(fixture.clientID, 2)
	newRestrictedReference, _ := clientRestrictedCredentialReference(fixture.clientID, 2)
	if _, err := fixture.secretStore.Get(newReference); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("stale lifecycle commit created a secret: %v", err)
	}
	if _, err := fixture.secretStore.Get(newRestrictedReference); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("stale lifecycle commit created a restricted secret: %v", err)
	}
}

func TestClientRevokeStateFirstLeavesAcceptanceDisabledWhenSecretCleanupFails(t *testing.T) {
	t.Parallel()

	fixture := newClientLifecycleFixture(t)
	before := loadPolicyState(t, fixture.stateStore)
	old := findClientTransport(t, before.Transports, fixture.clientID)
	oldRestricted, _ := findClientRestrictedTransport(before.Transports, fixture.clientID)
	failingSecrets := &clientSecretFailure{base: fixture.secretStore, deleteErr: errors.New("delete failed")}
	manager, err := NewClientManager(fixture.paths, fixture.stateStore, failingSecrets, ClientManagerRuntime{
		Now: fixture.now, NewUUID: fixture.uuid.New, Credentials: fixture.credentials,
	})
	if err != nil {
		t.Fatalf("NewClientManager() error = %v", err)
	}
	plan, err := manager.PlanRevoke("iphone")
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.CommitRevoke(plan)
	if !errors.Is(err, ErrClientCleanupPending) || !result.Changed || !result.CredentialCleanupNeeded {
		t.Fatalf("CommitRevoke(cleanup failure) = %#v, %v", result, err)
	}
	state := loadPolicyState(t, fixture.stateStore)
	accepted, acceptanceErr := ClientStandardCredentialAccepted(state, fixture.clientID, old.PublicKey)
	if acceptanceErr != nil || accepted || findClientByID(t, state.Clients, fixture.clientID).Lifecycle != model.LifecycleRevoked {
		t.Fatalf("cleanup failure weakened revoke: accepted=%t err=%v state=%#v", accepted, acceptanceErr, state)
	}
	if _, err := fixture.secretStore.Get(old.CredentialRef); err != nil {
		t.Fatalf("cleanup failure fixture unexpectedly removed secret: %v", err)
	}
	if _, err := fixture.secretStore.Get(oldRestricted.CredentialRef); err != nil {
		t.Fatalf("cleanup failure fixture unexpectedly removed restricted secret: %v", err)
	}
	if public := result.OutputResult(); public.Validate() != nil || public.Status != "pending" || len(public.RequiresAction) != 1 || public.RequiresAction[0].Code != "repair_client_credentials" {
		t.Fatalf("cleanup-pending output = %#v", public)
	}
}

type clientLifecycleFixture struct {
	manager     *ClientManager
	exporter    *ClientExporter
	paths       store.Paths
	stateStore  *store.StateStore
	secretStore *store.SecretStore
	credentials *deterministicClientCredentials
	uuid        *countingUUIDGenerator
	clientID    string
	now         func() time.Time
	gatewayKey  string
}

func newClientLifecycleFixture(t *testing.T) clientLifecycleFixture {
	t.Helper()
	manager, paths, stateStore, secretStore, credentials, uuid := newClientManagerFixture(t, nil)
	plan, err := manager.PlanAdd(ClientAddRequest{Name: "iphone", PresetNames: []string{"telegram"}})
	if err != nil {
		t.Fatalf("PlanAdd() error = %v", err)
	}
	created, err := manager.CommitAdd(context.Background(), plan)
	if err != nil {
		t.Fatalf("CommitAdd() error = %v", err)
	}
	exporter, err := NewClientExporter(paths, stateStore, secretStore)
	if err != nil {
		t.Fatalf("NewClientExporter() error = %v", err)
	}
	return clientLifecycleFixture{
		manager: manager, exporter: exporter, paths: paths, stateStore: stateStore, secretStore: secretStore,
		credentials: credentials, uuid: uuid, clientID: created.Client.ID,
		now:        func() time.Time { return time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC) },
		gatewayKey: v1CompatibleServerPublicKey,
	}
}

func exportLifecycleProfile(t *testing.T, fixture clientLifecycleFixture, format ClientExportFormat, outputPath string) ClientExportResult {
	t.Helper()
	result, err := fixture.exporter.Export(ClientExportRequest{
		ClientReference: fixture.clientID, Format: format, OutputPath: outputPath,
		GatewayPublicKey: fixture.gatewayKey,
	})
	if err != nil {
		t.Fatalf("Export(%s) error = %v", format, err)
	}
	return result
}

func showLifecycleClient(t *testing.T, manager *ClientManager) ClientShow {
	t.Helper()
	shown, err := manager.Show("iphone")
	if err != nil {
		t.Fatalf("Show(iphone) error = %v", err)
	}
	return shown
}

func replaceLifecyclePolicy(t *testing.T, fixture clientLifecycleFixture, presets []string) {
	t.Helper()
	manager, err := NewPolicyManager(fixture.paths, fixture.stateStore)
	if err != nil {
		t.Fatalf("NewPolicyManager() error = %v", err)
	}
	plan, err := manager.PlanClientSet(fixture.clientID, presets)
	if err != nil {
		t.Fatalf("PlanClientSet() error = %v", err)
	}
	if _, err := manager.Commit(plan); err != nil {
		t.Fatalf("Commit(policy) error = %v", err)
	}
}

func lifecycleManagerWithStateFailure(t *testing.T, fixture clientLifecycleFixture, saveErr error) (*ClientManager, *deterministicClientCredentials) {
	t.Helper()
	credentials := &deterministicClientCredentials{calls: 1, restrictedCalls: 1}
	manager, err := NewClientManager(fixture.paths, clientFixtureStateStore{base: fixture.stateStore, saveErr: saveErr}, fixture.secretStore, ClientManagerRuntime{
		Now: fixture.now, NewUUID: fixture.uuid.New, Credentials: credentials,
	})
	if err != nil {
		t.Fatalf("NewClientManager() error = %v", err)
	}
	return manager, credentials
}

type clientSecretFailure struct {
	base      *store.SecretStore
	deleteErr error
}

type clientLifecycleAdvancingLoadStore struct {
	base          *store.StateStore
	advanceOnLoad int
	loadCalls     int
	saveCalls     int
}

func (stateStore *clientLifecycleAdvancingLoadStore) Load() (model.State, error) {
	stateStore.loadCalls++
	state, err := stateStore.base.Load()
	if err == nil && stateStore.loadCalls == stateStore.advanceOnLoad {
		state.Generation++
	}
	return state, err
}

func (stateStore *clientLifecycleAdvancingLoadStore) Save(expectedGeneration uint64, candidate model.State) error {
	stateStore.saveCalls++
	return stateStore.base.Save(expectedGeneration, candidate)
}

func (failure *clientSecretFailure) PutIfAbsent(reference model.SecretRef, secret []byte) error {
	return failure.base.PutIfAbsent(reference, secret)
}

func (failure *clientSecretFailure) Delete(reference model.SecretRef) (bool, error) {
	if failure.deleteErr != nil {
		return false, failure.deleteErr
	}
	return failure.base.Delete(reference)
}
