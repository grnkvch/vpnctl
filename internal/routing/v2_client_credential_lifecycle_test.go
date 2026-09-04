package routing

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestV2ClientCredentialLifecycleE2E(t *testing.T) {
	t.Parallel()

	fixture := newClientLifecycleFixture(t)
	initialState := loadPolicyState(t, fixture.stateStore)
	initialClient := findClientByID(t, initialState.Clients, fixture.clientID)
	initialStandard := findClientTransport(t, initialState.Transports, fixture.clientID)
	initialRestricted, found := findClientRestrictedTransport(initialState.Transports, fixture.clientID)
	if !found {
		t.Fatal("initial client restricted transport is missing")
	}
	initialPolicies := append([]model.Policy(nil), initialState.Policies...)
	initialClash := exportLifecycleProfile(t, fixture, ClientExportClash, "")
	initialWireGuard := exportLifecycleProfile(t, fixture, ClientExportWireGuard, "")
	initialClashBytes := readExportFile(t, initialClash.OutputPath, clientExportFileMode)
	initialWireGuardBytes := readExportFile(t, initialWireGuard.OutputPath, clientExportFileMode)
	if _, err := fixture.manager.PlanDelete(fixture.clientID); !errors.Is(err, ErrClientDeleteRequiresRevoke) {
		t.Fatalf("active client delete error = %v", err)
	}

	rotation, err := fixture.manager.PlanRotate("iphone")
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := fixture.manager.CommitRotate(context.Background(), rotation)
	if err != nil || !rotated.Changed || rotated.CredentialGeneration != 2 || !rotated.RequiresClientReExport {
		t.Fatalf("client rotation = %+v, %v", rotated, err)
	}
	rotatedState := loadPolicyState(t, fixture.stateStore)
	rotatedClient := findClientByID(t, rotatedState.Clients, fixture.clientID)
	rotatedStandard := findClientTransport(t, rotatedState.Transports, fixture.clientID)
	rotatedRestricted, found := findClientRestrictedTransport(rotatedState.Transports, fixture.clientID)
	if !found || rotatedClient.ID != initialClient.ID || rotatedClient.Name != initialClient.Name ||
		rotatedClient.OverlayIPv4 != initialClient.OverlayIPv4 ||
		!reflect.DeepEqual(rotatedClient.AssignedPresets, initialClient.AssignedPresets) ||
		!reflect.DeepEqual(rotatedState.Policies, initialPolicies) || rotatedClient.CredentialGeneration != 2 ||
		rotatedStandard.CredentialGeneration != 2 || rotatedRestricted.CredentialGeneration != 2 {
		t.Fatalf("client rotation changed stable identity/policy or retained a mixed generation: %+v", rotatedClient)
	}
	oldAccepted, err := ClientStandardCredentialAccepted(rotatedState, fixture.clientID, initialStandard.PublicKey)
	if err != nil || oldAccepted {
		t.Fatalf("old client generation accepted after rotation: %t, %v", oldAccepted, err)
	}
	newAccepted, err := ClientStandardCredentialAccepted(rotatedState, fixture.clientID, rotatedStandard.PublicKey)
	if err != nil || !newAccepted {
		t.Fatalf("new client generation rejected after rotation: %t, %v", newAccepted, err)
	}
	for _, reference := range []model.SecretRef{initialStandard.CredentialRef, initialRestricted.CredentialRef} {
		if _, err := fixture.secretStore.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("old client secret remains after rotation: %s: %v", reference, err)
		}
	}
	if shown := showLifecycleClient(t, fixture.manager); shown.Resource.ExportState != ClientExportStale {
		t.Fatalf("rotation did not stale prior exports: %+v", shown.Resource)
	}

	newClash := exportLifecycleProfile(t, fixture, ClientExportClash, "")
	newWireGuard := exportLifecycleProfile(t, fixture, ClientExportWireGuard, "")
	if newClash.CredentialGeneration != 2 || newWireGuard.CredentialGeneration != 2 ||
		bytes.Equal(initialClashBytes, readExportFile(t, newClash.OutputPath, clientExportFileMode)) ||
		bytes.Equal(initialWireGuardBytes, readExportFile(t, newWireGuard.OutputPath, clientExportFileMode)) {
		t.Fatal("required re-export did not publish generation-two profiles")
	}
	if shown := showLifecycleClient(t, fixture.manager); shown.Resource.ExportState != ClientExportCurrent {
		t.Fatalf("generation-two exports are not current: %+v", shown.Resource)
	}

	revocation, err := fixture.manager.PlanRevoke(fixture.clientID)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := fixture.manager.CommitRevoke(revocation)
	if err != nil || !revoked.Changed || revoked.CredentialGeneration != 2 {
		t.Fatalf("client revoke = %+v, %v", revoked, err)
	}
	revokedState := loadPolicyState(t, fixture.stateStore)
	revokedClient := findClientByID(t, revokedState.Clients, fixture.clientID)
	if revokedClient.Lifecycle != model.LifecycleRevoked || revokedClient.ID != initialClient.ID ||
		revokedClient.OverlayIPv4 != initialClient.OverlayIPv4 ||
		!reflect.DeepEqual(revokedClient.AssignedPresets, initialClient.AssignedPresets) ||
		!reflect.DeepEqual(revokedState.Policies, initialPolicies) {
		t.Fatalf("client revoke changed stable resources: %+v", revokedClient)
	}
	if accepted, err := ClientStandardCredentialAccepted(revokedState, fixture.clientID, rotatedStandard.PublicKey); err != nil || accepted {
		t.Fatalf("current client generation accepted after revoke: %t, %v", accepted, err)
	}
	for _, reference := range []model.SecretRef{rotatedStandard.CredentialRef, rotatedRestricted.CredentialRef} {
		if _, err := fixture.secretStore.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("revoked client secret remains: %s: %v", reference, err)
		}
	}

	deletion, err := fixture.manager.PlanDelete("iphone")
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := fixture.manager.CommitDelete(deletion)
	if err != nil || !deleted.Changed || !deleted.ExternalProfilesRemain || len(deleted.PendingCleanupPaths) != 0 {
		t.Fatalf("client delete = %+v, %v", deleted, err)
	}
	finalState := loadPolicyState(t, fixture.stateStore)
	finalClient := findClientByID(t, finalState.Clients, fixture.clientID)
	if finalClient.Lifecycle != model.LifecycleDeleted || len(finalClient.AssignedPresets) != 0 ||
		len(finalState.Transports) != 0 || len(finalState.Policies) != 0 {
		t.Fatalf("client delete retained managed resources: client=%+v transports=%+v policies=%+v",
			finalClient, finalState.Transports, finalState.Policies)
	}
	for _, path := range []string{newClash.OutputPath, newWireGuard.OutputPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("client delete retained managed export %s: %v", path, err)
		}
	}
}
