package operations

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	rotationControlCAID     = "83000000-0000-4000-8000-000000000001"
	rotationControlServerID = "83000000-0000-4000-8000-000000000002"
	rotationPendingID       = "83000000-0000-4000-8000-000000000003"
	rotationDisabledID      = "83000000-0000-4000-8000-000000000004"
)

func TestPublicCertificateRotationPlanIsReadOnlyAndApplyPreservesUnrelatedIdentity(t *testing.T) {
	t.Parallel()

	fixture := newPublicCertificateRotationFixture(t)
	beforeRaw, err := model.EncodeState(fixture.state.state)
	if err != nil {
		t.Fatal(err)
	}
	exportBefore, err := os.ReadFile(fixture.exportPath)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := NewPublicCertificateRotationManager(
		fixture.state, fixture.secrets, fixture.runtime, fixture.exportPath,
		PublicCertificateRotationRuntimeOptions{Entropy: rejectingEntropy{}, Now: fixture.now},
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if plan.ExpectedStateGeneration != 11 || plan.NextStateGeneration != 12 ||
		plan.CurrentCertificate.Generation != 1 || plan.NextCertificateGeneration != 2 ||
		plan.PreviousSnapshotGeneration != 0 || len(plan.AffectedExposes) != 2 ||
		plan.AffectedExposes[0].Name != "openai" || plan.AffectedExposes[0].State != model.ExposeDegraded ||
		plan.AffectedExposes[1].Name != "telegram" || plan.AffectedExposes[1].State != model.ExposeReady {
		t.Fatalf("rotation plan = %+v", plan)
	}
	if _, err := json.Marshal(plan); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("rotation plan serialization error = %v", err)
	}
	afterPlanRaw, _ := model.EncodeState(fixture.state.state)
	exportAfterPlan, _ := os.ReadFile(fixture.exportPath)
	if !bytes.Equal(afterPlanRaw, beforeRaw) || !bytes.Equal(exportAfterPlan, exportBefore) || fixture.runtime.activateCalls != 0 {
		t.Fatal("read-only rotation plan changed state, export, or runtime")
	}
	assertRotationSecretMissing(t, fixture.secrets, 2)

	manager, err := NewPublicCertificateRotationManager(
		fixture.state, fixture.secrets, fixture.runtime, fixture.exportPath,
		PublicCertificateRotationRuntimeOptions{Entropy: rand.Reader, Now: fixture.now},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.StateGeneration != 12 || result.CertificateID != plan.CurrentCertificate.ID ||
		result.CertificateGeneration != 2 || result.PreviousCertificateGeneration != 1 ||
		result.PreviousFingerprint != plan.CurrentCertificate.Fingerprint ||
		result.CurrentFingerprint == plan.CurrentCertificate.Fingerprint || len(result.AffectedExposes) != 2 {
		t.Fatalf("rotation result = %+v", result)
	}
	assertRotationUnrelatedState(t, fixture.before, fixture.state.state)
	assertRotationGenerations(t, fixture.secrets, []uint64{1, 2}, []uint64{3})
	assertRotationExportMatchesState(t, fixture)

	secondPlan, err := manager.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if secondPlan.PreviousSnapshotGeneration != 1 || secondPlan.NextCertificateGeneration != 3 {
		t.Fatalf("second rotation plan = %+v", secondPlan)
	}
	second, err := manager.Apply(context.Background(), secondPlan)
	if err != nil {
		t.Fatal(err)
	}
	if second.CertificateGeneration != 3 || second.PreviousCertificateGeneration != 2 || fixture.runtime.activateCalls != 2 {
		t.Fatalf("second rotation = %+v runtime=%+v", second, fixture.runtime)
	}
	assertRotationUnrelatedState(t, fixture.before, fixture.state.state)
	assertRotationGenerations(t, fixture.secrets, []uint64{2, 3}, []uint64{1, 4})
	assertRotationExportMatchesState(t, fixture)
}

func TestPublicCertificateRotationFailureDispositionIsCrashSafe(t *testing.T) {
	t.Parallel()

	t.Run("known state not committed rolls back", func(t *testing.T) {
		fixture := newPublicCertificateRotationFixture(t)
		fixture.state.saveMode = rotationSaveReject
		beforeRaw, _ := model.EncodeState(fixture.state.state)
		exportBefore, _ := os.ReadFile(fixture.exportPath)
		manager := fixture.manager(t)
		plan, err := manager.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Apply(context.Background(), plan); err == nil || errors.Is(err, ErrPublicCertificateRotationUncertain) {
			t.Fatalf("known save failure = %v", err)
		}
		afterRaw, _ := model.EncodeState(fixture.state.state)
		exportAfter, _ := os.ReadFile(fixture.exportPath)
		if !bytes.Equal(afterRaw, beforeRaw) || !bytes.Equal(exportAfter, exportBefore) ||
			fixture.runtime.activateCalls != 1 || fixture.runtime.rollbackCalls != 1 {
			t.Fatalf("known rollback state/runtime = %+v", fixture.runtime)
		}
		assertRotationGenerations(t, fixture.secrets, []uint64{1}, []uint64{2})
	})

	t.Run("committed despite report is accepted", func(t *testing.T) {
		fixture := newPublicCertificateRotationFixture(t)
		fixture.state.saveMode = rotationSaveCommitAndReportError
		manager := fixture.manager(t)
		plan, _ := manager.Plan(context.Background())
		result, err := manager.Apply(context.Background(), plan)
		if err != nil || result.CertificateGeneration != 2 || fixture.runtime.rollbackCalls != 0 {
			t.Fatalf("committed report failure result=%+v err=%v runtime=%+v", result, err, fixture.runtime)
		}
		assertRotationGenerations(t, fixture.secrets, []uint64{1, 2}, nil)
		assertRotationExportMatchesState(t, fixture)
	})

	t.Run("ambiguous state does not blindly roll back", func(t *testing.T) {
		fixture := newPublicCertificateRotationFixture(t)
		fixture.state.saveMode = rotationSaveUnknown
		manager := fixture.manager(t)
		plan, _ := manager.Plan(context.Background())
		_, err := manager.Apply(context.Background(), plan)
		if !errors.Is(err, ErrPublicCertificateRotationUncertain) || fixture.runtime.rollbackCalls != 0 {
			t.Fatalf("ambiguous failure=%v runtime=%+v", err, fixture.runtime)
		}
		assertRotationGenerations(t, fixture.secrets, []uint64{1, 2}, nil)
		rotatedExport, readErr := os.ReadFile(fixture.exportPath)
		if readErr != nil || bytes.Equal(rotatedExport, fixture.exportBefore) {
			t.Fatalf("ambiguous export was blindly restored: %v", readErr)
		}
	})

	t.Run("invalid activation receipt rolls back", func(t *testing.T) {
		fixture := newPublicCertificateRotationFixture(t)
		fixture.runtime.invalidReceipt = true
		manager := fixture.manager(t)
		plan, _ := manager.Plan(context.Background())
		_, err := manager.Apply(context.Background(), plan)
		if err == nil || errors.Is(err, ErrPublicCertificateRotationUncertain) || fixture.runtime.rollbackCalls != 1 {
			t.Fatalf("invalid receipt failure=%v runtime=%+v", err, fixture.runtime)
		}
		exportAfter, _ := os.ReadFile(fixture.exportPath)
		if !bytes.Equal(exportAfter, fixture.exportBefore) {
			t.Fatal("invalid receipt changed the public export")
		}
		assertRotationGenerations(t, fixture.secrets, []uint64{1}, []uint64{2})
	})
}

type publicCertificateRotationFixture struct {
	state        *memoryCertificateRotationState
	secrets      *store.SecretStore
	runtime      *recordingCertificateRotationRuntime
	exportPath   string
	exportBefore []byte
	before       model.State
	issuedAt     time.Time
}

func newPublicCertificateRotationFixture(t *testing.T) *publicCertificateRotationFixture {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{paths.StateDir, paths.SecretsDir, paths.ExportsDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	state := exposeSagaGatewayState(t)
	issuedAt := exposeSagaCreatedAt().Add(-time.Hour)
	provisioner, err := ingress.NewPublicCertificateProvisioner(secrets, ingress.PublicCertificateRuntime{
		Entropy: rand.Reader,
		NewUUID: func() (string, error) { return exposeSagaCertificateID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	installation, err := provisioner.Provision(context.Background(), ingress.PublicCertificateRequest{
		GatewayID: state.Host.ID, PublicIPv4: state.Host.PublicIPv4, IssuedAt: issuedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, state = exposeRemovalStates(t)
	state.Certificates = append(rotationControlCertificates(state.Host.ID, issuedAt), installation.Certificate)
	state.EnrollmentIdentity = &model.EnrollmentIdentity{
		SchemaVersion: model.ResourceSchemaVersion, Algorithm: "Ed25519",
		Fingerprint:  "sha256:" + strings.Repeat("9", 64),
		PublicKeyRef: "enrollment-public:gateway", PrivateKeyRef: "enrollment-key:gateway",
		Generation: 1, CreatedAt: issuedAt,
	}
	state.Exposes[1].State = model.ExposeDegraded
	pending := state.Exposes[0]
	pending.ID, pending.Name, pending.Path, pending.TunnelPort = rotationPendingID, "pending", "/pending", 20002
	pending.State, pending.Generation = model.ExposePending, 1
	disabled := state.Exposes[0]
	disabled.ID, disabled.Name, disabled.Path, disabled.TunnelPort = rotationDisabledID, "disabled", "/disabled", 20003
	disabled.State, disabled.Generation = model.ExposeDisabled, 4
	state.Exposes = append(state.Exposes, pending, disabled)
	if err := state.Validate(); err != nil {
		t.Fatalf("certificate rotation fixture: %v", err)
	}
	exportPath := ingress.DefaultPublicCertificateExportPath(paths.ExportsDir)
	if _, err := ingress.ExportPublicCertificate(state, secrets, exportPath); err != nil {
		t.Fatal(err)
	}
	exportBefore, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := cloneExposeState(state)
	if err != nil {
		t.Fatal(err)
	}
	return &publicCertificateRotationFixture{
		state: &memoryCertificateRotationState{state: state}, secrets: secrets,
		runtime: &recordingCertificateRotationRuntime{}, exportPath: exportPath,
		exportBefore: exportBefore, before: cloned, issuedAt: issuedAt,
	}
}

func (fixture *publicCertificateRotationFixture) now() time.Time {
	return fixture.issuedAt.Add(24 * time.Hour)
}

func (fixture *publicCertificateRotationFixture) manager(t *testing.T) *PublicCertificateRotationManager {
	t.Helper()
	manager, err := NewPublicCertificateRotationManager(
		fixture.state, fixture.secrets, fixture.runtime, fixture.exportPath,
		PublicCertificateRotationRuntimeOptions{Entropy: rand.Reader, Now: fixture.now},
	)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func rotationControlCertificates(owner string, issuedAt time.Time) []model.Certificate {
	return []model.Certificate{
		{
			SchemaVersion: model.ResourceSchemaVersion, ID: rotationControlCAID, Kind: model.CertificateControlCA,
			OwnerKind: "host", OwnerID: owner, Fingerprint: "sha256:" + strings.Repeat("a", 64),
			SerialHex: "a1", Subject: "CN=vpnctl control CA", SANs: []string{},
			NotBefore: issuedAt, NotAfter: issuedAt.AddDate(5, 0, 0), WarningDays: 180, Generation: 1,
			CertificateRef: "control-cert:gateway-ca-g1", PrivateKeyRef: "control-key:gateway-ca-g1",
		},
		{
			SchemaVersion: model.ResourceSchemaVersion, ID: rotationControlServerID, Kind: model.CertificateControlServer,
			OwnerKind: "host", OwnerID: owner, Fingerprint: "sha256:" + strings.Repeat("b", 64),
			SerialHex: "b1", Subject: "CN=vpnctl control server", SANs: []string{"IP:10.67.0.1"},
			NotBefore: issuedAt, NotAfter: issuedAt.AddDate(5, 0, 0), WarningDays: 180, Generation: 1,
			CertificateRef: "control-cert:gateway-server-g1", PrivateKeyRef: "control-key:gateway-server-g1",
		},
	}
}

type rotationSaveMode int

const (
	rotationSaveSuccess rotationSaveMode = iota
	rotationSaveReject
	rotationSaveCommitAndReportError
	rotationSaveUnknown
)

type memoryCertificateRotationState struct {
	state     model.State
	saveMode  rotationSaveMode
	saveCalls int
}

func (state *memoryCertificateRotationState) Load() (model.State, error) {
	if state.saveMode == rotationSaveUnknown && state.saveCalls > 0 {
		return model.State{}, errors.New("injected state observation failure")
	}
	return cloneExposeState(state.state)
}

func (state *memoryCertificateRotationState) Save(expectedGeneration uint64, candidate model.State) error {
	state.saveCalls++
	if state.state.Generation != expectedGeneration {
		return errors.New("stale state generation")
	}
	if err := model.ValidateTransition(state.state, candidate); err != nil {
		return err
	}
	switch state.saveMode {
	case rotationSaveReject, rotationSaveUnknown:
		return errors.New("injected state publication failure")
	case rotationSaveCommitAndReportError:
		state.state, _ = cloneExposeState(candidate)
		return errors.New("injected post-commit report failure")
	default:
		state.state, _ = cloneExposeState(candidate)
		return nil
	}
}

type recordingCertificateRotationRuntime struct {
	activateCalls  int
	rollbackCalls  int
	invalidReceipt bool
	lastBefore     model.State
	lastCandidate  model.State
	lastActivation PublicCertificateIngressActivation
}

func (runtime *recordingCertificateRotationRuntime) Activate(
	_ context.Context,
	before model.State,
	candidate model.State,
) (PublicCertificateIngressActivation, error) {
	runtime.activateCalls++
	runtime.lastBefore, _ = cloneExposeState(before)
	runtime.lastCandidate, _ = cloneExposeState(candidate)
	certificate, err := rotationPublicCertificate(candidate)
	if err != nil {
		return PublicCertificateIngressActivation{}, err
	}
	activation := PublicCertificateIngressActivation{
		CertificateID: certificate.ID, StateGeneration: candidate.Generation, Fingerprint: certificate.Fingerprint,
		opaque: fmt.Sprintf("rotation-%d", candidate.Generation),
	}
	if runtime.invalidReceipt {
		activation.StateGeneration++
	}
	runtime.lastActivation = activation
	return activation, nil
}

func (runtime *recordingCertificateRotationRuntime) Rollback(_ context.Context, activation PublicCertificateIngressActivation) error {
	runtime.rollbackCalls++
	if activation != runtime.lastActivation {
		return errors.New("unexpected public certificate activation receipt")
	}
	return nil
}

func rotationPublicCertificate(state model.State) (model.Certificate, error) {
	for _, certificate := range state.Certificates {
		if certificate.Kind == model.CertificatePublicIngress {
			return certificate, nil
		}
	}
	return model.Certificate{}, errors.New("public certificate missing")
}

func assertRotationUnrelatedState(t *testing.T, before, after model.State) {
	t.Helper()
	beforePublic, err := rotationPublicCertificate(before)
	if err != nil {
		t.Fatal(err)
	}
	afterPublic, err := rotationPublicCertificate(after)
	if err != nil {
		t.Fatal(err)
	}
	before.Generation, after.Generation = 0, 0
	for index := range before.Certificates {
		if before.Certificates[index].ID == beforePublic.ID {
			before.Certificates[index] = afterPublic
		}
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("certificate rotation changed control/enrollment/node or ingress routing state")
	}
}

func assertRotationGenerations(t *testing.T, secrets *store.SecretStore, present, absent []uint64) {
	t.Helper()
	for _, generation := range present {
		certificateRef, keyRef, err := ingress.PublicCertificateReferences(generation)
		if err != nil {
			t.Fatal(err)
		}
		for _, reference := range []model.SecretRef{model.SecretRef(certificateRef), keyRef} {
			value, err := secrets.Get(reference)
			if err != nil || len(value) == 0 {
				t.Fatalf("expected public certificate generation %d reference %s: %v", generation, reference, err)
			}
			clear(value)
		}
	}
	for _, generation := range absent {
		assertRotationSecretMissing(t, secrets, generation)
	}
}

func assertRotationSecretMissing(t *testing.T, secrets *store.SecretStore, generation uint64) {
	t.Helper()
	certificateRef, keyRef, err := ingress.PublicCertificateReferences(generation)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []model.SecretRef{model.SecretRef(certificateRef), keyRef} {
		value, err := secrets.Get(reference)
		clear(value)
		if !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("unexpected public certificate generation %d reference %s: %v", generation, reference, err)
		}
	}
}

func assertRotationExportMatchesState(t *testing.T, fixture *publicCertificateRotationFixture) {
	t.Helper()
	certificate, err := rotationPublicCertificate(fixture.state.state)
	if err != nil {
		t.Fatal(err)
	}
	want, err := fixture.secrets.Get(model.SecretRef(certificate.CertificateRef))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)
	got, err := os.ReadFile(fixture.exportPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("public certificate export mismatch: %v", err)
	}
	if bytes.Contains(got, []byte("PRIVATE KEY")) {
		t.Fatal("public certificate export contains a private key")
	}
}

type rejectingEntropy struct{}

func (rejectingEntropy) Read([]byte) (int, error) {
	return 0, errors.New("read-only plan attempted to consume entropy")
}

var _ io.Reader = rejectingEntropy{}

func TestPublicCertificateRotationPlanRejectsStaleStateAndWrongRole(t *testing.T) {
	t.Parallel()

	fixture := newPublicCertificateRotationFixture(t)
	manager := fixture.manager(t)
	plan, err := manager.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fixture.state.state.Generation++
	if _, err := manager.Apply(context.Background(), plan); !errors.Is(err, ErrPublicCertificateRotationPlanStale) {
		t.Fatalf("stale rotation error = %v", err)
	}

	fixture = newPublicCertificateRotationFixture(t)
	fixture.state.state.Host.Role = model.RoleNode
	if _, err := fixture.manager(t).Plan(context.Background()); err == nil {
		t.Fatal("node role was accepted for public certificate rotation")
	}
}

func TestPublicCertificateRotationReferencesAreGenerationScoped(t *testing.T) {
	t.Parallel()

	for generation := uint64(1); generation <= 4; generation++ {
		certificateRef, keyRef, err := ingress.PublicCertificateReferences(generation)
		if err != nil {
			t.Fatal(err)
		}
		wantSuffix := "-g" + fmt.Sprint(generation)
		if !strings.HasSuffix(certificateRef, wantSuffix) || !strings.HasSuffix(keyRef.String(), wantSuffix) ||
			strings.ContainsAny(certificateRef+keyRef.String(), `/\\`) {
			t.Fatalf("generation %d refs = %q, %q", generation, certificateRef, keyRef)
		}
	}
}
