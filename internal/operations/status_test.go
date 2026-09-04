package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestStatusCollectorKeepsWarningsAndPendingSuccessfulAndLeaksNoSecrets(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	state := statusGatewayState(t, now)
	key := ManagedResourceKey{Component: "control", Kind: ManagedResourceState, ID: "fleet"}
	applied := convergenceManifest(t, 7, []ManagedResource{resource(key, "applied", ConvergenceImpactNone, ConvergenceImpactNone)})
	desired := convergenceManifest(t, 8, []ManagedResource{resource(key, "desired", ConvergenceImpactNone, ConvergenceImpactNone)})
	plannerSource := &auditedStatusConvergenceSource{snapshot: ConvergenceSnapshot{
		Desired: desired, Applied: applied,
		Pending: []PendingOperation{{
			ID: "operation-1", Type: "apply", ExpectedGeneration: 7, DesiredGeneration: 8,
			Resources: []ManagedResourceKey{key},
		}},
	}}
	discovery := &auditedStatusDiscovery{observed: observationsFromResources(applied.Resources)}
	planner, err := NewConvergencePlanner(plannerSource, discovery)
	if err != nil {
		t.Fatal(err)
	}
	stateSource := &auditedStatusStateSource{state: state}
	observer := &auditedPassiveStatusObserver{snapshot: healthyPassiveStatus()}
	collector, err := NewStatusCollector(model.RoleGateway, "v2.0.0-dev", func() time.Time { return now }, stateSource, planner, observer)
	if err != nil {
		t.Fatal(err)
	}
	before := cloneStatusTestState(t, stateSource.state)

	report, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall != StatusOverallHealthy || report.Category != StatusCategorySuccess ||
		report.Generation != 8 || report.DesiredGeneration != 8 || report.AppliedGeneration != 7 || len(report.Pending) != 1 {
		t.Fatalf("warning-only status = %+v", report)
	}
	for _, code := range []string{"active_invites", "backup_stale", "certificate_expiring", "expanded_logging_active", "pending_changes"} {
		if !hasStatusNotice(report.Warnings, code) {
			t.Fatalf("status warning %s missing from %+v", code, report.Warnings)
		}
	}
	if report.Counts["active_invites"] != 1 || report.Counts["log_opt_ins"] != 1 ||
		report.Counts["expiring_certificates"] != 1 || report.Counts["pending_changes"] != 1 || report.Counts["drift"] != 0 {
		t.Fatalf("status counts = %+v", report.Counts)
	}
	if len(report.Components) != 2 || report.Components[0].Name != "mihomo" || report.Components[1].SHA256 == "" || len(report.Runtime) != 2 {
		t.Fatalf("component/runtime status = %+v / %+v", report.Components, report.Runtime)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		statusSecretHashCanary, statusPrivateRefCanary, statusGatewayEndpointCanary,
		"secret_hash", "private_key_ref", "credential_ref", "webhook_path", "request_body",
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("status leaked %q: %s", forbidden, encoded)
		}
	}
	if !reflect.DeepEqual(stateSource.state, before) {
		t.Fatal("status observer mutated authoritative state through its input")
	}
	if stateSource.reads != 1 || stateSource.writes != 0 || plannerSource.reads != 1 || plannerSource.writes != 0 ||
		discovery.reads != 1 || discovery.mutations != 0 || observer.reads != 1 || observer.syntheticDNS != 0 ||
		observer.syntheticHTTP != 0 || observer.webhookCalls != 0 || observer.mutations != 0 {
		t.Fatalf("passive audit = state %+v convergence %+v discovery %+v observer %+v", stateSource, plannerSource, discovery, observer)
	}
}

func TestStatusCollectorMapsDriftAndRuntimeFailuresWithStablePrecedence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	state := statusGatewayState(t, now)
	state.Invites = []model.Invite{}
	state.Logging = []model.LoggingSession{}
	state.Certificates[0].NotAfter = now.AddDate(1, 0, 0)
	state.Backups[0].CreatedAt = now.Add(-time.Hour)
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	key := ManagedResourceKey{Component: "routing", Kind: ManagedResourceNetwork, ID: "table-inet-vpnctl"}
	manifest := convergenceManifest(t, 8, []ManagedResource{resource(key, "applied", ConvergenceImpactAvailability, ConvergenceImpactAvailability)})
	planner := statusPlanner(t, ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}},
		[]OwnedResourceObservation{observation(key, "manual", ConvergenceImpactAvailability)})
	collector := statusCollectorFixture(t, state, now, planner, healthyPassiveStatus())
	report, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Category != StatusCategoryConflict || report.Overall != StatusOverallDegraded || len(report.Drift) != 1 ||
		!hasStatusNotice(report.RequiredActions, "repair_owned_drift") {
		t.Fatalf("drift status = %+v", report)
	}

	passive := healthyPassiveStatus()
	passive.Resources[1].Condition = PassiveUnavailable
	passive.Resources[1].Code = "routing_process_absent"
	collector = statusCollectorFixture(t, state, now, planner, passive)
	report, err = collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Category != StatusCategoryUnavailable || report.Overall != StatusOverallDegraded || len(report.Problems) != 2 {
		t.Fatalf("runtime+drift status = %+v", report)
	}
}

func TestStatusCollectorInvalidStateStopsBeforeConvergenceAndPassiveObservation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	state := statusGatewayState(t, now)
	state.Generation = 0
	plannerSource := &auditedStatusConvergenceSource{err: errors.New("must not be read")}
	discovery := &auditedStatusDiscovery{}
	planner, err := NewConvergencePlanner(plannerSource, discovery)
	if err != nil {
		t.Fatal(err)
	}
	stateSource := &auditedStatusStateSource{state: state}
	observer := &auditedPassiveStatusObserver{snapshot: healthyPassiveStatus()}
	collector, err := NewStatusCollector(model.RoleGateway, "v2.0.0-dev", func() time.Time { return now }, stateSource, planner, observer)
	if err != nil {
		t.Fatal(err)
	}
	report, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Category != StatusCategoryValidation || report.Overall != StatusOverallFailed ||
		len(report.Problems) != 1 || report.Problems[0].Code != "invalid_state" {
		t.Fatalf("invalid state status = %+v", report)
	}
	if plannerSource.reads != 0 || discovery.reads != 0 || observer.reads != 0 {
		t.Fatal("invalid authoritative state reached convergence or runtime observation")
	}
}

func TestStatusCollectorRequiresCompletePassiveMetadataWithoutProbing(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	state := statusGatewayState(t, now)
	state.Invites = []model.Invite{}
	state.Logging = []model.LoggingSession{}
	state.Certificates = []model.Certificate{}
	state.Backups[0].CreatedAt = now
	key := ManagedResourceKey{Component: "control", Kind: ManagedResourceState, ID: "fleet"}
	manifest := convergenceManifest(t, 8, []ManagedResource{resource(key, "same", ConvergenceImpactNone, ConvergenceImpactNone)})
	planner := statusPlanner(t, ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}}, observationsFromResources(manifest.Resources))
	collector := statusCollectorFixture(t, state, now, planner, PassiveStatusSnapshot{Resources: []PassiveStatusResource{}})
	report, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Category != StatusCategoryUnavailable || !hasStatusProblem(report.Problems, "control_status_missing") ||
		!hasStatusProblem(report.Problems, "data_plane_status_missing") {
		t.Fatalf("incomplete passive status = %+v", report)
	}
}

func TestPassiveCoverageRequiresJoinedNodeGatewayAndSelectedTransportMetadata(t *testing.T) {
	t.Parallel()

	report := emptyStatusReport(model.RoleNode, "v2.0.0-dev")
	report.Runtime = healthyPassiveStatus().Resources
	state := model.State{
		Host:  model.Host{Role: model.RoleNode},
		Nodes: []model.Node{{Lifecycle: model.LifecycleActive, Gateway: &model.GatewayTrust{}}},
		Transports: []model.Transport{{
			OwnerKind: model.TargetNode, OwnerID: "11111111-1111-4111-8111-111111111111",
			Kind: model.TransportRestricted, State: model.TransportDegraded,
		}},
	}
	ensurePassiveCoverage(&report, state)
	if !hasStatusProblem(report.Problems, "gateway_status_missing") || !hasStatusProblem(report.Problems, "transport_status_missing") {
		t.Fatalf("joined-node passive coverage = %+v", report.Problems)
	}
}

func TestStatusCollectorWarnsAboutMissingGatewayBackupWithoutDegradingHealth(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	state := statusGatewayState(t, now)
	state.Invites = []model.Invite{}
	state.Logging = []model.LoggingSession{}
	state.Certificates[0].NotAfter = now.AddDate(1, 0, 0)
	state.Backups = []model.Backup{}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	collector := statusCollectorWithMatchingConvergence(t, state, now)
	report, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Category != StatusCategorySuccess || report.Overall != StatusOverallHealthy ||
		!hasStatusNotice(report.Warnings, "backup_missing") || !hasStatusNotice(report.RequiredActions, "create_gateway_backup") {
		t.Fatalf("missing-backup status = %+v", report)
	}
}

func TestStatusCollectorTreatsExpiredCertificateAsUnavailable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	state := statusGatewayState(t, now)
	state.Invites = []model.Invite{}
	state.Logging = []model.LoggingSession{}
	state.Certificates[0].NotAfter = now
	state.Backups[0].CreatedAt = now
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	collector := statusCollectorWithMatchingConvergence(t, state, now)
	report, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Category != StatusCategoryUnavailable || report.Overall != StatusOverallDegraded ||
		!hasStatusProblem(report.Problems, "certificate_expired") || !hasStatusNotice(report.RequiredActions, "rotate_public_certificate") {
		t.Fatalf("expired-certificate status = %+v", report)
	}
}

const (
	statusSecretHashCanary      = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	statusPrivateRefCanary      = "private-key:status-secret-canary"
	statusGatewayEndpointCanary = "https://203.0.113.10/.well-known/vpnctl/enroll"
)

type auditedStatusStateSource struct {
	state  model.State
	reads  int
	writes int
}

func (source *auditedStatusStateSource) ReadStatusState(context.Context) (model.State, error) {
	source.reads++
	return source.state, nil
}

func (source *auditedStatusStateSource) SaveStatusState(model.State) { source.writes++ }

type auditedStatusConvergenceSource struct {
	snapshot ConvergenceSnapshot
	err      error
	reads    int
	writes   int
}

func (source *auditedStatusConvergenceSource) ReadConvergenceSnapshot(context.Context) (ConvergenceSnapshot, error) {
	source.reads++
	return source.snapshot, source.err
}

func (source *auditedStatusConvergenceSource) SaveConvergenceSnapshot(ConvergenceSnapshot) {
	source.writes++
}

type auditedStatusDiscovery struct {
	observed  []OwnedResourceObservation
	reads     int
	mutations int
}

func (discovery *auditedStatusDiscovery) DiscoverOwnedResources(context.Context, ConvergenceManifest) ([]OwnedResourceObservation, error) {
	discovery.reads++
	return append([]OwnedResourceObservation{}, discovery.observed...), nil
}

func (discovery *auditedStatusDiscovery) RepairOwnedResources() { discovery.mutations++ }

type auditedPassiveStatusObserver struct {
	snapshot      PassiveStatusSnapshot
	reads         int
	syntheticDNS  int
	syntheticHTTP int
	webhookCalls  int
	mutations     int
}

func (observer *auditedPassiveStatusObserver) ReadPassiveStatus(_ context.Context, state model.State) (PassiveStatusSnapshot, error) {
	observer.reads++
	state.Host.ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	return observer.snapshot, nil
}

func (observer *auditedPassiveStatusObserver) ProbeDNS()      { observer.syntheticDNS++ }
func (observer *auditedPassiveStatusObserver) ProbeHTTP()     { observer.syntheticHTTP++ }
func (observer *auditedPassiveStatusObserver) CallWebhook()   { observer.webhookCalls++ }
func (observer *auditedPassiveStatusObserver) MutateRuntime() { observer.mutations++ }

func healthyPassiveStatus() PassiveStatusSnapshot {
	return PassiveStatusSnapshot{Resources: []PassiveStatusResource{
		{
			Class: PassiveStatusConnectivity, Resource: ManagedResourceKey{Component: "control", Kind: ManagedResourceState, ID: "control"},
			Condition: PassiveHealthy, Mandatory: true, Active: true, Version: "v2.0.0-dev", Protocol: "1.0",
			Generation: 8, RuntimeSHA256: ManagedFingerprint([]byte("control-runtime")), Code: "control_socket_ready",
		},
		{
			Class: PassiveStatusDataPlane, Resource: ManagedResourceKey{Component: "routing", Kind: ManagedResourceUnit, ID: "vpnctl-routing.service"},
			Condition: PassiveHealthy, Mandatory: true, Active: true, Version: "v1.19.30",
			Generation: 8, RuntimeSHA256: ManagedFingerprint([]byte("routing-runtime")), Code: "process_ready",
		},
	}}
}

func statusCollectorFixture(t *testing.T, state model.State, now time.Time, planner *ConvergencePlanner, passive PassiveStatusSnapshot) *StatusCollector {
	t.Helper()
	collector, err := NewStatusCollector(
		state.Host.Role, "v2.0.0-dev", func() time.Time { return now },
		&auditedStatusStateSource{state: state}, planner, &auditedPassiveStatusObserver{snapshot: passive},
	)
	if err != nil {
		t.Fatal(err)
	}
	return collector
}

func statusCollectorWithMatchingConvergence(t *testing.T, state model.State, now time.Time) *StatusCollector {
	t.Helper()
	key := ManagedResourceKey{Component: "control", Kind: ManagedResourceState, ID: "fleet"}
	manifest := convergenceManifest(t, state.Generation, []ManagedResource{resource(key, "same", ConvergenceImpactNone, ConvergenceImpactNone)})
	planner := statusPlanner(t, ConvergenceSnapshot{
		Desired: manifest, Applied: manifest, Pending: []PendingOperation{},
	}, observationsFromResources(manifest.Resources))
	return statusCollectorFixture(t, state, now, planner, healthyPassiveStatus())
}

func statusPlanner(t *testing.T, snapshot ConvergenceSnapshot, observed []OwnedResourceObservation) *ConvergencePlanner {
	t.Helper()
	planner, err := NewConvergencePlanner(&auditedStatusConvergenceSource{snapshot: snapshot}, &auditedStatusDiscovery{observed: observed})
	if err != nil {
		t.Fatal(err)
	}
	return planner
}

func statusGatewayState(t *testing.T, now time.Time) model.State {
	t.Helper()
	state := model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 8,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			Role: model.RoleGateway, OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: now.Add(-365 * 24 * time.Hour),
			PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", SSHPort: 22,
			ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24",
		},
		EnrollmentIdentity: &model.EnrollmentIdentity{
			SchemaVersion: model.ResourceSchemaVersion, Algorithm: "Ed25519",
			Fingerprint: "sha256:" + strings.Repeat("e", 64), PublicKeyRef: "enrollment-public:gateway",
			PrivateKeyRef: statusPrivateRefCanary, Generation: 1, CreatedAt: now.Add(-365 * 24 * time.Hour),
		},
		Invites: []model.Invite{{
			SchemaVersion: model.ResourceSchemaVersion, ID: "inv-ABC234", NodeName: "bot-server", ControlProtocol: "1.0",
			GatewayEndpoint: statusGatewayEndpointCanary, EnrollmentFingerprint: "sha256:" + strings.Repeat("e", 64),
			SecretHash: statusSecretHashCanary, State: model.InviteActive, IssuedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(10 * time.Minute),
		}},
		Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports: []model.Transport{}, Exposes: []model.Expose{},
		Certificates: []model.Certificate{{
			SchemaVersion: model.ResourceSchemaVersion, ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			Kind: model.CertificatePublicIngress, OwnerKind: "host", OwnerID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			Fingerprint: "sha256:" + strings.Repeat("f", 64), SerialHex: "01", Subject: "203.0.113.10",
			SANs: []string{"IP:203.0.113.10"}, NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: now.Add(100 * 24 * time.Hour),
			WarningDays: 180, Generation: 1, CertificateRef: "ingress-cert:public-g1", PrivateKeyRef: "ingress-key:public-g1",
		}},
		Operations: []model.Operation{},
		Logging: []model.LoggingSession{{
			SchemaVersion: model.ResourceSchemaVersion, ID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
			Scope: model.LogIngress, Level: model.LogTrace, Destination: model.LogToJournald, State: model.LogActive,
			StartedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(10 * time.Minute),
		}},
		Backups: []model.Backup{{
			SchemaVersion: model.ResourceSchemaVersion, ID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			State: model.BackupComplete, Format: "vpnctl-backup-v1", Path: "/var/lib/vpnctl/backups/status-test.v2b",
			SHA256: strings.Repeat("b", 64), SizeBytes: 4096, StateGeneration: 8, PublicIPv4: "203.0.113.10",
			CreatedAt: now.Add(-StatusBackupWarningAge),
		}},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0-dev",
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: model.StateSchemaVersion, StateSchemaMaximum: model.StateSchemaVersion,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1, MigrationReversible: true,
			Components: []model.ComponentPin{
				{Name: "vpnctl", Version: "v2.0.0-dev", Source: "bundle:vpnctl", Bundled: true, SHA256: strings.Repeat("a", 64), Capabilities: []string{"cli", "controller"}},
				{Name: "mihomo", Version: "v1.19.30", Source: "bundle:mihomo", Bundled: true, SHA256: strings.Repeat("d", 64), Capabilities: []string{"routing", "restricted"}},
			},
		},
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("status state fixture: %v", err)
	}
	return state
}

func cloneStatusTestState(t *testing.T, state model.State) model.State {
	t.Helper()
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var clone model.State
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func hasStatusNotice(values []StatusNotice, code string) bool {
	for _, value := range values {
		if value.Code == code {
			return true
		}
	}
	return false
}

func hasStatusProblem(values []StatusProblem, code string) bool {
	for _, value := range values {
		if value.Code == code {
			return true
		}
	}
	return false
}
