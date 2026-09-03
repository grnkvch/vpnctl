package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	storepkg "github.com/vgrinkevich/vpnctl/internal/store"
)

func TestInviteIssueStoresOnlyHashAndTokenRoundTrips(t *testing.T) {
	t.Parallel()

	clock := newInviteTestClock()
	stateStore := newInviteMemoryState(t, inviteGatewayState(clock.now))
	manager := newInviteTestManager(t, stateStore, clock, inviteEntropy(1))
	plan, err := manager.PlanIssue("bot-server")
	if err != nil {
		t.Fatalf("PlanIssue() error = %v", err)
	}
	if plan.ExpiresAt.Sub(plan.IssuedAt) != 15*time.Minute || plan.ExpectedStateGeneration != 1 {
		t.Fatalf("issue plan = %+v", plan)
	}
	result, err := manager.CommitIssue(context.Background(), plan)
	if err != nil {
		t.Fatalf("CommitIssue() error = %v", err)
	}
	defer result.Token.Destroy()
	if result.StateGeneration != 2 || result.Invite.ID == "" || result.Invite.State != InviteDisplayActive {
		t.Fatalf("issue result = %+v", result)
	}

	var encoded []byte
	if err := result.Token.Use(func(value []byte) error {
		encoded = append([]byte(nil), value...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeInviteToken(encoded)
	if err != nil {
		t.Fatalf("DecodeInviteToken() error = %v", err)
	}
	defer decoded.Destroy()
	if decoded.InviteID != result.Invite.ID || decoded.NodeName != "bot-server" || decoded.ControlProtocol != "1.0" ||
		decoded.GatewayEndpoint != "https://203.0.113.10/.well-known/vpnctl/enroll" ||
		decoded.EnrollmentFingerprint != inviteFingerprint("a") || !decoded.ExpiresAt.Equal(plan.ExpiresAt) {
		t.Fatalf("decoded token = %+v", decoded)
	}
	if err := decoded.secret.Use(func(secret []byte) error {
		if len(secret) != 32 {
			t.Fatalf("decoded invite secret length = %d", len(secret))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(decoded); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("Marshal(decoded token) error = %v", err)
	}

	state, err := stateStore.Load()
	if err != nil || len(state.Invites) != 1 || state.Invites[0].SecretHash == "" || len(state.Invites[0].SecretHash) != 64 {
		t.Fatalf("stored state = %+v, %v", state.Invites, err)
	}
	stateJSON, err := model.EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	secretText := tokenSecretText(t, encoded)
	for _, forbidden := range []string{string(encoded), secretText} {
		if strings.Contains(string(stateJSON), forbidden) {
			t.Fatalf("authoritative state contains token material %q", forbidden)
		}
	}
	statuses, err := manager.ActiveStatus()
	if err != nil || len(statuses) != 1 {
		t.Fatalf("ActiveStatus() = %+v, %v", statuses, err)
	}
	statusJSON, err := json.Marshal(statuses)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{state.Invites[0].SecretHash, string(encoded), secretText, "secret_hash"} {
		if strings.Contains(string(statusJSON), forbidden) {
			t.Fatalf("public status contains secret material %q: %s", forbidden, statusJSON)
		}
	}
}

func TestInviteTokenRejectsTamperAndNonCanonicalEncoding(t *testing.T) {
	t.Parallel()

	clock := newInviteTestClock()
	stateStore := newInviteMemoryState(t, inviteGatewayState(clock.now))
	manager := newInviteTestManager(t, stateStore, clock, inviteEntropy(2))
	encoded := issueInviteToken(t, manager, "private-node")

	parts := strings.Split(string(encoded), ".")
	payload, err := tokenEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)/2] ^= 1
	tampered := []byte(parts[0] + "." + tokenEncoding.EncodeToString(payload) + "." + parts[2])
	if _, err := DecodeInviteToken(tampered); !errors.Is(err, ErrInviteTokenInvalid) {
		t.Fatalf("tampered DecodeInviteToken() error = %v", err)
	}
	if _, err := DecodeInviteToken(append(encoded, '\n')); !errors.Is(err, ErrInviteTokenInvalid) {
		t.Fatalf("whitespace DecodeInviteToken() error = %v", err)
	}

	decoded, err := DecodeInviteToken(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Destroy()
	state, _ := stateStore.Load()
	invite := state.Invites[0]
	invite.NodeName = "substituted-node"
	var forged *output.Secret
	if err := decoded.secret.Use(func(secret []byte) error {
		var encodeErr error
		forged, encodeErr = encodeInviteToken(invite, secret)
		return encodeErr
	}); err != nil {
		t.Fatal(err)
	}
	defer forged.Destroy()
	var forgedBytes []byte
	_ = forged.Use(func(value []byte) error {
		forgedBytes = append([]byte(nil), value...)
		return nil
	})
	if _, err := manager.Consume(context.Background(), forgedBytes); !errors.Is(err, ErrInviteTokenInvalid) {
		t.Fatalf("metadata-substituted Consume() error = %v", err)
	}
}

func TestInviteExpiryIsFailClosedAtExactBoundary(t *testing.T) {
	t.Parallel()

	clock := newInviteTestClock()
	stateStore := newInviteMemoryState(t, inviteGatewayState(clock.now))
	manager := newInviteTestManager(t, stateStore, clock, inviteEntropy(3))
	encoded := issueInviteToken(t, manager, "expiring-node")
	clock.advance(model.InviteTTL)
	if _, err := manager.Consume(context.Background(), encoded); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("Consume(expired) error = %v", err)
	}
	state, _ := stateStore.Load()
	if state.Generation != 2 || state.Invites[0].State != model.InviteActive || state.Invites[0].ConsumedAt != nil {
		t.Fatalf("expired consume mutated state = generation %d invite %+v", state.Generation, state.Invites[0])
	}
	active, err := manager.ActiveStatus()
	if err != nil || len(active) != 0 {
		t.Fatalf("ActiveStatus(expired) = %+v, %v", active, err)
	}
	statuses, _ := manager.Status()
	if len(statuses) != 1 || statuses[0].State != InviteDisplayExpired {
		t.Fatalf("Status(expired) = %+v", statuses)
	}
}

func TestInviteConsumptionRejectsReplayWithoutSecondMutation(t *testing.T) {
	t.Parallel()

	clock := newInviteTestClock()
	stateStore := newInviteMemoryState(t, inviteGatewayState(clock.now))
	manager := newInviteTestManager(t, stateStore, clock, inviteEntropy(4))
	encoded := issueInviteToken(t, manager, "single-use")
	clock.advance(time.Minute)
	first, err := manager.Consume(context.Background(), encoded)
	if err != nil || first.StateGeneration != 3 || first.NodeName != "single-use" {
		t.Fatalf("first Consume() = %+v, %v", first, err)
	}
	if _, err := manager.Consume(context.Background(), encoded); !errors.Is(err, ErrInviteConsumed) {
		t.Fatalf("replayed Consume() error = %v", err)
	}
	state, _ := stateStore.Load()
	if state.Generation != 3 || state.Invites[0].State != model.InviteConsumed || len(state.Invites[0].ConsumptionHash) != 64 {
		t.Fatalf("replay state = generation %d invite %+v", state.Generation, state.Invites[0])
	}
}

func TestInviteCancellationIsImmediateAndIdempotent(t *testing.T) {
	t.Parallel()

	clock := newInviteTestClock()
	stateStore := newInviteMemoryState(t, inviteGatewayState(clock.now))
	manager := newInviteTestManager(t, stateStore, clock, inviteEntropy(5))
	encoded := issueInviteToken(t, manager, "cancelled-node")
	state, _ := stateStore.Load()
	id := state.Invites[0].ID
	clock.advance(time.Minute)
	plan, err := manager.PlanCancel(id)
	if err != nil || !plan.Changed || plan.NextStateGeneration != 3 {
		t.Fatalf("first PlanCancel() = %+v, %v", plan, err)
	}
	concurrentPlan, err := manager.PlanCancel(id)
	if err != nil || !concurrentPlan.Changed {
		t.Fatalf("concurrent PlanCancel() = %+v, %v", concurrentPlan, err)
	}
	first, err := manager.CommitCancel(plan)
	if err != nil || !first.Changed || first.StateGeneration != 3 {
		t.Fatalf("first CommitCancel() = %+v, %v", first, err)
	}
	if _, err := manager.Consume(context.Background(), encoded); !errors.Is(err, ErrInviteCancelled) {
		t.Fatalf("Consume(cancelled) error = %v", err)
	}
	concurrent, err := manager.CommitCancel(concurrentPlan)
	if err != nil || concurrent.Changed || concurrent.StateGeneration != 3 {
		t.Fatalf("concurrent CommitCancel() = %+v, %v", concurrent, err)
	}
	secondPlan, err := manager.PlanCancel(id)
	if err != nil || secondPlan.Changed || secondPlan.NextStateGeneration != 3 {
		t.Fatalf("second PlanCancel() = %+v, %v", secondPlan, err)
	}
	second, err := manager.CommitCancel(secondPlan)
	if err != nil || second.Changed || second.StateGeneration != 3 {
		t.Fatalf("second CommitCancel() = %+v, %v", second, err)
	}
}

func TestInviteConsumedCancellationDirectsToRevocation(t *testing.T) {
	t.Parallel()

	clock := newInviteTestClock()
	stateStore := newInviteMemoryState(t, inviteGatewayState(clock.now))
	manager := newInviteTestManager(t, stateStore, clock, inviteEntropy(6))
	encoded := issueInviteToken(t, manager, "joined-node")
	state, _ := stateStore.Load()
	id := state.Invites[0].ID
	clock.advance(time.Minute)
	if _, err := manager.Consume(context.Background(), encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.PlanCancel(id); !errors.Is(err, ErrInviteConsumed) || !strings.Contains(err.Error(), "revoke") {
		t.Fatalf("PlanCancel(consumed) error = %v", err)
	}
	if _, err := manager.PlanIssue("JOINED-NODE"); !errors.Is(err, ErrInviteNameConflict) {
		t.Fatalf("PlanIssue(consumed name) error = %v", err)
	}
}

func TestInviteNameReservationUsesNodesAndOnlyUnexpiredActiveInvites(t *testing.T) {
	t.Parallel()

	clock := newInviteTestClock()
	state := inviteGatewayState(clock.now)
	state.Nodes = append(state.Nodes, model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		Name: "existing-node", Lifecycle: model.LifecycleDeleted, OverlayIPv4: "10.67.0.2",
		CredentialGeneration: 1, AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
		IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: clock.now,
		RevokedAt: func() *time.Time { value := clock.now; return &value }(),
	})
	stateStore := newInviteMemoryState(t, state)
	manager := newInviteTestManager(t, stateStore, clock, inviteEntropy(7))
	if _, err := manager.PlanIssue("EXISTING-NODE"); !errors.Is(err, ErrInviteNameConflict) {
		t.Fatalf("PlanIssue(existing node) error = %v", err)
	}
	_ = issueInviteToken(t, manager, "reserved-name")
	if _, err := manager.PlanIssue("Reserved-Name"); !errors.Is(err, ErrInviteNameConflict) {
		t.Fatalf("PlanIssue(active reservation) error = %v", err)
	}
	clock.advance(model.InviteTTL)
	if _, err := manager.PlanIssue("reserved-name"); err != nil {
		t.Fatalf("PlanIssue(after expiry) error = %v", err)
	}
}

func TestInviteDryPlanConsumesNoEntropy(t *testing.T) {
	t.Parallel()

	clock := newInviteTestClock()
	stateStore := newInviteMemoryState(t, inviteGatewayState(clock.now))
	entropy := &countingReader{reader: bytes.NewReader(inviteEntropy(8))}
	manager, err := NewInviteManager(stateStore, entropy, func() time.Time { return clock.now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.PlanIssue("dry-run-node"); err != nil {
		t.Fatal(err)
	}
	if entropy.read != 0 {
		t.Fatalf("PlanIssue() consumed %d entropy bytes", entropy.read)
	}
	state, _ := stateStore.Load()
	if state.Generation != 1 || len(state.Invites) != 0 {
		t.Fatalf("PlanIssue() mutated state = generation %d invites %d", state.Generation, len(state.Invites))
	}
}

func TestInviteTTLStartsWhenTokenIsCommittedAndStalePlanCreatesNothing(t *testing.T) {
	t.Parallel()

	clock := newInviteTestClock()
	stateStore := newInviteMemoryState(t, inviteGatewayState(clock.now))
	manager := newInviteTestManager(t, stateStore, clock, append(inviteEntropy(9), inviteEntropy(19)...))
	plan, err := manager.PlanIssue("delayed-node")
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Minute)
	result, err := manager.CommitIssue(context.Background(), plan)
	if err != nil {
		t.Fatalf("CommitIssue(delayed) error = %v", err)
	}
	defer result.Token.Destroy()
	if !result.Invite.IssuedAt.Equal(clock.now) || result.Invite.ExpiresAt.Sub(result.Invite.IssuedAt) != model.InviteTTL {
		t.Fatalf("delayed invite window = %s..%s", result.Invite.IssuedAt, result.Invite.ExpiresAt)
	}

	stalePlan, err := manager.PlanIssue("stale-plan-node")
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(model.InviteTTL)
	if _, err := manager.CommitIssue(context.Background(), stalePlan); !errors.Is(err, ErrInvitePlanStale) {
		t.Fatalf("CommitIssue(stale plan) error = %v", err)
	}
	state, _ := stateStore.Load()
	if state.Generation != 2 || len(state.Invites) != 1 {
		t.Fatalf("stale issue mutated state = generation %d invites %d", state.Generation, len(state.Invites))
	}
}

func TestInviteLimitsMatchDevelopmentManifest(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "v2", "COMPONENT_LIMITS.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Limits struct {
			Enrollment struct {
				Transcript        string `json:"transcript"`
				Signature         string `json:"signature"`
				SecretBytes       int    `json:"invite_secret_bytes"`
				NodeNonceBytes    int    `json:"node_nonce_bytes"`
				GatewayNonceBytes int    `json:"gateway_nonce_bytes"`
				TTLSeconds        int    `json:"invite_ttl_seconds"`
				ClockSkewSeconds  int    `json:"clock_skew_seconds"`
			} `json:"enrollment"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Limits.Enrollment.SecretBytes != InviteSecretBytes ||
		manifest.Limits.Enrollment.Transcript != EnrollmentTranscriptDomain ||
		manifest.Limits.Enrollment.Signature != EnrollmentSignatureAlgorithm ||
		manifest.Limits.Enrollment.NodeNonceBytes != EnrollmentNonceBytes ||
		manifest.Limits.Enrollment.GatewayNonceBytes != EnrollmentNonceBytes ||
		time.Duration(manifest.Limits.Enrollment.TTLSeconds)*time.Second != model.InviteTTL ||
		time.Duration(manifest.Limits.Enrollment.ClockSkewSeconds)*time.Second != EnrollmentClockSkew {
		t.Fatalf("invite limits drifted: %+v", manifest.Limits.Enrollment)
	}
}

type inviteTestClock struct {
	now time.Time
}

func newInviteTestClock() *inviteTestClock {
	return &inviteTestClock{now: time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)}
}

func (clock *inviteTestClock) advance(duration time.Duration) { clock.now = clock.now.Add(duration) }

type inviteMemoryState struct {
	mu    sync.Mutex
	state model.State
}

func newInviteMemoryState(t *testing.T, state model.State) *inviteMemoryState {
	t.Helper()
	if err := state.Validate(); err != nil {
		t.Fatalf("invite state fixture: %v", err)
	}
	return &inviteMemoryState{state: cloneInviteState(t, state)}
}

func (store *inviteMemoryState) Load() (model.State, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	encoded, err := model.EncodeState(store.state)
	if err != nil {
		return model.State{}, err
	}
	return model.DecodeState(encoded)
}

func (store *inviteMemoryState) Save(expected uint64, candidate model.State) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state.Generation != expected {
		return storepkg.ErrStateConflict
	}
	if err := model.ValidateTransition(store.state, candidate); err != nil {
		return err
	}
	encoded, err := model.EncodeState(candidate)
	if err != nil {
		return err
	}
	store.state, err = model.DecodeState(encoded)
	return err
}

func cloneInviteState(t *testing.T, state model.State) model.State {
	t.Helper()
	encoded, err := model.EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := model.DecodeState(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}

func inviteGatewayState(now time.Time) model.State {
	return model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			Role: model.RoleGateway, OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: now,
			PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", SSHPort: 22,
			ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24",
		},
		EnrollmentIdentity: &model.EnrollmentIdentity{
			SchemaVersion: model.ResourceSchemaVersion, Algorithm: "Ed25519", Fingerprint: inviteFingerprint("a"),
			PublicKeyRef: "enrollment-public:gateway", PrivateKeyRef: "enrollment-key:gateway", Generation: 1, CreatedAt: now,
		},
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{},
		Policies: []model.Policy{}, Transports: []model.Transport{}, Exposes: []model.Expose{},
		Certificates: []model.Certificate{}, Operations: []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0-dev",
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: 1, StateSchemaMaximum: 1,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1,
			MigrationReversible: true,
			Components: []model.ComponentPin{{
				Name: "vpnctl", Version: "v2.0.0-dev", Source: "bundle:vpnctl", Bundled: true,
				SHA256: strings.Repeat("1", 64), Capabilities: []string{"cli", "controller"},
			}},
		},
	}
}

func newInviteTestManager(t *testing.T, store InviteStateStore, clock *inviteTestClock, entropy []byte) *InviteManager {
	t.Helper()
	manager, err := NewInviteManager(store, bytes.NewReader(entropy), func() time.Time { return clock.now })
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func inviteEntropy(seed byte) []byte {
	result := make([]byte, 4+InviteSecretBytes)
	for index := range result {
		result[index] = seed + byte(index)
	}
	return result
}

func issueInviteToken(t *testing.T, manager *InviteManager, name string) []byte {
	t.Helper()
	plan, err := manager.PlanIssue(name)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.CommitIssue(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Token.Destroy()
	var encoded []byte
	if err := result.Token.Use(func(value []byte) error {
		encoded = append([]byte(nil), value...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return encoded
}

func tokenSecretText(t *testing.T, encoded []byte) string {
	t.Helper()
	parts := strings.Split(string(encoded), ".")
	payload, err := tokenEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var envelope inviteTokenEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Secret
}

func inviteFingerprint(character string) string { return "sha256:" + strings.Repeat(character, 64) }

type countingReader struct {
	reader *bytes.Reader
	read   int
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.read += count
	return count, err
}

func TestInviteStatusOrderingIsStable(t *testing.T) {
	t.Parallel()

	clock := newInviteTestClock()
	stateStore := newInviteMemoryState(t, inviteGatewayState(clock.now))
	entropy := append(inviteEntropy(10), inviteEntropy(20)...)
	manager := newInviteTestManager(t, stateStore, clock, entropy)
	_ = issueInviteToken(t, manager, "first")
	clock.advance(time.Second)
	_ = issueInviteToken(t, manager, "second")
	statuses, err := manager.Status()
	if err != nil || len(statuses) != 2 || !reflect.DeepEqual([]string{statuses[0].NodeName, statuses[1].NodeName}, []string{"first", "second"}) {
		t.Fatalf("Status() = %+v, %v", statuses, err)
	}
}
