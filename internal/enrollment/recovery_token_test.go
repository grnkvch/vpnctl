package enrollment

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
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestRecoveryIssueBindsExpiredExistingNodeAndStoresNoPlaintext(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", false)
	defer fixture.destroy()
	state, _ := fixture.gatewayState.Load()
	certificate, err := currentNodeControlCertificate(state, state.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	now := certificate.NotAfter
	manager, err := NewRecoveryManager(
		fixture.gatewayState, bytes.NewReader(bytes.Repeat([]byte{0x37}, 128)), func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.PlanIssue(joinTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NodeID != joinTestNodeID || plan.NodeName != "private-node" ||
		plan.CredentialGeneration != 1 || plan.BindingFingerprint != certificate.Fingerprint ||
		plan.GatewayEndpoint != "https://203.0.113.10"+EnrollmentRecoveryPath ||
		plan.ExpiresAt.Sub(plan.IssuedAt) != 15*time.Minute || plan.ExpectedStateGeneration != state.Generation {
		t.Fatalf("PlanIssue() = %+v", plan)
	}
	result, err := manager.CommitIssue(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Token.Destroy()
	if result.RecoveryID == "" || result.NodeID != joinTestNodeID || result.StateGeneration != state.Generation+1 {
		t.Fatalf("CommitIssue() = %+v", result)
	}
	var encoded []byte
	if err := result.Token.Use(func(value []byte) error {
		encoded = append([]byte(nil), value...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRecoveryToken(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Destroy()
	if decoded.RecoveryID != result.RecoveryID || decoded.NodeID != joinTestNodeID ||
		decoded.CredentialGeneration != 1 || decoded.BindingFingerprint != certificate.Fingerprint ||
		decoded.ExpectedGatewayStateGeneration != state.Generation+1 {
		t.Fatalf("DecodeRecoveryToken() = %+v", decoded)
	}
	if _, err := json.Marshal(decoded); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	authorization, err := manager.Authorize(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.RequestedCredentialGeneration != 2 || authorization.ActiveTransport != model.TransportRestricted ||
		!reflect.DeepEqual(authorization.Presets, []string{"telegram"}) ||
		!reflect.DeepEqual(authorization.ExposeIDs, []string{rotationExposeID}) {
		t.Fatalf("Authorize() = %+v", authorization)
	}
	persisted, _ := fixture.gatewayState.Load()
	persistedJSON, _ := model.EncodeState(persisted)
	secretText := recoveryTokenSecretText(t, encoded)
	if strings.Contains(string(persistedJSON), string(encoded)) || strings.Contains(string(persistedJSON), secretText) ||
		persisted.Invites[len(persisted.Invites)-1].SecretHash == "" {
		t.Fatal("gateway state retained plaintext recovery token material or omitted its hash")
	}
	if statuses, err := fixture.manager.Status(); err != nil || len(statuses) != 1 {
		// The joined fixture retains its consumed enrollment invite. Recovery
		// records must not leak into the ordinary invite projection.
		t.Fatalf("ordinary invite status included recovery token: %+v, %v", statuses, err)
	}
}

func TestRecoveryAuthorizationExpiresFailClosedAtExactBoundary(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", false)
	defer fixture.destroy()
	state, _ := fixture.gatewayState.Load()
	certificate, _ := currentNodeControlCertificate(state, state.Nodes[0])
	now := certificate.NotAfter
	manager, _ := NewRecoveryManager(
		fixture.gatewayState, bytes.NewReader(bytes.Repeat([]byte{0x45}, 128)), func() time.Time { return now },
	)
	plan, _ := manager.PlanIssue(joinTestNodeID)
	result, err := manager.CommitIssue(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Token.Destroy()
	var token []byte
	_ = result.Token.Use(func(value []byte) error { token = append([]byte(nil), value...); return nil })
	now = result.ExpiresAt
	if _, err := manager.Authorize(token); !errors.Is(err, ErrRecoveryExpired) {
		t.Fatalf("Authorize(at expiry) error = %v", err)
	}
	after, _ := fixture.gatewayState.Load()
	if after.Generation != result.StateGeneration || after.Invites[len(after.Invites)-1].State != model.InviteActive {
		t.Fatalf("expired authorization mutated state: generation=%d invite=%+v", after.Generation, after.Invites[len(after.Invites)-1])
	}
}

func TestRecoveryIssueRejectsUnexpiredRevokedAndDeletedNodes(t *testing.T) {
	for _, lifecycle := range []model.Lifecycle{model.LifecycleActive, model.LifecycleRevoked, model.LifecycleDeleted} {
		name := string(lifecycle)
		if lifecycle == model.LifecycleActive {
			name = "unexpired"
		}
		test := struct {
			name      string
			lifecycle model.Lifecycle
		}{name: name, lifecycle: lifecycle}
		t.Run(test.name, func(t *testing.T) {
			fixture := newNodeRotationFixture(t, "", false)
			defer fixture.destroy()
			state, _ := fixture.gatewayState.Load()
			certificate, _ := currentNodeControlCertificate(state, state.Nodes[0])
			if test.lifecycle != model.LifecycleActive {
				revoked, err := buildNodeRevocationCandidate(state, joinTestNodeID, fixture.now.Add(3*time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				state = revoked
				if test.lifecycle == model.LifecycleDeleted {
					state, err = buildNodeDeletionCandidate(state, joinTestNodeID)
					if err != nil {
						t.Fatal(err)
					}
				}
				fixture.gatewayState.state = cloneInviteState(t, state)
			}
			now := certificate.NotAfter.Add(-time.Second)
			if test.name != "unexpired" {
				now = certificate.NotAfter
			}
			manager, _ := NewRecoveryManager(fixture.gatewayState, nil, func() time.Time { return now })
			_, err := manager.PlanIssue(joinTestNodeID)
			if !errors.Is(err, ErrRecoveryNodeInactive) && !errors.Is(err, ErrNodeNotFound) {
				t.Fatalf("PlanIssue(%s) error = %v", test.name, err)
			}
		})
	}
}

func TestRecoveryTokenRejectsTamperAndWrongNamespace(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", false)
	defer fixture.destroy()
	state, _ := fixture.gatewayState.Load()
	certificate, _ := currentNodeControlCertificate(state, state.Nodes[0])
	manager, _ := NewRecoveryManager(
		fixture.gatewayState, bytes.NewReader(bytes.Repeat([]byte{0x58}, 128)), func() time.Time { return certificate.NotAfter },
	)
	plan, _ := manager.PlanIssue(joinTestNodeID)
	result, err := manager.CommitIssue(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Token.Destroy()
	var token []byte
	_ = result.Token.Use(func(value []byte) error { token = append([]byte(nil), value...); return nil })
	tampered := append([]byte(nil), token...)
	tampered[len(tampered)-1] ^= 1
	if _, err := DecodeRecoveryToken(tampered); !errors.Is(err, ErrRecoveryTokenInvalid) {
		t.Fatalf("tampered token error = %v", err)
	}
	wrong := []byte(strings.Replace(string(token), RecoveryTokenPrefix, InviteTokenPrefix, 1))
	if _, err := DecodeRecoveryToken(wrong); !errors.Is(err, ErrRecoveryTokenInvalid) {
		t.Fatalf("wrong namespace error = %v", err)
	}
}

func recoveryTokenSecretText(t *testing.T, encoded []byte) string {
	t.Helper()
	decoded, err := DecodeRecoveryToken(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Destroy()
	var result string
	if err := decoded.secret.Use(func(value []byte) error {
		result = tokenEncoding.EncodeToString(value)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}
