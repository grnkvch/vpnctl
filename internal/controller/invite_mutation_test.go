package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestGatewayInviteDispatcherIssuesAndCancelsUnderControllerWriter(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.EnrollmentIdentity = &model.EnrollmentIdentity{
		SchemaVersion: model.ResourceSchemaVersion, Algorithm: "Ed25519",
		Fingerprint:  "sha256:" + strings.Repeat("a", 64),
		PublicKeyRef: "enrollment-public:gateway", PrivateKeyRef: "enrollment-key:gateway",
		Generation: 1, CreatedAt: now,
	}
	if err := stateStore.Save(state.Generation, withNextGeneration(t, state)); err != nil {
		t.Fatal(err)
	}
	state, err = stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}

	dispatcher := NewGatewayInviteMutationDispatcher(strings.NewReader(strings.Repeat("i", 128)), func() time.Time { return now })
	dns, err := NewGatewayDNSMutationDispatcher(paths, &gatewayDNSControllerRunner{})
	if err != nil {
		t.Fatal(err)
	}
	logging, err := NewGatewayLoggingMutationDispatcher(paths, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewGatewayMutationDispatcher(dns, logging, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewController(ControllerRuntime{
		Paths: paths, State: stateStore, Observer: &recordingObserver{}, Dispatcher: router,
	})
	if err != nil {
		t.Fatal(err)
	}
	issuePlan := enrollment.InviteIssuePlan{
		NodeName: "bot-server", ControlProtocol: state.Components.ControlProtocols[0],
		GatewayEndpoint:       "https://203.0.113.10/.well-known/vpnctl/enroll",
		EnrollmentFingerprint: state.EnrollmentIdentity.Fingerprint,
		IssuedAt:              now, ExpiresAt: now.Add(model.InviteTTL), ExpectedStateGeneration: state.Generation,
	}
	issuePayload, err := json.Marshal(GatewayInviteIssuePayload{Plan: issuePlan})
	if err != nil {
		t.Fatal(err)
	}
	issued := server.mutateResponse(control.LocalRequest{
		SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate,
		Operation: enrollment.InviteIssueOperation, ExpectedGeneration: state.Generation, Payload: issuePayload,
	})
	if !issued.OK || issued.Generation != state.Generation+1 {
		t.Fatalf("invite issue response = %+v", issued)
	}
	var issueData GatewayInviteIssueData
	if err := control.DecodeRPCPayload(issued.Data, &issueData); err != nil {
		t.Fatal(err)
	}
	if issueData.Token == "" || issueData.Invite.NodeName != "bot-server" {
		t.Fatalf("invite issue data = %+v", issueData)
	}
	afterIssue, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	encodedState, err := model.EncodeState(afterIssue)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedState), issueData.Token) || len(afterIssue.Invites) != 1 || afterIssue.Invites[0].SecretHash == "" {
		t.Fatalf("authoritative invite state contains token or lacks hash: %s", encodedState)
	}

	cancelPayload, err := json.Marshal(GatewayInviteCancelPayload{
		InviteID: issueData.Invite.ID, ExpectedStateGeneration: afterIssue.Generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	cancelled := server.mutateResponse(control.LocalRequest{
		SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate,
		Operation: enrollment.InviteCancelOperation, ExpectedGeneration: afterIssue.Generation, Payload: cancelPayload,
	})
	if !cancelled.OK || cancelled.Generation != afterIssue.Generation+1 {
		t.Fatalf("invite cancel response = %+v", cancelled)
	}
	afterCancel, err := stateStore.Load()
	if err != nil || afterCancel.Invites[0].State != model.InviteCancelled {
		t.Fatalf("cancelled invite state = %+v, %v", afterCancel.Invites, err)
	}
}

func TestGatewayInviteDispatcherRejectsAmbiguousPayloads(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	_ = paths
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := NewGatewayInviteMutationDispatcher(nil, nil)
	for _, test := range []struct {
		operation string
		payload   string
	}{
		{operation: enrollment.InviteIssueOperation, payload: `{"plan":{},"secret":"forbidden"}`},
		{operation: enrollment.InviteCancelOperation, payload: `{"invite_id":"inv-AAAAAA","expected_state_generation":1} {}`},
		{operation: "invite.rotate", payload: `{}`},
	} {
		if _, err := dispatcher.Prepare(context.Background(), state, test.operation, json.RawMessage(test.payload)); err == nil {
			t.Fatalf("Prepare(%s, %s) accepted invalid request", test.operation, test.payload)
		}
	}
}

func withNextGeneration(t *testing.T, state model.State) model.State {
	t.Helper()
	next, err := model.NextGeneration(state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	state.Generation = next
	return state
}
