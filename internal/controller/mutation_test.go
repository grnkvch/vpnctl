package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

const mutationTestNodeID = "20000000-0000-4000-8000-000000000001"

func TestNodeMutationResponseLossReplaysStoredResult(t *testing.T) {
	controller, stateStore, now := mutationTestController(t)
	dispatcher := &faultMutationDispatcher{desiredSSHPort: 2222}
	handler, err := controller.NewNodeMutationHandler(dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	request := mutationTestRequest("30000000-0000-4000-8000-000000000001", 2)

	committed, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request)
	if err != nil || committed.StatusCode != http.StatusOK || committed.Response.AuthoritativeGeneration != 3 || committed.Response.ResultHash == "" {
		t.Fatalf("initial HandleRPC() = %+v, %v", committed, err)
	}
	// Simulate loss after commit by discarding the first response and retaining
	// the exact locally persisted request ID and expected generation.
	replayed, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request)
	if err != nil || replayed.StatusCode != http.StatusOK || replayed.Response.AuthoritativeGeneration != 3 ||
		replayed.Response.ResultHash != committed.Response.ResultHash {
		t.Fatalf("replayed HandleRPC() = %+v, %v", replayed, err)
	}
	var replaySummary struct {
		Replayed     bool               `json:"replayed"`
		ResultStatus model.ResultStatus `json:"result_status"`
	}
	if err := json.Unmarshal(replayed.Response.Data, &replaySummary); err != nil || !replaySummary.Replayed || replaySummary.ResultStatus != model.ResultOK {
		t.Fatalf("replay summary = %+v, %v", replaySummary, err)
	}
	if err := replayed.Response.Validate(); err != nil {
		t.Fatalf("replay response validation = %v", err)
	}
	state, err := stateStore.Load()
	if err != nil || state.Generation != 3 || state.Host.SSHPort != 2222 || len(state.Nodes[0].IdempotencyRecords) != 1 {
		t.Fatalf("committed state = generation %d port %d records %d, %v", state.Generation, state.Host.SSHPort, len(state.Nodes[0].IdempotencyRecords), err)
	}
	record := state.Nodes[0].IdempotencyRecords[0]
	if record.RequestID != request.RequestID || record.Operation != model.OperationApply || record.ResultStatus != model.ResultOK ||
		record.ResultHash != committed.Response.ResultHash || record.StateGeneration != 3 || !record.RecordedAt.Equal(now) {
		t.Fatalf("stored idempotency record = %+v", record)
	}
	if calls, _, reconciles := dispatcher.counts(); calls != 1 || reconciles != 0 {
		t.Fatalf("dispatcher calls/reconciles = %d/%d, want 1/0", calls, reconciles)
	}

	conflicting := request
	conflicting.Operation = string(model.OperationDelete)
	result, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, conflicting)
	if err != nil || result.StatusCode != http.StatusConflict || result.Response.ErrorCode != "request_id_conflict" {
		t.Fatalf("request ID operation conflict = %+v, %v", result, err)
	}
	if calls, _, _ := dispatcher.counts(); calls != 1 {
		t.Fatalf("request ID conflict reached dispatcher %d times", calls)
	}
}

func TestNodeMutationConcurrentDuplicateRequestsHaveOneEffect(t *testing.T) {
	controller, stateStore, _ := mutationTestController(t)
	dispatcher := &faultMutationDispatcher{desiredSSHPort: 2222, dispatchDelay: 5 * time.Millisecond}
	handler, _ := controller.NewNodeMutationHandler(dispatcher)
	request := mutationTestRequest("30000000-0000-4000-8000-000000000002", 2)

	const callers = 24
	results := make(chan control.RPCHandlerResult, callers)
	errorsSeen := make(chan error, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request)
			results <- result
			errorsSeen <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Errorf("HandleRPC() error = %v", err)
		}
	}
	var resultHash string
	for result := range results {
		if result.StatusCode != http.StatusOK || result.Response.AuthoritativeGeneration != 3 || result.Response.ResultHash == "" {
			t.Errorf("duplicate result = %+v", result)
		}
		if resultHash == "" {
			resultHash = result.Response.ResultHash
		} else if result.Response.ResultHash != resultHash {
			t.Errorf("duplicate result hash = %q, want %q", result.Response.ResultHash, resultHash)
		}
	}
	if calls, maximumActive, reconciles := dispatcher.counts(); calls != 1 || maximumActive != 1 || reconciles != 0 {
		t.Fatalf("dispatcher calls/maximum/reconciles = %d/%d/%d, want 1/1/0", calls, maximumActive, reconciles)
	}
	state, err := stateStore.Load()
	if err != nil || state.Generation != 3 || state.Host.SSHPort != 2222 || len(state.Nodes[0].IdempotencyRecords) != 1 {
		t.Fatalf("state after duplicate burst = %+v, %v", state, err)
	}
}

func TestNodeMutationConcurrentStaleRequestsConflictWithoutPartialEffects(t *testing.T) {
	controller, stateStore, _ := mutationTestController(t)
	dispatcher := &faultMutationDispatcher{desiredSSHPort: 2222, dispatchDelay: 5 * time.Millisecond}
	handler, _ := controller.NewNodeMutationHandler(dispatcher)

	const callers = 12
	results := make(chan control.RPCHandlerResult, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func(sequence int) {
			defer group.Done()
			requestID := "40000000-0000-4000-8000-" + twelveDigit(sequence+1)
			result, _ := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, mutationTestRequest(requestID, 2))
			results <- result
		}(index)
	}
	group.Wait()
	close(results)
	successes, conflicts := 0, 0
	for result := range results {
		switch {
		case result.StatusCode == http.StatusOK:
			successes++
		case result.StatusCode == http.StatusConflict && result.Response.ErrorCode == "uncertain_request_conflict":
			conflicts++
		default:
			t.Errorf("concurrent result = %+v", result)
		}
	}
	if successes != 1 || conflicts != callers-1 {
		t.Fatalf("successes/conflicts = %d/%d, want 1/%d", successes, conflicts, callers-1)
	}
	if calls, maximumActive, reconciles := dispatcher.counts(); calls != 1 || maximumActive != 1 || reconciles != callers-1 {
		t.Fatalf("dispatcher calls/maximum/reconciles = %d/%d/%d", calls, maximumActive, reconciles)
	}
	state, err := stateStore.Load()
	if err != nil || state.Generation != 3 || state.Host.SSHPort != 2222 || len(state.Nodes[0].IdempotencyRecords) != 1 {
		t.Fatalf("state contains a partial stale mutation: generation=%d port=%d records=%d error=%v", state.Generation, state.Host.SSHPort, len(state.Nodes[0].IdempotencyRecords), err)
	}
}

func TestNodeMutationEvictedRequestReconcilesWithoutBlindReplay(t *testing.T) {
	controller, stateStore, committedAt := mutationTestController(t)
	dispatcher := &faultMutationDispatcher{desiredSSHPort: 2222}
	handler, _ := controller.NewNodeMutationHandler(dispatcher)
	request := mutationTestRequest("30000000-0000-4000-8000-000000000003", 2)

	initial, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request)
	if err != nil || initial.StatusCode != http.StatusOK {
		t.Fatalf("initial HandleRPC() = %+v, %v", initial, err)
	}
	controller.runtime.Now = func() time.Time { return committedAt.Add(model.IdempotencyMaxAge + time.Nanosecond) }
	dispatcher.setReconcileDetermined(true)
	reconciled, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request)
	if err != nil || reconciled.StatusCode != http.StatusOK || reconciled.Response.AuthoritativeGeneration != 3 || len(reconciled.Response.Warnings) != 1 {
		t.Fatalf("evicted HandleRPC() = %+v, %v", reconciled, err)
	}
	if calls, _, reconciles := dispatcher.counts(); calls != 1 || reconciles != 1 {
		t.Fatalf("evicted dispatcher calls/reconciles = %d/%d, want 1/1", calls, reconciles)
	}
	state, err := stateStore.Load()
	if err != nil || state.Generation != 3 || state.Host.SSHPort != 2222 {
		t.Fatalf("reconciliation mutated state = generation %d port %d, %v", state.Generation, state.Host.SSHPort, err)
	}

	dispatcher.setReconcileDetermined(false)
	unknown := mutationTestRequest("30000000-0000-4000-8000-000000000004", 2)
	conflict, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, unknown)
	if err != nil || conflict.StatusCode != http.StatusConflict || conflict.Response.ErrorCode != "uncertain_request_conflict" {
		t.Fatalf("unprovable evicted HandleRPC() = %+v, %v", conflict, err)
	}
	if calls, _, _ := dispatcher.counts(); calls != 1 {
		t.Fatalf("unprovable evicted request was blindly dispatched: calls=%d", calls)
	}
}

func TestNodeMutationRequiresPositiveCurrentExpectedGeneration(t *testing.T) {
	controller, _, _ := mutationTestController(t)
	dispatcher := &faultMutationDispatcher{desiredSSHPort: 2222}
	handler, _ := controller.NewNodeMutationHandler(dispatcher)

	missing := mutationTestRequest("30000000-0000-4000-8000-000000000005", 0)
	result, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, missing)
	if err != nil || result.StatusCode != http.StatusUnprocessableEntity || result.Response.ErrorCode != "expected_generation_required" {
		t.Fatalf("missing generation result = %+v, %v", result, err)
	}
	future := mutationTestRequest("30000000-0000-4000-8000-000000000006", 3)
	result, err = handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, future)
	if err != nil || result.StatusCode != http.StatusConflict || result.Response.ErrorCode != "generation_conflict" || result.Response.AuthoritativeGeneration != 2 {
		t.Fatalf("future generation result = %+v, %v", result, err)
	}
	if calls, _, reconciles := dispatcher.counts(); calls != 0 || reconciles != 0 {
		t.Fatalf("invalid generations reached dispatcher: calls/reconciles=%d/%d", calls, reconciles)
	}
}

func mutationTestController(t *testing.T) (*Controller, ControllerStateStore, time.Time) {
	t.Helper()
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	createdAt := state.Host.InitializedAt.Add(time.Minute)
	state.Generation++
	state.Nodes = append(state.Nodes, model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: mutationTestNodeID, Name: "private-1",
		Lifecycle: model.LifecycleActive, OverlayIPv4: "10.67.0.2", CredentialGeneration: 1,
		AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
		IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: createdAt,
	})
	state.Transports = append(state.Transports, model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: mutationTestNodeID,
		Kind: model.TransportStandard, State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP,
		Port: 51820, CredentialGeneration: 1, CredentialRef: "secret:node-standard",
		PublicKey: "test-public-key", ConfigHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err := stateStore.Save(1, state); err != nil {
		t.Fatal(err)
	}
	now := createdAt.Add(time.Minute)
	controller, err := NewController(ControllerRuntime{
		Paths: paths, State: stateStore, Observer: &recordingObserver{}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller, stateStore, now
}

func mutationTestRequest(requestID string, expected uint64) control.RPCRequest {
	return control.RPCRequest{
		ProtocolMajor: 1, ProtocolMinor: 0, RequestID: requestID,
		ExpectedStateGeneration: expected, NodeID: mutationTestNodeID, CredentialGeneration: 1,
		Operation: string(model.OperationApply), Payload: json.RawMessage(`{"ssh_port":2222}`),
	}
}

type faultMutationDispatcher struct {
	mu                  sync.Mutex
	calls               int
	active              int
	maximumActive       int
	reconciles          int
	desiredSSHPort      int
	dispatchDelay       time.Duration
	reconcileDetermined bool
}

func (dispatcher *faultMutationDispatcher) Dispatch(_ context.Context, state model.State, _ control.RPCRequest) (model.State, NodeMutationResult, error) {
	dispatcher.mu.Lock()
	dispatcher.calls++
	dispatcher.active++
	if dispatcher.active > dispatcher.maximumActive {
		dispatcher.maximumActive = dispatcher.active
	}
	delay := dispatcher.dispatchDelay
	dispatcher.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	state.Generation++
	state.Host.SSHPort = dispatcher.desiredSSHPort
	response := control.NewRPCResponse("success", state.Generation, json.RawMessage(`{"applied":true}`))
	response.ResourceIDs = map[string]string{"node_id": mutationTestNodeID}
	dispatcher.mu.Lock()
	dispatcher.active--
	dispatcher.mu.Unlock()
	return state, NodeMutationResult{Status: model.ResultOK, Response: response}, nil
}

func (dispatcher *faultMutationDispatcher) Reconcile(_ context.Context, state model.State, _ control.RPCRequest) (NodeMutationResult, bool, error) {
	dispatcher.mu.Lock()
	dispatcher.reconciles++
	determined := dispatcher.reconcileDetermined && state.Host.SSHPort == dispatcher.desiredSSHPort
	dispatcher.mu.Unlock()
	response := control.NewRPCResponse("success", state.Generation, json.RawMessage(`{"reconciled":true}`))
	response.ResourceIDs = map[string]string{"node_id": mutationTestNodeID}
	return NodeMutationResult{Status: model.ResultOK, Response: response}, determined, nil
}

func (dispatcher *faultMutationDispatcher) setReconcileDetermined(determined bool) {
	dispatcher.mu.Lock()
	dispatcher.reconcileDetermined = determined
	dispatcher.mu.Unlock()
}

func (dispatcher *faultMutationDispatcher) counts() (calls, maximumActive, reconciles int) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	return dispatcher.calls, dispatcher.maximumActive, dispatcher.reconciles
}

func twelveDigit(value int) string {
	encoded, _ := json.Marshal(value)
	digits := string(encoded)
	for len(digits) < 12 {
		digits = "0" + digits
	}
	return digits
}
