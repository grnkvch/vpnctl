package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestPublicEnrollmentHandlerSignsAndAtomicallyConsumesInvite(t *testing.T) {
	fixture := newPublicEnrollmentFixture(t, &testAuthorizedEnrollmentBuilder{})
	recorder := servePublicEnrollment(t, fixture.handler, InviteEnrollmentPath, PurposeEnroll, fixture.token, validPublicEnrollmentPayload())
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Connection") != "close" {
		t.Fatalf("response headers = %v", recorder.Header())
	}
	response, err := DecodePublicEnrollmentResponse(recorder.Body.Bytes(), PurposeEnroll)
	if err != nil {
		t.Fatalf("DecodePublicEnrollmentResponse() error = %v", err)
	}
	gatewayNonce := decodeTestNonce(t, response.GatewayNonce)
	decodedToken, err := DecodeInviteToken(fixture.token)
	if err != nil {
		t.Fatal(err)
	}
	defer decodedToken.Destroy()
	expected := preparedTestTranscript(t, PurposeEnroll, decodedToken.InviteID, decodedToken.GatewayEndpoint, decodedToken.IssuedAt, decodedToken.ExpiresAt, testNodeNonce(), gatewayNonce)
	replayHash, err := VerifyEnrollmentTranscript(response.SignedTranscript, expected, fixture.publicKeyPEM, fixture.fingerprint, fixture.clock.now)
	if err != nil {
		t.Fatalf("VerifyEnrollmentTranscript() error = %v", err)
	}
	state, _ := fixture.state.Load()
	if state.Generation != 3 || state.Invites[0].State != model.InviteConsumed || state.Invites[0].ConsumptionHash != replayHash {
		t.Fatalf("consumed state = generation %d invite %+v", state.Generation, state.Invites[0])
	}

	replay := servePublicEnrollment(t, fixture.handler, InviteEnrollmentPath, PurposeEnroll, fixture.token, validPublicEnrollmentPayload())
	if replay.Code != http.StatusNotFound || replay.Body.String() != `{"error":"not_found"}` {
		t.Fatalf("replay = %d %s", replay.Code, replay.Body.String())
	}
	afterReplay, _ := fixture.state.Load()
	if afterReplay.Generation != 3 || afterReplay.Invites[0].ConsumptionHash != replayHash {
		t.Fatalf("replay mutated state = generation %d invite %+v", afterReplay.Generation, afterReplay.Invites[0])
	}
}

func TestPublicEnrollmentCoordinatorMuxKeepsPurposeImplementationsSeparate(t *testing.T) {
	enrollmentCoordinator := &purposeRecordingCoordinator{purpose: PurposeEnroll}
	recoveryCoordinator := &purposeRecordingCoordinator{purpose: PurposeRecover}
	mux, err := NewPublicEnrollmentCoordinatorMux(enrollmentCoordinator, recoveryCoordinator)
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []EnrollmentPurpose{PurposeEnroll, PurposeRecover} {
		if _, err := mux.PreparePublicEnrollment(context.Background(), PublicEnrollmentRequest{Purpose: purpose}); !errors.Is(err, ErrPublicEnrollmentRejected) {
			t.Fatalf("PreparePublicEnrollment(%s) error = %v", purpose, err)
		}
	}
	if enrollmentCoordinator.calls != 1 || recoveryCoordinator.calls != 1 {
		t.Fatalf("mux calls enrollment=%d recovery=%d", enrollmentCoordinator.calls, recoveryCoordinator.calls)
	}
	if _, err := mux.PreparePublicEnrollment(context.Background(), PublicEnrollmentRequest{Purpose: "delete"}); !errors.Is(err, ErrPublicEnrollmentRejected) {
		t.Fatalf("unknown purpose error = %v", err)
	}
	if enrollmentCoordinator.calls != 1 || recoveryCoordinator.calls != 1 {
		t.Fatal("unknown purpose reached a purpose-specific coordinator")
	}
}

type purposeRecordingCoordinator struct {
	purpose EnrollmentPurpose
	calls   int
}

func (coordinator *purposeRecordingCoordinator) PreparePublicEnrollment(
	_ context.Context,
	request PublicEnrollmentRequest,
) (PublicEnrollmentTransaction, error) {
	coordinator.calls++
	if request.Purpose != coordinator.purpose {
		return nil, errors.New("wrong purpose routed")
	}
	return nil, ErrPublicEnrollmentRejected
}

func TestPublicEnrollmentScanningAndWrongPurposeAreIndistinguishable(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		purpose EnrollmentPurpose
		token   func([]byte) []byte
		method  string
	}{
		{name: "unknown path", path: "/.well-known/vpnctl/scan", purpose: PurposeEnroll, token: cloneBytes},
		{name: "random token", path: InviteEnrollmentPath, purpose: PurposeEnroll, token: func([]byte) []byte { return []byte(InviteTokenPrefix + ".random.invalid") }},
		{name: "enrollment token at recovery", path: EnrollmentRecoveryPath, purpose: PurposeRecover, token: cloneBytes},
		{name: "renamed enrollment token at recovery", path: EnrollmentRecoveryPath, purpose: PurposeRecover, token: func(value []byte) []byte {
			return []byte(strings.Replace(string(value), InviteTokenPrefix, RecoveryTokenPrefix, 1))
		}},
		{name: "body purpose mismatch", path: InviteEnrollmentPath, purpose: PurposeRecover, token: cloneBytes},
		{name: "wrong method", path: InviteEnrollmentPath, purpose: PurposeEnroll, token: cloneBytes, method: http.MethodGet},
		{name: "unknown field", path: InviteEnrollmentPath, purpose: PurposeEnroll, token: cloneBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublicEnrollmentFixture(t, &testAuthorizedEnrollmentBuilder{})
			body := publicEnrollmentRequestBody(t, test.purpose, test.token(fixture.token), validPublicEnrollmentPayload())
			if test.name == "unknown field" {
				body = bytes.Replace(body, []byte(`"payload":`), []byte(`"unknown":true,"payload":`), 1)
			}
			method := test.method
			if method == "" {
				method = http.MethodPost
			}
			request := httptest.NewRequest(method, "https://203.0.113.10"+test.path, bytes.NewReader(body))
			request.Header.Set("Content-Type", PublicEnrollmentContentType)
			recorder := httptest.NewRecorder()
			fixture.handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusNotFound || recorder.Body.String() != `{"error":"not_found"}` {
				t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), string(fixture.token)) {
				t.Fatal("public error disclosed the token")
			}
			state, _ := fixture.state.Load()
			if state.Generation != 2 || state.Invites[0].State != model.InviteActive {
				t.Fatalf("rejected request mutated state = generation %d invite %+v", state.Generation, state.Invites[0])
			}
		})
	}
}

func TestPublicEnrollmentHandlerBoundsRequestsAndPreparedResponses(t *testing.T) {
	t.Run("oversized request", func(t *testing.T) {
		fixture := newPublicEnrollmentFixture(t, &testAuthorizedEnrollmentBuilder{})
		request := httptest.NewRequest(http.MethodPost, "https://203.0.113.10"+InviteEnrollmentPath,
			bytes.NewReader(bytes.Repeat([]byte("x"), control.RPCMaximumRequestBytes+1)))
		request.Header.Set("Content-Type", PublicEnrollmentContentType)
		recorder := httptest.NewRecorder()
		fixture.handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d", recorder.Code)
		}
		assertInviteStillActive(t, fixture)
	})

	for _, test := range []struct {
		name     string
		response []byte
	}{
		{name: "non-object response", response: []byte(`[]`)},
		{name: "oversized response", response: []byte(`{"secret":"` + strings.Repeat("x", control.RPCMaximumResponseBytes) + `"}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublicEnrollmentFixture(t, &testAuthorizedEnrollmentBuilder{response: test.response})
			recorder := servePublicEnrollment(t, fixture.handler, InviteEnrollmentPath, PurposeEnroll, fixture.token, validPublicEnrollmentPayload())
			if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != `{"error":"unavailable"}` {
				t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
			}
			assertInviteStillActive(t, fixture)
		})
	}
}

func TestPublicEnrollmentSameInviteRaceHasOneWinner(t *testing.T) {
	const attempts = control.RPCMaximumConcurrentSessions
	builder := newBarrierEnrollmentBuilder(attempts)
	fixture := newPublicEnrollmentFixture(t, builder)
	body := publicEnrollmentRequestBody(t, PurposeEnroll, fixture.token, validPublicEnrollmentPayload())

	type result struct {
		status int
		body   []byte
	}
	results := make(chan result, attempts)
	var group sync.WaitGroup
	for index := 0; index < attempts; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			request := httptest.NewRequest(http.MethodPost, "https://203.0.113.10"+InviteEnrollmentPath, bytes.NewReader(body))
			request.Header.Set("Content-Type", PublicEnrollmentContentType)
			recorder := httptest.NewRecorder()
			fixture.handler.ServeHTTP(recorder, request)
			results <- result{status: recorder.Code, body: append([]byte(nil), recorder.Body.Bytes()...)}
		}()
	}
	group.Wait()
	close(results)
	winners := 0
	var winningBody []byte
	for result := range results {
		if result.status == http.StatusOK {
			winners++
			winningBody = result.body
			continue
		}
		if result.status != http.StatusNotFound || string(result.body) != `{"error":"not_found"}` {
			t.Fatalf("losing response = %d %s", result.status, result.body)
		}
	}
	if winners != 1 {
		t.Fatalf("successful races = %d, want 1", winners)
	}
	response, err := DecodePublicEnrollmentResponse(winningBody, PurposeEnroll)
	if err != nil {
		t.Fatal(err)
	}
	replayHash, err := EnrollmentReplayHash(response.SignedTranscript)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := fixture.state.Load()
	if state.Generation != 3 || state.Invites[0].State != model.InviteConsumed || state.Invites[0].ConsumptionHash != replayHash {
		t.Fatalf("race state = generation %d invite %+v", state.Generation, state.Invites[0])
	}
}

func TestPublicRecoveryReservedPathUsesSeparatePurpose(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	signer, publicPEM, fingerprint := testEnrollmentSigner(t)
	coordinator := &staticRecoveryCoordinator{now: now, fingerprint: fingerprint}
	handler, err := NewPublicEnrollmentHandler(PublicEnrollmentHandlerConfig{
		PublicIPv4: "203.0.113.10", Signer: signer, Coordinator: coordinator,
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x55}, EnrollmentNonceBytes)), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	token := []byte(RecoveryTokenPrefix + ".opaque.signature")
	recorder := servePublicEnrollment(t, handler, EnrollmentRecoveryPath, PurposeRecover, token, validPublicEnrollmentPayload())
	if recorder.Code != http.StatusOK || coordinator.commits != 1 {
		t.Fatalf("recovery response = %d %s, commits = %d", recorder.Code, recorder.Body.String(), coordinator.commits)
	}
	response, err := DecodePublicEnrollmentResponse(recorder.Body.Bytes(), PurposeRecover)
	if err != nil {
		t.Fatal(err)
	}
	transaction := coordinator.transaction
	if _, err := VerifyEnrollmentTranscript(response.SignedTranscript, transaction.transcript, publicPEM, fingerprint, now); err != nil {
		t.Fatalf("recovery transcript verification error = %v", err)
	}
}

type publicEnrollmentFixture struct {
	handler      *PublicEnrollmentHandler
	state        *inviteMemoryState
	clock        *inviteTestClock
	token        []byte
	publicKeyPEM []byte
	fingerprint  string
}

func newPublicEnrollmentFixture(t *testing.T, builder AuthorizedEnrollmentBuilder) publicEnrollmentFixture {
	t.Helper()
	clock := newInviteTestClock()
	signer, publicKeyPEM, fingerprint := testEnrollmentSigner(t)
	state := inviteGatewayState(clock.now)
	state.EnrollmentIdentity.Fingerprint = fingerprint
	stateStore := newInviteMemoryState(t, state)
	manager := newInviteTestManager(t, stateStore, clock, inviteEntropy(31))
	token := issueInviteToken(t, manager, "private-node")
	coordinator, err := NewInviteEnrollmentCoordinator(manager, builder)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewPublicEnrollmentHandler(PublicEnrollmentHandlerConfig{
		PublicIPv4: "203.0.113.10", Signer: signer, Coordinator: coordinator,
		Entropy: bytes.NewReader(publicHandlerEntropy(64)), Now: func() time.Time { return clock.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return publicEnrollmentFixture{
		handler: handler, state: stateStore, clock: clock, token: token,
		publicKeyPEM: publicKeyPEM, fingerprint: fingerprint,
	}
}

type testAuthorizedEnrollmentBuilder struct {
	mu       sync.Mutex
	response []byte
	waitFor  int
	arrived  int
	ready    chan struct{}
}

func newBarrierEnrollmentBuilder(waitFor int) *testAuthorizedEnrollmentBuilder {
	return &testAuthorizedEnrollmentBuilder{waitFor: waitFor, ready: make(chan struct{})}
}

func (builder *testAuthorizedEnrollmentBuilder) PrepareAuthorizedEnrollment(
	ctx context.Context,
	_ InviteAuthorization,
	_ PublicEnrollmentRequest,
) (PreparedEnrollmentArtifacts, error) {
	if builder.waitFor > 0 {
		builder.mu.Lock()
		builder.arrived++
		if builder.arrived == builder.waitFor {
			close(builder.ready)
		}
		ready := builder.ready
		builder.mu.Unlock()
		select {
		case <-ready:
		case <-ctx.Done():
			return PreparedEnrollmentArtifacts{}, ctx.Err()
		}
	}
	response := builder.response
	if response == nil {
		response = []byte(`{"client_certificate":"issued-certificate","tunnel_credential":"gateway-issued-secret"}`)
	}
	secret, err := output.NewSecret(response)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}
	controlHash := sha256.Sum256([]byte("control-csr"))
	wireGuardHash := sha256.Sum256([]byte("wireguard-public-key"))
	assignmentHash := sha256.Sum256([]byte("normalized-assignment"))
	return PreparedEnrollmentArtifacts{
		NodeID: "20000000-0000-4000-8000-000000000001", Transport: model.TransportRestricted,
		Presets:          []string{"Anthropic", "telegram"},
		PublicKeyHashes:  map[string][sha256.Size]byte{"control_csr": controlHash, "wireguard": wireGuardHash},
		AssignmentSHA256: assignmentHash, ResponseData: &secret,
	}, nil
}

type staticRecoveryCoordinator struct {
	now         time.Time
	fingerprint string
	transaction *staticPublicEnrollmentTransaction
	commits     int
}

func (coordinator *staticRecoveryCoordinator) PreparePublicEnrollment(_ context.Context, request PublicEnrollmentRequest) (PublicEnrollmentTransaction, error) {
	if request.Purpose != PurposeRecover {
		return nil, ErrPublicEnrollmentRejected
	}
	controlHash := sha256.Sum256([]byte("control-csr"))
	wireGuardHash := sha256.Sum256([]byte("wireguard-public-key"))
	assignmentHash := sha256.Sum256([]byte("normalized-assignment"))
	transcript, err := NewEnrollmentTranscript(
		PurposeRecover, "rec-ABC234", request.Endpoint, "20000000-0000-4000-8000-000000000001",
		coordinator.now.Add(-time.Minute), coordinator.now.Add(14*time.Minute), request.NodeNonce, request.GatewayNonce,
		model.TransportRestricted, []string{"Anthropic", "telegram"},
		map[string][sha256.Size]byte{"control_csr": controlHash, "wireguard": wireGuardHash}, assignmentHash,
	)
	if err != nil {
		return nil, ErrPublicEnrollmentUnavailable
	}
	secret, _ := output.NewSecretString(`{"recovery":"accepted"}`)
	transaction := &staticPublicEnrollmentTransaction{
		transcript: transcript, fingerprint: coordinator.fingerprint, responseData: &secret,
		commit: func(string) { coordinator.commits++ },
	}
	coordinator.transaction = transaction
	return transaction, nil
}

type staticPublicEnrollmentTransaction struct {
	transcript   EnrollmentTranscript
	fingerprint  string
	responseData *output.Secret
	commit       func(string)
}

func (transaction *staticPublicEnrollmentTransaction) Transcript() EnrollmentTranscript {
	return transaction.transcript
}
func (transaction *staticPublicEnrollmentTransaction) EnrollmentFingerprint() string {
	return transaction.fingerprint
}
func (transaction *staticPublicEnrollmentTransaction) UseResponseData(callback func(json.RawMessage) error) error {
	return transaction.responseData.Use(func(data []byte) error { return callback(json.RawMessage(data)) })
}
func (transaction *staticPublicEnrollmentTransaction) Commit(_ context.Context, replayHash string) error {
	if !hashPattern.MatchString(replayHash) {
		return errors.New("bad replay hash")
	}
	transaction.commit(replayHash)
	return nil
}
func (transaction *staticPublicEnrollmentTransaction) Destroy() { transaction.responseData.Destroy() }

func servePublicEnrollment(
	t *testing.T,
	handler http.Handler,
	path string,
	purpose EnrollmentPurpose,
	token []byte,
	payload json.RawMessage,
) *httptest.ResponseRecorder {
	t.Helper()
	body := publicEnrollmentRequestBody(t, purpose, token, payload)
	request := httptest.NewRequest(http.MethodPost, "https://203.0.113.10"+path, bytes.NewReader(body))
	request.Header.Set("Content-Type", PublicEnrollmentContentType)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func publicEnrollmentRequestBody(t *testing.T, purpose EnrollmentPurpose, token []byte, payload json.RawMessage) []byte {
	t.Helper()
	nonce, err := CanonicalPublicEnrollmentNonce(testNodeNonce())
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(publicEnrollmentWireRequest{
		SchemaVersion: PublicEnrollmentSchemaVersion, Purpose: purpose, Token: string(token), NodeNonce: nonce, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func validPublicEnrollmentPayload() json.RawMessage {
	return json.RawMessage(`{"node_id":"20000000-0000-4000-8000-000000000001"}`)
}

func preparedTestTranscript(
	t interface {
		Helper()
		Fatalf(string, ...any)
	},
	purpose EnrollmentPurpose,
	id, endpoint string,
	issuedAt, expiresAt time.Time,
	nodeNonce, gatewayNonce [EnrollmentNonceBytes]byte,
) EnrollmentTranscript {
	t.Helper()
	controlHash := sha256.Sum256([]byte("control-csr"))
	wireGuardHash := sha256.Sum256([]byte("wireguard-public-key"))
	assignmentHash := sha256.Sum256([]byte("normalized-assignment"))
	transcript, err := NewEnrollmentTranscript(
		purpose, id, endpoint, "20000000-0000-4000-8000-000000000001", issuedAt, expiresAt,
		nodeNonce, gatewayNonce, model.TransportRestricted, []string{"Anthropic", "telegram"},
		map[string][sha256.Size]byte{"control_csr": controlHash, "wireguard": wireGuardHash}, assignmentHash,
	)
	if err != nil {
		t.Fatalf("NewEnrollmentTranscript() error = %v", err)
	}
	return transcript
}

func decodeTestNonce(t *testing.T, encoded string) [EnrollmentNonceBytes]byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != EnrollmentNonceBytes {
		t.Fatalf("decode nonce = %x, %v", decoded, err)
	}
	var nonce [EnrollmentNonceBytes]byte
	copy(nonce[:], decoded)
	return nonce
}

func testNodeNonce() [EnrollmentNonceBytes]byte {
	return [EnrollmentNonceBytes]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
}

func publicHandlerEntropy(nonces int) []byte {
	result := make([]byte, nonces*EnrollmentNonceBytes)
	for nonce := 0; nonce < nonces; nonce++ {
		for index := 0; index < EnrollmentNonceBytes; index++ {
			result[nonce*EnrollmentNonceBytes+index] = byte(nonce + 2)
		}
	}
	return result
}

func assertInviteStillActive(t *testing.T, fixture publicEnrollmentFixture) {
	t.Helper()
	state, _ := fixture.state.Load()
	if state.Generation != 2 || state.Invites[0].State != model.InviteActive || state.Invites[0].ConsumptionHash != "" {
		t.Fatalf("invite mutated = generation %d invite %+v", state.Generation, state.Invites[0])
	}
}

func cloneBytes(value []byte) []byte { return append([]byte(nil), value...) }
