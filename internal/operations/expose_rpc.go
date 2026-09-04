package operations

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	ExposePlanRPCOperation    = "expose.plan"
	ExposeReserveRPCOperation = "expose.reserve"
	ExposePublishRPCOperation = "expose.publish"
	ExposeAbortRPCOperation   = "expose.abort"
	ExposeDeferRPCOperation   = "expose.defer"
)

type exposeRequestWire struct {
	Upstream         string `json:"upstream"`
	Name             string `json:"name,omitempty"`
	Path             string `json:"path,omitempty"`
	Prefix           bool   `json:"prefix"`
	AllowNonLoopback bool   `json:"allow_non_loopback"`
	BodyLimitSet     bool   `json:"body_limit_set"`
	BodyBytes        int64  `json:"body_bytes"`
	TimeoutSet       bool   `json:"timeout_set"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
}

type exposePlanWarningWire struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type normalizedExposePlanWire struct {
	ExposeID                string                  `json:"expose_id"`
	NodeID                  string                  `json:"node_id"`
	Name                    string                  `json:"name,omitempty"`
	Upstream                string                  `json:"upstream"`
	RouteMode               model.RouteMode         `json:"route_mode"`
	Path                    string                  `json:"path"`
	NonLoopback             bool                    `json:"non_loopback"`
	Warnings                []exposePlanWarningWire `json:"warnings"`
	BodyBytes               int64                   `json:"body_bytes"`
	UpstreamTimeoutSeconds  int                     `json:"upstream_timeout_seconds"`
	ConcurrentRequests      int                     `json:"concurrent_requests"`
	CreatedAt               time.Time               `json:"created_at"`
	ExpectedStateGeneration uint64                  `json:"expected_state_generation"`
}

type exposePlanWire struct {
	Normalized                     normalizedExposePlanWire `json:"normalized"`
	Expose                         model.Expose             `json:"expose"`
	NodeHostID                     string                   `json:"node_host_id"`
	ExpectedLocalStateGeneration   uint64                   `json:"expected_local_state_generation"`
	ExpectedGatewayStateGeneration uint64                   `json:"expected_gateway_state_generation"`
	GatewayID                      string                   `json:"gateway_id"`
	PublicIPv4                     string                   `json:"public_ipv4"`
	Certificate                    model.Certificate        `json:"certificate"`
	CertificateExportPath          string                   `json:"certificate_export_path"`
}

type exposeSnapshotWire struct {
	GatewayID             string                   `json:"gateway_id"`
	Generation            uint64                   `json:"generation"`
	PublicIPv4            string                   `json:"public_ipv4"`
	Node                  model.Node               `json:"node"`
	Normalized            normalizedExposePlanWire `json:"normalized"`
	TunnelPort            int                      `json:"tunnel_port"`
	Certificate           model.Certificate        `json:"certificate"`
	CertificateExportPath string                   `json:"certificate_export_path"`
}

type exposeRPCPlanRequest struct {
	Request exposeRequestWire `json:"request"`
}

type exposeRPCPlanResponse struct {
	Snapshot exposeSnapshotWire `json:"snapshot"`
}

type exposeRPCReserveRequest struct {
	Plan exposePlanWire `json:"plan"`
}

type exposeRPCReserveResponse struct {
	Reservation ExposeGatewayReservation `json:"reservation"`
}

type exposeRPCPublishRequest struct {
	NodeID         string                   `json:"node_id"`
	Reservation    ExposeGatewayReservation `json:"reservation"`
	EffectiveState model.ExposeState        `json:"effective_state"`
}

type exposeRPCPublishResponse struct {
	Publication ExposeGatewayPublication `json:"publication"`
}

type exposeRPCAbortRequest struct {
	NodeID      string                   `json:"node_id"`
	Reservation ExposeGatewayReservation `json:"reservation"`
}

type exposeRPCAbortResponse struct {
	Generation uint64 `json:"generation"`
}

type exposeRPCDeferRequest struct {
	Plan exposePlanWire `json:"plan"`
}

type exposeRPCDeferResponse struct {
	Registration ExposeDeferredRegistration `json:"registration"`
}

func exposeRequestToWire(request ingress.ExposeCreateRequest) exposeRequestWire {
	return exposeRequestWire{
		Upstream: request.Upstream, Name: request.Name, Path: request.Path, Prefix: request.Prefix,
		AllowNonLoopback: request.AllowNonLoopback, BodyLimitSet: request.LimitOverrides.BodyLimitSet,
		BodyBytes: request.LimitOverrides.BodyBytes, TimeoutSet: request.LimitOverrides.TimeoutSet,
		TimeoutSeconds: request.LimitOverrides.TimeoutSeconds,
	}
}

func (wire exposeRequestWire) domain() ingress.ExposeCreateRequest {
	return ingress.ExposeCreateRequest{
		Upstream: wire.Upstream, Name: wire.Name, Path: wire.Path, Prefix: wire.Prefix, AllowNonLoopback: wire.AllowNonLoopback,
		LimitOverrides: ingress.ExposeLimitOverrides{
			BodyLimitSet: wire.BodyLimitSet, BodyBytes: wire.BodyBytes,
			TimeoutSet: wire.TimeoutSet, TimeoutSeconds: wire.TimeoutSeconds,
		},
	}
}

func normalizedExposePlanToWire(plan ingress.ExposePlan) normalizedExposePlanWire {
	warnings := make([]exposePlanWarningWire, len(plan.Warnings))
	for index, warning := range plan.Warnings {
		warnings[index] = exposePlanWarningWire{Code: warning.Code, Message: warning.Message}
	}
	return normalizedExposePlanWire{
		ExposeID: plan.ExposeID, NodeID: plan.NodeID, Name: plan.Name, Upstream: plan.Upstream,
		RouteMode: plan.RouteMode, Path: plan.Path, NonLoopback: plan.NonLoopback, Warnings: warnings,
		BodyBytes: plan.Limits.BodyBytes, UpstreamTimeoutSeconds: plan.Limits.UpstreamTimeoutSeconds,
		ConcurrentRequests: plan.Limits.ConcurrentRequests, CreatedAt: plan.CreatedAt,
		ExpectedStateGeneration: plan.ExpectedStateGeneration,
	}
}

func (wire normalizedExposePlanWire) domain() ingress.ExposePlan {
	warnings := make([]ingress.ExposePlanWarning, len(wire.Warnings))
	for index, warning := range wire.Warnings {
		warnings[index] = ingress.ExposePlanWarning{Code: warning.Code, Message: warning.Message}
	}
	return ingress.ExposePlan{
		ExposeID: wire.ExposeID, NodeID: wire.NodeID, Name: wire.Name, Upstream: wire.Upstream,
		RouteMode: wire.RouteMode, Path: wire.Path, NonLoopback: wire.NonLoopback, Warnings: warnings,
		Limits:    ingress.ExposeLimits{BodyBytes: wire.BodyBytes, UpstreamTimeoutSeconds: wire.UpstreamTimeoutSeconds, ConcurrentRequests: wire.ConcurrentRequests},
		CreatedAt: wire.CreatedAt, ExpectedStateGeneration: wire.ExpectedStateGeneration,
	}
}

func exposePlanToWire(plan ExposeCreatePlan) exposePlanWire {
	return exposePlanWire{
		Normalized: normalizedExposePlanToWire(plan.Normalized), Expose: plan.Expose, NodeHostID: plan.NodeHostID,
		ExpectedLocalStateGeneration: plan.ExpectedLocalStateGeneration, ExpectedGatewayStateGeneration: plan.ExpectedGatewayStateGeneration,
		GatewayID: plan.GatewayID, PublicIPv4: plan.PublicIPv4, Certificate: plan.Certificate,
		CertificateExportPath: plan.CertificateExportPath,
	}
}

func (wire exposePlanWire) domain() (ExposeCreatePlan, error) {
	plan := ExposeCreatePlan{
		Normalized: wire.Normalized.domain(), Expose: wire.Expose, NodeHostID: wire.NodeHostID,
		ExpectedLocalStateGeneration: wire.ExpectedLocalStateGeneration, ExpectedGatewayStateGeneration: wire.ExpectedGatewayStateGeneration,
		GatewayID: wire.GatewayID, PublicIPv4: wire.PublicIPv4, Certificate: wire.Certificate,
		CertificateExportPath: wire.CertificateExportPath,
	}
	return plan, plan.Validate()
}

func exposeSnapshotToWire(snapshot ExposeGatewaySnapshot) exposeSnapshotWire {
	return exposeSnapshotWire{
		GatewayID: snapshot.GatewayID, Generation: snapshot.Generation, PublicIPv4: snapshot.PublicIPv4,
		Node: snapshot.Node, Normalized: normalizedExposePlanToWire(snapshot.Normalized), TunnelPort: snapshot.TunnelPort,
		Certificate: snapshot.Certificate, CertificateExportPath: snapshot.CertificateExportPath,
	}
}

func (wire exposeSnapshotWire) domain() ExposeGatewaySnapshot {
	return ExposeGatewaySnapshot{
		GatewayID: wire.GatewayID, Generation: wire.Generation, PublicIPv4: wire.PublicIPv4,
		Node: wire.Node, Normalized: wire.Normalized.domain(), TunnelPort: wire.TunnelPort,
		Certificate: wire.Certificate, CertificateExportPath: wire.CertificateExportPath,
	}
}

type ExposeGatewayRPCCaller interface {
	CallManagement(context.Context, control.RPCRequest) (control.RPCCallResult, error)
}

// RemoteExposeGatewayCoordinator is the private-node side of expose creation.
// Every phase uses one bounded mTLS request and no implicit retry or queue.
type RemoteExposeGatewayCoordinator struct {
	caller               ExposeGatewayRPCCaller
	protocol             control.RPCProtocolVersion
	nodeID               string
	credentialGeneration uint64
	lastKnownGeneration  uint64
	now                  func() time.Time
	newUUID              model.UUIDGenerator
	entropy              io.Reader
}

func NewRemoteExposeGatewayCoordinator(
	caller ExposeGatewayRPCCaller,
	protocol control.RPCProtocolVersion,
	nodeID string,
	credentialGeneration uint64,
	lastKnownGeneration uint64,
	now func() time.Time,
	newUUID model.UUIDGenerator,
	entropy io.Reader,
) (*RemoteExposeGatewayCoordinator, error) {
	if caller == nil || protocol.Major < 1 || protocol.Minor < 0 || model.ValidateResourceID(nodeID) != nil ||
		credentialGeneration == 0 || lastKnownGeneration == 0 {
		return nil, fmt.Errorf("remote expose gateway identity is invalid")
	}
	if now == nil {
		now = time.Now
	}
	if newUUID == nil {
		newUUID = model.NewUUID
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return &RemoteExposeGatewayCoordinator{
		caller: caller, protocol: protocol, nodeID: nodeID, credentialGeneration: credentialGeneration,
		lastKnownGeneration: lastKnownGeneration, now: now, newUUID: newUUID, entropy: entropy,
	}, nil
}

func (client *RemoteExposeGatewayCoordinator) Plan(ctx context.Context, nodeID string, request ingress.ExposeCreateRequest) (ExposeGatewaySnapshot, error) {
	if client == nil || nodeID != client.nodeID {
		return ExposeGatewaySnapshot{}, fmt.Errorf("remote expose node identity differs")
	}
	var response exposeRPCPlanResponse
	generation, err := client.call(ctx, ExposePlanRPCOperation, client.lastKnownGeneration, exposeRPCPlanRequest{Request: exposeRequestToWire(request)}, &response, false)
	if err != nil {
		return ExposeGatewaySnapshot{}, err
	}
	snapshot := response.Snapshot.domain()
	if snapshot.Generation != generation {
		return ExposeGatewaySnapshot{}, &remoteExposeRPCError{cause: errors.New("gateway plan generation differs"), possible: false}
	}
	return snapshot, nil
}

func (client *RemoteExposeGatewayCoordinator) Reserve(ctx context.Context, plan ExposeCreatePlan) (ExposeGatewayReservation, error) {
	if err := plan.Validate(); err != nil || client == nil || plan.Expose.NodeID != client.nodeID {
		return ExposeGatewayReservation{}, fmt.Errorf("remote expose reservation plan is invalid")
	}
	var response exposeRPCReserveResponse
	generation, err := client.call(ctx, ExposeReserveRPCOperation, plan.ExpectedGatewayStateGeneration, exposeRPCReserveRequest{Plan: exposePlanToWire(plan)}, &response, true)
	if err != nil {
		return ExposeGatewayReservation{}, err
	}
	if response.Reservation.Generation != generation {
		return ExposeGatewayReservation{}, &remoteExposeRPCError{cause: errors.New("gateway reservation generation differs"), possible: true}
	}
	return response.Reservation, nil
}

func (client *RemoteExposeGatewayCoordinator) Publish(ctx context.Context, reservation ExposeGatewayReservation, state model.ExposeState) (ExposeGatewayPublication, error) {
	if client == nil || validateGatewayExposeReservationShape(reservation) != nil {
		return ExposeGatewayPublication{}, fmt.Errorf("remote expose publication input is invalid")
	}
	var response exposeRPCPublishResponse
	generation, err := client.call(ctx, ExposePublishRPCOperation, reservation.Generation, exposeRPCPublishRequest{
		NodeID: client.nodeID, Reservation: reservation, EffectiveState: state,
	}, &response, true)
	if err != nil {
		return ExposeGatewayPublication{}, err
	}
	if response.Publication.Generation != generation {
		return ExposeGatewayPublication{}, &remoteExposeRPCError{cause: errors.New("gateway publication generation differs"), possible: true}
	}
	return response.Publication, nil
}

func (client *RemoteExposeGatewayCoordinator) Abort(ctx context.Context, reservation ExposeGatewayReservation) (uint64, error) {
	if client == nil || validateGatewayExposeReservationShape(reservation) != nil {
		return 0, fmt.Errorf("remote expose abort input is invalid")
	}
	var response exposeRPCAbortResponse
	generation, err := client.call(ctx, ExposeAbortRPCOperation, reservation.Generation, exposeRPCAbortRequest{
		NodeID: client.nodeID, Reservation: reservation,
	}, &response, true)
	if err != nil {
		return 0, err
	}
	if response.Generation != generation {
		return 0, &remoteExposeRPCError{cause: errors.New("gateway abort generation differs"), possible: true}
	}
	return response.Generation, nil
}

func (client *RemoteExposeGatewayCoordinator) Defer(ctx context.Context, plan ExposeCreatePlan) (ExposeDeferredRegistration, error) {
	if err := plan.Validate(); err != nil || client == nil || plan.Expose.NodeID != client.nodeID {
		return ExposeDeferredRegistration{}, fmt.Errorf("remote deferred expose plan is invalid")
	}
	var response exposeRPCDeferResponse
	generation, err := client.call(ctx, ExposeDeferRPCOperation, plan.ExpectedGatewayStateGeneration, exposeRPCDeferRequest{Plan: exposePlanToWire(plan)}, &response, true)
	if err != nil {
		return ExposeDeferredRegistration{}, err
	}
	if response.Registration.Generation != generation {
		return ExposeDeferredRegistration{}, &remoteExposeRPCError{cause: errors.New("gateway deferred generation differs"), possible: true}
	}
	return response.Registration, nil
}

func (client *RemoteExposeGatewayCoordinator) call(
	ctx context.Context,
	operation string,
	expectedGeneration uint64,
	payload any,
	destination any,
	commitPossible bool,
) (uint64, error) {
	if ctx == nil || client == nil || client.caller == nil || client.now == nil || client.newUUID == nil || client.entropy == nil {
		return 0, fmt.Errorf("remote expose gateway coordinator is incomplete")
	}
	requestID, err := client.newUUID()
	if err != nil || model.ValidateResourceID(requestID) != nil {
		return 0, fmt.Errorf("allocate expose RPC request identity")
	}
	nonce := make([]byte, control.RPCNonceBytes)
	if _, err := io.ReadFull(client.entropy, nonce); err != nil {
		return 0, fmt.Errorf("generate expose RPC nonce: %w", err)
	}
	defer clearExposeRPCSecret(nonce)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("encode expose RPC payload: %w", err)
	}
	call, err := client.caller.CallManagement(ctx, control.RPCRequest{
		ProtocolMajor: client.protocol.Major, ProtocolMinor: client.protocol.Minor,
		RequestID: requestID, ExpectedStateGeneration: expectedGeneration, NodeID: client.nodeID,
		CredentialGeneration: client.credentialGeneration, Timestamp: client.now().UTC(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Operation: operation, Payload: encoded,
	})
	if err != nil {
		return 0, &remoteExposeRPCError{cause: err, possible: false}
	}
	if call.StatusCode != http.StatusOK || call.Response.Category != "success" {
		cause := errors.New("gateway rejected expose request")
		switch call.Response.Category {
		case "conflict":
			cause = ErrExposePlanStale
		case "unavailable":
			cause = ErrExposeGatewayUnavailable
		case "validation":
			cause = ErrExposeSagaInvalid
		}
		return 0, &remoteExposeRPCError{cause: cause, possible: commitPossible}
	}
	if call.Response.AuthoritativeGeneration == 0 {
		return 0, &remoteExposeRPCError{cause: errors.New("gateway response has no authoritative generation"), possible: commitPossible}
	}
	if err := control.DecodeRPCPayload(call.Response.Data, destination); err != nil {
		return 0, &remoteExposeRPCError{cause: err, possible: commitPossible}
	}
	return call.Response.AuthoritativeGeneration, nil
}

type remoteExposeRPCError struct {
	cause    error
	possible bool
}

func (failure *remoteExposeRPCError) Error() string { return "gateway expose RPC failed" }
func (failure *remoteExposeRPCError) Unwrap() error { return failure.cause }
func (failure *remoteExposeRPCError) CommitPossible() bool {
	return failure != nil && failure.possible
}

// NewSystemRemoteExposeGatewayCoordinator loads only the joined node's current
// control identity and creates a short-lived mTLS RPC adapter.
func NewSystemRemoteExposeGatewayCoordinator(paths store.Paths, now func() time.Time) (*RemoteExposeGatewayCoordinator, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	state, err := stateStore.Load()
	if err != nil || state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Gateway == nil {
		return nil, fmt.Errorf("node expose gateway trust is unavailable")
	}
	node := state.Nodes[0]
	protocol, err := control.ParseRPCProtocolVersion(node.Gateway.ControlProtocol)
	if err != nil {
		return nil, err
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, err
	}
	caBundle := make([]byte, 0)
	for _, rawReference := range node.Gateway.ControlCACertificateRefs {
		certificate, readErr := secrets.Get(model.SecretRef(rawReference))
		if readErr != nil {
			clearExposeRPCSecret(caBundle)
			return nil, readErr
		}
		caBundle = append(caBundle, certificate...)
		caBundle = append(caBundle, '\n')
		clearExposeRPCSecret(certificate)
	}
	defer clearExposeRPCSecret(caBundle)
	leaf, found := currentExposeNodeControlCertificate(state, node)
	if !found {
		return nil, fmt.Errorf("current node control certificate is missing")
	}
	certificatePEM, err := secrets.Get(model.SecretRef(leaf.CertificateRef))
	if err != nil {
		return nil, err
	}
	defer clearExposeRPCSecret(certificatePEM)
	privateKeyPEM, err := secrets.Get(leaf.PrivateKeyRef)
	if err != nil {
		return nil, err
	}
	defer clearExposeRPCSecret(privateKeyPEM)
	rpc, err := control.NewRPCClient(control.RPCClientConfig{
		Address:   net.JoinHostPort(node.Gateway.GatewayOverlayIPv4, strconv.Itoa(control.RPCControlTCPPort)),
		GatewayID: node.Gateway.GatewayID, NodeID: node.ID, CACertificatePEM: caBundle,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM, Now: now,
	})
	if err != nil {
		return nil, err
	}
	return NewRemoteExposeGatewayCoordinator(
		rpc, protocol, node.ID, node.CredentialGeneration, node.Gateway.LastKnownGatewayGeneration,
		now, nil, nil,
	)
}

func currentExposeNodeControlCertificate(state model.State, node model.Node) (model.Certificate, bool) {
	var result model.Certificate
	found := false
	for _, certificate := range state.Certificates {
		if certificate.Kind != model.CertificateControlNode || certificate.OwnerKind != "node" || certificate.OwnerID != node.ID ||
			certificate.EffectiveCredentialGeneration() != node.CredentialGeneration || certificate.CertificateRef == "" || certificate.PrivateKeyRef == "" {
			continue
		}
		if found {
			return model.Certificate{}, false
		}
		result, found = certificate, true
	}
	return result, found
}

func clearExposeRPCSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// ExposeGatewayRPCHandler is the authenticated gateway half. The supplied
// locker is the controller's global authoritative mutation lock.
type ExposeGatewayRPCHandler struct {
	locker  sync.Locker
	service *GatewayExposeCoordinatorService
}

func NewExposeGatewayRPCHandler(locker sync.Locker, service *GatewayExposeCoordinatorService) (*ExposeGatewayRPCHandler, error) {
	if locker == nil || service == nil || service.state == nil {
		return nil, fmt.Errorf("gateway expose RPC dependencies are incomplete")
	}
	return &ExposeGatewayRPCHandler{locker: locker, service: service}, nil
}

func (handler *ExposeGatewayRPCHandler) HandleRPC(ctx context.Context, peer control.RPCPeer, request control.RPCRequest) (control.RPCHandlerResult, error) {
	if ctx == nil || handler == nil || handler.locker == nil || handler.service == nil {
		return control.RPCHandlerResult{}, fmt.Errorf("gateway expose RPC handler is incomplete")
	}
	if peer.NodeID == "" || peer.NodeID != request.NodeID {
		return exposeRPCFailure(request, http.StatusForbidden, "validation", 0, "identity_mismatch", "the certificate and request node identities differ"), nil
	}
	handler.locker.Lock()
	defer handler.locker.Unlock()
	if err := ctx.Err(); err != nil {
		return exposeRPCFailure(request, http.StatusServiceUnavailable, "unavailable", 0, "request_cancelled", "the expose request was cancelled"), nil
	}

	switch request.Operation {
	case ExposePlanRPCOperation:
		var payload exposeRPCPlanRequest
		if control.DecodeRPCPayload(request.Payload, &payload) != nil {
			return exposeRPCFailure(request, http.StatusUnprocessableEntity, "validation", handler.currentGeneration(), "invalid_payload", "the expose plan payload is invalid"), nil
		}
		snapshot, err := handler.service.Plan(ctx, request.NodeID, payload.Request.domain())
		if err != nil {
			return handler.failure(request, err), nil
		}
		return exposeRPCSuccess(request, snapshot.Generation, "expose_id", snapshot.Normalized.ExposeID, exposeRPCPlanResponse{Snapshot: exposeSnapshotToWire(snapshot)})

	case ExposeReserveRPCOperation:
		var payload exposeRPCReserveRequest
		if control.DecodeRPCPayload(request.Payload, &payload) != nil {
			return exposeRPCFailure(request, http.StatusUnprocessableEntity, "validation", handler.currentGeneration(), "invalid_payload", "the expose reservation payload is invalid"), nil
		}
		plan, err := payload.Plan.domain()
		if err != nil || plan.Expose.NodeID != request.NodeID || request.ExpectedStateGeneration != plan.ExpectedGatewayStateGeneration {
			return exposeRPCFailure(request, http.StatusUnprocessableEntity, "validation", handler.currentGeneration(), "invalid_plan", "the expose reservation plan is invalid"), nil
		}
		reservation, err := handler.service.Reserve(ctx, plan)
		if err != nil {
			return handler.failure(request, err), nil
		}
		return exposeRPCSuccess(request, reservation.Generation, "expose_id", reservation.ExposeID, exposeRPCReserveResponse{Reservation: reservation})

	case ExposePublishRPCOperation:
		var payload exposeRPCPublishRequest
		if control.DecodeRPCPayload(request.Payload, &payload) != nil || payload.NodeID != request.NodeID ||
			request.ExpectedStateGeneration != payload.Reservation.Generation || !handler.reservationBelongsToNode(payload.NodeID, payload.Reservation) {
			return exposeRPCFailure(request, http.StatusUnprocessableEntity, "validation", handler.currentGeneration(), "invalid_publication", "the expose publication input is invalid"), nil
		}
		publication, err := handler.service.Publish(ctx, payload.Reservation, payload.EffectiveState)
		if err != nil {
			return handler.failure(request, err), nil
		}
		return exposeRPCSuccess(request, publication.Generation, "expose_id", publication.ExposeID, exposeRPCPublishResponse{Publication: publication})

	case ExposeAbortRPCOperation:
		var payload exposeRPCAbortRequest
		if control.DecodeRPCPayload(request.Payload, &payload) != nil || payload.NodeID != request.NodeID ||
			request.ExpectedStateGeneration != payload.Reservation.Generation || !handler.reservationBelongsToNode(payload.NodeID, payload.Reservation) {
			return exposeRPCFailure(request, http.StatusUnprocessableEntity, "validation", handler.currentGeneration(), "invalid_abort", "the expose abort input is invalid"), nil
		}
		generation, err := handler.service.Abort(ctx, payload.Reservation)
		if err != nil {
			return handler.failure(request, err), nil
		}
		return exposeRPCSuccess(request, generation, "expose_id", payload.Reservation.ExposeID, exposeRPCAbortResponse{Generation: generation})

	case ExposeDeferRPCOperation:
		var payload exposeRPCDeferRequest
		if control.DecodeRPCPayload(request.Payload, &payload) != nil {
			return exposeRPCFailure(request, http.StatusUnprocessableEntity, "validation", handler.currentGeneration(), "invalid_payload", "the deferred expose payload is invalid"), nil
		}
		plan, err := payload.Plan.domain()
		if err != nil || plan.Expose.NodeID != request.NodeID || request.ExpectedStateGeneration != plan.ExpectedGatewayStateGeneration {
			return exposeRPCFailure(request, http.StatusUnprocessableEntity, "validation", handler.currentGeneration(), "invalid_plan", "the deferred expose plan is invalid"), nil
		}
		registration, err := handler.service.Defer(ctx, plan)
		if err != nil {
			return handler.failure(request, err), nil
		}
		return exposeRPCSuccess(request, registration.Generation, "expose_id", registration.ExposeID, exposeRPCDeferResponse{Registration: registration})
	default:
		return exposeRPCFailure(request, http.StatusUnprocessableEntity, "validation", handler.currentGeneration(), "invalid_operation", "the handler accepts only expose operations"), nil
	}
}

func (handler *ExposeGatewayRPCHandler) reservationBelongsToNode(nodeID string, reservation ExposeGatewayReservation) bool {
	if validateGatewayExposeReservationShape(reservation) != nil {
		return false
	}
	state, err := handler.service.state.Load()
	if err != nil || state.Generation != reservation.Generation {
		return false
	}
	for _, expose := range state.Exposes {
		if expose.ID == reservation.ExposeID {
			return expose.NodeID == nodeID && expose.State == model.ExposePending
		}
	}
	return false
}

func (handler *ExposeGatewayRPCHandler) currentGeneration() uint64 {
	if handler == nil || handler.service == nil || handler.service.state == nil {
		return 0
	}
	state, err := handler.service.state.Load()
	if err != nil {
		return 0
	}
	return state.Generation
}

func (handler *ExposeGatewayRPCHandler) failure(request control.RPCRequest, err error) control.RPCHandlerResult {
	generation := handler.currentGeneration()
	switch {
	case errors.Is(err, ErrExposePlanStale), errors.Is(err, store.ErrStateConflict):
		return exposeRPCFailure(request, http.StatusConflict, "conflict", generation, "expose_conflict", "the expose conflicts with authoritative state")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return exposeRPCFailure(request, http.StatusServiceUnavailable, "unavailable", generation, "expose_unavailable", "the expose operation did not finish before its deadline")
	case errors.Is(err, ingress.ErrExposeInvalidInput), errors.Is(err, ingress.ErrExposeNameConflict),
		errors.Is(err, ingress.ErrExposeRouteConflict), errors.Is(err, ingress.ErrExposeReservedPath),
		errors.Is(err, ingress.ErrExposeNonLoopbackOptIn), errors.Is(err, ingress.ErrExposeLimitInvalid):
		return exposeRPCFailure(request, http.StatusUnprocessableEntity, "validation", generation, "expose_validation", "the expose request is invalid")
	default:
		return exposeRPCFailure(request, http.StatusInternalServerError, "internal", generation, "expose_failed", "the gateway could not complete the expose operation")
	}
}

func exposeRPCSuccess(request control.RPCRequest, generation uint64, resourceKey, resourceID string, payload any) (control.RPCHandlerResult, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return control.RPCHandlerResult{}, err
	}
	response := control.NewRPCResponse("success", generation, encoded)
	response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
	if resourceKey != "" {
		response.ResourceIDs[resourceKey] = resourceID
	}
	return control.RPCHandlerResult{StatusCode: http.StatusOK, Response: response}, nil
}

func exposeRPCFailure(request control.RPCRequest, status int, category string, generation uint64, code, message string) control.RPCHandlerResult {
	response := control.NewRPCResponse(category, generation, json.RawMessage(`{}`))
	response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
	response.ErrorCode, response.Message = code, message
	return control.RPCHandlerResult{StatusCode: status, Response: response}
}

var _ ExposeGatewayCoordinator = (*RemoteExposeGatewayCoordinator)(nil)
var _ control.RPCHandler = (*ExposeGatewayRPCHandler)(nil)
