package operations

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const exposeCompensationTimeout = 15 * time.Second

var (
	ErrExposeGatewayUnavailable = errors.New("authoritative gateway is unavailable")
	ErrExposePlanStale          = errors.New("expose creation plan is stale")
	ErrExposeTunnelNotReady     = errors.New("expose tunnel mapping is not ready")
	ErrExposeOutcomeUncertain   = errors.New("expose creation outcome is uncertain")
	ErrExposeSagaInvalid        = errors.New("expose creation saga input is invalid")
)

type ExposeNodeStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

// ExposeGatewaySnapshot is the bounded result of authoritative read-only
// planning. The gateway checks its global route/port namespace but returns only
// the new node-owned plan, never existing webhook paths from other nodes.
type ExposeGatewaySnapshot struct {
	GatewayID             string
	Generation            uint64
	PublicIPv4            string
	Node                  model.Node
	Normalized            ingress.ExposePlan
	TunnelPort            int
	Certificate           model.Certificate
	CertificateExportPath string
}

func (ExposeGatewaySnapshot) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type ExposeGatewayReservation struct {
	ExposeID           string
	PreviousGeneration uint64
	Generation         uint64
}

type ExposeGatewayPublication struct {
	ExposeID   string
	Generation uint64
}

type ExposeDeferredRegistration struct {
	ExposeID    string
	OperationID string
	Generation  uint64
}

// ExposeGatewayCoordinator is implemented by the node's authenticated control
// client. Reserve exports the public certificate and persists a pending
// authoritative expose without publishing an ingress route; Publish activates
// ingress and commits the effective state.
type ExposeGatewayCoordinator interface {
	Plan(context.Context, string, ingress.ExposeCreateRequest) (ExposeGatewaySnapshot, error)
	Reserve(context.Context, ExposeCreatePlan) (ExposeGatewayReservation, error)
	Publish(context.Context, ExposeGatewayReservation, model.ExposeState) (ExposeGatewayPublication, error)
	Abort(context.Context, ExposeGatewayReservation) (uint64, error)
	Defer(context.Context, ExposeCreatePlan) (ExposeDeferredRegistration, error)
}

type ExposeTunnelActivation struct {
	ExposeID      string
	Candidate     tunnel.CandidateDescriptor
	frpCandidate  *tunnel.FRPCandidate
	rollbackState *model.State
}

func (ExposeTunnelActivation) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

// ExposeNodeTunnel owns only the complete node tunnel candidate. The gateway
// ingress route is intentionally outside this interface and cannot be made
// public by a successful tunnel reload alone.
type ExposeNodeTunnel interface {
	Activate(context.Context, model.State, model.State, model.Expose) (ExposeTunnelActivation, error)
	Observe(context.Context, ExposeTunnelActivation, model.Expose) (tunnel.TunnelReadinessResult, error)
	Rollback(context.Context, ExposeTunnelActivation) error
}

type ExposeCreatePlan struct {
	Normalized                     ingress.ExposePlan
	Expose                         model.Expose
	NodeHostID                     string
	ExpectedLocalStateGeneration   uint64
	ExpectedGatewayStateGeneration uint64
	GatewayID                      string
	PublicIPv4                     string
	Certificate                    model.Certificate
	CertificateExportPath          string
}

func (ExposeCreatePlan) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type ExposeCreateResult struct {
	ExposeID               string
	State                  model.ExposeState
	LocalStateGeneration   uint64
	GatewayStateGeneration uint64
	PublicIPv4             string
	CertificateID          string
	CertificateFingerprint string
	CertificateExportPath  string
	publicURL              output.SensitivePath
}

type ExposeCreateDeferredResult struct {
	ExposeID               string
	OperationID            string
	GatewayStateGeneration uint64
}

type ExposeCreateSaga struct {
	state   ExposeNodeStateStore
	gateway ExposeGatewayCoordinator
	tunnel  ExposeNodeTunnel
}

func NewExposeCreateSaga(
	state ExposeNodeStateStore,
	gateway ExposeGatewayCoordinator,
	tunnelRuntime ExposeNodeTunnel,
) (*ExposeCreateSaga, error) {
	if state == nil || gateway == nil || tunnelRuntime == nil {
		return nil, fmt.Errorf("%w: state, gateway, and tunnel are required", ErrExposeSagaInvalid)
	}
	return &ExposeCreateSaga{state: state, gateway: gateway, tunnel: tunnelRuntime}, nil
}

// Plan is read-only on both hosts. In particular, certificate export and the
// authoritative pending registration happen only in Apply or Defer.
func (saga *ExposeCreateSaga) Plan(ctx context.Context, request ingress.ExposeCreateRequest) (ExposeCreatePlan, error) {
	if ctx == nil || saga == nil || saga.state == nil || saga.gateway == nil || saga.tunnel == nil {
		return ExposeCreatePlan{}, fmt.Errorf("%w: saga is incomplete", ErrExposeSagaInvalid)
	}
	local, node, err := saga.loadJoinedNode()
	if err != nil {
		return ExposeCreatePlan{}, err
	}
	snapshot, err := saga.gateway.Plan(ctx, node.ID, request)
	if err != nil {
		return ExposeCreatePlan{}, errors.Join(ErrExposeGatewayUnavailable, err)
	}
	if err := validateExposeGatewaySnapshot(snapshot, node); err != nil {
		return ExposeCreatePlan{}, err
	}
	if snapshot.PublicIPv4 != node.Gateway.PublicIPv4 || snapshot.Generation < node.Gateway.LastKnownGatewayGeneration {
		return ExposeCreatePlan{}, fmt.Errorf("%w: gateway identity or generation differs from node trust", ErrExposePlanStale)
	}
	normalized := snapshot.Normalized
	expose := model.Expose{
		SchemaVersion: model.ResourceSchemaVersion,
		ID:            normalized.ExposeID, NodeID: normalized.NodeID, Name: normalized.Name,
		Upstream: normalized.Upstream, RouteMode: normalized.RouteMode, Path: normalized.Path,
		BodyLimitBytes:         normalized.Limits.BodyBytes,
		UpstreamTimeoutSeconds: normalized.Limits.UpstreamTimeoutSeconds,
		ConcurrentRequests:     normalized.Limits.ConcurrentRequests,
		TunnelPort:             snapshot.TunnelPort, State: model.ExposePending, Generation: 1, CreatedAt: normalized.CreatedAt,
	}
	plan := ExposeCreatePlan{
		Normalized: normalized, Expose: expose, NodeHostID: local.Host.ID,
		ExpectedLocalStateGeneration: local.Generation, ExpectedGatewayStateGeneration: snapshot.Generation,
		GatewayID: snapshot.GatewayID, PublicIPv4: snapshot.PublicIPv4,
		Certificate: snapshot.Certificate, CertificateExportPath: snapshot.CertificateExportPath,
	}
	if err := plan.Validate(); err != nil {
		return ExposeCreatePlan{}, err
	}
	return plan, nil
}

func (plan ExposeCreatePlan) Validate() error {
	if err := plan.Normalized.Validate(); err != nil {
		return err
	}
	if err := plan.Expose.Validate(); err != nil {
		return fmt.Errorf("%w: expose candidate: %v", ErrExposeSagaInvalid, err)
	}
	if plan.Expose.ID != plan.Normalized.ExposeID || plan.Expose.NodeID != plan.Normalized.NodeID ||
		plan.Expose.Name != plan.Normalized.Name || plan.Expose.Upstream != plan.Normalized.Upstream ||
		plan.Expose.RouteMode != plan.Normalized.RouteMode || plan.Expose.Path != plan.Normalized.Path ||
		plan.Expose.BodyLimitBytes != plan.Normalized.Limits.BodyBytes ||
		plan.Expose.UpstreamTimeoutSeconds != plan.Normalized.Limits.UpstreamTimeoutSeconds ||
		plan.Expose.ConcurrentRequests != plan.Normalized.Limits.ConcurrentRequests ||
		plan.Expose.State != model.ExposePending || plan.Expose.Generation != 1 ||
		!plan.Expose.CreatedAt.Equal(plan.Normalized.CreatedAt) {
		return fmt.Errorf("%w: expose candidate differs from normalized input", ErrExposeSagaInvalid)
	}
	if err := model.ValidateResourceID(plan.NodeHostID); err != nil || plan.ExpectedLocalStateGeneration == 0 ||
		plan.ExpectedGatewayStateGeneration == 0 || plan.ExpectedGatewayStateGeneration != plan.Normalized.ExpectedStateGeneration {
		return fmt.Errorf("%w: expected host/state identity is invalid", ErrExposeSagaInvalid)
	}
	if err := model.ValidateResourceID(plan.GatewayID); err != nil {
		return fmt.Errorf("%w: gateway identity is invalid", ErrExposeSagaInvalid)
	}
	address, err := netip.ParseAddr(plan.PublicIPv4)
	if err != nil || !address.Is4() || address.String() != plan.PublicIPv4 {
		return fmt.Errorf("%w: public IPv4 is invalid", ErrExposeSagaInvalid)
	}
	if err := plan.Certificate.Validate(); err != nil || plan.Certificate.Kind != model.CertificatePublicIngress ||
		plan.Certificate.OwnerKind != "host" || plan.Certificate.OwnerID != plan.GatewayID {
		return fmt.Errorf("%w: public certificate metadata is invalid", ErrExposeSagaInvalid)
	}
	if plan.CertificateExportPath == "" || !filepath.IsAbs(plan.CertificateExportPath) ||
		filepath.Clean(plan.CertificateExportPath) != plan.CertificateExportPath ||
		strings.ContainsAny(plan.CertificateExportPath, "\x00\r\n") || filepath.Base(plan.CertificateExportPath) == "." {
		return fmt.Errorf("%w: public certificate export path is invalid", ErrExposeSagaInvalid)
	}
	return nil
}

func (saga *ExposeCreateSaga) Apply(ctx context.Context, plan ExposeCreatePlan) (ExposeCreateResult, error) {
	if ctx == nil || saga == nil {
		return ExposeCreateResult{}, fmt.Errorf("%w: saga and context are required", ErrExposeSagaInvalid)
	}
	if err := plan.Validate(); err != nil {
		return ExposeCreateResult{}, err
	}
	before, node, err := saga.loadJoinedNode()
	if err != nil {
		return ExposeCreateResult{}, err
	}
	if before.Generation != plan.ExpectedLocalStateGeneration || before.Host.ID != plan.NodeHostID ||
		node.ID != plan.Expose.NodeID || node.Gateway.LastKnownGatewayGeneration > plan.ExpectedGatewayStateGeneration ||
		containsExpose(before.Exposes, plan.Expose.ID) {
		return ExposeCreateResult{}, ErrExposePlanStale
	}

	reservation, err := saga.gateway.Reserve(ctx, plan)
	if err != nil {
		if exposeCommitPossible(err) {
			return ExposeCreateResult{}, &ExposeOutcomeUncertainError{Stage: "gateway_reserve", Cause: err}
		}
		return ExposeCreateResult{}, fmt.Errorf("reserve authoritative expose: %w", err)
	}
	if err := validateExposeReservation(reservation, plan); err != nil {
		return ExposeCreateResult{}, &ExposeOutcomeUncertainError{Stage: "gateway_reservation_receipt", Cause: err}
	}
	pending, err := addPendingNodeExpose(before, plan.Expose, reservation.Generation)
	if err != nil {
		return ExposeCreateResult{}, saga.compensate(err, before, model.State{}, plan, reservation, ExposeTunnelActivation{}, false, false)
	}
	activation, err := saga.tunnel.Activate(ctx, before, pending, plan.Expose)
	if err != nil {
		return ExposeCreateResult{}, saga.compensate(fmt.Errorf("activate node tunnel mapping: %w", err), before, model.State{}, plan, reservation, ExposeTunnelActivation{}, false, false)
	}
	if err := validateExposeTunnelActivation(activation, pending, plan.Expose); err != nil {
		return ExposeCreateResult{}, saga.compensate(err, before, model.State{}, plan, reservation, activation, true, false)
	}
	if err := saga.state.Save(before.Generation, pending); err != nil {
		return ExposeCreateResult{}, saga.compensate(fmt.Errorf("persist node pending expose: %w", err), before, model.State{}, plan, reservation, activation, true, false)
	}
	readiness, err := saga.tunnel.Observe(ctx, activation, plan.Expose)
	if err != nil {
		return ExposeCreateResult{}, saga.compensate(fmt.Errorf("observe node tunnel mapping: %w", err), before, pending, plan, reservation, activation, true, true)
	}
	effectiveState, err := effectiveExposeState(readiness, activation, plan.Expose)
	if err != nil {
		return ExposeCreateResult{}, saga.compensate(err, before, pending, plan, reservation, activation, true, true)
	}
	publication, err := saga.gateway.Publish(ctx, reservation, effectiveState)
	if err != nil {
		if exposeCommitPossible(err) {
			return ExposeCreateResult{}, &ExposeOutcomeUncertainError{Stage: "gateway_publish", Cause: err}
		}
		return ExposeCreateResult{}, saga.compensate(fmt.Errorf("publish gateway ingress: %w", err), before, pending, plan, reservation, activation, true, true)
	}
	wantPublicationGeneration, generationErr := model.NextGeneration(reservation.Generation)
	if generationErr != nil || publication.ExposeID != plan.Expose.ID || publication.Generation != wantPublicationGeneration {
		return ExposeCreateResult{}, &ExposeOutcomeUncertainError{Stage: "gateway_publication_receipt", Cause: ErrExposeSagaInvalid}
	}
	final, err := finalizeNodeExpose(pending, plan.Expose.ID, effectiveState, publication.Generation)
	if err != nil {
		return ExposeCreateResult{}, &ExposeOutcomeUncertainError{Stage: "node_finalize_plan", Cause: err}
	}
	if err := saga.state.Save(pending.Generation, final); err != nil {
		return ExposeCreateResult{}, &ExposeOutcomeUncertainError{Stage: "node_finalize_state", Cause: err}
	}
	result, err := NewExposeCreateResult(plan, effectiveState, final.Generation, publication.Generation)
	if err != nil {
		return ExposeCreateResult{}, &ExposeOutcomeUncertainError{Stage: "result_url", Cause: err}
	}
	return result, nil
}

// Defer performs exactly one authoritative gateway write. It deliberately does
// not call the node tunnel or node state interfaces.
func (saga *ExposeCreateSaga) Defer(ctx context.Context, plan ExposeCreatePlan) (ExposeCreateDeferredResult, error) {
	if ctx == nil || saga == nil {
		return ExposeCreateDeferredResult{}, fmt.Errorf("%w: saga and context are required", ErrExposeSagaInvalid)
	}
	if err := plan.Validate(); err != nil {
		return ExposeCreateDeferredResult{}, err
	}
	registration, err := saga.gateway.Defer(ctx, plan)
	if err != nil {
		return ExposeCreateDeferredResult{}, errors.Join(ErrExposeGatewayUnavailable, err)
	}
	wantRegistrationGeneration, generationErr := model.NextGeneration(plan.ExpectedGatewayStateGeneration)
	if generationErr != nil || registration.ExposeID != plan.Expose.ID || registration.Generation != wantRegistrationGeneration ||
		model.ValidateResourceID(registration.OperationID) != nil {
		return ExposeCreateDeferredResult{}, fmt.Errorf("%w: deferred gateway receipt is invalid", ErrExposeSagaInvalid)
	}
	return ExposeCreateDeferredResult{
		ExposeID: registration.ExposeID, OperationID: registration.OperationID,
		GatewayStateGeneration: registration.Generation,
	}, nil
}

func (plan ExposeCreatePlan) PreviewOutput() (output.Result, error) {
	if err := plan.Validate(); err != nil {
		return output.Result{}, err
	}
	commandResult := output.NewResult("expose", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": false, "generation": plan.ExpectedGatewayStateGeneration,
		"output_path": plan.CertificateExportPath, "fingerprint": plan.Certificate.Fingerprint,
		"scp_command": "scp root@" + plan.PublicIPv4 + ":" + plan.CertificateExportPath + " ./" + filepath.Base(plan.CertificateExportPath),
	})
	commandResult.ResourceIDs["expose_id"] = plan.Expose.ID
	commandResult.ResourceIDs["certificate_id"] = plan.Certificate.ID
	publicURL, err := exposePublicURL(plan.PublicIPv4, plan.Normalized.Path)
	if err != nil {
		return output.Result{}, err
	}
	if err := commandResult.AddHumanSensitivePath("public_url", publicURL); err != nil {
		return output.Result{}, err
	}
	for _, warning := range plan.Normalized.Warnings {
		commandResult.Warnings = append(commandResult.Warnings, output.Message{
			Code: warning.Code, Message: warning.Message,
			ResourceIDs: map[string]string{"expose_id": plan.Expose.ID},
		})
	}
	return commandResult, commandResult.Validate()
}

func NewExposeCreateResult(
	plan ExposeCreatePlan,
	state model.ExposeState,
	localGeneration uint64,
	gatewayGeneration uint64,
) (ExposeCreateResult, error) {
	if err := plan.Validate(); err != nil {
		return ExposeCreateResult{}, err
	}
	reservedGeneration, generationErr := model.NextGeneration(plan.ExpectedGatewayStateGeneration)
	wantGatewayGeneration, publicationErr := model.NextGeneration(reservedGeneration)
	if state != model.ExposeReady && state != model.ExposeDegraded || localGeneration == 0 ||
		generationErr != nil || publicationErr != nil || gatewayGeneration != wantGatewayGeneration {
		return ExposeCreateResult{}, fmt.Errorf("%w: expose result state or generation is invalid", ErrExposeSagaInvalid)
	}
	publicURL, err := exposePublicURL(plan.PublicIPv4, plan.Normalized.Path)
	if err != nil {
		return ExposeCreateResult{}, err
	}
	return ExposeCreateResult{
		ExposeID: plan.Expose.ID, State: state,
		LocalStateGeneration: localGeneration, GatewayStateGeneration: gatewayGeneration,
		PublicIPv4: plan.PublicIPv4, CertificateID: plan.Certificate.ID,
		CertificateFingerprint: plan.Certificate.Fingerprint, CertificateExportPath: plan.CertificateExportPath,
		publicURL: publicURL,
	}, nil
}

func (result ExposeCreateResult) Output() (output.Result, error) {
	if result.State != model.ExposeReady && result.State != model.ExposeDegraded {
		return output.Result{}, fmt.Errorf("%w: expose result state is invalid", ErrExposeSagaInvalid)
	}
	if err := model.ValidateResourceID(result.ExposeID); err != nil || errResourceID(result.CertificateID) != nil ||
		result.LocalStateGeneration == 0 || result.GatewayStateGeneration == 0 {
		return output.Result{}, fmt.Errorf("%w: expose result identity is invalid", ErrExposeSagaInvalid)
	}
	if result.CertificateFingerprint == "" || result.CertificateExportPath == "" {
		return output.Result{}, fmt.Errorf("%w: expose certificate result is incomplete", ErrExposeSagaInvalid)
	}
	address, err := netip.ParseAddr(result.PublicIPv4)
	if err != nil || !address.Is4() || address.String() != result.PublicIPv4 ||
		!filepath.IsAbs(result.CertificateExportPath) || filepath.Clean(result.CertificateExportPath) != result.CertificateExportPath ||
		strings.ContainsAny(result.CertificateExportPath, "\x00\r\n") {
		return output.Result{}, fmt.Errorf("%w: expose public endpoint result is invalid", ErrExposeSagaInvalid)
	}
	status, category := output.StatusOK, output.CategorySuccess
	if result.State == model.ExposeDegraded {
		status, category = output.StatusDegraded, output.CategoryUnavailable
	}
	commandResult := output.NewResult("expose", status, category, output.SafeObject{
		"changed": true, "generation": result.GatewayStateGeneration,
		"expose_state": string(result.State), "output_path": result.CertificateExportPath,
		"fingerprint": result.CertificateFingerprint,
		"scp_command": "scp root@" + result.PublicIPv4 + ":" + result.CertificateExportPath + " ./" + filepath.Base(result.CertificateExportPath),
	})
	commandResult.ResourceIDs["expose_id"] = result.ExposeID
	commandResult.ResourceIDs["certificate_id"] = result.CertificateID
	if err := commandResult.AddHumanSensitivePath("public_url", result.publicURL); err != nil {
		return output.Result{}, err
	}
	if result.State == model.ExposeDegraded {
		commandResult.Warnings = append(commandResult.Warnings, output.Message{
			Code: "local_application_unavailable", Message: "The expose is registered, but its local application is not accepting requests; public requests return 503.",
			ResourceIDs: map[string]string{"expose_id": result.ExposeID},
		})
		commandResult.RequiresAction = append(commandResult.RequiresAction, output.Action{
			Code: "start_local_application", Message: "Start the configured local application and verify the expose again.",
			ResourceIDs: map[string]string{"expose_id": result.ExposeID},
		})
	}
	return commandResult, commandResult.Validate()
}

func (result ExposeCreateDeferredResult) Output() (output.Result, error) {
	if model.ValidateResourceID(result.ExposeID) != nil || model.ValidateResourceID(result.OperationID) != nil || result.GatewayStateGeneration == 0 {
		return output.Result{}, fmt.Errorf("%w: deferred result is invalid", ErrExposeSagaInvalid)
	}
	commandResult := output.NewResult("expose", output.StatusPending, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": result.GatewayStateGeneration, "operation_id": result.OperationID,
	})
	commandResult.ResourceIDs["expose_id"] = result.ExposeID
	commandResult.ResourceIDs["operation_id"] = result.OperationID
	return commandResult, commandResult.Validate()
}

type ExposeOutcomeUncertainError struct {
	Stage string
	Cause error
}

func (failure *ExposeOutcomeUncertainError) Error() string {
	if failure == nil {
		return ErrExposeOutcomeUncertain.Error()
	}
	return fmt.Sprintf("%s: %s", ErrExposeOutcomeUncertain, failure.Stage)
}

func (failure *ExposeOutcomeUncertainError) Unwrap() error {
	if failure == nil || failure.Cause == nil {
		return ErrExposeOutcomeUncertain
	}
	return errors.Join(ErrExposeOutcomeUncertain, failure.Cause)
}

type exposeCommitPossibility interface {
	CommitPossible() bool
}

func exposeCommitPossible(err error) bool {
	var uncertain exposeCommitPossibility
	return errors.As(err, &uncertain) && uncertain.CommitPossible()
}

func (saga *ExposeCreateSaga) loadJoinedNode() (model.State, model.Node, error) {
	state, err := saga.state.Load()
	if err != nil {
		return model.State{}, model.Node{}, fmt.Errorf("load node state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return model.State{}, model.Node{}, fmt.Errorf("%w: node state: %v", ErrExposeSagaInvalid, err)
	}
	if state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Lifecycle != model.LifecycleActive || state.Nodes[0].Gateway == nil {
		return model.State{}, model.Node{}, fmt.Errorf("%w: expose requires one joined active node", ErrExposeSagaInvalid)
	}
	return state, state.Nodes[0], nil
}

func validateExposeGatewaySnapshot(snapshot ExposeGatewaySnapshot, local model.Node) error {
	if model.ValidateResourceID(snapshot.GatewayID) != nil || snapshot.Generation == 0 {
		return fmt.Errorf("%w: gateway snapshot identity is invalid", ErrExposeSagaInvalid)
	}
	address, err := netip.ParseAddr(snapshot.PublicIPv4)
	if err != nil || !address.Is4() || address.String() != snapshot.PublicIPv4 {
		return fmt.Errorf("%w: gateway snapshot public IPv4 is invalid", ErrExposeSagaInvalid)
	}
	if err := snapshot.Node.Validate(); err != nil || snapshot.Node.Gateway != nil || snapshot.Node.ID != local.ID ||
		snapshot.Node.Name != local.Name || snapshot.Node.Lifecycle != model.LifecycleActive ||
		snapshot.Node.OverlayIPv4 != local.OverlayIPv4 || snapshot.Node.CredentialGeneration != local.CredentialGeneration ||
		snapshot.Node.ActiveTransport != local.ActiveTransport {
		return fmt.Errorf("%w: gateway node record differs from local identity", ErrExposePlanStale)
	}
	if err := snapshot.Normalized.Validate(); err != nil || snapshot.Normalized.NodeID != local.ID ||
		snapshot.Normalized.ExpectedStateGeneration != snapshot.Generation ||
		snapshot.TunnelPort < tunnel.DefaultLoopbackPortFirst || snapshot.TunnelPort > tunnel.DefaultLoopbackPortLast {
		return fmt.Errorf("%w: authoritative expose plan is invalid", ErrExposeSagaInvalid)
	}
	if err := snapshot.Certificate.Validate(); err != nil || snapshot.Certificate.Kind != model.CertificatePublicIngress ||
		snapshot.Certificate.OwnerKind != "host" || snapshot.Certificate.OwnerID != snapshot.GatewayID {
		return fmt.Errorf("%w: gateway public certificate metadata is invalid", ErrExposeSagaInvalid)
	}
	if snapshot.CertificateExportPath == "" || !filepath.IsAbs(snapshot.CertificateExportPath) ||
		filepath.Clean(snapshot.CertificateExportPath) != snapshot.CertificateExportPath || strings.ContainsAny(snapshot.CertificateExportPath, "\x00\r\n") {
		return fmt.Errorf("%w: gateway certificate export path is invalid", ErrExposeSagaInvalid)
	}
	return nil
}

func validateExposeReservation(receipt ExposeGatewayReservation, plan ExposeCreatePlan) error {
	wantGeneration, err := model.NextGeneration(plan.ExpectedGatewayStateGeneration)
	if receipt.ExposeID != plan.Expose.ID || receipt.PreviousGeneration != plan.ExpectedGatewayStateGeneration ||
		err != nil || receipt.Generation != wantGeneration {
		return fmt.Errorf("%w: gateway reservation receipt is invalid", ErrExposeSagaInvalid)
	}
	return nil
}

func validateExposeTunnelActivation(activation ExposeTunnelActivation, pending model.State, expose model.Expose) error {
	if activation.ExposeID != expose.ID || activation.Candidate.Validate() != nil ||
		activation.Candidate.HostRole != model.RoleNode || activation.Candidate.HostID != pending.Host.ID ||
		activation.Candidate.NodeID != expose.NodeID || activation.Candidate.Generation != pending.Generation {
		return fmt.Errorf("%w: tunnel activation belongs to another candidate", ErrExposeSagaInvalid)
	}
	return nil
}

func effectiveExposeState(readiness tunnel.TunnelReadinessResult, activation ExposeTunnelActivation, expose model.Expose) (model.ExposeState, error) {
	if err := readiness.Validate(); err != nil || readiness.Candidate != activation.Candidate {
		return "", fmt.Errorf("%w: readiness belongs to another tunnel candidate", ErrExposeTunnelNotReady)
	}
	if readiness.Configuration.State != tunnel.TunnelProbePassed || readiness.Connection.State != tunnel.TunnelProbePassed ||
		readiness.MappingSet.State != tunnel.TunnelProbePassed {
		return "", ErrExposeTunnelNotReady
	}
	wantedName, err := tunnel.MappingName(expose.NodeID, expose.ID)
	if err != nil {
		return "", err
	}
	for _, mapping := range readiness.Mappings {
		if mapping.ExposeID != expose.ID {
			continue
		}
		if mapping.Name != wantedName || mapping.Generation != expose.Generation || mapping.Registration.State != tunnel.TunnelProbePassed {
			return "", ErrExposeTunnelNotReady
		}
		if mapping.Upstream.State == tunnel.TunnelProbePassed {
			return model.ExposeReady, nil
		}
		return model.ExposeDegraded, nil
	}
	return "", ErrExposeTunnelNotReady
}

func addPendingNodeExpose(before model.State, expose model.Expose, gatewayGeneration uint64) (model.State, error) {
	candidate, err := cloneExposeState(before)
	if err != nil {
		return model.State{}, err
	}
	candidate.Generation, err = model.NextGeneration(before.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate.Exposes = append(candidate.Exposes, expose)
	candidate.Nodes[0].Gateway.LastKnownGatewayGeneration = gatewayGeneration
	if err := model.ValidateTransition(before, candidate); err != nil {
		return model.State{}, fmt.Errorf("build node pending expose state: %w", err)
	}
	return candidate, nil
}

func finalizeNodeExpose(pending model.State, exposeID string, state model.ExposeState, gatewayGeneration uint64) (model.State, error) {
	final, err := cloneExposeState(pending)
	if err != nil {
		return model.State{}, err
	}
	final.Generation, err = model.NextGeneration(pending.Generation)
	if err != nil {
		return model.State{}, err
	}
	found := false
	for index := range final.Exposes {
		if final.Exposes[index].ID == exposeID {
			final.Exposes[index].State = state
			found = true
			break
		}
	}
	if !found {
		return model.State{}, ErrExposePlanStale
	}
	final.Nodes[0].Gateway.LastKnownGatewayGeneration = gatewayGeneration
	if err := model.ValidateTransition(pending, final); err != nil {
		return model.State{}, fmt.Errorf("build node final expose state: %w", err)
	}
	return final, nil
}

func removePendingNodeExpose(pending model.State, exposeID string, gatewayGeneration uint64) (model.State, error) {
	rollback, err := cloneExposeState(pending)
	if err != nil {
		return model.State{}, err
	}
	rollback.Generation, err = model.NextGeneration(pending.Generation)
	if err != nil {
		return model.State{}, err
	}
	filtered := rollback.Exposes[:0]
	for _, expose := range rollback.Exposes {
		if expose.ID != exposeID {
			filtered = append(filtered, expose)
		}
	}
	rollback.Exposes = filtered
	if gatewayGeneration != 0 {
		rollback.Nodes[0].Gateway.LastKnownGatewayGeneration = gatewayGeneration
	}
	if err := model.ValidateTransition(pending, rollback); err != nil {
		return model.State{}, fmt.Errorf("build node expose rollback state: %w", err)
	}
	return rollback, nil
}

func (saga *ExposeCreateSaga) compensate(
	primary error,
	before, pending model.State,
	plan ExposeCreatePlan,
	reservation ExposeGatewayReservation,
	activation ExposeTunnelActivation,
	tunnelActive, localPending bool,
) error {
	rollbackContext, cancel := context.WithTimeout(context.Background(), exposeCompensationTimeout)
	defer cancel()
	errorsFound := []error{primary}
	if tunnelActive {
		if err := saga.tunnel.Rollback(rollbackContext, activation); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("rollback node tunnel mapping: %w", err))
		}
	}
	gatewayGeneration, err := saga.gateway.Abort(rollbackContext, reservation)
	if err != nil {
		errorsFound = append(errorsFound, fmt.Errorf("abort gateway expose reservation: %w", err))
	}
	if localPending {
		rollback, buildErr := removePendingNodeExpose(pending, plan.Expose.ID, gatewayGeneration)
		if buildErr != nil {
			errorsFound = append(errorsFound, buildErr)
		} else if saveErr := saga.state.Save(pending.Generation, rollback); saveErr != nil {
			errorsFound = append(errorsFound, fmt.Errorf("persist node expose rollback: %w", saveErr))
		}
	}
	_ = before
	return errors.Join(errorsFound...)
}

func cloneExposeState(source model.State) (model.State, error) {
	encoded, err := model.EncodeState(source)
	if err != nil {
		return model.State{}, err
	}
	return model.DecodeState(encoded)
}

func containsExpose(exposes []model.Expose, exposeID string) bool {
	for _, expose := range exposes {
		if expose.ID == exposeID {
			return true
		}
	}
	return false
}

func exposePublicURL(publicIPv4, path string) (output.SensitivePath, error) {
	return output.NewSensitivePath("https://" + publicIPv4 + path)
}

func errResourceID(value string) error { return model.ValidateResourceID(value) }
