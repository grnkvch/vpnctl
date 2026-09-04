package operations

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

type GatewayExposeStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

// GatewayExposeCertificateExporter ensures that the stable public certificate
// already has its public-only SCP source before an expose is reserved.
type GatewayExposeCertificateExporter interface {
	Ensure(model.State, string) error
}

type gatewayExposeCertificateAvailability interface {
	Available(model.State, string) (bool, error)
}

type GatewayExposeUnavailablePorts interface {
	Unavailable(context.Context) ([]int, error)
}

type GatewayExposeIngressActivation struct {
	ExposeID        string
	StateGeneration uint64
	ConfigHash      string
	opaque          any
}

func (GatewayExposeIngressActivation) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

// GatewayExposeIngressPublisher is deliberately domain-specific. Task 13.2
// supplies the reusable filesystem/service transaction adapter beneath it.
type GatewayExposeIngressPublisher interface {
	Activate(context.Context, model.State, model.State) (GatewayExposeIngressActivation, error)
	Rollback(context.Context, GatewayExposeIngressActivation) error
}

type GatewayExposeDeferredWriter interface {
	Register(context.Context, ExposeCreatePlan) (ExposeDeferredRegistration, error)
}

// GatewayExposeCoordinatorService is the gateway-side implementation behind
// the authenticated node control RPC. It is the sole authoritative state
// writer for expose creation.
type GatewayExposeCoordinatorService struct {
	state      GatewayExposeStateStore
	exporter   GatewayExposeCertificateExporter
	ports      GatewayExposeUnavailablePorts
	publisher  GatewayExposeIngressPublisher
	deferred   GatewayExposeDeferredWriter
	normalizer *ingress.ExposeNormalizer
	exportPath string
}

func NewGatewayExposeCoordinatorService(
	state GatewayExposeStateStore,
	exporter GatewayExposeCertificateExporter,
	ports GatewayExposeUnavailablePorts,
	publisher GatewayExposeIngressPublisher,
	deferred GatewayExposeDeferredWriter,
	normalizer *ingress.ExposeNormalizer,
	exportPath string,
) (*GatewayExposeCoordinatorService, error) {
	if state == nil || exporter == nil || ports == nil || publisher == nil || deferred == nil || normalizer == nil || exportPath == "" {
		return nil, fmt.Errorf("gateway expose coordinator dependencies are incomplete")
	}
	return &GatewayExposeCoordinatorService{
		state: state, exporter: exporter, ports: ports, publisher: publisher, deferred: deferred,
		normalizer: normalizer, exportPath: exportPath,
	}, nil
}

func (service *GatewayExposeCoordinatorService) Plan(
	ctx context.Context,
	nodeID string,
	request ingress.ExposeCreateRequest,
) (ExposeGatewaySnapshot, error) {
	if ctx == nil || service == nil || service.state == nil || service.ports == nil || service.normalizer == nil {
		return ExposeGatewaySnapshot{}, fmt.Errorf("gateway expose coordinator is incomplete")
	}
	if err := model.ValidateResourceID(nodeID); err != nil {
		return ExposeGatewaySnapshot{}, fmt.Errorf("gateway expose node identity is invalid")
	}
	state, node, certificate, err := service.loadGatewayResources(nodeID)
	if err != nil {
		return ExposeGatewaySnapshot{}, err
	}
	unavailable, err := service.ports.Unavailable(ctx)
	if err != nil {
		return ExposeGatewaySnapshot{}, fmt.Errorf("inspect gateway tunnel port namespace: %w", err)
	}
	if unavailable == nil {
		unavailable = []int{}
	}
	normalized, err := service.normalizer.Normalize(ingress.ExposeNamespace{
		NodeID: node.ID, StateGeneration: state.Generation, Existing: state.Exposes,
	}, request)
	if err != nil {
		return ExposeGatewaySnapshot{}, err
	}
	allocator, remaps, err := tunnel.DefaultLoopbackAllocatorFromExposes(state.Exposes, unavailable)
	if err != nil {
		return ExposeGatewaySnapshot{}, err
	}
	if len(remaps) != 0 {
		return ExposeGatewaySnapshot{}, fmt.Errorf("%w: persisted tunnel assignments require repair before expose creation", ErrExposePlanStale)
	}
	port, err := allocator.Allocate(normalized.ExposeID)
	if err != nil {
		return ExposeGatewaySnapshot{}, err
	}
	snapshot := ExposeGatewaySnapshot{
		GatewayID: state.Host.ID, Generation: state.Generation, PublicIPv4: state.Host.PublicIPv4,
		Node: node, Normalized: normalized, TunnelPort: port,
		Certificate: certificate, CertificateExportPath: service.exportPath,
	}
	if err := validateExposeGatewaySnapshot(snapshot, node); err != nil {
		return ExposeGatewaySnapshot{}, err
	}
	return snapshot, nil
}

// Inspect implements the bounded gateway half of node-side expose list/show.
// refreshCertificate is reserved for show: list remains a read-only operation.
func (service *GatewayExposeCoordinatorService) Inspect(
	ctx context.Context,
	nodeID string,
	refreshCertificate bool,
) (GatewayExposeCatalogSnapshot, error) {
	if ctx == nil || service == nil || service.state == nil || service.exporter == nil {
		return GatewayExposeCatalogSnapshot{}, fmt.Errorf("gateway expose coordinator is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return GatewayExposeCatalogSnapshot{}, err
	}
	state, node, certificate, err := service.loadGatewayResources(nodeID)
	if err != nil {
		return GatewayExposeCatalogSnapshot{}, err
	}
	available := false
	if refreshCertificate {
		if err := service.exporter.Ensure(state, service.exportPath); err != nil {
			return GatewayExposeCatalogSnapshot{}, fmt.Errorf("refresh public ingress certificate export: %w", err)
		}
		available = true
	} else if inspector, ok := service.exporter.(gatewayExposeCertificateAvailability); ok {
		available, err = inspector.Available(state, service.exportPath)
		if err != nil {
			return GatewayExposeCatalogSnapshot{}, fmt.Errorf("inspect public ingress certificate export: %w", err)
		}
	}
	exposes := make([]model.Expose, 0)
	for _, expose := range state.Exposes {
		if expose.NodeID == node.ID {
			exposes = append(exposes, expose)
		}
	}
	return GatewayExposeCatalogSnapshot{
		GatewayID: state.Host.ID, Generation: state.Generation, PublicIPv4: state.Host.PublicIPv4,
		NodeID: node.ID, Exposes: exposes, Certificate: certificate,
		CertificateExportPath: service.exportPath, CertificateAvailable: available,
	}, nil
}

func (service *GatewayExposeCoordinatorService) Reserve(ctx context.Context, plan ExposeCreatePlan) (ExposeGatewayReservation, error) {
	if ctx == nil || service == nil || service.state == nil || service.exporter == nil {
		return ExposeGatewayReservation{}, fmt.Errorf("gateway expose coordinator is incomplete")
	}
	if err := plan.Validate(); err != nil {
		return ExposeGatewayReservation{}, err
	}
	state, node, certificate, err := service.loadGatewayResources(plan.Expose.NodeID)
	if err != nil {
		return ExposeGatewayReservation{}, err
	}
	if state.Generation != plan.ExpectedGatewayStateGeneration || state.Host.ID != plan.GatewayID ||
		state.Host.PublicIPv4 != plan.PublicIPv4 || service.exportPath != plan.CertificateExportPath ||
		node.Lifecycle != model.LifecycleActive || !reflect.DeepEqual(certificate, plan.Certificate) {
		return ExposeGatewayReservation{}, ErrExposePlanStale
	}
	if err := service.exporter.Ensure(state, service.exportPath); err != nil {
		return ExposeGatewayReservation{}, fmt.Errorf("export public ingress certificate: %w", err)
	}
	candidate, err := cloneExposeState(state)
	if err != nil {
		return ExposeGatewayReservation{}, err
	}
	candidate.Generation, err = model.NextGeneration(state.Generation)
	if err != nil {
		return ExposeGatewayReservation{}, err
	}
	candidate.Exposes = append(candidate.Exposes, plan.Expose)
	if err := model.ValidateTransition(state, candidate); err != nil {
		return ExposeGatewayReservation{}, fmt.Errorf("reserve gateway expose: %w", err)
	}
	if err := service.state.Save(state.Generation, candidate); err != nil {
		return ExposeGatewayReservation{}, err
	}
	return ExposeGatewayReservation{ExposeID: plan.Expose.ID, PreviousGeneration: state.Generation, Generation: candidate.Generation}, nil
}

func (service *GatewayExposeCoordinatorService) Publish(
	ctx context.Context,
	reservation ExposeGatewayReservation,
	effectiveState model.ExposeState,
) (ExposeGatewayPublication, error) {
	if ctx == nil || service == nil || service.state == nil || service.publisher == nil {
		return ExposeGatewayPublication{}, fmt.Errorf("gateway expose coordinator is incomplete")
	}
	if effectiveState != model.ExposeReady && effectiveState != model.ExposeDegraded {
		return ExposeGatewayPublication{}, fmt.Errorf("gateway expose publication state is invalid")
	}
	if err := validateGatewayExposeReservationShape(reservation); err != nil {
		return ExposeGatewayPublication{}, err
	}
	state, err := service.state.Load()
	if err != nil {
		return ExposeGatewayPublication{}, err
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway || state.Generation != reservation.Generation {
		return ExposeGatewayPublication{}, ErrExposePlanStale
	}
	candidate, err := cloneExposeState(state)
	if err != nil {
		return ExposeGatewayPublication{}, err
	}
	candidate.Generation, err = model.NextGeneration(state.Generation)
	if err != nil {
		return ExposeGatewayPublication{}, err
	}
	found := false
	for index := range candidate.Exposes {
		if candidate.Exposes[index].ID != reservation.ExposeID {
			continue
		}
		if candidate.Exposes[index].State != model.ExposePending {
			return ExposeGatewayPublication{}, ErrExposePlanStale
		}
		candidate.Exposes[index].State = effectiveState
		found = true
		break
	}
	if !found {
		return ExposeGatewayPublication{}, ErrExposePlanStale
	}
	if err := model.ValidateTransition(state, candidate); err != nil {
		return ExposeGatewayPublication{}, err
	}
	activation, err := service.publisher.Activate(ctx, state, candidate)
	if err != nil {
		return ExposeGatewayPublication{}, err
	}
	if activation.ExposeID != reservation.ExposeID || activation.StateGeneration != candidate.Generation {
		return ExposeGatewayPublication{}, &gatewayExposeCommitError{cause: errors.New("ingress activation receipt is invalid"), possible: true}
	}
	if err := service.state.Save(state.Generation, candidate); err != nil {
		rollbackContext, cancel := context.WithTimeout(context.Background(), exposeCompensationTimeout)
		defer cancel()
		if rollbackErr := service.publisher.Rollback(rollbackContext, activation); rollbackErr != nil {
			return ExposeGatewayPublication{}, &gatewayExposeCommitError{cause: errors.Join(err, rollbackErr), possible: true}
		}
		return ExposeGatewayPublication{}, err
	}
	return ExposeGatewayPublication{ExposeID: reservation.ExposeID, Generation: candidate.Generation}, nil
}

func (service *GatewayExposeCoordinatorService) Abort(ctx context.Context, reservation ExposeGatewayReservation) (uint64, error) {
	if ctx == nil || service == nil || service.state == nil {
		return 0, fmt.Errorf("gateway expose coordinator is incomplete")
	}
	if err := validateGatewayExposeReservationShape(reservation); err != nil {
		return 0, err
	}
	state, err := service.state.Load()
	if err != nil {
		return 0, err
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway || state.Generation != reservation.Generation {
		return 0, ErrExposePlanStale
	}
	candidate, err := cloneExposeState(state)
	if err != nil {
		return 0, err
	}
	candidate.Generation, err = model.NextGeneration(state.Generation)
	if err != nil {
		return 0, err
	}
	found := false
	filtered := candidate.Exposes[:0]
	for _, expose := range candidate.Exposes {
		if expose.ID == reservation.ExposeID {
			if expose.State != model.ExposePending {
				return 0, ErrExposePlanStale
			}
			found = true
			continue
		}
		filtered = append(filtered, expose)
	}
	if !found {
		return 0, ErrExposePlanStale
	}
	candidate.Exposes = filtered
	if err := model.ValidateTransition(state, candidate); err != nil {
		return 0, err
	}
	if err := service.state.Save(state.Generation, candidate); err != nil {
		return 0, err
	}
	return candidate.Generation, nil
}

func (service *GatewayExposeCoordinatorService) Defer(ctx context.Context, plan ExposeCreatePlan) (ExposeDeferredRegistration, error) {
	if ctx == nil || service == nil || service.deferred == nil {
		return ExposeDeferredRegistration{}, fmt.Errorf("gateway expose coordinator is incomplete")
	}
	if err := plan.Validate(); err != nil {
		return ExposeDeferredRegistration{}, err
	}
	state, node, certificate, err := service.loadGatewayResources(plan.Expose.NodeID)
	if err != nil {
		return ExposeDeferredRegistration{}, err
	}
	if state.Generation != plan.ExpectedGatewayStateGeneration || state.Host.ID != plan.GatewayID ||
		state.Host.PublicIPv4 != plan.PublicIPv4 || service.exportPath != plan.CertificateExportPath ||
		node.Lifecycle != model.LifecycleActive || !reflect.DeepEqual(certificate, plan.Certificate) {
		return ExposeDeferredRegistration{}, ErrExposePlanStale
	}
	registration, err := service.deferred.Register(ctx, plan)
	if err != nil {
		return ExposeDeferredRegistration{}, err
	}
	next, nextErr := model.NextGeneration(state.Generation)
	if nextErr != nil || registration.ExposeID != plan.Expose.ID || registration.Generation != next ||
		model.ValidateResourceID(registration.OperationID) != nil {
		return ExposeDeferredRegistration{}, &gatewayExposeCommitError{cause: errors.New("deferred registration receipt is invalid"), possible: true}
	}
	return registration, nil
}

func (service *GatewayExposeCoordinatorService) loadGatewayResources(nodeID string) (model.State, model.Node, model.Certificate, error) {
	state, err := service.state.Load()
	if err != nil {
		return model.State{}, model.Node{}, model.Certificate{}, err
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return model.State{}, model.Node{}, model.Certificate{}, fmt.Errorf("gateway expose authoritative state is invalid")
	}
	var node model.Node
	nodeFound := false
	for _, candidate := range state.Nodes {
		if candidate.ID == nodeID {
			node, nodeFound = candidate, true
			break
		}
	}
	if !nodeFound || node.Lifecycle != model.LifecycleActive {
		return model.State{}, model.Node{}, model.Certificate{}, ErrExposePlanStale
	}
	var certificate model.Certificate
	certificateFound := false
	for _, candidate := range state.Certificates {
		if candidate.Kind != model.CertificatePublicIngress {
			continue
		}
		if certificateFound {
			return model.State{}, model.Node{}, model.Certificate{}, fmt.Errorf("multiple public ingress certificates")
		}
		certificate, certificateFound = candidate, true
	}
	if !certificateFound {
		return model.State{}, model.Node{}, model.Certificate{}, ingress.ErrPublicCertificateNotFound
	}
	return state, node, certificate, nil
}

type PublicCertificateExportEnsurer struct {
	secrets ingress.PublicCertificateSecretStore
}

func NewPublicCertificateExportEnsurer(secrets ingress.PublicCertificateSecretStore) (*PublicCertificateExportEnsurer, error) {
	if secrets == nil {
		return nil, fmt.Errorf("public certificate source is required")
	}
	return &PublicCertificateExportEnsurer{secrets: secrets}, nil
}

func (exporter *PublicCertificateExportEnsurer) Ensure(state model.State, path string) error {
	if exporter == nil || exporter.secrets == nil {
		return fmt.Errorf("public certificate exporter is incomplete")
	}
	_, err := ingress.ExportPublicCertificate(state, exporter.secrets, path)
	return err
}

func (exporter *PublicCertificateExportEnsurer) Available(state model.State, path string) (bool, error) {
	if exporter == nil || exporter.secrets == nil {
		return false, fmt.Errorf("public certificate exporter is incomplete")
	}
	return ingress.PublicCertificateExportAvailable(state, exporter.secrets, path)
}

type gatewayExposeCommitError struct {
	cause    error
	possible bool
}

func (failure *gatewayExposeCommitError) Error() string { return "gateway ingress commit is uncertain" }
func (failure *gatewayExposeCommitError) Unwrap() error { return failure.cause }
func (failure *gatewayExposeCommitError) CommitPossible() bool {
	return failure != nil && failure.possible
}

func validateGatewayExposeReservationShape(reservation ExposeGatewayReservation) error {
	if model.ValidateResourceID(reservation.ExposeID) != nil || reservation.PreviousGeneration == 0 {
		return fmt.Errorf("gateway expose reservation is invalid")
	}
	next, err := model.NextGeneration(reservation.PreviousGeneration)
	if err != nil || reservation.Generation != next {
		return fmt.Errorf("gateway expose reservation generation is invalid")
	}
	return nil
}

var _ ExposeGatewayCoordinator = (*GatewayExposeCoordinatorService)(nil)
var _ ExposeGatewayCatalog = (*GatewayExposeCoordinatorService)(nil)
