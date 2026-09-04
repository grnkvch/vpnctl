package operations

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

// SystemGatewayExposeIngressPublisher connects the implementation-neutral
// expose transaction to the complete generated nginx tree. The previous tree
// remains retained until authoritative state has been committed.
type SystemGatewayExposeIngressPublisher struct {
	paths   store.Paths
	manager *ingress.NginxActivationManager
}

func NewSystemGatewayExposeIngressPublisher(paths store.Paths, runner linuxplatform.ProbeRunner) (*SystemGatewayExposeIngressPublisher, error) {
	if runner == nil {
		return nil, fmt.Errorf("gateway ingress probe runner is required")
	}
	manager, err := ingress.NewNginxActivationManager(paths, runner, ingress.OSNginxReloadRunner{})
	if err != nil {
		return nil, err
	}
	return &SystemGatewayExposeIngressPublisher{paths: paths, manager: manager}, nil
}

func (publisher *SystemGatewayExposeIngressPublisher) Activate(ctx context.Context, before, candidate model.State) (GatewayExposeIngressActivation, error) {
	if ctx == nil || publisher == nil || publisher.manager == nil {
		return GatewayExposeIngressActivation{}, fmt.Errorf("system gateway ingress publisher is incomplete")
	}
	if err := before.Validate(); err != nil || before.Host.Role != model.RoleGateway {
		return GatewayExposeIngressActivation{}, fmt.Errorf("prior gateway state is invalid")
	}
	if err := model.ValidateTransition(before, candidate); err != nil {
		return GatewayExposeIngressActivation{}, fmt.Errorf("gateway ingress state transition is invalid: %w", err)
	}
	exposeID, err := changedGatewayExposeID(before.Exposes, candidate.Exposes)
	if err != nil {
		return GatewayExposeIngressActivation{}, err
	}
	certificate, err := gatewayPublicIngressCertificate(candidate)
	if err != nil {
		return GatewayExposeIngressActivation{}, err
	}
	nginxCandidate, err := ingress.RenderNginxConfig(ingress.NginxRenderRequest{
		StateGeneration:  candidate.Generation,
		PublicIPv4:       candidate.Host.PublicIPv4,
		CertificatePath:  systemExposeSecretPath(publisher.paths, model.SecretRef(certificate.CertificateRef)),
		PrivateKeyPath:   systemExposeSecretPath(publisher.paths, certificate.PrivateKeyRef),
		RuntimeDirectory: ingress.NginxRuntimeDirectory(publisher.paths),
		Limits:           ingress.DefaultGatewayHardLimits(),
		Exposes:          append([]model.Expose(nil), candidate.Exposes...),
	})
	if err != nil {
		return GatewayExposeIngressActivation{}, err
	}
	result, retained, err := publisher.manager.ActivateRetained(ctx, nginxCandidate)
	if err != nil {
		return GatewayExposeIngressActivation{}, err
	}
	if retained == nil || !result.Changed || result.StateGeneration != candidate.Generation || result.ConfigHash != nginxCandidate.ConfigHash() {
		return GatewayExposeIngressActivation{}, fmt.Errorf("nginx did not retain the requested gateway ingress generation")
	}
	return GatewayExposeIngressActivation{
		ExposeID: exposeID, StateGeneration: candidate.Generation, ConfigHash: result.ConfigHash, opaque: retained,
	}, nil
}

func (publisher *SystemGatewayExposeIngressPublisher) Commit(ctx context.Context, activation GatewayExposeIngressActivation) error {
	retained, ok := activation.opaque.(*ingress.NginxRetainedActivation)
	if !ok || retained == nil || publisher == nil || publisher.manager == nil {
		return fmt.Errorf("gateway ingress activation receipt is invalid")
	}
	return publisher.manager.CommitRetained(ctx, retained)
}

func (publisher *SystemGatewayExposeIngressPublisher) Rollback(ctx context.Context, activation GatewayExposeIngressActivation) error {
	retained, ok := activation.opaque.(*ingress.NginxRetainedActivation)
	if !ok || retained == nil || publisher == nil || publisher.manager == nil {
		return fmt.Errorf("gateway ingress activation receipt is invalid")
	}
	return publisher.manager.RollbackRetained(ctx, retained)
}

func changedGatewayExposeID(before, candidate []model.Expose) (string, error) {
	prior := make(map[string]model.Expose, len(before))
	for _, expose := range before {
		prior[expose.ID] = expose
	}
	changed := ""
	for _, expose := range candidate {
		old, found := prior[expose.ID]
		if found {
			delete(prior, expose.ID)
		}
		if found && reflect.DeepEqual(old, expose) {
			continue
		}
		if changed != "" {
			return "", fmt.Errorf("gateway ingress transaction changes multiple exposes")
		}
		changed = expose.ID
	}
	for id := range prior {
		if changed != "" {
			return "", fmt.Errorf("gateway ingress transaction changes multiple exposes")
		}
		changed = id
	}
	if model.ValidateResourceID(changed) != nil {
		return "", fmt.Errorf("gateway ingress transaction has no unique expose target")
	}
	return changed, nil
}

func gatewayPublicIngressCertificate(state model.State) (model.Certificate, error) {
	var certificate model.Certificate
	found := false
	for _, candidate := range state.Certificates {
		if candidate.Kind != model.CertificatePublicIngress {
			continue
		}
		if found {
			return model.Certificate{}, fmt.Errorf("gateway has multiple public ingress certificates")
		}
		certificate, found = candidate, true
	}
	if !found {
		return model.Certificate{}, ingress.ErrPublicCertificateNotFound
	}
	return certificate, nil
}

func systemExposeSecretPath(paths store.Paths, reference model.SecretRef) string {
	kind, id, err := reference.Parts()
	if err != nil || strings.ContainsAny(kind+id, `/\\`) {
		return ""
	}
	return filepath.Join(paths.SecretsDir, kind, id)
}

// SystemGatewayExposeUnavailablePorts reads the kernel listener namespace
// through ss and returns only ports from vpnctl's managed FRP loopback range.
type SystemGatewayExposeUnavailablePorts struct{ runner linuxplatform.ProbeRunner }

func NewSystemGatewayExposeUnavailablePorts(runner linuxplatform.ProbeRunner) (*SystemGatewayExposeUnavailablePorts, error) {
	if runner == nil {
		return nil, fmt.Errorf("gateway port inspector runner is required")
	}
	return &SystemGatewayExposeUnavailablePorts{runner: runner}, nil
}

func (inspector *SystemGatewayExposeUnavailablePorts) Unavailable(ctx context.Context) ([]int, error) {
	if ctx == nil || inspector == nil || inspector.runner == nil {
		return nil, fmt.Errorf("gateway port inspector is incomplete")
	}
	result, err := inspector.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "ss", Args: []string{"-H", "-ltn"}})
	if err != nil || result.ExitCode != 0 || len(strings.TrimSpace(string(result.Stderr))) != 0 {
		return nil, fmt.Errorf("inspect gateway TCP listeners")
	}
	seen := make(map[int]struct{})
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return nil, fmt.Errorf("inspect gateway TCP listeners: malformed ss output")
		}
		separator := strings.LastIndexByte(fields[3], ':')
		if separator < 0 || separator == len(fields[3])-1 {
			return nil, fmt.Errorf("inspect gateway TCP listeners: malformed local endpoint")
		}
		port, parseErr := strconv.Atoi(fields[3][separator+1:])
		if parseErr != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("inspect gateway TCP listeners: malformed local port")
		}
		if port >= tunnel.DefaultLoopbackPortFirst && port <= tunnel.DefaultLoopbackPortLast {
			seen[port] = struct{}{}
		}
	}
	ports := make([]int, 0, len(seen))
	for port := tunnel.DefaultLoopbackPortFirst; port <= tunnel.DefaultLoopbackPortLast; port++ {
		if _, found := seen[port]; found {
			ports = append(ports, port)
		}
	}
	return ports, nil
}

// GatewayExposeStateDeferredWriter durably registers the desired pending
// expose and an apply operation without activating tunnel or ingress runtime.
type GatewayExposeStateDeferredWriter struct {
	state   GatewayExposeStateStore
	now     func() time.Time
	newUUID model.UUIDGenerator
}

func NewGatewayExposeStateDeferredWriter(state GatewayExposeStateStore, now func() time.Time, newUUID model.UUIDGenerator) (*GatewayExposeStateDeferredWriter, error) {
	if state == nil {
		return nil, fmt.Errorf("gateway deferred expose state store is required")
	}
	if now == nil {
		now = time.Now
	}
	if newUUID == nil {
		newUUID = model.NewUUID
	}
	return &GatewayExposeStateDeferredWriter{state: state, now: now, newUUID: newUUID}, nil
}

func (writer *GatewayExposeStateDeferredWriter) Register(ctx context.Context, plan ExposeCreatePlan) (ExposeDeferredRegistration, error) {
	if ctx == nil || writer == nil || writer.state == nil || writer.now == nil || writer.newUUID == nil {
		return ExposeDeferredRegistration{}, fmt.Errorf("gateway deferred expose writer is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return ExposeDeferredRegistration{}, err
	}
	if err := plan.Validate(); err != nil {
		return ExposeDeferredRegistration{}, err
	}
	state, err := writer.state.Load()
	if err != nil {
		return ExposeDeferredRegistration{}, err
	}
	if state.Generation != plan.ExpectedGatewayStateGeneration || state.Host.ID != plan.GatewayID {
		return ExposeDeferredRegistration{}, ErrExposePlanStale
	}
	operationID, err := model.AllocateUUID(occupiedGatewayExposeIDs(state, plan.Expose.ID), writer.newUUID)
	if err != nil {
		return ExposeDeferredRegistration{}, err
	}
	next, err := model.NextGeneration(state.Generation)
	if err != nil {
		return ExposeDeferredRegistration{}, err
	}
	at := writer.now().UTC()
	operation := model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: operationID, Type: model.OperationExposeCreate,
		State: model.OperationPending, TargetKind: "expose", TargetID: plan.Expose.ID,
		ExpectedGeneration: state.Generation, DesiredGeneration: next,
		Steps:     []model.OperationStep{{Name: "tunnel", State: model.OperationPending, UpdatedAt: at}, {Name: "ingress", State: model.OperationPending, UpdatedAt: at}},
		CreatedAt: at, UpdatedAt: at,
	}
	if err := operation.Validate(); err != nil {
		return ExposeDeferredRegistration{}, err
	}
	candidate, err := cloneExposeState(state)
	if err != nil {
		return ExposeDeferredRegistration{}, err
	}
	candidate.Generation = next
	candidate.Exposes = append(candidate.Exposes, plan.Expose)
	candidate.Operations = append(candidate.Operations, operation)
	if err := model.ValidateTransition(state, candidate); err != nil {
		return ExposeDeferredRegistration{}, err
	}
	if err := writer.state.Save(state.Generation, candidate); err != nil {
		return ExposeDeferredRegistration{}, err
	}
	return ExposeDeferredRegistration{ExposeID: plan.Expose.ID, OperationID: operationID, Generation: next}, nil
}

func occupiedGatewayExposeIDs(state model.State, extra string) map[string]struct{} {
	occupied := map[string]struct{}{state.Host.ID: {}, extra: {}}
	for _, node := range state.Nodes {
		occupied[node.ID] = struct{}{}
	}
	for _, expose := range state.Exposes {
		occupied[expose.ID] = struct{}{}
	}
	for _, operation := range state.Operations {
		occupied[operation.ID] = struct{}{}
		if operation.RequestID != "" {
			occupied[operation.RequestID] = struct{}{}
		}
	}
	return occupied
}

var _ GatewayExposeIngressPublisher = (*SystemGatewayExposeIngressPublisher)(nil)
var _ GatewayExposeUnavailablePorts = (*SystemGatewayExposeUnavailablePorts)(nil)
var _ GatewayExposeDeferredWriter = (*GatewayExposeStateDeferredWriter)(nil)
