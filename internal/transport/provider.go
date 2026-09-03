package transport

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

// Provider owns one transport implementation. Rendered configuration and
// secret material remain behind Candidate so transport-neutral orchestration
// cannot inspect or accidentally serialize provider-private data.
type Provider interface {
	Kind() model.TransportKind
	Render(context.Context, RenderRequest) (Candidate, error)
	Prepare(context.Context, Candidate) error
	Validate(context.Context, Candidate) error
	StartTest(context.Context, Candidate) (TestResult, error)
	Activate(context.Context, Candidate) error
	Health(context.Context, HealthRequest) (Health, error)
	Drain(context.Context, DrainRequest) error
	Rollback(context.Context, Candidate) error
}

// Candidate is an opaque provider-owned rendered configuration. Descriptor is
// deliberately limited to non-secret identity and generation metadata.
type Candidate interface {
	Descriptor() CandidateDescriptor
}

type CandidateDescriptor struct {
	OwnerKind            model.TargetKind
	OwnerID              string
	Kind                 model.TransportKind
	CredentialGeneration uint64
	ConfigHash           string
}

func DescriptorFromTransport(value model.Transport) CandidateDescriptor {
	return CandidateDescriptor{
		OwnerKind:            value.OwnerKind,
		OwnerID:              value.OwnerID,
		Kind:                 value.Kind,
		CredentialGeneration: value.CredentialGeneration,
		ConfigHash:           value.ConfigHash,
	}
}

func (descriptor CandidateDescriptor) Validate() error {
	if descriptor.OwnerKind != model.TargetNode && descriptor.OwnerKind != model.TargetClient {
		return fmt.Errorf("unsupported transport owner kind %q", descriptor.OwnerKind)
	}
	if strings.TrimSpace(descriptor.OwnerID) == "" {
		return fmt.Errorf("transport owner ID is required")
	}
	if !isTransportKind(descriptor.Kind) {
		return fmt.Errorf("unsupported transport kind %q", descriptor.Kind)
	}
	if descriptor.CredentialGeneration == 0 {
		return fmt.Errorf("transport credential generation must be positive")
	}
	if len(descriptor.ConfigHash) != 64 {
		return fmt.Errorf("transport config hash must be a SHA-256 hex digest")
	}
	for _, character := range descriptor.ConfigHash {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return fmt.Errorf("transport config hash must be a SHA-256 hex digest")
		}
	}
	return nil
}

type RenderRequest struct {
	Transport model.Transport
}

func (request RenderRequest) Validate() error {
	if err := request.Transport.Validate(); err != nil {
		return fmt.Errorf("validate transport render request: %w", err)
	}
	return nil
}

type Identity struct {
	OwnerKind            model.TargetKind
	OwnerID              string
	CredentialGeneration uint64
}

func IdentityFromTransport(value model.Transport) Identity {
	return Identity{
		OwnerKind:            value.OwnerKind,
		OwnerID:              value.OwnerID,
		CredentialGeneration: value.CredentialGeneration,
	}
}

func (identity Identity) Validate() error {
	if identity.OwnerKind != model.TargetNode && identity.OwnerKind != model.TargetClient {
		return fmt.Errorf("unsupported transport owner kind %q", identity.OwnerKind)
	}
	if strings.TrimSpace(identity.OwnerID) == "" {
		return fmt.Errorf("transport owner ID is required")
	}
	if identity.CredentialGeneration == 0 {
		return fmt.Errorf("transport credential generation must be positive")
	}
	return nil
}

type HealthRequest struct {
	Identity Identity
}

type DrainRequest struct {
	Identity Identity
	Deadline time.Time
}

func (request DrainRequest) Validate(now time.Time) error {
	if err := request.Identity.Validate(); err != nil {
		return err
	}
	if request.Deadline.IsZero() || !request.Deadline.After(now) {
		return fmt.Errorf("transport drain deadline must be in the future")
	}
	return nil
}

type RuntimeRole string

const (
	RuntimeActive  RuntimeRole = "active"
	RuntimeStandby RuntimeRole = "standby"
)

type HealthCondition string

const (
	HealthHealthy     HealthCondition = "healthy"
	HealthDegraded    HealthCondition = "degraded"
	HealthUnavailable HealthCondition = "unavailable"
)

// Health separates the selected runtime role from reachability. An active
// transport remains active when degraded or unavailable; condition must never
// be interpreted as permission to activate standby.
type Health struct {
	Identity  Identity
	Kind      model.TransportKind
	Role      RuntimeRole
	Condition HealthCondition
	Code      string
}

func (health Health) Validate() error {
	if err := health.Identity.Validate(); err != nil {
		return err
	}
	if !isTransportKind(health.Kind) {
		return fmt.Errorf("unsupported transport kind %q", health.Kind)
	}
	if health.Role != RuntimeActive && health.Role != RuntimeStandby {
		return fmt.Errorf("unsupported transport runtime role %q", health.Role)
	}
	switch health.Condition {
	case HealthHealthy, HealthDegraded, HealthUnavailable:
	default:
		return fmt.Errorf("unsupported transport health condition %q", health.Condition)
	}
	if strings.TrimSpace(health.Code) == "" {
		return fmt.Errorf("transport health code is required")
	}
	return nil
}

type ProbeState string

const (
	ProbePassed ProbeState = "passed"
	ProbeFailed ProbeState = "failed"
)

type ProbeResult struct {
	State ProbeState
	Code  string
}

func (result ProbeResult) Validate() error {
	if result.State != ProbePassed && result.State != ProbeFailed {
		return fmt.Errorf("unsupported transport probe state %q", result.State)
	}
	if strings.TrimSpace(result.Code) == "" {
		return fmt.Errorf("transport probe code is required")
	}
	return nil
}

type TestResult struct {
	Control       ProbeResult
	ReverseTunnel ProbeResult
	SelectedTCP   ProbeResult
	SelectedUDP   ProbeResult
}

func (result TestResult) Validate() error {
	probes := []struct {
		name   string
		result ProbeResult
	}{
		{name: "control", result: result.Control},
		{name: "reverse tunnel", result: result.ReverseTunnel},
		{name: "selected TCP", result: result.SelectedTCP},
		{name: "selected UDP", result: result.SelectedUDP},
	}
	for _, probe := range probes {
		if err := probe.result.Validate(); err != nil {
			return fmt.Errorf("%s probe: %w", probe.name, err)
		}
	}
	return nil
}

func (result TestResult) Ready() bool {
	return result.Validate() == nil &&
		result.Control.State == ProbePassed &&
		result.ReverseTunnel.State == ProbePassed &&
		result.SelectedTCP.State == ProbePassed &&
		result.SelectedUDP.State == ProbePassed
}

func isTransportKind(kind model.TransportKind) bool {
	return kind == model.TransportStandard || kind == model.TransportRestricted
}
