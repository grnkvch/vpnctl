package operations

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const StatusBackupWarningAge = 30 * 24 * time.Hour

type StatusOverall string

const (
	StatusOverallHealthy  StatusOverall = "healthy"
	StatusOverallDegraded StatusOverall = "degraded"
	StatusOverallFailed   StatusOverall = "failed"
)

type StatusCategory string

const (
	StatusCategorySuccess     StatusCategory = "success"
	StatusCategoryValidation  StatusCategory = "validation"
	StatusCategoryConflict    StatusCategory = "conflict"
	StatusCategoryUnavailable StatusCategory = "unavailable"
)

type PassiveHealth string

const (
	PassiveHealthy     PassiveHealth = "healthy"
	PassiveDegraded    PassiveHealth = "degraded"
	PassiveUnavailable PassiveHealth = "unavailable"
)

type PassiveStatusClass string

const (
	PassiveStatusConnectivity    PassiveStatusClass = "connectivity"
	PassiveStatusActiveTransport PassiveStatusClass = "active_transport"
	PassiveStatusDataPlane       PassiveStatusClass = "data_plane"
)

// PassiveStatusResource contains cached or process metadata only. Status
// readers must never populate it by generating DNS, transport, tunnel, HTTP,
// webhook, or third-party traffic; explicit probing belongs to doctor.
type PassiveStatusResource struct {
	Class         PassiveStatusClass `json:"class"`
	Resource      ManagedResourceKey `json:"resource"`
	Condition     PassiveHealth      `json:"condition"`
	Mandatory     bool               `json:"mandatory"`
	Active        bool               `json:"active"`
	Version       string             `json:"version,omitempty"`
	Protocol      string             `json:"protocol,omitempty"`
	Generation    uint64             `json:"generation,omitempty"`
	RuntimeSHA256 string             `json:"runtime_sha256,omitempty"`
	Code          string             `json:"code"`
}

type PassiveStatusSnapshot struct {
	Resources []PassiveStatusResource `json:"resources"`
}

type StatusStateSource interface {
	ReadStatusState(context.Context) (model.State, error)
}

// PassiveStatusObserver deliberately exposes one read method and no probe or
// mutation method. Implementations inspect cached/process metadata only.
type PassiveStatusObserver interface {
	ReadPassiveStatus(context.Context, model.State) (PassiveStatusSnapshot, error)
}

type StatusComponent struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Bundled      bool     `json:"bundled"`
	SHA256       string   `json:"sha256,omitempty"`
	Capabilities []string `json:"capabilities"`
}

// StatusResource is a deliberately non-secret projection of authoritative
// resources. Credential references, keys, invite hashes, expose paths and
// upstreams never enter the report.
type StatusResource struct {
	Kind               string   `json:"kind"`
	ID                 string   `json:"id"`
	Name               string   `json:"name,omitempty"`
	OwnerKind          string   `json:"owner_kind,omitempty"`
	OwnerID            string   `json:"owner_id,omitempty"`
	State              string   `json:"state,omitempty"`
	ActiveTransport    string   `json:"active_transport,omitempty"`
	Provider           string   `json:"provider,omitempty"`
	OperationType      string   `json:"operation_type,omitempty"`
	Protocol           string   `json:"protocol,omitempty"`
	Port               int      `json:"port,omitempty"`
	Generation         uint64   `json:"generation,omitempty"`
	ExpectedGeneration uint64   `json:"expected_generation,omitempty"`
	DesiredGeneration  uint64   `json:"desired_generation,omitempty"`
	SHA256             string   `json:"sha256,omitempty"`
	Presets            []string `json:"presets,omitempty"`
}

type StatusPendingChange struct {
	OperationID                 string             `json:"operation_id"`
	OperationType               string             `json:"operation_type"`
	OperationExpectedGeneration uint64             `json:"operation_expected_generation"`
	OperationDesiredGeneration  uint64             `json:"operation_desired_generation"`
	TargetKind                  string             `json:"target_kind,omitempty"`
	TargetID                    string             `json:"target_id,omitempty"`
	Resource                    ManagedResourceKey `json:"resource"`
	Kind                        DesiredChangeKind  `json:"kind"`
	Impact                      ConvergenceImpact  `json:"impact"`
	FromSHA256                  string             `json:"from_sha256,omitempty"`
	ToSHA256                    string             `json:"to_sha256,omitempty"`
}

type StatusDrift struct {
	Resource       ManagedResourceKey `json:"resource"`
	Kind           OwnedDriftKind     `json:"kind"`
	Impact         ConvergenceImpact  `json:"impact"`
	ExpectedSHA256 string             `json:"expected_sha256,omitempty"`
	ActualSHA256   string             `json:"actual_sha256,omitempty"`
}

type StatusInvite struct {
	ID        string    `json:"id"`
	Purpose   string    `json:"purpose,omitempty"`
	NodeName  string    `json:"node_name"`
	NodeID    string    `json:"node_id,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type StatusLogOptIn struct {
	ID          string               `json:"id"`
	Scope       model.LogScope       `json:"scope"`
	Level       model.LogLevel       `json:"level"`
	Destination model.LogDestination `json:"destination"`
	StartedAt   time.Time            `json:"started_at"`
	ExpiresAt   time.Time            `json:"expires_at"`
}

type StatusCertificateCondition string

const (
	StatusCertificateHealthy  StatusCertificateCondition = "healthy"
	StatusCertificateExpiring StatusCertificateCondition = "expiring"
	StatusCertificateExpired  StatusCertificateCondition = "expired"
)

type StatusCertificate struct {
	ID                   string                     `json:"id"`
	Kind                 model.CertificateKind      `json:"kind"`
	OwnerKind            string                     `json:"owner_kind"`
	OwnerID              string                     `json:"owner_id"`
	Fingerprint          string                     `json:"fingerprint"`
	Generation           uint64                     `json:"generation"`
	CredentialGeneration uint64                     `json:"credential_generation"`
	NotAfter             time.Time                  `json:"not_after"`
	WarningStartsAt      time.Time                  `json:"warning_starts_at"`
	Condition            StatusCertificateCondition `json:"condition"`
}

type StatusBackup struct {
	ID              string            `json:"id"`
	State           model.BackupState `json:"state"`
	Format          string            `json:"format"`
	SHA256          string            `json:"sha256"`
	SizeBytes       int64             `json:"size_bytes"`
	StateGeneration uint64            `json:"state_generation"`
	CreatedAt       time.Time         `json:"created_at"`
}

type StatusProblem struct {
	Kind      string        `json:"kind"`
	ID        string        `json:"id"`
	Condition PassiveHealth `json:"condition"`
	Code      string        `json:"code"`
}

type StatusNotice struct {
	Code         string `json:"code"`
	Message      string `json:"message"`
	Command      string `json:"command,omitempty"`
	ResourceKind string `json:"resource_kind,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
}

type StatusReport struct {
	Role                  model.Role              `json:"role"`
	Overall               StatusOverall           `json:"overall"`
	Category              StatusCategory          `json:"category"`
	Generation            uint64                  `json:"generation"`
	DesiredGeneration     uint64                  `json:"desired_generation"`
	AppliedGeneration     uint64                  `json:"applied_generation"`
	BinaryVersion         string                  `json:"binary_version"`
	ManifestBinaryVersion string                  `json:"manifest_binary_version,omitempty"`
	ControlProtocols      []string                `json:"control_protocols"`
	Components            []StatusComponent       `json:"components"`
	Counts                map[string]int          `json:"counts"`
	Resources             []StatusResource        `json:"resources"`
	Runtime               []PassiveStatusResource `json:"runtime"`
	Pending               []StatusPendingChange   `json:"pending"`
	Drift                 []StatusDrift           `json:"drift"`
	ActiveInvites         []StatusInvite          `json:"active_invites"`
	LogOptIns             []StatusLogOptIn        `json:"log_opt_ins"`
	Certificates          []StatusCertificate     `json:"certificates"`
	Backups               []StatusBackup          `json:"backups"`
	Problems              []StatusProblem         `json:"problems"`
	Warnings              []StatusNotice          `json:"warnings"`
	RequiredActions       []StatusNotice          `json:"required_actions"`
}

type StatusCollector struct {
	role          model.Role
	binaryVersion string
	now           func() time.Time
	state         StatusStateSource
	planner       *ConvergencePlanner
	observer      PassiveStatusObserver
}

func NewStatusCollector(
	role model.Role,
	binaryVersion string,
	now func() time.Time,
	state StatusStateSource,
	planner *ConvergencePlanner,
	observer PassiveStatusObserver,
) (*StatusCollector, error) {
	if role != model.RoleGateway && role != model.RoleNode {
		return nil, fmt.Errorf("status role is invalid")
	}
	if strings.TrimSpace(binaryVersion) == "" || strings.ContainsAny(binaryVersion, "\r\n\x00") {
		return nil, fmt.Errorf("status binary version must be a single-line token")
	}
	if now == nil || nilInterface(state) || planner == nil || nilInterface(observer) {
		return nil, fmt.Errorf("status dependencies are incomplete")
	}
	return &StatusCollector{role: role, binaryVersion: binaryVersion, now: now, state: state, planner: planner, observer: observer}, nil
}

func (collector *StatusCollector) Collect(ctx context.Context) (StatusReport, error) {
	if ctx == nil {
		return StatusReport{}, fmt.Errorf("context is required")
	}
	if err := collector.validate(); err != nil {
		return StatusReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return StatusReport{}, err
	}
	report := emptyStatusReport(collector.role, collector.binaryVersion)
	state, err := collector.state.ReadStatusState(ctx)
	if err != nil {
		addStatusProblem(&report, StatusProblem{Kind: "state", ID: "authoritative", Condition: PassiveUnavailable, Code: "state_unavailable"})
		report.RequiredActions = append(report.RequiredActions, StatusNotice{
			Code: "validate_state", Message: "Inspect the local authoritative state and controller availability.", Command: "sudo vpnctl validate",
		})
		finalizeStatusReport(&report, false)
		return report, report.Validate()
	}
	report.Generation = state.Generation
	if state.Host.Role != collector.role || state.Validate() != nil {
		addStatusProblem(&report, StatusProblem{Kind: "state", ID: "authoritative", Condition: PassiveUnavailable, Code: "invalid_state"})
		report.RequiredActions = append(report.RequiredActions, StatusNotice{
			Code: "validate_state", Message: "Validate the authoritative state before any repair or apply.", Command: "sudo vpnctl validate",
		})
		finalizeStatusReport(&report, true)
		return report, report.Validate()
	}
	state, err = cloneStatusState(state)
	if err != nil {
		return StatusReport{}, err
	}
	now := collector.now().UTC()
	if now.IsZero() {
		return StatusReport{}, fmt.Errorf("status clock returned a zero time")
	}
	projectStatusState(&report, state, now)

	convergence, err := collector.planner.Plan(ctx)
	if err != nil {
		if errors.Is(err, ErrConvergencePlanInvalid) {
			addStatusProblem(&report, StatusProblem{Kind: "state", ID: "convergence", Condition: PassiveUnavailable, Code: "invalid_convergence_state"})
			report.RequiredActions = append(report.RequiredActions, StatusNotice{
				Code: "validate_convergence_state", Message: "Validate desired, applied, and pending convergence metadata.", Command: "sudo vpnctl validate",
			})
			finalizeStatusReport(&report, true)
			return report, report.Validate()
		}
		if err := ctx.Err(); err != nil {
			return StatusReport{}, err
		}
		addStatusProblem(&report, StatusProblem{Kind: "convergence", ID: "planner", Condition: PassiveUnavailable, Code: "convergence_unavailable"})
		report.RequiredActions = append(report.RequiredActions, StatusNotice{
			Code: "diagnose_convergence", Message: "Inspect local controller and owned-resource observation.", Command: "sudo vpnctl doctor",
		})
	} else {
		projectConvergence(&report, convergence)
		if report.Generation != convergence.DesiredGeneration {
			addStatusProblem(&report, StatusProblem{
				Kind: "snapshot", ID: "authoritative", Condition: PassiveUnavailable, Code: "status_generation_changed",
			})
			report.RequiredActions = append(report.RequiredActions, StatusNotice{
				Code: "refresh_status", Message: "Authoritative generation changed during passive status collection; run status again.", Command: "sudo vpnctl status",
			})
		}
	}

	observedState, err := cloneStatusState(state)
	if err != nil {
		return StatusReport{}, err
	}
	passive, err := collector.observer.ReadPassiveStatus(ctx, observedState)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return StatusReport{}, err
		}
		addStatusProblem(&report, StatusProblem{Kind: "runtime", ID: "passive-observer", Condition: PassiveUnavailable, Code: "passive_status_unavailable"})
		report.RequiredActions = append(report.RequiredActions, StatusNotice{
			Code: "diagnose_runtime", Message: "Run bounded active diagnostics for the unavailable runtime metadata.", Command: "sudo vpnctl doctor",
		})
	} else {
		canonical, canonicalErr := canonicalPassiveStatus(passive)
		if canonicalErr != nil {
			addStatusProblem(&report, StatusProblem{Kind: "runtime", ID: "passive-observer", Condition: PassiveUnavailable, Code: "invalid_passive_status"})
			report.RequiredActions = append(report.RequiredActions, StatusNotice{
				Code: "validate_runtime_status", Message: "The passive runtime status metadata is invalid.", Command: "sudo vpnctl validate",
			})
		} else {
			report.Runtime = canonical.Resources
			ensurePassiveCoverage(&report, state)
			for _, resource := range report.Runtime {
				if resource.Condition != PassiveHealthy && (resource.Mandatory || resource.Active) {
					addStatusProblem(&report, StatusProblem{
						Kind: string(resource.Class), ID: resourceOrder(resource.Resource),
						Condition: resource.Condition, Code: resource.Code,
					})
				}
			}
		}
	}
	finalizeStatusReport(&report, false)
	return report, report.Validate()
}

func (collector *StatusCollector) validate() error {
	if collector == nil || collector.now == nil || nilInterface(collector.state) || collector.planner == nil || nilInterface(collector.observer) {
		return fmt.Errorf("status collector is incomplete")
	}
	if collector.role != model.RoleGateway && collector.role != model.RoleNode {
		return fmt.Errorf("status collector role is invalid")
	}
	if strings.TrimSpace(collector.binaryVersion) == "" || strings.ContainsAny(collector.binaryVersion, "\r\n\x00") {
		return fmt.Errorf("status binary version is invalid")
	}
	return nil
}

func emptyStatusReport(role model.Role, binaryVersion string) StatusReport {
	return StatusReport{
		Role: role, Overall: StatusOverallHealthy, Category: StatusCategorySuccess, BinaryVersion: binaryVersion,
		ControlProtocols: []string{}, Components: []StatusComponent{}, Counts: map[string]int{},
		Resources: []StatusResource{}, Runtime: []PassiveStatusResource{}, Pending: []StatusPendingChange{},
		Drift: []StatusDrift{}, ActiveInvites: []StatusInvite{}, LogOptIns: []StatusLogOptIn{},
		Certificates: []StatusCertificate{}, Backups: []StatusBackup{}, Problems: []StatusProblem{},
		Warnings: []StatusNotice{}, RequiredActions: []StatusNotice{},
	}
}

func projectStatusState(report *StatusReport, state model.State, now time.Time) {
	report.ManifestBinaryVersion = state.Components.VPNCTLVersion
	report.ControlProtocols = append([]string{}, state.Components.ControlProtocols...)
	for _, pin := range state.Components.Components {
		report.Components = append(report.Components, StatusComponent{
			Name: pin.Name, Version: pin.Version, Bundled: pin.Bundled, SHA256: pin.SHA256,
			Capabilities: sortedStatusStrings(pin.Capabilities),
		})
	}
	sort.Slice(report.Components, func(left, right int) bool { return report.Components[left].Name < report.Components[right].Name })
	if report.BinaryVersion != report.ManifestBinaryVersion {
		addStatusProblem(report, StatusProblem{Kind: "component", ID: "vpnctl", Condition: PassiveDegraded, Code: "binary_manifest_version_mismatch"})
		report.RequiredActions = append(report.RequiredActions, StatusNotice{
			Code: "align_binary_bundle", Message: "The running vpnctl binary differs from the installed component manifest.", Command: "sudo vpnctl update",
			ResourceKind: "component", ResourceID: "vpnctl",
		})
	}

	report.Resources = statusResources(state)
	report.Counts = statusCounts(state)
	projectInvitesAndLogging(report, state, now)
	projectCertificates(report, state, now)
	projectBackups(report, state, now)
	projectStateProblems(report, state)
}

func projectConvergence(report *StatusReport, plan ConvergencePlan) {
	report.DesiredGeneration = plan.DesiredGeneration
	report.AppliedGeneration = plan.AppliedGeneration
	for _, change := range plan.Changes {
		report.Pending = append(report.Pending, StatusPendingChange{
			OperationID: change.OperationID, OperationType: change.OperationType,
			OperationExpectedGeneration: change.OperationExpectedGeneration,
			OperationDesiredGeneration:  change.OperationDesiredGeneration,
			TargetKind:                  change.TargetKind, TargetID: change.TargetID,
			Resource: change.Resource, Kind: change.Kind, Impact: change.Impact,
			FromSHA256: change.FromSHA256, ToSHA256: change.ToSHA256,
		})
	}
	report.Counts["pending_changes"] = len(report.Pending)
	if len(report.Pending) != 0 {
		report.Warnings = append(report.Warnings, StatusNotice{
			Code: "pending_changes", Message: fmt.Sprintf("%d registered pending resource change(s) await explicit apply.", len(report.Pending)),
		})
		report.RequiredActions = append(report.RequiredActions,
			StatusNotice{Code: "review_pending_changes", Message: "Review registered pending changes.", Command: "sudo vpnctl plan"},
			StatusNotice{Code: "apply_pending_changes", Message: "After review, explicitly apply registered pending changes.", Command: "sudo vpnctl apply"},
		)
	}
	for _, drift := range plan.Drift {
		report.Drift = append(report.Drift, StatusDrift{
			Resource: drift.Resource, Kind: drift.Kind, Impact: drift.Impact,
			ExpectedSHA256: drift.ExpectedSHA256, ActualSHA256: drift.ActualSHA256,
		})
		addStatusProblem(report, StatusProblem{
			Kind: "drift", ID: resourceOrder(drift.Resource), Condition: PassiveDegraded,
			Code: "owned_" + string(drift.Kind),
		})
	}
	report.Counts["drift"] = len(report.Drift)
	if len(plan.Drift) != 0 {
		report.Warnings = append(report.Warnings, StatusNotice{
			Code: "owned_drift", Message: fmt.Sprintf("%d vpnctl-owned resource(s) differ from the applied generation.", len(plan.Drift)),
		})
		report.RequiredActions = append(report.RequiredActions, StatusNotice{
			Code: "repair_owned_drift", Message: "Preview and explicitly repair vpnctl-owned drift.", Command: "sudo vpnctl repair --dry-run",
		})
	}
}

func projectInvitesAndLogging(report *StatusReport, state model.State, now time.Time) {
	for _, invite := range state.Invites {
		if invite.State != model.InviteActive || now.Before(invite.IssuedAt) || !now.Before(invite.ExpiresAt) {
			continue
		}
		report.ActiveInvites = append(report.ActiveInvites, StatusInvite{
			ID: invite.ID, Purpose: invite.Purpose, NodeName: invite.NodeName, NodeID: invite.NodeID,
			IssuedAt: invite.IssuedAt.UTC(), ExpiresAt: invite.ExpiresAt.UTC(),
		})
	}
	sort.Slice(report.ActiveInvites, func(left, right int) bool { return report.ActiveInvites[left].ID < report.ActiveInvites[right].ID })
	report.Counts["active_invites"] = len(report.ActiveInvites)
	if len(report.ActiveInvites) != 0 {
		report.Warnings = append(report.Warnings, StatusNotice{
			Code: "active_invites", Message: fmt.Sprintf("%d unexpired one-time invite(s) remain active.", len(report.ActiveInvites)),
		})
		for _, invite := range report.ActiveInvites {
			report.RequiredActions = append(report.RequiredActions, StatusNotice{
				Code: "cancel_unused_invite", Message: "Cancel this invite if it will not be used.",
				Command: "sudo vpnctl invite cancel " + invite.ID, ResourceKind: "invite", ResourceID: invite.ID,
			})
		}
	}

	for _, session := range state.Logging {
		if session.State != model.LogActive || now.Before(session.StartedAt) || !now.Before(session.ExpiresAt) {
			continue
		}
		report.LogOptIns = append(report.LogOptIns, StatusLogOptIn{
			ID: session.ID, Scope: session.Scope, Level: session.Level, Destination: session.Destination,
			StartedAt: session.StartedAt.UTC(), ExpiresAt: session.ExpiresAt.UTC(),
		})
	}
	sort.Slice(report.LogOptIns, func(left, right int) bool { return report.LogOptIns[left].ID < report.LogOptIns[right].ID })
	report.Counts["log_opt_ins"] = len(report.LogOptIns)
	if len(report.LogOptIns) != 0 {
		report.Warnings = append(report.Warnings, StatusNotice{
			Code: "expanded_logging_active", Message: fmt.Sprintf("%d temporary expanded logging opt-in(s) are active.", len(report.LogOptIns)),
		})
		for _, session := range report.LogOptIns {
			report.RequiredActions = append(report.RequiredActions, StatusNotice{
				Code: "disable_logging_early", Message: "Disable this logging scope early when diagnostics are complete.",
				Command: "sudo vpnctl log disable " + string(session.Scope), ResourceKind: "logging", ResourceID: session.ID,
			})
		}
	}
}

func projectCertificates(report *StatusReport, state model.State, now time.Time) {
	expiring, expired := 0, 0
	for _, certificate := range state.Certificates {
		warningStartsAt := certificate.NotAfter.Add(-time.Duration(certificate.WarningDays) * 24 * time.Hour)
		condition := StatusCertificateHealthy
		if !now.Before(certificate.NotAfter) {
			condition = StatusCertificateExpired
		} else if !now.Before(warningStartsAt) {
			condition = StatusCertificateExpiring
		}
		item := StatusCertificate{
			ID: certificate.ID, Kind: certificate.Kind, OwnerKind: certificate.OwnerKind, OwnerID: certificate.OwnerID,
			Fingerprint: certificate.Fingerprint, Generation: certificate.Generation,
			CredentialGeneration: certificate.EffectiveCredentialGeneration(), NotAfter: certificate.NotAfter.UTC(),
			WarningStartsAt: warningStartsAt.UTC(), Condition: condition,
		}
		report.Certificates = append(report.Certificates, item)
		if condition == StatusCertificateHealthy {
			continue
		}
		if condition == StatusCertificateExpired {
			expired++
		} else {
			expiring++
		}
		code := "certificate_expiring"
		message := fmt.Sprintf("Certificate %s expires at %s.", certificate.ID, certificate.NotAfter.UTC().Format(time.RFC3339))
		if condition == StatusCertificateExpired {
			code = "certificate_expired"
			message = fmt.Sprintf("Certificate %s expired at %s.", certificate.ID, certificate.NotAfter.UTC().Format(time.RFC3339))
			addStatusProblem(report, StatusProblem{Kind: "certificate", ID: certificate.ID, Condition: PassiveUnavailable, Code: code})
		}
		report.Warnings = append(report.Warnings, StatusNotice{
			Code: code, Message: message, ResourceKind: "certificate", ResourceID: certificate.ID,
		})
		report.RequiredActions = append(report.RequiredActions, certificateStatusAction(state.Host.Role, certificate, condition))
	}
	sort.Slice(report.Certificates, func(left, right int) bool { return report.Certificates[left].ID < report.Certificates[right].ID })
	report.Counts["expiring_certificates"] = expiring
	report.Counts["expired_certificates"] = expired
}

func certificateStatusAction(role model.Role, certificate model.Certificate, condition StatusCertificateCondition) StatusNotice {
	command := "sudo vpnctl trust rotate"
	code := "rotate_control_trust"
	message := "Rotate control trust before certificate expiry."
	switch certificate.Kind {
	case model.CertificatePublicIngress:
		command, code, message = "sudo vpnctl cert rotate", "rotate_public_certificate", "Rotate the public ingress certificate and re-register affected external webhooks."
	case model.CertificateControlNode:
		command, code, message = "sudo vpnctl node rotate", "rotate_node_credentials", "Rotate the complete node credential set before certificate expiry."
		if condition == StatusCertificateExpired {
			command, code, message = "sudo vpnctl node recover", "recover_node_credentials", "Recover the original node identity with a gateway-issued one-time token."
			if role == model.RoleGateway {
				command = "sudo vpnctl node recover " + certificate.OwnerID
				message = "Issue a one-time recovery token, then recover credentials on the original private node."
			}
		}
	}
	return StatusNotice{Code: code, Message: message, Command: command, ResourceKind: "certificate", ResourceID: certificate.ID}
}

func projectBackups(report *StatusReport, state model.State, now time.Time) {
	for _, backup := range state.Backups {
		report.Backups = append(report.Backups, StatusBackup{
			ID: backup.ID, State: backup.State, Format: backup.Format, SHA256: backup.SHA256,
			SizeBytes: backup.SizeBytes, StateGeneration: backup.StateGeneration, CreatedAt: backup.CreatedAt.UTC(),
		})
	}
	sort.Slice(report.Backups, func(left, right int) bool {
		if report.Backups[left].CreatedAt.Equal(report.Backups[right].CreatedAt) {
			return report.Backups[left].ID < report.Backups[right].ID
		}
		return report.Backups[left].CreatedAt.Before(report.Backups[right].CreatedAt)
	})
	if state.Host.Role != model.RoleGateway {
		return
	}
	if len(report.Backups) == 0 {
		report.Warnings = append(report.Warnings, StatusNotice{Code: "backup_missing", Message: "No successful portable gateway backup is recorded."})
		report.RequiredActions = append(report.RequiredActions, StatusNotice{
			Code: "create_gateway_backup", Message: "Create and store an encrypted portable gateway backup.", Command: "sudo vpnctl backup",
		})
		return
	}
	latest := report.Backups[len(report.Backups)-1]
	if now.Sub(latest.CreatedAt) >= StatusBackupWarningAge {
		report.Warnings = append(report.Warnings, StatusNotice{
			Code: "backup_stale", Message: fmt.Sprintf("Latest portable gateway backup is at least 30 days old (%s).", latest.CreatedAt.Format(time.RFC3339)),
			ResourceKind: "backup", ResourceID: latest.ID,
		})
		report.RequiredActions = append(report.RequiredActions, StatusNotice{
			Code: "refresh_gateway_backup", Message: "Create a fresh encrypted portable gateway backup.", Command: "sudo vpnctl backup",
			ResourceKind: "backup", ResourceID: latest.ID,
		})
	}
}

func projectStateProblems(report *StatusReport, state model.State) {
	for _, transport := range state.Transports {
		if transport.State == model.TransportDegraded {
			addStatusProblem(report, StatusProblem{
				Kind: "transport", ID: statusTransportID(transport), Condition: PassiveDegraded, Code: "transport_degraded",
			})
		}
	}
	for _, expose := range state.Exposes {
		if expose.State == model.ExposeDegraded {
			addStatusProblem(report, StatusProblem{Kind: "expose", ID: expose.ID, Condition: PassiveDegraded, Code: "expose_degraded"})
		}
	}
	for _, operation := range state.Operations {
		if operation.State == model.OperationDegraded || operation.State == model.OperationFailed {
			condition := PassiveDegraded
			if operation.State == model.OperationFailed {
				condition = PassiveUnavailable
			}
			addStatusProblem(report, StatusProblem{Kind: "operation", ID: operation.ID, Condition: condition, Code: "operation_" + string(operation.State)})
		}
	}
}

func ensurePassiveCoverage(report *StatusReport, state model.State) {
	hasControl := false
	hasGateway := state.Host.Role != model.RoleNode || !nodeHasGatewayTrust(state)
	hasDataPlane := false
	observedTransports := make(map[string]struct{})
	for _, item := range report.Runtime {
		if item.Class == PassiveStatusConnectivity && item.Resource.ID == "control" && item.Mandatory && item.Active {
			hasControl = true
		}
		if item.Class == PassiveStatusConnectivity && item.Resource.ID == "gateway" && item.Mandatory && item.Active {
			hasGateway = true
		}
		if item.Class == PassiveStatusDataPlane && item.Active {
			hasDataPlane = true
		}
		if item.Class == PassiveStatusActiveTransport && item.Active {
			observedTransports[item.Resource.ID] = struct{}{}
		}
	}
	if !hasControl {
		addMissingPassiveResource(report, "connectivity", "control", "control_status_missing")
	}
	if !hasGateway {
		addMissingPassiveResource(report, "connectivity", "gateway", "gateway_status_missing")
	}
	if !hasDataPlane {
		addMissingPassiveResource(report, "data_plane", "active", "data_plane_status_missing")
	}
	for _, transport := range state.Transports {
		if transport.State != model.TransportActive && transport.State != model.TransportDegraded {
			continue
		}
		id := statusTransportID(transport)
		if _, observed := observedTransports[id]; !observed {
			addMissingPassiveResource(report, "active_transport", id, "transport_status_missing")
		}
	}
}

func addMissingPassiveResource(report *StatusReport, kind, id, code string) {
	addStatusProblem(report, StatusProblem{Kind: kind, ID: id, Condition: PassiveUnavailable, Code: code})
	report.RequiredActions = append(report.RequiredActions, StatusNotice{
		Code: code, Message: "Required passive runtime metadata is unavailable.", Command: "sudo vpnctl doctor",
		ResourceKind: kind, ResourceID: id,
	})
}

func nodeHasGatewayTrust(state model.State) bool {
	for _, node := range state.Nodes {
		if node.Gateway != nil && node.Lifecycle == model.LifecycleActive {
			return true
		}
	}
	return false
}

func finalizeStatusReport(report *StatusReport, invalid bool) {
	sortStatusReport(report)
	if invalid {
		report.Overall = StatusOverallFailed
		report.Category = StatusCategoryValidation
		return
	}
	category := StatusCategorySuccess
	for _, problem := range report.Problems {
		if problem.Kind == "drift" {
			if category == StatusCategorySuccess {
				category = StatusCategoryConflict
			}
			continue
		}
		category = StatusCategoryUnavailable
	}
	report.Category = category
	if category == StatusCategorySuccess {
		report.Overall = StatusOverallHealthy
	} else {
		report.Overall = StatusOverallDegraded
	}
}

func sortStatusReport(report *StatusReport) {
	sort.Slice(report.Problems, func(left, right int) bool {
		return report.Problems[left].Kind+"\x00"+report.Problems[left].ID < report.Problems[right].Kind+"\x00"+report.Problems[right].ID
	})
	sort.Slice(report.Warnings, func(left, right int) bool {
		return statusNoticeOrder(report.Warnings[left]) < statusNoticeOrder(report.Warnings[right])
	})
	sort.Slice(report.RequiredActions, func(left, right int) bool {
		return statusNoticeOrder(report.RequiredActions[left]) < statusNoticeOrder(report.RequiredActions[right])
	})
}

func statusNoticeOrder(notice StatusNotice) string {
	return notice.Code + "\x00" + notice.ResourceKind + "\x00" + notice.ResourceID
}

func addStatusProblem(report *StatusReport, problem StatusProblem) {
	for _, existing := range report.Problems {
		if existing.Kind == problem.Kind && existing.ID == problem.ID && existing.Code == problem.Code {
			return
		}
	}
	report.Problems = append(report.Problems, problem)
}

func canonicalPassiveStatus(snapshot PassiveStatusSnapshot) (PassiveStatusSnapshot, error) {
	if snapshot.Resources == nil {
		return PassiveStatusSnapshot{}, fmt.Errorf("passive resources must be present")
	}
	resources := append([]PassiveStatusResource{}, snapshot.Resources...)
	for index, resource := range resources {
		if err := resource.validate(); err != nil {
			return PassiveStatusSnapshot{}, fmt.Errorf("passive resource %d: %w", index, err)
		}
	}
	sort.Slice(resources, func(left, right int) bool {
		return string(resources[left].Class)+"\x00"+resourceOrder(resources[left].Resource) <
			string(resources[right].Class)+"\x00"+resourceOrder(resources[right].Resource)
	})
	for index := 1; index < len(resources); index++ {
		if resources[index].Class == resources[index-1].Class && resources[index].Resource == resources[index-1].Resource {
			return PassiveStatusSnapshot{}, fmt.Errorf("passive resource is duplicated")
		}
	}
	return PassiveStatusSnapshot{Resources: resources}, nil
}

func (resource PassiveStatusResource) validate() error {
	switch resource.Class {
	case PassiveStatusConnectivity, PassiveStatusActiveTransport, PassiveStatusDataPlane:
	default:
		return fmt.Errorf("class is invalid")
	}
	if resource.Class == PassiveStatusActiveTransport && !resource.Active {
		return fmt.Errorf("active transport status must be active")
	}
	if err := resource.Resource.validate(); err != nil {
		return err
	}
	switch resource.Condition {
	case PassiveHealthy, PassiveDegraded, PassiveUnavailable:
	default:
		return fmt.Errorf("condition is invalid")
	}
	if resource.Code == "" || !statusCodePattern.MatchString(resource.Code) {
		return fmt.Errorf("code is invalid")
	}
	for _, value := range []string{resource.Version, resource.Protocol} {
		if strings.ContainsAny(value, "\r\n\x00") || len(value) > 128 {
			return fmt.Errorf("version or protocol is invalid")
		}
	}
	if resource.RuntimeSHA256 != "" && validateFingerprint(resource.RuntimeSHA256) != nil {
		return fmt.Errorf("runtime SHA-256 is invalid")
	}
	return nil
}

func (report StatusReport) Validate() error {
	if report.Role != model.RoleGateway && report.Role != model.RoleNode {
		return fmt.Errorf("status role is invalid")
	}
	if report.Overall != StatusOverallHealthy && report.Overall != StatusOverallDegraded && report.Overall != StatusOverallFailed {
		return fmt.Errorf("status overall is invalid")
	}
	switch report.Category {
	case StatusCategorySuccess, StatusCategoryValidation, StatusCategoryConflict, StatusCategoryUnavailable:
	default:
		return fmt.Errorf("status category is invalid")
	}
	if strings.TrimSpace(report.BinaryVersion) == "" || strings.ContainsAny(report.BinaryVersion, "\r\n\x00") {
		return fmt.Errorf("binary version is invalid")
	}
	if report.ControlProtocols == nil || report.Components == nil || report.Counts == nil || report.Resources == nil ||
		report.Runtime == nil || report.Pending == nil || report.Drift == nil || report.ActiveInvites == nil ||
		report.LogOptIns == nil || report.Certificates == nil || report.Backups == nil || report.Problems == nil ||
		report.Warnings == nil || report.RequiredActions == nil {
		return fmt.Errorf("status collections must be present")
	}
	if report.Category == StatusCategorySuccess && (report.Overall != StatusOverallHealthy || len(report.Problems) != 0) {
		return fmt.Errorf("successful status must be healthy and problem-free")
	}
	if report.Category == StatusCategoryValidation && report.Overall != StatusOverallFailed {
		return fmt.Errorf("invalid state status must be failed")
	}
	if (report.Category == StatusCategoryConflict || report.Category == StatusCategoryUnavailable) && report.Overall != StatusOverallDegraded {
		return fmt.Errorf("runtime problem status must be degraded")
	}
	for key, count := range report.Counts {
		if key == "" || !statusCodePattern.MatchString(key) || count < 0 {
			return fmt.Errorf("status count is invalid")
		}
	}
	for index, resource := range report.Runtime {
		if err := resource.validate(); err != nil {
			return fmt.Errorf("runtime %d: %w", index, err)
		}
	}
	for index, problem := range report.Problems {
		if problem.Kind == "" || problem.ID == "" || problem.Code == "" || !statusCodePattern.MatchString(problem.Code) {
			return fmt.Errorf("problem %d is invalid", index)
		}
		if problem.Condition != PassiveDegraded && problem.Condition != PassiveUnavailable {
			return fmt.Errorf("problem %d condition is invalid", index)
		}
	}
	for index, notice := range append(append([]StatusNotice{}, report.Warnings...), report.RequiredActions...) {
		if notice.Code == "" || !statusCodePattern.MatchString(notice.Code) || notice.Message == "" || strings.ContainsAny(notice.Message, "\r\n\x00") {
			return fmt.Errorf("notice %d is invalid", index)
		}
	}
	return nil
}

func statusResources(state model.State) []StatusResource {
	resources := make([]StatusResource, 0, len(state.Nodes)+len(state.Clients)+len(state.Presets)+len(state.Policies)+len(state.Transports)+len(state.Exposes)+len(state.Operations))
	for _, node := range state.Nodes {
		resources = append(resources, StatusResource{
			Kind: "node", ID: node.ID, Name: node.Name, State: string(node.Lifecycle), ActiveTransport: string(node.ActiveTransport),
			Generation: node.CredentialGeneration, Presets: sortedStatusStrings(node.AssignedPresets),
		})
	}
	for _, client := range state.Clients {
		resources = append(resources, StatusResource{
			Kind: "client", ID: client.ID, Name: client.Name, State: string(client.Lifecycle), ActiveTransport: string(client.ActiveTransport),
			Generation: client.CredentialGeneration, Presets: sortedStatusStrings(client.AssignedPresets),
		})
	}
	for _, preset := range state.Presets {
		resources = append(resources, StatusResource{Kind: "preset", ID: preset.Name, Name: preset.Name, Generation: preset.Generation, SHA256: preset.EffectiveHash})
	}
	for _, policy := range state.Policies {
		id := string(policy.TargetKind) + ":" + policy.TargetID
		resources = append(resources, StatusResource{
			Kind: "policy", ID: id, OwnerKind: string(policy.TargetKind), OwnerID: policy.TargetID,
			Generation: policy.Generation, SHA256: policy.EffectiveHash, Presets: sortedStatusStrings(policy.PresetNames),
		})
	}
	for _, transport := range state.Transports {
		resources = append(resources, StatusResource{
			Kind: "transport", ID: statusTransportID(transport), OwnerKind: string(transport.OwnerKind), OwnerID: transport.OwnerID,
			State: string(transport.State), Provider: transport.Provider, Protocol: string(transport.Protocol), Port: transport.Port,
			Generation: transport.CredentialGeneration, SHA256: transport.ConfigHash,
		})
	}
	for _, expose := range state.Exposes {
		resources = append(resources, StatusResource{
			Kind: "expose", ID: expose.ID, Name: expose.Name, OwnerKind: "node", OwnerID: expose.NodeID,
			State: string(expose.State), Port: expose.TunnelPort, Generation: expose.Generation,
		})
	}
	for _, operation := range state.Operations {
		resources = append(resources, StatusResource{
			Kind: "operation", ID: operation.ID, OwnerKind: operation.TargetKind, OwnerID: operation.TargetID,
			State: string(operation.State), OperationType: string(operation.Type),
			ExpectedGeneration: operation.ExpectedGeneration, DesiredGeneration: operation.DesiredGeneration,
		})
	}
	sort.Slice(resources, func(left, right int) bool {
		return resources[left].Kind+"\x00"+resources[left].ID < resources[right].Kind+"\x00"+resources[right].ID
	})
	return resources
}

func statusCounts(state model.State) map[string]int {
	activeNodes, activeClients, activeTransports, readyExposes, pendingOperations := 0, 0, 0, 0, 0
	for _, node := range state.Nodes {
		if node.Lifecycle == model.LifecycleActive {
			activeNodes++
		}
	}
	for _, client := range state.Clients {
		if client.Lifecycle == model.LifecycleActive {
			activeClients++
		}
	}
	for _, transport := range state.Transports {
		if transport.State == model.TransportActive || transport.State == model.TransportDegraded {
			activeTransports++
		}
	}
	for _, expose := range state.Exposes {
		if expose.State == model.ExposeReady {
			readyExposes++
		}
	}
	for _, operation := range state.Operations {
		if operation.State == model.OperationPending {
			pendingOperations++
		}
	}
	return map[string]int{
		"nodes": len(state.Nodes), "active_nodes": activeNodes,
		"clients": len(state.Clients), "active_clients": activeClients,
		"presets": len(state.Presets), "policies": len(state.Policies),
		"transports": len(state.Transports), "active_transports": activeTransports,
		"exposes": len(state.Exposes), "ready_exposes": readyExposes,
		"certificates": len(state.Certificates), "operations": len(state.Operations),
		"pending_operations": pendingOperations, "backups": len(state.Backups),
	}
}

func statusTransportID(transport model.Transport) string {
	return string(transport.OwnerKind) + ":" + transport.OwnerID + ":" + string(transport.Kind)
}

func sortedStatusStrings(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	return result
}

func cloneStatusState(state model.State) (model.State, error) {
	encoded, err := model.EncodeState(state)
	if err != nil {
		return model.State{}, fmt.Errorf("clone status state: %w", err)
	}
	clone, err := model.DecodeState(encoded)
	if err != nil {
		return model.State{}, fmt.Errorf("decode cloned status state: %w", err)
	}
	return clone, nil
}

var statusCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
